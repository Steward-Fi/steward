/**
 * Approval concurrency, fault-injection, and crash-recovery matrix (spec §13).
 * Uses real Promise.all races and the service's named fault hooks (production
 * no-ops; not settable from runtime input). Under PGLite the per-tenant audit
 * queue + unique/revision constraints yield exactly one transition (C14).
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  approvalQueue,
  closeDb,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { providerActionService } from "../services/provider-action-service";
import { AuditUnavailableError, providerApprovalService } from "../services/provider-approval";
import {
  auditCount,
  bindingRow,
  correlatedAudit,
  createApprovalRequired,
  F,
  freshMfa,
  queueRow,
  seedFixture,
} from "./provider-approval-fixture";

setDefaultTimeout(120_000);

async function wipe() {
  const db = getDb();
  for (const t of [
    providerActionAuditOutbox,
    approvalQueue,
    providerActionBindings,
    intents,
    providerGrants,
    providerRoleBindings,
    providerOperations,
    providerAccounts,
    secretRoutes,
    secrets,
    workspaces,
    userTenants,
    users,
    tenants,
  ]) {
    await db.delete(t);
  }
}

async function withRealAuditFailure<T>(run: () => Promise<T>): Promise<T> {
  const previous = process.env.STEWARD_AUDIT_HMAC_KEY;
  process.env.STEWARD_AUDIT_HMAC_KEY = "too-weak";
  __resetAuditHmacKeyCacheForTests();
  try {
    return await run();
  } finally {
    if (previous === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previous;
    __resetAuditHmacKeyCacheForTests();
  }
}

function decideBody(
  intentId: string,
  requestHash: string,
  actionDigest: string,
  overrides: Partial<Parameters<typeof providerApprovalService.decide>[0]> = {},
) {
  return {
    intentId,
    tenantId: F.TENANT,
    authenticatedUserId: F.APPROVER,
    sessionMfaVerifiedAt: freshMfa(),
    decision: "approve" as const,
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey: "conc-key",
    ...overrides,
  };
}

describe("provider approval concurrency and fault matrix", () => {
  const priorExecutionAuthSecret = process.env.STEWARD_EXECUTION_AUTH_SECRET;
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "1".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    if (priorExecutionAuthSecret === undefined) delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    else process.env.STEWARD_EXECUTION_AUTH_SECRET = priorExecutionAuthSecret;
  });
  beforeEach(async () => {
    await wipe();
    await seedFixture();
  });
  afterEach(() => {
    providerApprovalService.faultHooks = {};
  });

  test("C01: two humans approve the same pending action concurrently => exactly one transition + one decided event", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // APPROVER_2 already exists (fixture) as an admin member; add a second
    // eligible workspace_approver binding for the race.
    await getDb().insert(providerRoleBindings).values({
      tenantId: F.TENANT,
      workspaceId: F.WORKSPACE,
      principalType: "human",
      principalId: F.APPROVER_2,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: F.GRANTOR,
      reason: "second approver",
    });
    const [r1, r2] = await Promise.all([
      providerApprovalService.decide(
        decideBody(intentId, requestHash, actionDigest, { idempotencyKey: "c01-a" }),
      ),
      providerApprovalService.decide(
        decideBody(intentId, requestHash, actionDigest, {
          authenticatedUserId: F.APPROVER_2,
          idempotencyKey: "c01-b",
        }),
      ),
    ]);
    const oks = [r1, r2].filter((r) => r.ok).length;
    expect(oks).toBe(1);
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approved");
    expect(b.bindingRevision).toBe(2);
    // exactly one decided event.
    const decided = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.approval.decided",
    );
    expect(decided.length).toBe(1);
  });

  test("C02: approve and deny race => exactly one immutable decision wins, tuple is wholly one or the other", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const [r1, r2] = await Promise.all([
      providerApprovalService.decide(
        decideBody(intentId, requestHash, actionDigest, { idempotencyKey: "c02-approve" }),
      ),
      providerApprovalService.decide(
        decideBody(intentId, requestHash, actionDigest, {
          decision: "deny",
          reasonCode: "approver_manual_deny",
          idempotencyKey: "c02-deny",
        }),
      ),
    ]);
    expect([r1, r2].filter((r) => r.ok).length).toBe(1);
    const b = await bindingRow(intentId);
    expect(["approved", "approval_denied"]).toContain(b.status);
    const q = await queueRow(intentId);
    expect(b.status === "approved" ? q.status === "approved" : q.status === "rejected").toBe(true);
  });

  test("C05: many concurrent execute calls => one approved->ready update, one resumeAttemptId, one ready event", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideBody(intentId, requestHash, actionDigest));
    const results = await Promise.all(
      Array.from({ length: 25 }, () =>
        providerApprovalService.resume({ intentId, tenantId: F.TENANT }),
      ),
    );
    const readyIds = new Set(
      results.filter((r) => r.ok).map((r) => (r as { resumeAttemptId?: string }).resumeAttemptId),
    );
    expect(readyIds.size).toBe(1);
    const b = await bindingRow(intentId);
    expect(b.status).toBe("execution_ready");
    expect(b.bindingRevision).toBe(3);
    const ready = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.resume.ready",
    );
    expect(ready.length).toBe(1);
  });

  // C06/C07/C08: a dependency change that commits before the guarded resume claim
  // is seen by the in-tx revalidation (which reads current state at claim time)
  // and stales the action; no ready state is produced. (PGLite is single-writer,
  // so a genuinely-concurrent mid-transaction commit cannot be injected without
  // deadlock; committing the change immediately before resume is the equivalent
  // deterministic oracle for the revalidation-at-claim predicate.)
  test("P2-2: resume transaction rechecks the execute caller and rejects unrelated principals", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const approved = await providerApprovalService.decide(
      decideBody(intentId, requestHash, actionDigest),
    );
    expect(approved.ok).toBe(true);

    const result = await providerApprovalService.resume({
      intentId,
      tenantId: F.TENANT,
      caller: { userId: F.APPROVER_2 },
    });
    expect(result).toEqual({
      ok: false,
      code: "SCOPE_RESOURCE_NOT_FOUND",
      httpStatus: 404,
    });
    expect((await bindingRow(intentId)).status).toBe("approved");
    expect((await queueRow(intentId)).status).toBe("approved");
  });

  test("C06: grant revoked before the resume claim => stale, no ready state", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideBody(intentId, requestHash, actionDigest));
    await getDb()
      .update(providerGrants)
      .set({ status: "revoked" })
      .where(eq(providerGrants.id, F.GRANT));
    const res = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("APPROVAL_GRANT_STALE");
    expect((await bindingRow(intentId)).status).toBe("approval_stale");
    // No ready audit event was produced.
    const ready = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.resume.ready",
    );
    expect(ready.length).toBe(0);
  });

  test("C08: credential rotated before the resume claim => stale credential, no ready state", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideBody(intentId, requestHash, actionDigest));
    await getDb()
      .update(providerAccounts)
      .set({ credentialVersion: 2 })
      .where(eq(providerAccounts.id, F.ACCOUNT));
    const res = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("APPROVAL_CREDENTIAL_STALE");
    expect((await bindingRow(intentId)).status).toBe("approval_stale");
  });

  test("C13 (codex P2): concurrent stale attempts emit exactly one staled event, no double audit", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideBody(intentId, requestHash, actionDigest));
    // Revoke a matched grant so both concurrent resume attempts detect a stale
    // condition; the guarded CAS must let only ONE win + emit one staled event.
    await getDb()
      .update(providerGrants)
      .set({ status: "revoked" })
      .where(eq(providerGrants.id, F.GRANT));
    const results = await Promise.all([
      providerApprovalService.resume({ intentId, tenantId: F.TENANT }),
      providerApprovalService.resume({ intentId, tenantId: F.TENANT }),
      providerApprovalService.resume({ intentId, tenantId: F.TENANT }),
    ]);
    // All fail (stale); the binding is stale exactly once.
    expect(results.every((r) => !r.ok)).toBe(true);
    expect((await bindingRow(intentId)).status).toBe("approval_stale");
    const staled = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.approval.staled",
    );
    expect(staled.length).toBe(1);
  });

  test("C09/C10/N49: audit append fault rolls back the WHOLE tuple (evidence before visibility)", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const auditsBefore = await auditCount();
    // Inject an audit failure at the append boundary.
    providerApprovalService.faultHooks = {
      beforeAudit: () => {
        throw new AuditUnavailableError("audit unavailable");
      },
    };
    const res = await providerApprovalService.decide(
      decideBody(intentId, requestHash, actionDigest),
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE");
    expect(res.httpStatus).toBe(503);
    // Lifecycle tuple fully rolled back: still pending, no new audit rows.
    const b = await bindingRow(intentId);
    expect(b.status).toBe("pending_approval");
    expect(b.bindingRevision).toBe(1);
    const q = await queueRow(intentId);
    expect(q.status).toBe("pending");
    const i = await getDb().select().from(intents).where(eq(intents.id, intentId));
    expect(i[0].status).toBe("pending");
    expect(await auditCount()).toBe(auditsBefore);
  });

  test("P2-1 decide: real audit persistence failure returns exact audit-unavailable code and rolls back", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const auditsBefore = await auditCount();
    const res = await withRealAuditFailure(() =>
      providerApprovalService.decide(decideBody(intentId, requestHash, actionDigest)),
    );

    expect(res).toEqual({
      ok: false,
      code: "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE",
      httpStatus: 503,
    });
    const binding = await bindingRow(intentId);
    expect(binding.status).toBe("pending_approval");
    expect(binding.bindingRevision).toBe(1);
    expect((await queueRow(intentId)).status).toBe("pending");
    const [intent] = await getDb().select().from(intents).where(eq(intents.id, intentId));
    expect(intent.status).toBe("pending");
    expect(await auditCount()).toBe(auditsBefore);
  });

  test("P2-1 resume: real audit persistence failure returns exact audit-unavailable code and rolls back", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const approved = await providerApprovalService.decide(
      decideBody(intentId, requestHash, actionDigest),
    );
    expect(approved.ok).toBe(true);
    const auditsBefore = await auditCount();

    const res = await withRealAuditFailure(() =>
      providerApprovalService.resume({ intentId, tenantId: F.TENANT }),
    );

    expect(res).toEqual({
      ok: false,
      code: "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE",
      httpStatus: 503,
    });
    const binding = await bindingRow(intentId);
    expect(binding.status).toBe("approved");
    expect(binding.bindingRevision).toBe(2);
    expect(binding.resumeAttemptId).toBeNull();
    expect((await queueRow(intentId)).status).toBe("approved");
    const [intent] = await getDb().select().from(intents).where(eq(intents.id, intentId));
    expect(intent.executedBy).toBeNull();
    expect(await auditCount()).toBe(auditsBefore);
  });

  test("C2 crash recovery: a crash between commit and drain leaves an undelivered outbox row; the sweeper signs it exactly once", async () => {
    // Create an approval-required action but SIMULATE a crash before the drain by
    // marking the just-created outbox row undelivered again (createApprovalRequired
    // already drains). Instead: create a fresh action and null delivered_at to
    // emulate a crash between commit and drain.
    const { intentId } = await createApprovalRequired();
    await getDb()
      .update(providerActionAuditOutbox)
      .set({ deliveredAt: null })
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    // Delete any signed event that was produced so we can prove the sweeper
    // produces exactly one.
    await getDb().execute(
      sql`DELETE FROM audit_events WHERE tenant_id = ${F.TENANT} AND resource_id = ${intentId}`,
    );
    // First sweep signs it; second sweep is a no-op (exactly once).
    const first = await providerActionService.recoverUnsignedIntents(F.TENANT, intentId);
    const second = await providerActionService.recoverUnsignedIntents(F.TENANT, intentId);
    expect(first).toBe(1);
    expect(second).toBe(0);
    const events = await correlatedAudit(intentId);
    expect(events.filter((e) => e.action === "provider.action.approval_required").length).toBe(1);
    // The outbox row is delivered.
    const [row] = await getDb()
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    expect(row.deliveredAt).not.toBeNull();
  });

  test("C2 recovery is idempotent under concurrency: two parallel sweeps sign exactly once", async () => {
    const { intentId } = await createApprovalRequired();
    await getDb()
      .update(providerActionAuditOutbox)
      .set({ deliveredAt: null })
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    await getDb().execute(
      sql`DELETE FROM audit_events WHERE tenant_id = ${F.TENANT} AND resource_id = ${intentId}`,
    );
    const [a, b] = await Promise.all([
      providerActionService.recoverUnsignedIntents(F.TENANT, intentId),
      providerActionService.recoverUnsignedIntents(F.TENANT, intentId),
    ]);
    expect(a + b).toBe(1);
    const events = await correlatedAudit(intentId);
    expect(events.length).toBe(1);
  });
});
