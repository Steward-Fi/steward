/**
 * PR3 approval lifecycle (state machine) integration tests against PGLite.
 * Covers creation, approve, deny, expiry, staleness, and safe resume through the
 * real provider-approval service + the exact atomic state machine (spec §6).
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import {
  approvalQueue,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerActionReservationGenerations,
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
import { __setProviderPolicyClockForTests } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";
import {
  APPROVAL_RULES,
  bindingRow,
  correlatedAudit,
  createApprovalRequired,
  F,
  freshMfa,
  intentRow,
  queueRow,
  seedFixture,
} from "./provider-approval-fixture";

setDefaultTimeout(120_000);

let priorExecutionAuthSecret: string | undefined;

async function wipe() {
  const db = getDb();
  await db.delete(providerActionAuditOutbox);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  await db.delete(providerGrants);
  await db.delete(providerRoleBindings);
  await db.delete(providerOperations);
  await db.delete(providerAccounts);
  await db.delete(secretRoutes);
  await db.delete(secrets);
  await db.delete(workspaces);
  await db.delete(userTenants);
  await db.delete(users);
  await db.delete(tenants);
}

function decideInput(
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
    idempotencyKey: "decide-key-0001",
    ...overrides,
  };
}

describe("PR3 approval lifecycle", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    priorExecutionAuthSecret = process.env.STEWARD_EXECUTION_AUTH_SECRET;
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "1".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    __setProviderPolicyClockForTests(null);
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    if (priorExecutionAuthSecret === undefined) {
      delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    } else {
      process.env.STEWARD_EXECUTION_AUTH_SECRET = priorExecutionAuthSecret;
    }
  });
  beforeEach(async () => {
    __setProviderPolicyClockForTests(null);
    await wipe();
    await seedFixture();
  });

  test("creation: one intent + one binding + one queue row + one requested audit event", async () => {
    const { intentId } = await createApprovalRequired();
    const b = await bindingRow(intentId);
    const q = await queueRow(intentId);
    const i = await intentRow(intentId);
    expect(b.status).toBe("pending_approval");
    expect(b.bindingRevision).toBe(1);
    expect(b.approvalQueueId).toBe(q.id);
    expect(b.approvalCommitmentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(q.approvalKind).toBe("provider_action");
    expect(q.status).toBe("pending");
    expect(q.expectedBindingRevision).toBe(1);
    expect(q.approvalCommitmentHash).toBe(b.approvalCommitmentHash);
    expect(i.status).toBe("pending");
    // exactly one requested correlated audit event with C1 fields.
    const events = await correlatedAudit(intentId);
    expect(events.length).toBe(1);
    expect(events[0].action).toBe("provider.action.approval_required");
    expect(events[0].resource_type).toBe("provider_action");
    expect(events[0].resource_id).toBe(intentId);
    expect(events[0].intent_meta).toBe(intentId);
  });

  test("approve: pending_approval -> approved, intent authorized, decided audit", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const res = await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest),
    );
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("approve failed");
    expect(res.status).toBe("approved");
    expect(res.version).toBe(2);
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approved");
    expect(b.bindingRevision).toBe(2);
    expect(b.approvalActorUserId).toBe(F.APPROVER);
    expect(b.approvedAt).not.toBeNull();
    const q = await queueRow(intentId);
    expect(q.status).toBe("approved");
    expect(q.resolvedById).toBe(F.APPROVER);
    const i = await intentRow(intentId);
    expect(i.status).toBe("authorized");
    expect(i.authorizedBy).toBe(`user:${F.APPROVER}`);
    const events = await correlatedAudit(intentId);
    expect(events.map((e) => e.action)).toEqual([
      "provider.action.approval_required",
      "provider.approval.decided",
    ]);
  });

  test("deny: pending_approval -> approval_denied, reason required", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // no reason code => 400
    const missing = await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest, { decision: "deny", idempotencyKey: "d1" }),
    );
    expect(missing.ok).toBe(false);
    if (missing.ok) throw new Error("unexpected");
    expect(missing.code).toBe("APPROVAL_REASON_REQUIRED");

    const res = await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest, {
        decision: "deny",
        reasonCode: "approver_manual_deny",
        idempotencyKey: "d2",
      }),
    );
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("deny failed");
    expect(res.status).toBe("approval_denied");
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approval_denied");
    const i = await intentRow(intentId);
    expect(i.status).toBe("rejected");
  });

  test("safe resume: approved -> execution_ready, consumes approval once, no execution", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideInput(intentId, requestHash, actionDigest));
    const res = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("resume failed");
    expect(res.status).toBe("execution_ready");
    expect(res.resumeAttemptId).toBeTruthy();
    const b = await bindingRow(intentId);
    expect(b.status).toBe("execution_ready");
    expect(b.resumeActor).toBe("steward-system");
    expect(b.bindingRevision).toBe(3);
    const q = await queueRow(intentId);
    expect(q.status).toBe("consumed");
    expect(q.consumedBy).toBe("steward-system");
    const i = await intentRow(intentId);
    // execution_ready must NOT set executed/executed_at (no external execution).
    expect(i.status).toBe("authorized");
    expect(i.executedAt).toBeNull();
    expect(i.executedBy).toBe("steward-system");
    // resume idempotent: same resumeAttemptId, no new event.
    const events1 = (await correlatedAudit(intentId)).length;
    const res2 = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(res2.ok).toBe(true);
    if (!res2.ok) throw new Error();
    expect(res2.resumeAttemptId).toBe(res.resumeAttemptId);
    const events2 = (await correlatedAudit(intentId)).length;
    expect(events2).toBe(events1);
  });

  test("#207 queues in-window but fresh resume recheck denies after business hours", async () => {
    const windowedRules = APPROVAL_RULES.map((rule) =>
      rule.config.effect === "allow"
        ? {
            ...rule,
            config: {
              ...rule.config,
              constraints: {
                timeWindow: {
                  timezone: "UTC",
                  allow: [{ days: ["mon"], from: "11:00", to: "13:00" }],
                },
              },
            },
          }
        : rule,
    );
    await getDb()
      .update(providerOperations)
      .set({ requestProfile: { policyRules: windowedRules } })
      .where(eq(providerOperations.id, F.OP));

    __setProviderPolicyClockForTests(() => new Date("2026-08-17T12:00:00.000Z"));
    const { intentId, requestHash, actionDigest } = await createApprovalRequired("hours-open");
    expect(
      (
        await providerApprovalService.decide(
          decideInput(intentId, requestHash, actionDigest, {
            idempotencyKey: "hours-open-approve",
          }),
        )
      ).ok,
    ).toBe(true);

    // No operation/policy mutation: only the authoritative server instant moves.
    // The approved immutable action is rebound to a fresh policy decision at
    // resume and cannot cross the window boundary.
    __setProviderPolicyClockForTests(() => new Date("2026-08-17T14:00:00.000Z"));
    expect(await providerApprovalService.resume({ intentId, tenantId: F.TENANT })).toEqual({
      ok: false,
      code: "POLICY_HARD_DENY",
      httpStatus: 403,
    });
    expect((await bindingRow(intentId)).status).toBe("approved");
    expect((await queueRow(intentId)).status).toBe("approved");
    expect(
      (
        await getDb()
          .select()
          .from(providerActionReservationGenerations)
          .where(eq(providerActionReservationGenerations.intentId, intentId))
      ).length,
    ).toBe(0);
  });

  test("resume idempotent path re-ensures v2 authorization only for an evidence-bound execution_ready row", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideInput(intentId, requestHash, actionDigest));
    const first = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(first.ok).toBe(true);
    // A nonce was minted on the first resume.
    const before = await getDb()
      .select({ id: executionAuthorizationNonces.authorizationId })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    expect(before.length).toBe(1);
    // Simulate loss of the authorization while retaining the immutable 0084
    // execution-policy evidence.
    await getDb()
      .delete(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    const gone = await getDb()
      .select({ id: executionAuthorizationNonces.authorizationId })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    expect(gone.length).toBe(0);
    // Resume again: the idempotent execution_ready branch must re-mint the nonce.
    const second = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error("second resume failed");
    expect(second.status).toBe("execution_ready");
    const after = await getDb()
      .select({ id: executionAuthorizationNonces.authorizationId })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    expect(after.length).toBe(1);

    // Presence is insufficient: corrupting the frozen decision hash must stop
    // the idempotent path before it can mint another durable authorization.
    await getDb()
      .delete(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    await getDb().execute(
      sql`DROP TRIGGER provider_action_bindings_immutable ON provider_action_bindings`,
    );
    await getDb()
      .update(providerActionBindings)
      .set({ executionPolicyDecisionHash: `sha256:${"0".repeat(64)}` })
      .where(eq(providerActionBindings.intentId, intentId));
    await getDb().execute(sql`
      CREATE TRIGGER provider_action_bindings_immutable
      BEFORE UPDATE ON provider_action_bindings
      FOR EACH ROW EXECUTE FUNCTION steward_provider_action_binding_guard()
    `);
    expect(await providerApprovalService.resume({ intentId, tenantId: F.TENANT })).toEqual({
      ok: false,
      code: "EXECUTION_POLICY_EVIDENCE_MISSING",
      httpStatus: 409,
    });
    expect(
      await getDb()
        .select({ id: executionAuthorizationNonces.authorizationId })
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.intentId, intentId)),
    ).toHaveLength(0);
  });

  test("#239 rollout: resume never mints for a legacy execution_ready row without policy evidence", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(decideInput(intentId, requestHash, actionDigest));
    expect((await providerApprovalService.resume({ intentId, tenantId: F.TENANT })).ok).toBe(true);
    const db = getDb();
    await db
      .delete(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    await db.execute(
      sql`ALTER TABLE provider_action_bindings DROP CONSTRAINT provider_action_bindings_execution_policy_ready_chk`,
    );
    await db.execute(
      sql`DROP TRIGGER provider_action_bindings_immutable ON provider_action_bindings`,
    );
    await db
      .update(providerActionBindings)
      .set({
        executionPolicyDecisionId: null,
        executionPolicyRevisionHash: null,
        executionPolicyDecision: null,
        executionPolicyDecisionHash: null,
        executionPolicyEvaluatedAt: null,
      })
      .where(eq(providerActionBindings.intentId, intentId));
    await db.execute(sql`
      CREATE TRIGGER provider_action_bindings_immutable
      BEFORE UPDATE ON provider_action_bindings
      FOR EACH ROW EXECUTE FUNCTION steward_provider_action_binding_guard()
    `);
    await db.execute(sql`
      ALTER TABLE provider_action_bindings
      ADD CONSTRAINT provider_action_bindings_execution_policy_ready_chk CHECK (
        status NOT IN ('execution_ready','executing') OR execution_policy_decision_id IS NOT NULL
      ) NOT VALID
    `);

    expect(await providerApprovalService.resume({ intentId, tenantId: F.TENANT })).toEqual({
      ok: false,
      code: "EXECUTION_POLICY_EVIDENCE_MISSING",
      httpStatus: 409,
    });
    const nonce = await db
      .select({ id: executionAuthorizationNonces.id })
      .from(executionAuthorizationNonces)
      .where(eq(executionAuthorizationNonces.intentId, intentId));
    expect(nonce).toHaveLength(0);
  });

  test("resume of a non-approved (pending) action => RESUME_NOT_APPROVED", async () => {
    const { intentId } = await createApprovalRequired();
    const res = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("RESUME_NOT_APPROVED");
  });

  test("expiry: an expired pending action denies with APPROVAL_EXPIRED and persists expired tuple", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // Force the deadline into the past.
    await getDb()
      .update(approvalQueue)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(approvalQueue.intentId, intentId));
    const res = await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest),
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("APPROVAL_EXPIRED");
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approval_expired");
    const i = await intentRow(intentId);
    expect(i.status).toBe("expired");
  });

  test("terminal: a denied action cannot be re-approved (APPROVAL_ALREADY_DECIDED / TERMINAL)", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest, {
        decision: "deny",
        reasonCode: "approver_manual_deny",
        idempotencyKey: "deny-terminal",
      }),
    );
    const res = await providerApprovalService.decide(
      decideInput(intentId, requestHash, actionDigest, {
        decision: "approve",
        expectedVersion: 2,
        idempotencyKey: "approve-after-deny",
      }),
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error();
    expect(res.code).toBe("APPROVAL_ALREADY_DECIDED");
    // original decision unchanged
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approval_denied");
    expect(b.approvalActorUserId).toBe(F.APPROVER);
  });
});
