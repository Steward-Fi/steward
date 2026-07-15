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
  userTenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { providerApprovalService } from "../services/provider-approval";
import {
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
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });
  beforeEach(async () => {
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
    // execution_ready must NOT set executed/executed_at (no third-party execution).
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
