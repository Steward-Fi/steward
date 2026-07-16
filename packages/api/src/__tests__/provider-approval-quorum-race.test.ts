/**
 * #205 concurrent-Nth-approval race against REAL Postgres (C-DRIFT-2 /
 * requirement 9). Gated on DATABASE_URL: only runs against a genuine PG pool so
 * two concurrent Nth approvals execute on SEPARATE connections in parallel
 * (PGLite is single-connection and serializes, so this is the only place the
 * single-winner discipline is proven under true concurrency).
 *
 * The guarded CAS on quorum_approvals_count + the pending->approved transition
 * (WHERE status='pending' AND count>=threshold) must yield EXACTLY ONE
 * execute-reachable transition even when both Nth approvals commit concurrently.
 *
 * This file does NOT install a PGLite override, so getDb() resolves the real
 * pool the preload left in place when DATABASE_URL is set.
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
  getDb,
  intents,
  providerAccounts,
  providerActionApprovals,
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
import { providerApprovalService } from "../services/provider-approval";
import {
  approvalRowCount,
  bindingRow,
  correlatedAudit,
  createApprovalRequired,
  F,
  freshMfa,
  queueRow,
  seedFixture,
} from "./provider-approval-fixture";

setDefaultTimeout(120_000);

const SKIP = !process.env.DATABASE_URL;

async function wipe() {
  const db = getDb();
  await db.delete(providerActionApprovals);
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

function decide(
  intentId: string,
  requestHash: string,
  actionDigest: string,
  userId: string,
  idempotencyKey: string,
) {
  return providerApprovalService.decide({
    intentId,
    tenantId: F.TENANT,
    authenticatedUserId: userId,
    sessionMfaVerifiedAt: freshMfa(),
    decision: "approve" as const,
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey,
  });
}

const TWO_OF_THREE = {
  threshold: 2,
  eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2, F.APPROVER_3],
};

describe.skipIf(SKIP)("#205 quorum Nth-approval race (real PG)", () => {
  beforeAll(() => {
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.STEWARD_EXECUTION_AUTH_SECRET ||= "1".repeat(64);
  });
  afterAll(async () => {
    if (!SKIP) await wipe();
  });
  beforeEach(async () => {
    await wipe();
    await seedFixture({ quorum: TWO_OF_THREE });
  });

  test("two concurrent Nth approvals => exactly one execute-reachable transition", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // First approval brings the tally to N-1.
    await decide(intentId, requestHash, actionDigest, F.APPROVER, "race-a1");

    // APPROVER_2 and APPROVER_3 both satisfy the 2/3 threshold; fire them truly
    // concurrently on separate pooled connections.
    const [r2, r3] = await Promise.all([
      decide(intentId, requestHash, actionDigest, F.APPROVER_2, "race-a2"),
      decide(intentId, requestHash, actionDigest, F.APPROVER_3, "race-a3"),
    ]);

    // Exactly ONE drives the binding to approved; the other lands after the
    // quorum is already satisfied and is rejected loudly (never a second
    // execute-reachable transition). Whether the loser sees ALREADY_DECIDED or a
    // STATE_CONFLICT, it is NOT ok+approved.
    const approvedTransitions = [r2, r3].filter(
      (r) => r.ok && (r as { status?: string }).status === "approved",
    );
    expect(approvedTransitions.length).toBe(1);
    const loser = [r2, r3].find((r) => !r.ok || (r as { status?: string }).status !== "approved");
    expect(loser).toBeDefined();
    expect(loser?.ok).toBe(false);

    const b = await bindingRow(intentId);
    expect(b.status).toBe("approved");
    // Single-winner: exactly one binding-revision bump for the satisfying flip.
    expect(b.bindingRevision).toBe(2);

    const q = await queueRow(intentId);
    expect(q.status).toBe("approved");
    // Tally capped at threshold: the guarded CAS never exceeds it even with a
    // concurrent double increment.
    expect(q.quorumApprovalsCount).toBe(2);

    // Exactly the satisfying set of distinct votes was recorded (a1 + the
    // winning Nth). The loser landed after satisfaction and recorded no vote.
    expect(await approvalRowCount(intentId)).toBe(2);
    const decided = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.approval.decided",
    );
    expect(decided.length).toBe(2);
  });

  test("many concurrent approvals from distinct eligible approvers => tally never exceeds threshold", async () => {
    // Re-seed a 3-of-3 so all three race for the final slots.
    await wipe();
    await seedFixture({
      quorum: { threshold: 3, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2, F.APPROVER_3] },
    });
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const results = await Promise.all([
      decide(intentId, requestHash, actionDigest, F.APPROVER, "m-a1"),
      decide(intentId, requestHash, actionDigest, F.APPROVER_2, "m-a2"),
      decide(intentId, requestHash, actionDigest, F.APPROVER_3, "m-a3"),
    ]);
    // All three are distinct valid votes.
    const oks = results.filter((r) => r.ok).length;
    expect(oks).toBe(3);
    const q = await queueRow(intentId);
    expect(q.status).toBe("approved");
    expect(q.quorumApprovalsCount).toBe(3);
    expect(await approvalRowCount(intentId)).toBe(3);
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approved");
  });

  test("concurrent same-approver double-submit counts exactly once (distinctness under race)", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // Same approver fires the same vote twice concurrently: distinctness index
    // must keep exactly one row; the loser is a loud duplicate/conflict.
    const [a, b] = await Promise.all([
      decide(intentId, requestHash, actionDigest, F.APPROVER, "dup-a"),
      decide(intentId, requestHash, actionDigest, F.APPROVER, "dup-b"),
    ]);
    const oks = [a, b].filter((r) => r.ok).length;
    // At most one succeeds as a fresh vote (the other is a duplicate-approver
    // conflict); never two counted votes.
    expect(oks).toBeLessThanOrEqual(1);
    expect(await approvalRowCount(intentId)).toBe(1);
    const q = await queueRow(intentId);
    expect(q.quorumApprovalsCount).toBe(1);
  });
});
