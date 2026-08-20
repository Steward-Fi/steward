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
import { inArray } from "drizzle-orm";
import { providerApprovalService } from "../services/provider-approval";
import {
  approvalRowCount,
  approveRowCount,
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
  const tenantIds = [F.TENANT, F.TENANT_B];
  await db
    .delete(providerActionApprovals)
    .where(inArray(providerActionApprovals.tenantId, tenantIds));
  await db
    .delete(providerActionAuditOutbox)
    .where(inArray(providerActionAuditOutbox.tenantId, tenantIds));
  await db.delete(approvalQueue).where(inArray(approvalQueue.tenantId, tenantIds));
  await db
    .delete(providerActionBindings)
    .where(inArray(providerActionBindings.tenantId, tenantIds));
  await db.delete(intents).where(inArray(intents.tenantId, tenantIds));
  await db.delete(providerGrants).where(inArray(providerGrants.tenantId, tenantIds));
  await db.delete(providerRoleBindings).where(inArray(providerRoleBindings.tenantId, tenantIds));
  await db.delete(providerOperations).where(inArray(providerOperations.tenantId, tenantIds));
  await db.delete(providerAccounts).where(inArray(providerAccounts.tenantId, tenantIds));
  await db.delete(secretRoutes).where(inArray(secretRoutes.tenantId, tenantIds));
  await db.delete(secrets).where(inArray(secrets.tenantId, tenantIds));
  await db.delete(workspaces).where(inArray(workspaces.tenantId, tenantIds));
  await db.delete(userTenants).where(inArray(userTenants.tenantId, tenantIds));
  await db
    .delete(users)
    .where(inArray(users.id, [F.GRANTOR, F.AGENT_OWNER, F.APPROVER, F.APPROVER_2, F.APPROVER_3]));
  await db.delete(tenants).where(inArray(tenants.id, tenantIds));
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

  // GATE-236 adversarial interleaving: at N-1, a concurrent approve (which would
  // satisfy the quorum) races a deny (which must terminate). The terminal state
  // must be UNAMBIGUOUS and fail-closed: EITHER approved OR denied, never a torn
  // state where the queue is denied but the binding approved (or vice-versa),
  // and NEVER an orphan approve tally left on a denied queue. Deny-wins is the
  // desired posture, but the hard invariant the gate enforces is single-terminal
  // consistency: the queue, binding, and intent agree, and no execute-reachable
  // transition coexists with a deny.
  test("concurrent approve+deny at N-1 => single consistent terminal, no torn state", async () => {
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    // Bring the tally to N-1 = 1 (2-of-3).
    await decide(intentId, requestHash, actionDigest, F.APPROVER, "ad-a1");

    // APPROVER_2 approves (would satisfy) and APPROVER_3 denies, concurrently on
    // separate pooled connections.
    const [approveRes, denyRes] = await Promise.all([
      decide(intentId, requestHash, actionDigest, F.APPROVER_2, "ad-a2"),
      providerApprovalService.decide({
        intentId,
        tenantId: F.TENANT,
        authenticatedUserId: F.APPROVER_3,
        sessionMfaVerifiedAt: freshMfa(),
        decision: "deny" as const,
        expectedVersion: 1,
        expectedRequestHash: requestHash,
        expectedActionDigest: actionDigest,
        reasonCode: "approver_manual_deny",
        reason: null,
        idempotencyKey: "ad-deny",
      }),
    ]);

    // At most one of the two racers may report a fresh terminal success; the
    // loser rolls back with a state conflict (never two committed terminals).
    const terminalOks = [approveRes, denyRes].filter(
      (r) =>
        r.ok &&
        ((r as { status?: string }).status === "approved" ||
          (r as { status?: string }).status === "approval_denied"),
    );
    expect(terminalOks.length).toBe(1);

    const b = await bindingRow(intentId);
    const q = await queueRow(intentId);
    const decided = (await correlatedAudit(intentId)).filter(
      (e) => e.action === "provider.approval.decided",
    );

    // Single consistent terminal: the binding + queue + intent agree on ONE
    // outcome. Exactly one of the two racers won the terminal transition; the
    // loser rolled back (its non-counted evidence row is never committed).
    if (b.status === "approval_denied") {
      // Deny won (or deny raced in after the approve): queue rejected, no orphan
      // approve tally left dangling above what actually counted, and NO
      // execute-reachable transition was fabricated.
      expect(q.status).toBe("rejected");
      // The winning terminal decision emitted exactly one decided event for it.
      // The approve loser, if it lost the pending->approved CAS, rolled back and
      // recorded no vote (QuorumStateConflictError).
      expect(b.status).not.toBe("approved");
    } else {
      // Approve won the race and satisfied the quorum: the deny then lost against
      // the already-approved queue (terminated approve lineage). The binding is
      // approved and the deny did not tear it back to denied.
      expect(b.status).toBe("approved");
      expect(q.status).toBe("approved");
      // The approve tally equals the distinct persisted approve rows (never torn
      // by the racing deny).
      expect(q.quorumApprovalsCount).toBe(await approveRowCount(intentId));
    }

    // No matter who won: at most one terminal decided event (the winner). The
    // loser's row rolled back, so it produced no committed decided event.
    const terminalDecided = decided.filter((e) => e.action === "provider.approval.decided");
    // a1 (partial approve) + exactly one terminal (approve-satisfy or deny).
    expect(terminalDecided.length).toBe(2);
    // The approve tally never exceeds the distinct approve rows regardless of
    // the winner (no request-count-based inflation under the race).
    expect(q.quorumApprovalsCount).toBe(await approveRowCount(intentId));
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
