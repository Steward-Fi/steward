/**
 * #205 M-of-N quorum approval integration tests against PGLite, through the REAL
 * provider-approval + provider-action services (spec-binding adversarial cases):
 *
 *   - threshold boundary: N-1 approvals are NOT executable, the Nth is
 *   - deny-after-partial-quorum terminates the whole approval (deny wins)
 *   - stale-after-first-approval invalidates the collected set
 *   - duplicate approver rejected loudly (counts once)
 *   - requester-as-approver can never count
 *   - ineligible Nth approver cannot complete the quorum
 *   - malformed configs fail closed at BOTH store time and eval time
 *   - single-approver regression (absent quorum) untouched
 *
 * The concurrent-Nth-approval race lives in provider-approval-quorum-race.test.ts
 * (real Postgres, DATABASE_URL required).
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
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { providerApprovalService } from "../services/provider-approval";
import {
  approvalRowCount,
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
  overrides: Partial<Parameters<typeof providerApprovalService.decide>[0]> = {},
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
    ...overrides,
  });
}

const TWO_OF_THREE = {
  threshold: 2,
  eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2, F.APPROVER_3],
};

describe("#205 M-of-N quorum approval", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.STEWARD_EXECUTION_AUTH_SECRET ||= "1".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  // ── happy path + boundary ────────────────────────────────────────────────
  describe("2-of-3 lifecycle", () => {
    beforeEach(async () => {
      await wipe();
      await seedFixture({ quorum: TWO_OF_THREE });
    });

    test("creation persists quorum config on the queue row + commitment", async () => {
      const { intentId } = await createApprovalRequired();
      const q = await queueRow(intentId);
      expect(q.quorumThreshold).toBe(2);
      expect([...(q.quorumEligibleUserIds ?? [])].sort()).toEqual(
        [F.APPROVER, F.APPROVER_2, F.APPROVER_3].sort(),
      );
      expect(q.quorumApprovalsCount).toBe(0);
      const commitment = q.approvalCommitment as { approvalRequirements?: { quorum?: unknown } };
      expect(commitment.approvalRequirements?.quorum).toEqual({
        threshold: 2,
        eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2, F.APPROVER_3].sort(),
      } as never);
    });

    test("boundary: first approval (N-1) leaves pending, NOT execute-reachable", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      const r1 = await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      expect(r1.ok).toBe(true);
      if (!r1.ok) throw new Error("a1 failed");
      expect(r1.status).toBe("pending_approval");

      const b = await bindingRow(intentId);
      expect(b.status).toBe("pending_approval");
      const q = await queueRow(intentId);
      expect(q.status).toBe("pending");
      expect(q.quorumApprovalsCount).toBe(1);
      const i = await intentRow(intentId);
      expect(i.status).toBe("pending");
      expect(await approvalRowCount(intentId)).toBe(1);

      // Resume must be unreachable while pending (N-1).
      const resume = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
      expect(resume.ok).toBe(false);
      if (resume.ok) throw new Error("resume should be unreachable at N-1");
      expect(resume.code).toBe("RESUME_NOT_APPROVED");
    });

    test("Nth distinct approval satisfies the quorum -> approved + authorized + resumable", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      const r2 = await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-a2");
      expect(r2.ok).toBe(true);
      if (!r2.ok) throw new Error("a2 failed");
      expect(r2.status).toBe("approved");

      const b = await bindingRow(intentId);
      expect(b.status).toBe("approved");
      const q = await queueRow(intentId);
      expect(q.status).toBe("approved");
      expect(q.quorumApprovalsCount).toBe(2);
      const i = await intentRow(intentId);
      expect(i.status).toBe("authorized");
      expect(await approvalRowCount(intentId)).toBe(2);

      // Now resume is reachable.
      const resume = await providerApprovalService.resume({ intentId, tenantId: F.TENANT });
      expect(resume.ok).toBe(true);
      if (!resume.ok) throw new Error("resume failed");
      expect(resume.status).toBe("execution_ready");

      // Audit trail: two decided events with quorum progress + resume ready.
      const events = await correlatedAudit(intentId);
      const decided = events.filter((e) => e.action === "provider.approval.decided");
      expect(decided.length).toBe(2);
    });

    test("duplicate approver: same user approving twice is rejected loudly, counts once", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      const dup = await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1-dup");
      expect(dup.ok).toBe(false);
      if (dup.ok) throw new Error("duplicate should fail");
      expect(dup.code).toBe("APPROVAL_DUPLICATE_APPROVER");
      const q = await queueRow(intentId);
      expect(q.quorumApprovalsCount).toBe(1);
      expect(await approvalRowCount(intentId)).toBe(1);
    });

    test("exact retry of the same approver vote replays (idempotent), counts once", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      const r1 = await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-retry");
      expect(r1.ok).toBe(true);
      const r1b = await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-retry");
      expect(r1b.ok).toBe(true);
      if (!r1b.ok) throw new Error("retry failed");
      expect(r1b.replayed).toBe(true);
      const q = await queueRow(intentId);
      expect(q.quorumApprovalsCount).toBe(1);
      expect(await approvalRowCount(intentId)).toBe(1);
    });

    test("concurrent Nth approvals => exactly one execute-reachable transition", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      // Pre-collect one approval so the next two are both "the Nth".
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-race-a1");
      // Fire APPROVER_2 and APPROVER_3 concurrently: both would satisfy the 2/3
      // threshold. Exactly one must flip the queue to approved.
      const [r2, r3] = await Promise.all([
        decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-race-a2"),
        decide(intentId, requestHash, actionDigest, F.APPROVER_3, "q-race-a3"),
      ]);
      // Both approvals are recorded as distinct decision rows (both are valid
      // votes), but only ONE drives the pending->approved transition; the other
      // sees the queue already approved and reports a state conflict.
      const approvedResults = [r2, r3].filter(
        (r) => r.ok && (r as { status?: string }).status === "approved",
      );
      expect(approvedResults.length).toBe(1);
      const b = await bindingRow(intentId);
      expect(b.status).toBe("approved");
      expect(b.bindingRevision).toBe(2);
      const q = await queueRow(intentId);
      expect(q.status).toBe("approved");
      // The tally is capped at the threshold: the guarded CAS increment never
      // pushes count above threshold.
      expect(q.quorumApprovalsCount).toBe(2);
      // Exactly the satisfying transition is a single approved decided event
      // whose toStatus is approved.
      const decided = (await correlatedAudit(intentId)).filter(
        (e) => e.action === "provider.approval.decided",
      );
      // three votes attempted; the two winners that actually recorded (a1 + one
      // of a2/a3) produce decided events. Under PGLite serialization the loser
      // that hit the count cap does not emit a satisfying transition.
      expect(decided.length).toBeGreaterThanOrEqual(2);
    });

    test("deny after a partial quorum terminates the whole approval (deny wins)", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      const deny = await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-deny", {
        decision: "deny",
        reasonCode: "approver_manual_deny",
      });
      expect(deny.ok).toBe(true);
      if (!deny.ok) throw new Error("deny failed");
      expect(deny.status).toBe("approval_denied");
      const b = await bindingRow(intentId);
      expect(b.status).toBe("approval_denied");
      const q = await queueRow(intentId);
      expect(q.status).toBe("rejected");
      const i = await intentRow(intentId);
      expect(i.status).toBe("rejected");

      // A third approver can no longer complete the quorum (terminated).
      const late = await decide(intentId, requestHash, actionDigest, F.APPROVER_3, "q-a3-late");
      expect(late.ok).toBe(false);
    });

    test("ineligible Nth approver (not in eligible set) cannot complete the quorum", async () => {
      // APPROVER + APPROVER_2 are in the set; drop APPROVER_2 from the set so
      // only APPROVER + APPROVER_3 are eligible, but role-bind APPROVER_2 anyway.
      // Re-seed with a 2-of-2 set of APPROVER + APPROVER_3.
      await wipe();
      await seedFixture({
        quorum: { threshold: 2, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_3] },
      });
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      // APPROVER_2 has the role but is NOT in the eligible set.
      const bad = await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-bad");
      expect(bad.ok).toBe(false);
      if (bad.ok) throw new Error("ineligible approver should fail");
      expect(bad.code).toBe("APPROVAL_NOT_ELIGIBLE_APPROVER");
      const q = await queueRow(intentId);
      expect(q.quorumApprovalsCount).toBe(1);
    });

    test("ineligible-by-lost-role Nth approver cannot complete the quorum", async () => {
      const { intentId, requestHash, actionDigest } = await createApprovalRequired();
      await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
      // Revoke APPROVER_2's workspace_approver role after the first approval.
      await getDb()
        .update(providerRoleBindings)
        .set({ status: "revoked" })
        .where(eq(providerRoleBindings.id, F.APPROVER_BINDING_2));
      const bad = await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-lostrole");
      expect(bad.ok).toBe(false);
      if (bad.ok) throw new Error("lost-role approver should fail");
      expect(bad.code).toBe("APPROVAL_ROLE_REQUIRED");
      // APPROVER_3 (still eligible) CAN complete it.
      const ok = await decide(intentId, requestHash, actionDigest, F.APPROVER_3, "q-a3");
      expect(ok.ok).toBe(true);
    });
  });

  // ── requester separation generalized ─────────────────────────────────────
  test("requester (agent owner) can never count toward the quorum", async () => {
    await wipe();
    // Make APPROVER the agent owner AND list them as eligible: the requester
    // guard must still reject them.
    await seedFixture({
      quorum: { threshold: 2, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2, F.APPROVER_3] },
      agentOwnerUserId: F.APPROVER,
    });
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const bad = await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-owner");
    expect(bad.ok).toBe(false);
    if (bad.ok) throw new Error("requester should never vote");
    expect(bad.code).toBe("APPROVAL_REQUESTER_SEPARATION_REQUIRED");
    // Two OTHER distinct approvers still satisfy it.
    await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-a2");
    const done = await decide(intentId, requestHash, actionDigest, F.APPROVER_3, "q-a3");
    expect(done.ok).toBe(true);
    if (!done.ok) throw new Error("quorum should complete without requester");
    expect(done.status).toBe("approved");
  });

  // ── staleness invalidates the collected set ──────────────────────────────
  test("stale after first approval invalidates the whole set", async () => {
    await wipe();
    await seedFixture({ quorum: TWO_OF_THREE });
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    await decide(intentId, requestHash, actionDigest, F.APPROVER, "q-a1");
    // Mutate a committed dependency: bump the provider account revision so the
    // exact-revision re-eval stales the whole action on the next decide.
    await getDb()
      .update(providerAccounts)
      .set({ revision: 99 })
      .where(eq(providerAccounts.id, F.ACCOUNT));
    const second = await decide(intentId, requestHash, actionDigest, F.APPROVER_2, "q-a2");
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error("expected stale");
    expect(second.code).toBe("APPROVAL_PROVIDER_ACCOUNT_STALE");
    const b = await bindingRow(intentId);
    expect(b.status).toBe("approval_stale");
    const q = await queueRow(intentId);
    expect(q.status).toBe("stale");
    // The whole set is dead: even a fresh eligible approver cannot revive it.
    const revive = await decide(intentId, requestHash, actionDigest, F.APPROVER_3, "q-a3");
    expect(revive.ok).toBe(false);
  });

  // ── malformed config fails closed at store time ──────────────────────────
  describe("malformed config fails closed at store time", () => {
    const cases: Array<{ name: string; quorum: unknown }> = [
      { name: "threshold 0", quorum: { threshold: 0, eligibleApproverUserIds: [F.APPROVER] } },
      {
        name: "threshold negative",
        quorum: { threshold: -1, eligibleApproverUserIds: [F.APPROVER] },
      },
      {
        name: "threshold non-integer",
        quorum: { threshold: 1.5, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2] },
      },
      {
        name: "threshold > eligible set size",
        quorum: { threshold: 3, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2] },
      },
      { name: "empty eligible set", quorum: { threshold: 1, eligibleApproverUserIds: [] } },
      {
        name: "duplicate eligible ids",
        quorum: { threshold: 2, eligibleApproverUserIds: [F.APPROVER, F.APPROVER] },
      },
      {
        name: "unknown key",
        quorum: { threshold: 1, eligibleApproverUserIds: [F.APPROVER], nested: true },
      },
    ];

    for (const c of cases) {
      test(`rejects: ${c.name}`, async () => {
        await wipe();
        await seedFixture({ quorum: c.quorum as never });
        // createApprovalRequired throws when the outcome is not approval_required;
        // a malformed quorum fails creation closed (APPROVAL_QUORUM_CONFIG_INVALID).
        let threw = false;
        try {
          await createApprovalRequired();
        } catch (e) {
          threw = true;
          expect(String((e as Error).message)).toContain("APPROVAL_QUORUM_CONFIG_INVALID");
        }
        expect(threw).toBe(true);
        // No queue / binding / approval row leaked.
        const rows = await getDb().select().from(approvalQueue);
        expect(rows.length).toBe(0);
      });
    }
  });

  // ── unreachable quorum fails closed at store time (codex P2) ─────────────
  test("unreachable quorum (eligible ids that cannot vote) fails closed at store time", async () => {
    await wipe();
    // threshold 2 but the eligible set is [real approver, unknown UUID]: the
    // unknown id has no workspace_approver role, so only 1 can ever vote < 2.
    await seedFixture({
      quorum: {
        threshold: 2,
        eligibleApproverUserIds: [F.APPROVER, "cccccccc-0000-4000-8000-000000000099"],
      },
    });
    let threw = false;
    try {
      await createApprovalRequired();
    } catch (e) {
      threw = true;
      expect(String((e as Error).message)).toContain("APPROVAL_QUORUM_CONFIG_INVALID");
    }
    expect(threw).toBe(true);
    const rows = await getDb().select().from(approvalQueue);
    expect(rows.length).toBe(0);
  });

  test("unreachable quorum where the only extra eligible member is the requester fails closed", async () => {
    await wipe();
    // threshold 2, eligible = [APPROVER, APPROVER_2] but APPROVER_2 is the agent
    // owner (requester) => only 1 can vote (< 2) => reject at store time.
    await seedFixture({
      quorum: { threshold: 2, eligibleApproverUserIds: [F.APPROVER, F.APPROVER_2] },
      agentOwnerUserId: F.APPROVER_2,
    });
    let threw = false;
    try {
      await createApprovalRequired();
    } catch (e) {
      threw = true;
      expect(String((e as Error).message)).toContain("APPROVAL_QUORUM_CONFIG_INVALID");
    }
    expect(threw).toBe(true);
  });

  // ── single-approver regression floor stays untouched ─────────────────────
  test("absent quorum: single-approver approve path is byte-for-byte unchanged", async () => {
    await wipe();
    await seedFixture(); // no quorum
    const { intentId, requestHash, actionDigest } = await createApprovalRequired();
    const res = await decide(intentId, requestHash, actionDigest, F.APPROVER, "single-1");
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("single approve failed");
    expect(res.status).toBe("approved");
    expect(res.version).toBe(2);
    const q = await queueRow(intentId);
    expect(q.quorumThreshold).toBeNull();
    expect(q.quorumApprovalsCount).toBe(0);
    // No provider_action_approvals rows for the single-approver path.
    expect(await approvalRowCount(intentId)).toBe(0);
    const i = await intentRow(intentId);
    expect(i.status).toBe("authorized");
  });
});
