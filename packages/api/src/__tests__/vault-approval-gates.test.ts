/**
 * REAL behavioral coverage for the vault manual-approval money path
 * (`POST /:agentId/approve/:txId`).
 *
 * The deleted vault-trade-audit-gates.test.ts was source-grep theater: it
 * `readFileSync`'d vault.ts and asserted the source *mentioned*
 * `hasTenantAdminSession`, `hasRecentSessionMfa`, a `vault.approve.authorized`
 * audit string, and that the audit `indexOf` came before the sign call. It never
 * ran the route, so a regression that dropped the MFA gate — or moved the audit
 * write to AFTER the irreversible sign — would still pass.
 *
 * This drives the REAL approve handler against an in-memory PGLite DB + the REAL
 * PolicyEngine and proves, behaviorally:
 *   1. an api-key principal (no owner/admin session) is refused (403) BEFORE any
 *      state is touched,
 *   2. an owner session WITHOUT recent MFA is refused (403) — the step-up gate is
 *      load-bearing, not decorative,
 *   3. a pending tx that no longer satisfies the CURRENT policy is re-evaluated
 *      at approval time and flipped to "rejected" (approval is not a blind replay
 *      of the queued decision), and
 *   4. the `vault.approve.authorized` audit row is written BEFORE the irreversible
 *      signing call — proven by fault-injecting a `signTransaction` throw and
 *      showing the audit row persists while the approval is rolled back to
 *      pending (fail-closed: a sign failure never leaves the tx approved/signed).
 *
 * The only mocked seam (test 4) is `Vault.prototype.signTransaction`, stubbed to
 * throw so the post-audit / pre-sign ordering is observable without real key
 * material. Everything else — auth gates, policy re-evaluation, the audit HMAC
 * chain write, and the rollback — runs for real.
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import {
  agents,
  approvalQueue,
  auditEvents,
  closeDb,
  getDb,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `approval-gate-tenant-${Date.now()}`;
const ACTOR_ID = "00000000-0000-4000-8000-000000000001";
const REMOVED_ACTOR_ID = "00000000-0000-4000-8000-000000000002";
// Recipient the pending transactions pay; "code" is irrelevant here because the
// approve path re-evaluates POLICY (not the native-transfer eth_getCode guard).
const RECIPIENT = "0x1234567890123456789012345678901234567890";
const OTHER_ADDRESS = "0x9999999999999999999999999999999999999999";

const AGENT_POLICY_REJECT = `approval-reject-${Date.now()}`;
const AGENT_AUDIT = `approval-audit-${Date.now()}`;
const AGENT_LIFECYCLE = `approval-lifecycle-${Date.now()}`;
const AGENT_SEPARATION = `approval-separation-${Date.now()}`;
const AGENT_REMOVED_REVIEWER = `approval-removed-reviewer-${Date.now()}`;

// One app per auth posture. The approve route reads auth purely from context
// variables, so a per-test middleware that sets exactly the desired posture is
// the honest way to exercise each gate in isolation.
async function makeApp(opts: {
  authType: "session-jwt" | "api-key";
  role?: "owner" | "admin" | "member";
  mfa: boolean;
  userId?: string;
}) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", opts.authType);
    c.set("tenantRole", opts.role ?? "owner");
    c.set("userId", opts.userId ?? ACTOR_ID);
    // Set MFA fresh at request time so it is always within the 5-minute window.
    if (opts.mfa) c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

async function seedAgent(agentId: string, walletSuffix: string) {
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId: TENANT_ID,
      name: `Approval Gate Agent ${agentId}`,
      walletAddress: `0x${walletSuffix.padStart(40, "0")}`,
    });
}

async function seedWhitelist(agentId: string, addresses: string[]) {
  await getDb()
    .insert(policies)
    .values({
      id: `${agentId}-approved`,
      agentId,
      type: "approved-addresses",
      enabled: true,
      config: { addresses, mode: "whitelist" },
    });
}

// A pending native-transfer transaction + its approval-queue row, exactly as the
// /sign path would persist when an op is routed to manual approval.
async function seedPendingTx(
  agentId: string,
  txId: string,
  to: string,
  requestedBy?: { type: string; id: string },
) {
  await getDb()
    .insert(transactions)
    .values({
      id: txId,
      agentId,
      status: "pending",
      toAddress: to,
      value: "1000",
      chainId: 8453,
      actionPayload: { type: "transaction", broadcast: false },
      policyResults: [],
    });
  await getDb()
    .insert(approvalQueue)
    .values({
      id: `aq-${txId}`,
      txId,
      agentId,
      status: "pending",
      requestedByType: requestedBy?.type,
      requestedById: requestedBy?.id,
    });
}

function approve(app: Awaited<ReturnType<typeof makeApp>>, agentId: string, txId: string) {
  return app.request(`/vault/${agentId}/approve/${txId}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
}

describe("vault approval gates (real /approve path)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "approval-gate-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "approval-gate-test-audit-hmac-key-0123456789abcdef0123456789";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Approval Gate Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb()
      .insert(users)
      .values([
        { id: ACTOR_ID, email: "approval-gate-owner@example.test" },
        { id: REMOVED_ACTOR_ID, email: "approval-gate-removed@example.test" },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ACTOR_ID, tenantId: TENANT_ID, role: "owner" },
        { userId: REMOVED_ACTOR_ID, tenantId: TENANT_ID, role: "owner" },
      ]);

    // Reject scenario: the agent's ONLY allowlisted address is some OTHER address,
    // so the pending tx to RECIPIENT is now a hard policy failure at approval time.
    await seedAgent(AGENT_POLICY_REJECT, "1");
    await seedWhitelist(AGENT_POLICY_REJECT, [OTHER_ADDRESS]);
    await seedPendingTx(AGENT_POLICY_REJECT, "tx-policy-reject", RECIPIENT);

    // Audit scenario: RECIPIENT is allowlisted, so policy APPROVES and the route
    // proceeds to the (fault-injected) sign call.
    await seedAgent(AGENT_AUDIT, "2");
    await seedWhitelist(AGENT_AUDIT, [RECIPIENT]);
    await seedPendingTx(AGENT_AUDIT, "tx-audit-order", RECIPIENT);

    // Separation-of-duties scenario: same authenticated user queued the approval.
    await seedAgent(AGENT_SEPARATION, "4");
    await seedWhitelist(AGENT_SEPARATION, [RECIPIENT]);
    await seedPendingTx(AGENT_SEPARATION, "tx-same-requester", RECIPIENT, {
      type: "user",
      id: ACTOR_ID,
    });

    await seedAgent(AGENT_REMOVED_REVIEWER, "5");
    await seedWhitelist(AGENT_REMOVED_REVIEWER, [RECIPIENT]);
    await seedPendingTx(AGENT_REMOVED_REVIEWER, "tx-removed-reviewer", RECIPIENT);

    // Lifecycle scenario: a tx that reached "broadcast" but whose approval-queue
    // row is somehow still pending. The lifecycle route must refuse to promote it
    // (confirmed/broadcasted/replaced) until that approval is resolved, so a stuck
    // queue row can never be laundered into a confirmed state.
    await seedAgent(AGENT_LIFECYCLE, "3");
    await getDb()
      .insert(transactions)
      .values({
        id: "tx-lifecycle-pending",
        agentId: AGENT_LIFECYCLE,
        status: "broadcast",
        toAddress: RECIPIENT,
        value: "1000",
        chainId: 8453,
        txHash: "0xfeed",
        actionPayload: { type: "transaction", broadcast: true },
        policyResults: [],
      });
    await getDb().insert(approvalQueue).values({
      id: "aq-tx-lifecycle-pending",
      txId: "tx-lifecycle-pending",
      agentId: AGENT_LIFECYCLE,
      status: "pending",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("refuses approval from an api-key principal (no owner/admin session)", async () => {
    // api-key auth fails hasTenantAdminSession even with role=owner + MFA set.
    const app = await makeApp({ authType: "api-key", role: "owner", mfa: true });
    const res = await approve(app, AGENT_AUDIT, "tx-audit-order");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Transaction approval requires owner or admin session");
  });

  it("refuses approval from an owner session WITHOUT recent MFA", async () => {
    const app = await makeApp({ authType: "session-jwt", role: "owner", mfa: false });
    const res = await approve(app, AGENT_AUDIT, "tx-audit-order");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Transaction approval requires recent MFA verification");

    // The gate returns BEFORE touching state: the pending tx is untouched.
    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "tx-audit-order"));
    expect(row.status).toBe("pending");
  });

  it("refuses approval when the reviewer was removed from the tenant after session issuance", async () => {
    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.userId, REMOVED_ACTOR_ID), eq(userTenants.tenantId, TENANT_ID)));
    const app = await makeApp({
      authType: "session-jwt",
      role: "owner",
      mfa: true,
      userId: REMOVED_ACTOR_ID,
    });
    const res = await approve(app, AGENT_REMOVED_REVIEWER, "tx-removed-reviewer");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe(
      "Transaction approval requires an active owner or admin tenant membership at review time",
    );

    const [tx] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "tx-removed-reviewer"));
    expect(tx.status).toBe("pending");
    const [queue] = await getDb()
      .select({ status: approvalQueue.status, resolvedById: approvalQueue.resolvedById })
      .from(approvalQueue)
      .where(eq(approvalQueue.txId, "tx-removed-reviewer"));
    expect(queue.status).toBe("pending");
    expect(queue.resolvedById).toBeNull();
  });

  it("re-evaluates current policy and rejects a pending tx that no longer passes", async () => {
    const app = await makeApp({ authType: "session-jwt", role: "owner", mfa: true });
    const res = await approve(app, AGENT_POLICY_REJECT, "tx-policy-reject");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Pending transaction no longer satisfies current policy");

    // The route flips BOTH the tx and its queue row to rejected (not a blind replay).
    const [tx] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "tx-policy-reject"));
    expect(tx.status).toBe("rejected");
    const [queue] = await getDb()
      .select({
        status: approvalQueue.status,
        resolvedBy: approvalQueue.resolvedBy,
        resolvedByType: approvalQueue.resolvedByType,
        resolvedById: approvalQueue.resolvedById,
      })
      .from(approvalQueue)
      .where(eq(approvalQueue.txId, "tx-policy-reject"));
    expect(queue.status).toBe("rejected");
    expect(queue.resolvedBy).toBe(`user:${ACTOR_ID}`);
    expect(queue.resolvedByType).toBe("user");
    expect(queue.resolvedById).toBe(ACTOR_ID);

    // A re-evaluation rejection is itself audited.
    const auditRows = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.resourceId, "tx-policy-reject"),
          eq(auditEvents.action, "vault.approve.rejected_by_current_policy"),
        ),
      );
    expect(auditRows.length).toBe(1);
  });

  it("refuses approval by the same authenticated principal that requested it", async () => {
    const app = await makeApp({ authType: "session-jwt", role: "owner", mfa: true });
    const res = await approve(app, AGENT_SEPARATION, "tx-same-requester");
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Manual approval requires separation of duties from the requester");

    const [tx] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "tx-same-requester"));
    expect(tx.status).toBe("pending");
    const [queue] = await getDb()
      .select({
        status: approvalQueue.status,
        resolvedByType: approvalQueue.resolvedByType,
        resolvedById: approvalQueue.resolvedById,
      })
      .from(approvalQueue)
      .where(eq(approvalQueue.txId, "tx-same-requester"));
    expect(queue.status).toBe("pending");
    expect(queue.resolvedByType).toBeNull();
    expect(queue.resolvedById).toBeNull();
  });

  it("refuses a lifecycle promotion while the tx still has a pending approval", async () => {
    const app = await makeApp({ authType: "session-jwt", role: "owner", mfa: true });
    const res = await app.request(
      `/vault/${AGENT_LIFECYCLE}/transactions/tx-lifecycle-pending/lifecycle`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "transaction.broadcasted" }),
      },
    );
    expect(res.status).toBe(409);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Pending approval must be resolved before lifecycle promotion");

    // The tx was NOT mutated by the refused promotion.
    const [tx] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "tx-lifecycle-pending"));
    expect(tx.status).toBe("broadcast");
  });

  it("writes the authorized audit row BEFORE the irreversible sign, and rolls back on sign failure", async () => {
    // Fault-inject the sign so the route reaches it (policy approves) then throws.
    const spy = spyOn(Vault.prototype, "signTransaction").mockRejectedValue(
      new Error("hsm offline"),
    );
    try {
      const app = await makeApp({ authType: "session-jwt", role: "owner", mfa: true });
      const res = await approve(app, AGENT_AUDIT, "tx-audit-order");
      // The irreversible call failed → request errors out (no signature surfaced).
      expect(res.status).toBe(500);
      const body = (await res.json()) as { ok: boolean; signedTx?: string; txHash?: string };
      expect(body.ok).toBe(false);
      expect(body.signedTx).toBeUndefined();
      expect(body.txHash).toBeUndefined();
      // The sign was actually attempted (proves we got past policy re-eval).
      expect(spy).toHaveBeenCalled();

      // CRITICAL ordering invariant: the authorized-intent audit row was written
      // BEFORE the sign call, so it survives even though the sign threw.
      const authorizedRows = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.resourceId, "tx-audit-order"),
            eq(auditEvents.action, "vault.approve.authorized"),
          ),
        );
      expect(authorizedRows.length).toBe(1);

      // Fail-closed: the sign failure rolled the approval back to pending and left
      // the tx pending — never approved/signed/broadcast on an errored sign.
      const [tx] = await getDb()
        .select({ status: transactions.status, txHash: transactions.txHash })
        .from(transactions)
        .where(eq(transactions.id, "tx-audit-order"));
      expect(tx.status).toBe("pending");
      expect(tx.txHash).toBeNull();
      const [queue] = await getDb()
        .select({ status: approvalQueue.status })
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, "tx-audit-order"));
      expect(queue.status).toBe("pending");

      // And no success audit row was emitted for the failed sign.
      const successRows = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.resourceId, "tx-audit-order"),
            eq(auditEvents.action, "vault.approve"),
          ),
        );
      expect(successRows.length).toBe(0);
    } finally {
      spy.mockRestore();
    }
  });
});
