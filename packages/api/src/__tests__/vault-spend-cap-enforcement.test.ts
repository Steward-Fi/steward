/**
 * REAL route-level spend-cap enforcement for the vault money path.
 *
 * The audit flagged vault-send-calls-spend.test.ts as theater: it only
 * `readFileSync`'d routes/vault.ts and asserted the source *contained*
 * substrings ("getTransactionStats", "runningSpentToday += callValue", a
 * referenceId lookup). It never executed the route, so a regression that
 * silently dropped the cap check would still pass. Spend-cap ROUTE enforcement
 * and the per-batch cumulative running total had ZERO behavioral coverage.
 *
 * This drives the REAL `POST /:agentId/actions/send-calls` handler against an
 * in-memory PGLite DB and the REAL PolicyEngine, and proves behaviorally:
 *   - a daily `spending-limit` cap denies once seeded prior spend + this op
 *     exceeds it (the route actually reads getTransactionStats().spentToday),
 *   - within a single batch the cap is evaluated against a RUNNING total, so
 *     two calls that each individually pass cannot both slip through when their
 *     cumulative value crosses the cap (the read-before-write fence the
 *     advisory lock protects against under real Postgres concurrency),
 *   - an operation within the cap is NOT blocked (the gate is not a blanket
 *     deny),
 *   - replaying a referenceId is rejected and does NOT create a second action
 *     (idempotent re-send protection).
 *
 * Nothing in the enforcement path is mocked. send-calls is used (not /sign)
 * because it reaches policy evaluation with no `eth_getCode` RPC dependency, so
 * the test is hermetic.
 *
 * NOTE ON THE ADVISORY LOCK: `withAgentSpendLock` is a deliberate no-op under
 * PGLite (pg_advisory_xact_lock has no meaning on a single-connection in-memory
 * DB), so true cross-request concurrent serialization is exercised only by the
 * Postgres integration env. What IS provable here — and is the same invariant —
 * is the in-process cumulative accounting: the route never evaluates a later op
 * against a stale pre-op spend snapshot.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `spend-cap-tenant-${Date.now()}`;
const ALLOWED = "0x1234567890123456789012345678901234567890";
const MAX_WEEK = "1000000000000000000000000";

// One agent per scenario so each test is hermetic: getTransactionStats sums
// per-agent, so seeded prior spend on one agent never leaks into another.
const AGENT_SEEDED_OVER = `spend-cap-seeded-${Date.now()}`;
const AGENT_BATCH_CUMULATIVE = `spend-cap-batch-${Date.now()}`;
const AGENT_UNDER_CAP = `spend-cap-under-${Date.now()}`;
const AGENT_REPLAY = `spend-cap-replay-${Date.now()}`;

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "spend-cap-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

async function seedAgentWithCap(
  agentId: string,
  walletSuffix: string,
  spendingConfig: Record<string, unknown>,
) {
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId: TENANT_ID,
      name: `Spend Cap Agent ${agentId}`,
      walletAddress: `0x${walletSuffix.padStart(40, "0")}`,
    });
  await getDb()
    .insert(policies)
    .values({
      id: `${agentId}-approved`,
      agentId,
      type: "approved-addresses",
      enabled: true,
      config: { addresses: [ALLOWED], mode: "whitelist" },
    });
  await getDb()
    .insert(policies)
    .values({
      id: `${agentId}-spend`,
      agentId,
      type: "spending-limit",
      enabled: true,
      config: spendingConfig,
    });
}

function sendCalls(
  app: Awaited<ReturnType<typeof makeApp>>,
  agentId: string,
  calls: Array<{ to: string; value: string }>,
  extra: Record<string, unknown> = {},
) {
  return app.request(`/vault/${agentId}/actions/send-calls`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ chainId: 8453, broadcast: false, calls, ...extra }),
  });
}

describe("vault spend-cap route enforcement (real send-calls path)", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "spend-cap-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "spend-cap-enforcement-test-audit-hmac-key-0123456789abcdef";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Spend Cap Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });

    // Daily cap 1000, generous per-tx + per-week so only the DAILY cap can bind.
    await seedAgentWithCap(AGENT_SEEDED_OVER, "1", {
      maxPerTx: "100000",
      maxPerDay: "1000",
      maxPerWeek: MAX_WEEK,
    });
    // Per-tx 600 so each 600 call passes individually; daily 1000 so the SECOND
    // 600 in one batch crosses the cap via the running total.
    await seedAgentWithCap(AGENT_BATCH_CUMULATIVE, "2", {
      maxPerTx: "600",
      maxPerDay: "1000",
      maxPerWeek: MAX_WEEK,
    });
    await seedAgentWithCap(AGENT_UNDER_CAP, "3", {
      maxPerTx: "100000",
      maxPerDay: "1000",
      maxPerWeek: MAX_WEEK,
    });
    // Replay agent: cap high enough that the first op is allowed; the 409 must
    // come from referenceId reuse, not from the cap.
    await seedAgentWithCap(AGENT_REPLAY, "4", {
      maxPerTx: "100000",
      maxPerDay: "100000",
      maxPerWeek: MAX_WEEK,
    });

    // Pre-load AGENT_SEEDED_OVER's spentToday to 800 with a committed signed tx.
    // getTransactionStats only counts signed/broadcast/confirmed, so this is the
    // exact value the route's cap check must read back.
    await getDb()
      .insert(transactions)
      .values({
        id: `seeded-spend-${Date.now()}`,
        agentId: AGENT_SEEDED_OVER,
        status: "signed",
        toAddress: ALLOWED,
        value: "800",
        chainId: 8453,
        policyResults: [],
        signedAt: new Date(),
      });

    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("DENIES an op when seeded prior spend + this op exceeds the daily cap", async () => {
    // spentToday is 800 (seeded). 800 + 300 = 1100 > 1000 → must be rejected.
    const res = await sendCalls(app, AGENT_SEEDED_OVER, [{ to: ALLOWED, value: "300" }]);
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      ok: boolean;
      error?: string;
      data: {
        id: string;
        status: string;
        policyResults: Array<{ passed: boolean; reason?: string }>;
      };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Batch calls rejected by policy");
    expect(body.data.status).toBe("rejected");
    // The denial is specifically the DAILY spending limit (not the recipient,
    // which is allowlisted, and not the per-tx cap, which is 100000).
    const failed = body.data.policyResults.filter((r) => !r.passed);
    expect(failed.some((r) => (r.reason ?? "").includes("daily spending limit"))).toBe(true);

    // A rejected transaction row is persisted for audit/status polling and does
    // NOT increase future spend (rejected rows are excluded by getTransactionStats).
    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.id));
    expect(row.status).toBe("rejected");
    expect(row.actionType).toBe("send_calls");
  });

  it("DENIES the 2nd call in a batch via the running per-batch total (cumulative fence)", async () => {
    // Each 600 passes per-tx (cap 600) and call #1 passes daily (0+600 ≤ 1000),
    // but the running total makes call #2 (600+600 = 1200 > 1000) fail. Without
    // the running accumulation both would pass and double-spend the cap.
    const res = await sendCalls(app, AGENT_BATCH_CUMULATIVE, [
      { to: ALLOWED, value: "600" },
      { to: ALLOWED, value: "600" },
    ]);
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        status: string;
        policyResults: Array<{ callIndex?: number; passed: boolean; reason?: string }>;
      };
    };
    expect(body.data.status).toBe("rejected");

    // The FIRST call's spending-limit result passes; the SECOND fails on daily.
    const call0Spend = body.data.policyResults.find(
      (r) => r.callIndex === 0 && (r.reason ?? "").includes("spending limit"),
    );
    const call1DailyFail = body.data.policyResults.find(
      (r) => r.callIndex === 1 && !r.passed && (r.reason ?? "").includes("daily spending limit"),
    );
    // call0 has no failing spending-limit result …
    expect(
      body.data.policyResults.some(
        (r) => r.callIndex === 0 && !r.passed && (r.reason ?? "").includes("daily spending limit"),
      ),
    ).toBe(false);
    // … while call1 does — proving the cap was evaluated against the running total.
    expect(call1DailyFail).toBeDefined();
    void call0Spend;
  });

  it("ALLOWS an op within the daily cap (the gate is not a blanket deny)", async () => {
    // 0 + 300 = 300 ≤ 1000 → approved. send-calls always queues batch actions
    // for approval, so an allowed op surfaces as 202 pending_approval (the cap
    // did NOT reject it — contrast with the 403s above).
    const res = await sendCalls(app, AGENT_UNDER_CAP, [{ to: ALLOWED, value: "300" }]);
    expect(res.status).toBe(202);
    const body = (await res.json()) as { ok: boolean; data: { id: string; status: string } };
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("pending_approval");
  });

  it("REJECTS a replayed referenceId and does not create a duplicate action", async () => {
    const referenceId = `replay-ref-${Date.now()}`;
    const first = await sendCalls(app, AGENT_REPLAY, [{ to: ALLOWED, value: "5" }], {
      referenceId,
    });
    expect(first.status).toBe(202);
    const firstBody = (await first.json()) as { data: { id: string } };
    const firstId = firstBody.data.id;

    const replay = await sendCalls(app, AGENT_REPLAY, [{ to: ALLOWED, value: "5" }], {
      referenceId,
    });
    expect(replay.status).toBe(409);
    const replayBody = (await replay.json()) as {
      ok: boolean;
      error?: string;
      data: { actionId: string; status: string };
    };
    expect(replayBody.ok).toBe(false);
    expect(replayBody.error).toContain("referenceId has already been used");
    // The replay resolves to the SAME action id — no second action created.
    expect(replayBody.data.actionId).toBe(firstId);

    const rows = await getDb()
      .select({ id: transactions.id })
      .from(transactions)
      .where(
        and(eq(transactions.agentId, AGENT_REPLAY), eq(transactions.actionType, "send_calls")),
      );
    expect(rows).toHaveLength(1);
    expect(rows[0].id).toBe(firstId);
  });
});
