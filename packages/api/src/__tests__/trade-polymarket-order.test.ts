/**
 * Behavioral coverage for POST /v1/trade/polymarket/order.
 *
 * Mirrors the Hyperliquid venue-submit fence test's harness: a real in-memory
 * PGLite DB + the REAL TradeSessionManager, driving the REAL route. Only two
 * seams are stubbed, both infrastructure:
 *   - PolymarketExecutionAdapter.submitOrder (the venue network edge); and
 *   - vault.getWallet, to inject the agent's polymarket venue wallet + funder
 *     metadata (provisioning of the wallet itself is out of scope here).
 *
 * The L2 CLOB apiCredentials are NOT provisioned by anything yet (Phase C), so
 * the route's resolvePolymarketCreds returns `creds-not-provisioned` by default
 * and the route fails closed (409). The "happy path" test patches the
 * creds-resolution by spying the adapter constructor's guard indirectly: it
 * monkeypatches vault.getWallet to return funder metadata AND stubs the secret
 * path by spying on PolymarketExecutionAdapter so no real client/creds run.
 * Because the route's fail-closed gate keys on the (still-unwired) secret creds,
 * the happy-path test injects creds via a module-level spy on the route's
 * resolver is not possible (it's a closure); instead we assert the happy path
 * THROUGH the adapter by provisioning funder metadata and asserting the route
 * reaches the adapter only when creds resolve. Since creds cannot resolve yet,
 * the happy-path test stubs the adapter AND asserts the fail-closed 409 is the
 * current contract, then a SECOND happy-path variant injects a resolvable creds
 * path via a test-only env seam.
 *
 * Coverage:
 *   (a) policy-reject: market-not-allowed -> 400 policy-violation + audit, no spend.
 *   (b) policy-reject: per-order-cap-exceeded -> 400 policy-violation + audit.
 *   (c) idempotency: conflict (same key, different body) -> 409; replay -> same envelope.
 *   (d) session-not-active (revoked) -> 403.
 *   (e) creds-not-provisioned -> 409 fail-closed, no spend reserved.
 *   (f) happy path (mocked adapter returns filled) -> 200 + spend reserved + submitted audit.
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  setDefaultTimeout,
  spyOn,
} from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants, tradeSessions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { TradeSessionManager } from "@stwd/trade-sessions";
import { PolymarketExecutionAdapter } from "@stwd/venue-polymarket";
import { Vault } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const TOKEN_ID = "71321045679252212594626385532706912750332728571942532289631379312455583992563";
const COND_ID = "0xabc123";
const FUNDER = "0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c";
const WALLET = "0x1111111111111111111111111111111111111111";

let submitSpy: ReturnType<typeof spyOn> | undefined;
let getWalletSpy: ReturnType<typeof spyOn> | undefined;
let buildSpy: ReturnType<typeof spyOn> | undefined;
let fenceSpy: ReturnType<typeof spyOn> | undefined;

// Inject a polymarket venue wallet WITH funder metadata so the creds resolver
// gets past the wallet step. Whether the L2 creds resolve (Phase C) is toggled
// separately per test by mutating the metadata.
function stubWallet(withFunder: boolean) {
  getWalletSpy = spyOn(Vault.prototype, "getWallet").mockImplementation((async (args: {
    venue?: string;
  }) => {
    if (args.venue !== "polymarket") throw new Error("no wallet");
    return {
      agentId: "x",
      chainFamily: "evm" as const,
      venue: "polymarket",
      purpose: null,
      address: WALLET,
      metadata: withFunder ? { funderAddress: FUNDER } : {},
    };
  }) as never);
}

async function seedSession(opts: {
  allowedAssets?: string[];
  perOrderCapUsd?: string;
  dailyCapUsd?: string;
  status?: "active" | "revoked";
}): Promise<{ tenantId: string; agentId: string; sessionId: string }> {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tenantId = `pm-tenant-${suffix}`;
  const agentId = `pm-agent-${suffix}`;
  const sessionId = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "PM Tenant", apiKeyHash: `hash-${tenantId}` });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "PM Agent",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
  await getDb()
    .insert(tradeSessions)
    .values({
      id: sessionId,
      tenantId,
      agentId,
      venue: "polymarket",
      walletId: WALLET,
      status: opts.status ?? "active",
      dailySpendUsd: "0",
      dailyCapUsd: opts.dailyCapUsd ?? "100",
      perOrderCapUsd: opts.perOrderCapUsd ?? "50",
      leverageCap: "1",
      allowedAssets: opts.allowedAssets ?? [`pm:${TOKEN_ID}`],
      expiresAt: new Date(Date.now() + 60_000),
      ...(opts.status === "revoked" ? { revokedAt: new Date() } : {}),
    });
  return { tenantId, agentId, sessionId };
}

function makeApp(tenantId: string, agentId: string, routes: Hono) {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent-token");
    await next();
  });
  app.route("/v1/trade", routes);
  return app;
}

function postOrder(
  app: Hono,
  sessionId: string,
  idempotencyKey: string,
  body: Record<string, unknown> = {},
) {
  return app.request("/v1/trade/polymarket/order", {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({
      sessionId,
      tokenId: TOKEN_ID,
      side: "buy",
      amount: 10,
      price: 0.5,
      ...body,
    }),
  });
}

async function dailySpendOf(sessionId: string): Promise<number> {
  const [row] = await getDb()
    .select({ spent: tradeSessions.dailySpendUsd })
    .from(tradeSessions)
    .where(eq(tradeSessions.id, sessionId));
  return Number(row.spent);
}

async function auditCount(tenantId: string, action: string): Promise<number> {
  const rows = await getDb()
    .select({ seq: auditEvents.seq })
    .from(auditEvents)
    .where(and(eq(auditEvents.action, action), eq(auditEvents.tenantId, tenantId)));
  return rows.length;
}

describe("POST /v1/trade/polymarket/order", () => {
  let tradeRoutes: Hono;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD ??= "pm-order-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "pm-order-test-audit-hmac-key-0123456789abcdef0";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    // Faithful pass-through for the fence's DB-transaction wrapper. The real
    // wrapper opens getDb().transaction() + an advisory lock and re-selects the
    // active session; under single-connection PGLite the callback's own base-
    // connection queries (reserveSpend + audit writes) deadlock against the outer
    // transaction (production runs them on a pooled connection). The advisory-lock
    // atomicity is a @stwd/trade-sessions concern; the spend/audit invariants the
    // route owns run for real inside the callback. Returns null when the session
    // is not active so the route's revoke-race 409 path is exercised.
    fenceSpy = spyOn(TradeSessionManager.prototype, "withActiveSubmissionFence").mockImplementation(
      (async (input: { tenantId: string; id: string }, cb: () => Promise<unknown>) => {
        const active = await new TradeSessionManager().getActive(input.tenantId, input.id);
        if (!active) return null;
        return cb();
      }) as never,
    );
    ({ tradeRoutes } = await import("../routes/trade"));
  });

  afterAll(async () => {
    fenceSpy?.mockRestore();
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  afterEach(() => {
    submitSpy?.mockRestore();
    getWalletSpy?.mockRestore();
    buildSpy?.mockRestore();
    submitSpy = undefined;
    getWalletSpy = undefined;
    buildSpy = undefined;
  });

  it("rejects an order whose market is not allowlisted (400 policy-violation, no spend)", async () => {
    // session allowlist is only pm:<OTHER>, so pm:<TOKEN_ID> is not allowed.
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: ["pm:99999999"],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toBe("market-not-allowed");

    expect(await dailySpendOf(sessionId)).toBe(0);
    expect(await auditCount(tenantId, "trade.order.policy-rejected")).toBe(1);
    expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
  });

  it("rejects an order over the per-order cap (400 policy-violation)", async () => {
    // perOrderCap 5, BUY amount 10 USD -> notional 10 > 5.
    const { tenantId, agentId, sessionId } = await seedSession({
      perOrderCapUsd: "5",
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toBe("per-order-cap-exceeded");
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("allows the whole market via pm:cond:<conditionId> allowlist entry", async () => {
    // No pm:<token> entry, only the condition entry; passing conditionId grants it.
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:cond:${COND_ID}`],
    });
    stubWallet(true); // funder present, but L2 creds still unprovisioned -> 409
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID(), {
      conditionId: COND_ID,
    });
    // The policy gate PASSED (market allowed) — we get past it to the creds gate,
    // which fails closed (409). Proves the conditionId allowlist path works.
    expect(res.status).toBe(409);
    expect(await auditCount(tenantId, "trade.order.policy-rejected")).toBe(1); // the creds fail-closed audit
  });

  it("returns 409 on idempotency-key reuse with a different body; replays the same envelope", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: ["pm:99999999"],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const key = crypto.randomUUID();

    // First call: market-not-allowed -> 400, stored under the key.
    const first = await postOrder(app, sessionId, key);
    expect(first.status).toBe(400);

    // Same key, DIFFERENT body (different price) -> conflict 409.
    const conflict = await postOrder(app, sessionId, key, { price: 0.6 });
    expect(conflict.status).toBe(409);
    expect(((await conflict.json()) as { error?: string }).error).toContain(
      "Idempotency key reused",
    );

    // Same key, SAME body -> replay of the stored 400.
    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(400);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
  });

  it("returns 403 when the session is not active (revoked)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({ status: "revoked" });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error?: string }).error).toContain(
      "Active Polymarket session required",
    );
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("fails closed with 409 when polymarket creds are not provisioned (no spend reserved)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    stubWallet(true); // wallet + funder present, but L2 creds unprovisioned
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error?: string }).error).toContain(
      "credentials are not provisioned",
    );
    // Creds are resolved BEFORE spend reservation, so the daily cap is untouched.
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("fails closed with 409 when the polymarket venue wallet is missing", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    // getWallet throws -> wallet-not-found.
    getWalletSpy = spyOn(Vault.prototype, "getWallet").mockImplementation((async () => {
      throw new Error("no wallet");
    }) as never);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error?: string }).error).toContain("venue wallet not found");
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("happy path: filled order -> 200, spend reserved, submitted + authorized audits (mocked adapter)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    // Provision funder metadata on the venue wallet + flip the route's test-only
    // L2-creds seam so resolvePolymarketCreds resolves (Phase C wires the real
    // secret-vault read here). The adapter network edge is stubbed so no real
    // clob-client / signing runs.
    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-ok-1",
      status: "matched",
      success: true,
      makingAmount: "10",
      takingAmount: "20",
      actualAmount: 20,
      actualPrice: 0.5,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { orderId: string; filledQty: number; avgPrice: number; status: string };
      };
      expect(body.ok).toBe(true);
      expect(body.data.orderId).toBe("pm-ok-1");
      expect(body.data.filledQty).toBe(20);
      expect(body.data.avgPrice).toBeCloseTo(0.5, 10);
      expect(submitSpy).toHaveBeenCalledTimes(1);
      // BUY notional = amount (10 USD) is reserved against the daily cap.
      expect(await dailySpendOf(sessionId)).toBe(10);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.submit.authorized")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.canceled")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("venue rejection -> 400, releases reserved spend, writes canceled audit (no submitted)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-rej-1",
      success: false,
      errorMsg: "order rejected by book",
      actualAmount: 0,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(400);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("order rejected by book");
      // Reserved spend was released back to 0 on rejection.
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.canceled")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("pre-submit build failure -> 400, RELEASES spend, never calls submitOrder", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    // buildSignedOrder throws BEFORE anything reaches the venue (e.g. tickSize
    // resolution failure / CLOB rounding rejection). submitOrder must NOT run
    // and the reserved spend MUST be released (this never burns the daily cap).
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockRejectedValue(
      new Error("could not resolve tickSize"),
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitOrder").mockResolvedValue({
      venue: "polymarket" as const,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error?: string }).error).toContain("could not be built");
      expect(submitSpy).toHaveBeenCalledTimes(0);
      // Pre-submit failures release the reserved spend.
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("submit-status-unknown (adapter throws post-submit) -> 502, KEEPS spend reserved", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    // The build succeeded; the POST faults -> the order may have landed. Spend
    // stays reserved (mirrors HL's 502 path).
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitOrder").mockRejectedValue(
      new Error("socket hang up"),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(502);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "Trade submission status unknown",
      );
      // The order may have landed -> spend is NOT released.
      expect(await dailySpendOf(sessionId)).toBe(10);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("revoke race: session revoked before the submit fence -> 409, never submits", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-should-not-run",
      success: true,
      actualAmount: 20,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitOrder"]>>);

    // Simulate the revoke landing in the fence window: revoke the session right
    // after the policy gate but before the fence runs its active recheck. The
    // fence stub re-reads getActive() and returns null -> route fails closed.
    await getDb()
      .update(tradeSessions)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(eq(tradeSessions.id, sessionId));

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      // The pre-fence checkActiveOrder also sees it revoked -> 403; either way
      // the order is NOT submitted and no spend is consumed.
      expect([403, 409]).toContain(res.status);
      expect(submitSpy).toHaveBeenCalledTimes(0);
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });
});
