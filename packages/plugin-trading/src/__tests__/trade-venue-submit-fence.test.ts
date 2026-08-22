/**
 * REAL behavioral coverage for the Hyperliquid venue-submit spend-fence and the
 * submit-authorization ordering on POST /v1/trade/hyperliquid/order.
 *
 * The retired structural backstop (in vault-trade-audit-gates.test.ts) only
 * readFileSync'd trade.ts and asserted, by substring/index order, that:
 *   - the rejected branch releases spend + writes trade.order.canceled and
 *     returns before trade.order.submitted;
 *   - the submitAttempted branch keeps spend + idempotency fenced and returns a
 *     502 without releasing;
 *   - "trade.order.submit.authorized" appears before adapter.signOrder.
 * A grep cannot prove any of those FIRE. This drives the REAL route against an
 * in-memory PGLite DB + the REAL TradeSessionManager and proves them by
 * execution:
 *
 *   (a) venue rejection (submitOrder resolves status:"rejected") → 400 carrying
 *       the venue error, the reserved spend is RELEASED (dailySpendUsd back to 0),
 *       a trade.order.canceled audit is written, NO trade.order.submitted audit
 *       exists, and an idempotent replay returns the same 400 WITHOUT re-hitting
 *       the venue.
 *   (b) unknown status (submitOrder throws AFTER the submit was attempted) → 502
 *       "Trade submission status unknown", and — because the order may have landed
 *       at the venue — the spend is NOT released (dailySpendUsd stays at the
 *       reserved notional); an idempotent replay returns the same 502 WITHOUT
 *       re-submitting.
 *   (c) success → 200, and the trade.order.submit.authorized audit is sequenced
 *       BEFORE trade.order.submitted (authorization is durably recorded as part of
 *       the committed submit), with signOrder invoked before submitOrder.
 *
 * Two seams are stubbed, both infrastructure:
 *   - the venue adapter's network edge — HyperliquidAdapter.signOrder /
 *     .submitOrder at the prototype (signOrder's output is irrelevant since
 *     submitOrder is stubbed too, so no key material or typed-data signing runs);
 *   - TradeSessionManager's initial and final DB-transaction fence wrappers,
 *     replaced by controlled pass-throughs. The final wrapper can also choose a
 *     revoke-first result without contacting the venue. Actual advisory-lock
 *     ordering across two connections lives in the real-Postgres companion test;
 *     this mounted suite owns route-side sign/submit/spend/audit behavior.
 *
 * Everything else runs for real: routing, validation, policy evaluation, spend
 * reserve/release, the submit-attempt catch, idempotency claim/replay, the audit
 * writes, and the HTTP envelopes.
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
import { fileURLToPath } from "node:url";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  runPluginMigrations,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { IoredisLike } from "@stwd/redis";
import type { AppVariables } from "@stwd/shared";
import { TradeSessionManager } from "@stwd/trade-sessions";
import { HyperliquidAdapter } from "@stwd/venue-hyperliquid";
import { and, eq, sql } from "drizzle-orm";
import { migrate } from "drizzle-orm/pglite/migrator";
import { Hono } from "hono";
import { tradingOrderOutcomes } from "../schema";

// size 1 @ limitPx 10 (a BUY, so estimateHyperliquidOrderUsd needs no price
// fetch) → sizeUsd 10: under perOrderCap 50 and dailyCap 100, leverage within cap.
const SIZE_USD = 10;
const ORDER_BODY = {
  asset: "BTC" as const,
  side: "buy" as const,
  size: 1,
  limitPx: 10,
  leverage: 1,
};

setDefaultTimeout(30000);

let signSpy: ReturnType<typeof spyOn> | undefined;
let submitSpy: ReturnType<typeof spyOn> | undefined;
let updateLeverageSpy: ReturnType<typeof spyOn> | undefined;
let fenceSpy: ReturnType<typeof spyOn> | undefined;
let venueFenceSpy: ReturnType<typeof spyOn> | undefined;

function redisWithFailedCompletionCas(): { client: IoredisLike; values: Map<string, string> } {
  const values = new Map<string, string>();
  const client = {
    get: async (key: string) => values.get(key) ?? null,
    set: async (...args: Array<string | number>) => {
      const [key, value, mode, , condition] = args;
      if (condition === "NX" && values.has(String(key))) return null;
      values.set(String(key), String(value));
      return mode === "PX" ? "OK" : "OK";
    },
    setex: async (key: string, _seconds: number, value: string) => {
      values.set(key, value);
      return "OK";
    },
    del: async (...keys: string[]) => {
      let removed = 0;
      for (const key of keys) removed += values.delete(key) ? 1 : 0;
      return removed;
    },
    eval: async (script: string) => {
      if (script.includes("ZREMRANGEBYSCORE")) return [1, 1, String(Date.now())];
      throw new Error("redis completion CAS unavailable");
    },
  } as unknown as IoredisLike;
  return { client, values };
}

async function seedSession(
  allowedAssets: string[] = ["BTC"],
): Promise<{ tenantId: string; agentId: string; sessionId: string }> {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tenantId = `venue-fence-tenant-${suffix}`;
  const agentId = `venue-fence-agent-${suffix}`;
  const sessionId = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "Venue Fence Tenant", apiKeyHash: `hash-${tenantId}` });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "Venue Fence Agent",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
  await getDb()
    .insert(tradeSessions)
    .values({
      id: sessionId,
      tenantId,
      agentId,
      venue: "hyperliquid",
      walletId: "0x0000000000000000000000000000000000000001",
      status: "active",
      dailySpendUsd: "0",
      dailyCapUsd: "100",
      perOrderCapUsd: "50",
      leverageCap: "5",
      allowedAssets,
      expiresAt: new Date(Date.now() + 60_000),
    });
  return { tenantId, agentId, sessionId };
}

function makeApp(tenantId: string, agentId: string, routes: Hono) {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent");
    await next();
  });
  app.route("/v1/trade", routes);
  return app;
}

function postOrder(
  app: Hono,
  sessionId: string,
  idempotencyKey: string,
  body: Record<string, unknown> = ORDER_BODY,
) {
  return app.request("/v1/trade/hyperliquid/order", {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({ sessionId, ...body }),
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

async function terminalPhaseCount(tenantId: string, agentId: string): Promise<number> {
  const rows = await getDb()
    .select({ id: tradingOrderOutcomes.id })
    .from(tradingOrderOutcomes)
    .where(
      and(
        eq(tradingOrderOutcomes.tenantId, tenantId),
        eq(tradingOrderOutcomes.agentId, agentId),
        eq(tradingOrderOutcomes.phase, "terminal"),
      ),
    );
  return rows.length;
}

async function setTerminalPersistenceFault(enabled: boolean): Promise<void> {
  await getDb().execute(sql.raw("DROP TRIGGER IF EXISTS trading_test_reject_terminal ON trading_order_outcomes"));
  await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS trading_test_reject_terminal()"));
  if (!enabled) return;
  await getDb().execute(sql.raw(`
    CREATE FUNCTION trading_test_reject_terminal() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.phase = 'terminal' THEN
        RAISE EXCEPTION 'injected terminal persistence fault' USING ERRCODE = '53100';
      END IF;
      RETURN NEW;
    END;
    $$
  `));
  await getDb().execute(sql.raw(`
    CREATE TRIGGER trading_test_reject_terminal
    BEFORE INSERT ON trading_order_outcomes
    FOR EACH ROW EXECUTE FUNCTION trading_test_reject_terminal()
  `));
}

describe("Hyperliquid venue-submit spend-fence (real /hyperliquid/order path)", () => {
  let tradeRoutes: Hono;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD ??= "venue-fence-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "venue-submit-fence-test-audit-hmac-key-0123456789abcdef";
    const { db, client } = await createPGLiteDb("memory://");
    await runPluginMigrations(
      {
        id: "trading-test",
        migrationsFolder: fileURLToPath(new URL("../../drizzle", import.meta.url)),
      },
      { db, useAdvisoryLock: false, migrateFn: migrate as never },
    );
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    // Pass through the initial fence's DB-transaction wrapper. The callback's
    // spend/audit behavior runs for real; advisory-lock ordering is covered by the
    // real-Postgres companion test. The route ignores this session argument.
    fenceSpy = spyOn(TradeSessionManager.prototype, "withActiveSubmissionFence").mockImplementation(
      (async (_input, cb) => cb(undefined)) as never,
    );
    // The final venue fence itself is exercised with two real PostgreSQL
    // connections in trade-session-revocation-fence.real-pg.test.ts. Here the
    // seam lets the mounted route deterministically choose each winner while
    // every route-side sign/submit/spend/audit behavior remains real.
    venueFenceSpy = spyOn(
      TradeSessionManager.prototype,
      "withActiveVenueSubmissionFence",
    ).mockImplementation((async (_input, cb) => cb(undefined)) as never);
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    tradeRoutes = createTradeRoutes(testCtx());
  });

  afterAll(async () => {
    fenceSpy?.mockRestore();
    venueFenceSpy?.mockRestore();
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  afterEach(async () => {
    signSpy?.mockRestore();
    submitSpy?.mockRestore();
    updateLeverageSpy?.mockRestore();
    signSpy = undefined;
    submitSpy = undefined;
    updateLeverageSpy = undefined;
    await setTerminalPersistenceFault(false);
  });

  it("releases spend and cancels (no submitted audit) when the venue rejects the order", async () => {
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, tradeRoutes);

    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "hl-rejected-1",
      status: "rejected",
      error: "insufficient margin",
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);

    const key = crypto.randomUUID();
    const res = await postOrder(app, sessionId, key);
    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error?: string; data?: { status: string } };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("insufficient margin");
    expect(body.data?.status).toBe("rejected");

    // The venue WAS attempted, but the rejection released the reserved spend.
    expect(submitSpy).toHaveBeenCalledTimes(1);
    expect(await dailySpendOf(sessionId)).toBe(0);

    // A canceled audit exists; the success audit was never written.
    expect(await auditCount(tenantId, "trade.order.canceled")).toBe(1);
    expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    // The submit was authorized before the venue was contacted, and that
    // authorization audit persists even though the order was ultimately rejected.
    expect(await auditCount(tenantId, "trade.order.submit.authorized")).toBe(1);

    // Idempotent replay returns the same 400 envelope WITHOUT re-hitting the venue.
    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(400);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(((await replay.json()) as { error?: string }).error).toBe("insufficient margin");
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("keeps spend reserved and returns 502 when the venue submit status is unknown", async () => {
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, tradeRoutes);

    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    // The submit was attempted (submitAttempted=true is set before submitOrder),
    // then the venue call faults — we cannot know whether the order landed.
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockRejectedValue(
      new Error("socket hang up"),
    );

    const key = crypto.randomUUID();
    const res = await postOrder(app, sessionId, key);
    expect(res.status).toBe(502);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Trade submission status unknown");

    // The order may have hit the venue → the spend stays reserved (NOT released).
    expect(submitSpy).toHaveBeenCalledTimes(1);
    expect(await dailySpendOf(sessionId)).toBe(SIZE_USD);
    expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    // Authorization was recorded before the faulting submit attempt.
    expect(await auditCount(tenantId, "trade.order.submit.authorized")).toBe(1);

    // Idempotent replay returns the same 502 WITHOUT re-submitting to the venue.
    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(502);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(((await replay.json()) as { error?: string }).error).toContain(
      "Trade submission status unknown",
    );
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("records submit-authorization before the submitted audit, with signOrder before submitOrder", async () => {
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const callOrder: string[] = [];
    let observedProviderRequestId: string | undefined;
    let observedSignedCloid: string | undefined;
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockImplementation(
      async (order) => {
        callOrder.push("sign");
        return {
          action: { orders: [{ c: order.cloid }] },
        } as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>;
      },
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockImplementation(async (signed) => {
      expect(await terminalPhaseCount(tenantId, agentId)).toBe(0);
      const claims = await getDb()
        .select({ phase: tradingOrderOutcomes.phase, response: tradingOrderOutcomes.response })
        .from(tradingOrderOutcomes)
        .where(
          and(
            eq(tradingOrderOutcomes.tenantId, tenantId),
            eq(tradingOrderOutcomes.agentId, agentId),
          ),
        );
      expect(claims).toHaveLength(1);
      expect(claims[0]?.phase).toBe("claim");
      observedProviderRequestId = (
        claims[0]?.response as { body?: { data?: { providerRequestId?: string } } }
      ).body?.data?.providerRequestId;
      observedSignedCloid = (
        (signed.action.orders as Array<Record<string, unknown>>)[0] as { c?: string }
      ).c;
      callOrder.push("submit");
      return {
        orderId: "hl-ok-1",
        status: "filled",
        filledQty: 1,
        avgPrice: 10,
        txHash: "0xabc",
      } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>;
    });

    const key = crypto.randomUUID();
    const res = await postOrder(app, sessionId, key);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string; orderId: string } };
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("filled");
    expect(body.data.orderId).toBe("hl-ok-1");
    expect(observedProviderRequestId).toBe(observedSignedCloid);
    expect(observedProviderRequestId).toMatch(/^0x[0-9a-f]{32}$/);

    // signing happened before submission …
    expect(callOrder).toEqual(["sign", "submit"]);
    // … the spend is consumed (a successful submit is not released) …
    expect(await dailySpendOf(sessionId)).toBe(SIZE_USD);

    // … and the authorization audit is attributed to the agent and sequenced
    // BEFORE the success audit (it was committed as part of the same submit).
    const authorized = await getDb()
      .select({
        seq: auditEvents.seq,
        actorType: auditEvents.actorType,
        actorId: auditEvents.actorId,
      })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.action, "trade.order.submit.authorized"),
          eq(auditEvents.tenantId, tenantId),
        ),
      );
    const submitted = await getDb()
      .select({ seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(eq(auditEvents.action, "trade.order.submitted"), eq(auditEvents.tenantId, tenantId)),
      );
    expect(authorized.length).toBe(1);
    expect(submitted.length).toBe(1);
    expect(authorized[0].actorType).toBe("agent");
    expect(authorized[0].actorId).toBe(agentId);
    expect(authorized[0].seq).toBeLessThan(submitted[0].seq);
    expect(await terminalPhaseCount(tenantId, agentId)).toBe(1);
  });

  for (const scenario of ["filled", "rejected", "ambiguous"] as const) {
    it(`keeps ${scenario} terminal-persistence faults non-resubmittable`, async () => {
      const { tenantId, agentId, sessionId } = await seedSession();
      const app = makeApp(tenantId, agentId, tradeRoutes);
      signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue({} as never);
      submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder");
      if (scenario === "filled") {
        submitSpy.mockResolvedValue({
          orderId: "hl-persist-filled",
          status: "filled",
          filledQty: 1,
          avgPrice: 10,
        } as never);
      } else if (scenario === "rejected") {
        submitSpy.mockResolvedValue({
          orderId: "hl-persist-rejected",
          status: "rejected",
          error: "definite rejection",
        } as never);
      } else {
        submitSpy.mockRejectedValue(new Error("connection lost after write"));
      }
      await setTerminalPersistenceFault(true);

      const key = crypto.randomUUID();
      const response = await postOrder(app, sessionId, key);
      expect(response.status).toBe(502);
      expect(((await response.json()) as { error: string }).error).toBe(
        "Trade execution requires reconciliation",
      );
      expect(submitSpy).toHaveBeenCalledTimes(1);
      expect(await dailySpendOf(sessionId)).toBe(SIZE_USD);
      expect(await terminalPhaseCount(tenantId, agentId)).toBe(0);

      // Simulate restart/Redis loss with a fresh router. The immutable claim is
      // sufficient to fence the movement until an operator reconciles it.
      const { createTradeRoutes } = await import("../routes/trade");
      const { testCtx } = await import("./_ctx");
      const replay = await postOrder(
        makeApp(tenantId, agentId, createTradeRoutes(testCtx())),
        sessionId,
        key,
      );
      expect(replay.status).toBe(502);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(submitSpy).toHaveBeenCalledTimes(1);
    });
  }

  it("does not call the venue when revocation wins the post-sign submission fence", async () => {
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, tradeRoutes);
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "must-not-submit",
      status: "filled",
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);
    venueFenceSpy?.mockImplementationOnce((async (input) => {
      await new TradeSessionManager().revokeSession({ ...input, revokedBy: "test-revoker" });
      return null;
    }) as never);

    const key = crypto.randomUUID();
    const response = await postOrder(app, sessionId, key);
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      ok: false,
      error: "Trade session was revoked before order submission",
    });
    expect(signSpy).toHaveBeenCalledTimes(1);
    expect(submitSpy).not.toHaveBeenCalled();
    expect(await dailySpendOf(sessionId)).toBe(0);

    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(409);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitSpy).not.toHaveBeenCalled();
  });

  it("returns and replays a terminal fill when the completion audit fails", async () => {
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    const baseCtx = testCtx();
    const failingRoutes = createTradeRoutes({
      ...baseCtx,
      writeAuditEvent: async (event) => {
        if (event.action === "trade.order.submitted") throw new Error("audit unavailable");
        await baseCtx.writeAuditEvent(event);
      },
    });
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, failingRoutes);
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "hl-audit-failure-terminal",
      status: "filled",
      filledQty: 1,
      avgPrice: 10,
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);

    const key = crypto.randomUUID();
    const response = await postOrder(app, sessionId, key);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { orderId: string } }).data.orderId).toBe(
      "hl-audit-failure-terminal",
    );
    const replayRoutes = createTradeRoutes(baseCtx);
    const replay = await postOrder(makeApp(tenantId, agentId, replayRoutes), sessionId, key);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(((await replay.json()) as { data: { orderId: string } }).data.orderId).toBe(
      "hl-audit-failure-terminal",
    );
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("replays from PostgreSQL when Redis completion CAS leaves the claim pending", async () => {
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    const redis = redisWithFailedCompletionCas();
    const baseCtx = testCtx();
    const routes = createTradeRoutes({ ...baseCtx, getRedisClient: () => redis.client });
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, routes);
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "hl-durable-db-replay",
      status: "filled",
      filledQty: 1,
      avgPrice: 10,
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);

    const key = crypto.randomUUID();
    const response = await postOrder(app, sessionId, key);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { orderId: string } }).data.orderId).toBe(
      "hl-durable-db-replay",
    );
    expect([...redis.values.values()].some((value) => value.includes('"state":"pending"'))).toBe(
      true,
    );

    // A fresh router has an empty process-local store. PostgreSQL must win over
    // the stale Redis pending marker and replay without touching the venue.
    const restartedRoutes = createTradeRoutes({ ...baseCtx, getRedisClient: () => redis.client });
    const replay = await postOrder(makeApp(tenantId, agentId, restartedRoutes), sessionId, key);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(((await replay.json()) as { data: { orderId: string } }).data.orderId).toBe(
      "hl-durable-db-replay",
    );
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("durably replays an ambiguous 502 when Redis completion CAS fails", async () => {
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    const redis = redisWithFailedCompletionCas();
    const baseCtx = testCtx();
    const routes = createTradeRoutes({ ...baseCtx, getRedisClient: () => redis.client });
    const { tenantId, agentId, sessionId } = await seedSession();
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockRejectedValue(
      new Error("connection lost after write"),
    );

    const key = crypto.randomUUID();
    const response = await postOrder(makeApp(tenantId, agentId, routes), sessionId, key);
    expect(response.status).toBe(502);
    expect(((await response.json()) as { error: string }).error).toBe(
      "Trade submission status unknown",
    );
    expect([...redis.values.values()].some((value) => value.includes('"state":"pending"'))).toBe(
      true,
    );

    const restartedRoutes = createTradeRoutes({ ...baseCtx, getRedisClient: () => redis.client });
    const replay = await postOrder(makeApp(tenantId, agentId, restartedRoutes), sessionId, key);
    expect(replay.status).toBe(502);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(((await replay.json()) as { error: string }).error).toBe(
      "Trade submission status unknown",
    );
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("preserves a known venue result when the fence transaction faults afterward", async () => {
    const { tenantId, agentId, sessionId } = await seedSession();
    const app = makeApp(tenantId, agentId, tradeRoutes);
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "hl-post-submit-fence-fault",
      status: "filled",
      filledQty: 1,
      avgPrice: 10,
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);
    venueFenceSpy?.mockImplementationOnce((async (_input, callback) => {
      await callback(undefined);
      throw new Error("transaction commit failed after venue response");
    }) as never);

    const key = crypto.randomUUID();
    const response = await postOrder(app, sessionId, key);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { orderId: string } }).data.orderId).toBe(
      "hl-post-submit-fence-fault",
    );
    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitSpy).toHaveBeenCalledTimes(1);
  });

  it("sets clamped isolated leverage before signing builder-perp orders", async () => {
    const builderAsset = "xyz:SPCX";
    const { tenantId, agentId, sessionId } = await seedSession([builderAsset]);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const callOrder: string[] = [];
    updateLeverageSpy = spyOn(HyperliquidAdapter.prototype, "updateLeverage").mockImplementation(
      async () => {
        callOrder.push("updateLeverage");
        return { status: "ok", raw: { response: { type: "default" } } } as Awaited<
          ReturnType<HyperliquidAdapter["updateLeverage"]>
        >;
      },
    );
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockImplementation(async () => {
      callOrder.push("sign");
      return {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>;
    });
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockImplementation(async () => {
      callOrder.push("submit");
      return {
        orderId: "hl-builder-ok-1",
        status: "filled",
        filledQty: 1,
        avgPrice: 10,
      } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>;
    });

    const key = crypto.randomUUID();
    const res = await postOrder(app, sessionId, key, {
      asset: builderAsset,
      side: "buy",
      size: 1,
      limitPx: 10,
      leverage: 10,
    });

    expect(res.status).toBe(200);
    expect(callOrder).toEqual(["updateLeverage", "sign", "submit"]);
    expect(updateLeverageSpy).toHaveBeenCalledTimes(1);
    expect(updateLeverageSpy).toHaveBeenCalledWith({
      coin: builderAsset,
      leverage: 3,
      isCross: false,
    });
    expect(signSpy).toHaveBeenCalledWith(
      expect.objectContaining({ asset: builderAsset, leverage: 3 }),
    );
    expect(await auditCount(tenantId, "trade.order.leverage.set")).toBe(1);
  });

  it("does not sign or submit when builder-perp leverage setup is rejected", async () => {
    const builderAsset = "xyz:SPCX";
    const { tenantId, agentId, sessionId } = await seedSession([builderAsset]);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    updateLeverageSpy = spyOn(HyperliquidAdapter.prototype, "updateLeverage").mockRejectedValue(
      new Error("venue leverage rejected"),
    );
    signSpy = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue(
      {} as Awaited<ReturnType<HyperliquidAdapter["signOrder"]>>,
    );
    submitSpy = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "must-not-submit",
      status: "filled",
    } as Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>);

    const response = await postOrder(app, sessionId, crypto.randomUUID(), {
      asset: builderAsset,
      side: "buy",
      size: 1,
      limitPx: 10,
      leverage: 10,
    });
    expect(response.status).toBe(502);
    expect(updateLeverageSpy).toHaveBeenCalledWith({
      coin: builderAsset,
      leverage: 3,
      isCross: false,
    });
    expect(signSpy).not.toHaveBeenCalled();
    expect(submitSpy).not.toHaveBeenCalled();
    expect(await dailySpendOf(sessionId)).toBe(0);
    expect(await auditCount(tenantId, "trade.order.leverage.failed")).toBe(1);
  });
});
