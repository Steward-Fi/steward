/**
 * SEC-108 regression coverage: the Polymarket L2 CLOB creds cached in Redis
 * are AES-256-GCM encrypted at rest (never plaintext), a second order hits the
 * cache instead of re-deriving, and a legacy plaintext entry is treated as a
 * cache miss and rewritten encrypted.
 *
 * Harness mirrors trade-polymarket-order.test.ts's deterministic E2E: real
 * in-memory PGLite, real vault wallet + signer, the CLOB SDK intercepted at
 * the network edge — plus an in-memory Redis injected through the plugin ctx
 * so the RAW stored bytes are assertable.
 */
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
  spyOn,
} from "bun:test";
import { ClobClient } from "@polymarket/clob-client";
import { agents, closeDb, getDb, tenants, tradeSessions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { AppVariables } from "@stwd/shared";
import { TradeSessionManager } from "@stwd/trade-sessions";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";

setDefaultTimeout(30000);

// In-memory Redis stand-in injected via the plugin ctx. Records RAW stored
// values so the test can assert the cached L2 creds are encrypted (SEC-108).
const redisStore = new Map<string, string>();
const fakeRedis = {
  get: async (key: string) => redisStore.get(key) ?? null,
  setex: async (key: string, _ttlSeconds: number, value: string) => {
    redisStore.set(key, value);
    return "OK";
  },
  del: async (...keys: string[]) => {
    let deleted = 0;
    for (const key of keys) if (redisStore.delete(key)) deleted += 1;
    return deleted;
  },
};

// With a Redis client present the route's rate limiter calls the real
// @stwd/redis singleton; keep it in-memory for this harness.
mock.module("@stwd/redis", () => ({
  checkRateLimit: async () => ({ allowed: true, remaining: 9, resetMs: 1_000 }),
  checkSpendLimit: async () => ({ allowed: true, spent: 0, remaining: 1 }),
  createUpstashIoredisAdapter: () => ({ ping: async () => "PONG" }),
  disconnectRedis: async () => undefined,
  estimateCost: () => 0,
  getAggregationSnapshot: async () => null,
  getCachedPolicies: async () => null,
  getPricingTable: () => ({}),
  getRedis: () => fakeRedis,
  getRedisDriver: () => "ioredis",
  getSpend: async () => 0,
  getSpendByHost: async () => ({}),
  invalidateCache: async () => undefined,
  invalidateTenantCache: async () => undefined,
  isKnownHost: () => false,
  recordAggregationEvent: async () => undefined,
  recordSpend: async () => undefined,
  reserveSpend: async () => ({ allowed: true, reservationId: "reservation-test" }),
  setCachedPolicies: async () => undefined,
  settleReservedSpend: async () => undefined,
}));

const TOKEN_ID = "71321045679252212594626385532706912750332728571942532289631379312455583992563";
const DERIVED_CREDS = {
  apiKey: "cache-test-key",
  secret: "cache-test-secret-plaintext",
  passphrase: "cache-test-pass",
};

let fenceSpy: ReturnType<typeof spyOn> | undefined;

async function seedTenantAgent(): Promise<{ tenantId: string; agentId: string }> {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tenantId = `pm-cache-tenant-${suffix}`;
  const agentId = `pm-cache-agent-${suffix}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "PM Cache Tenant", apiKeyHash: `hash-${tenantId}` });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "PM Cache Agent",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
  return { tenantId, agentId };
}

async function seedSession(
  tenantId: string,
  agentId: string,
  walletId: string,
): Promise<string> {
  const sessionId = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tradeSessions)
    .values({
      id: sessionId,
      tenantId,
      agentId,
      venue: "polymarket",
      walletId,
      status: "active",
      dailySpendUsd: "0",
      dailyCapUsd: "100",
      perOrderCapUsd: "50",
      leverageCap: "1",
      allowedAssets: [`pm:${TOKEN_ID}`],
      expiresAt: new Date(Date.now() + 60_000),
    });
  return sessionId;
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

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "pm-creds-cache-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "pm-creds-cache-audit-hmac-key-0123456789abcdef";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  // Same faithful fence pass-through as trade-polymarket-order.test.ts (the
  // real wrapper's outer transaction would deadlock single-connection PGLite).
  fenceSpy = spyOn(TradeSessionManager.prototype, "withActiveSubmissionFence").mockImplementation(
    (async (input: { tenantId: string; id: string }, cb: () => Promise<unknown>) => {
      const active = await new TradeSessionManager().getActive(input.tenantId, input.id);
      if (!active) return null;
      return cb();
    }) as never,
  );
});

afterAll(async () => {
  fenceSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
});

beforeEach(() => {
  redisStore.clear();
});

describe("SEC-108: Polymarket L2 creds Redis cache is encrypted at rest", () => {
  it("caches creds encrypted, serves the next order from cache, and rewrites legacy plaintext", async () => {
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    const ctx = {
      ...testCtx(),
      getRedisClient: () => fakeRedis,
    } as unknown as StewardAppContext;
    const tradeRoutes = createTradeRoutes(ctx);

    const { tenantId, agentId } = await seedTenantAgent();
    // Real provisioning into the encrypted venue-scoped vault; no key material
    // leaves the vault, and the L1->L2 derivation signs for real.
    const wallet = await ctx.vault.createWallet({
      agentId,
      venue: "polymarket",
      chainType: "evm",
    });
    const sessionId = await seedSession(tenantId, agentId, wallet.address);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const authKeyRequests: unknown[] = [];
    type ClobHttpOptions = { headers?: Record<string, string>; data?: unknown };
    type ClobHttpPrototype = {
      get(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
      post(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
    };
    const clobPrototype = ClobClient.prototype as unknown as ClobHttpPrototype;
    const getSpy = spyOn(clobPrototype, "get").mockImplementation((async (endpoint: string) => {
      const path = new URL(endpoint).pathname;
      if (path === "/tick-size") return { minimum_tick_size: 0.01 };
      if (path === "/fee-rate") return { base_fee: 0 };
      throw new Error(`unexpected CLOB GET ${path}`);
    }) as never);
    const postSpy = spyOn(clobPrototype, "post").mockImplementation((async (
      endpoint: string,
      options?: ClobHttpOptions,
    ) => {
      const path = new URL(endpoint).pathname;
      const headers = new Headers(options?.headers);
      if (path === "/auth/api-key") {
        authKeyRequests.push(options?.data);
        return DERIVED_CREDS;
      }
      if (path === "/order") {
        expect(headers.get("poly_api_key")).toBe(DERIVED_CREDS.apiKey);
        return {
          orderID: "pm-cache-order-1",
          status: "matched",
          success: true,
          makingAmount: "10000000",
          takingAmount: "20000000",
        };
      }
      throw new Error(`unexpected CLOB POST ${path}`);
    }) as never);

    process.env.POLYMARKET_CLOB_API_URL = "https://clob.e2e.invalid";
    try {
      const postOrder = () =>
        app.request("/v1/trade/polymarket/order", {
          method: "POST",
          headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
          body: JSON.stringify({
            sessionId,
            tokenId: TOKEN_ID,
            side: "buy",
            amount: 10,
            price: 0.5,
            tickSize: "0.01",
            negRisk: true,
          }),
        });

      // 1) Cache miss -> real L1->L2 derivation -> encrypted cache write.
      const first = await postOrder();
      expect(first.status).toBe(200);
      expect(authKeyRequests).toHaveLength(1);

      const pmKeys = [...redisStore.keys()].filter((key) => key.startsWith("pm:clob-l2:"));
      expect(pmKeys).toHaveLength(1);
      const storedRaw = redisStore.get(pmKeys[0] as string) as string;
      expect(storedRaw.startsWith("stwd_pmclob_v1:")).toBe(true);
      expect(storedRaw.includes(DERIVED_CREDS.secret)).toBe(false);
      expect(storedRaw.includes(DERIVED_CREDS.apiKey)).toBe(false);

      // 2) Second order resolves from the cache: no second derivation.
      const second = await postOrder();
      expect(second.status).toBe(200);
      expect(authKeyRequests).toHaveLength(1);

      // 3) A legacy PLAINTEXT entry is not trusted: it is treated as a cache
      // miss (re-derive) and rewritten encrypted.
      redisStore.set(pmKeys[0] as string, JSON.stringify(DERIVED_CREDS));
      const third = await postOrder();
      expect(third.status).toBe(200);
      expect(authKeyRequests).toHaveLength(2);
      const rewritten = redisStore.get(pmKeys[0] as string) as string;
      expect(rewritten.startsWith("stwd_pmclob_v1:")).toBe(true);
      expect(rewritten.includes(DERIVED_CREDS.secret)).toBe(false);
    } finally {
      delete process.env.POLYMARKET_CLOB_API_URL;
      getSpy.mockRestore();
      postSpy.mockRestore();
    }
  });

  it("skips the cache entirely when no encryption key material is configured", async () => {
    const { createTradeRoutes } = await import("../routes/trade");
    const { testCtx } = await import("./_ctx");
    const ctx = {
      ...testCtx(),
      getRedisClient: () => fakeRedis,
    } as unknown as StewardAppContext;
    const tradeRoutes = createTradeRoutes(ctx);

    const { tenantId, agentId } = await seedTenantAgent();
    const wallet = await ctx.vault.createWallet({
      agentId,
      venue: "polymarket",
      chainType: "evm",
    });
    const sessionId = await seedSession(tenantId, agentId, wallet.address);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    type ClobHttpOptions = { headers?: Record<string, string>; data?: unknown };
    type ClobHttpPrototype = {
      get(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
      post(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
    };
    const clobPrototype = ClobClient.prototype as unknown as ClobHttpPrototype;
    const getSpy = spyOn(clobPrototype, "get").mockImplementation((async (endpoint: string) => {
      const path = new URL(endpoint).pathname;
      if (path === "/tick-size") return { minimum_tick_size: 0.01 };
      if (path === "/fee-rate") return { base_fee: 0 };
      throw new Error(`unexpected CLOB GET ${path}`);
    }) as never);
    let deriveCount = 0;
    const postSpy = spyOn(clobPrototype, "post").mockImplementation((async (endpoint: string) => {
      const path = new URL(endpoint).pathname;
      if (path === "/auth/api-key") {
        deriveCount += 1;
        return DERIVED_CREDS;
      }
      if (path === "/order") {
        return {
          orderID: "pm-cache-order-2",
          status: "matched",
          success: true,
          makingAmount: "10000000",
          takingAmount: "20000000",
        };
      }
      throw new Error(`unexpected CLOB POST ${path}`);
    }) as never);

    const prevMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_MASTER_PASSWORD;
    process.env.POLYMARKET_CLOB_API_URL = "https://clob.e2e.invalid";
    try {
      const res = await app.request("/v1/trade/polymarket/order", {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": crypto.randomUUID() },
        body: JSON.stringify({
          sessionId,
          tokenId: TOKEN_ID,
          side: "buy",
          amount: 10,
          price: 0.5,
          tickSize: "0.01",
          negRisk: true,
        }),
      });
      // Fail closed WITHOUT failing the order: the order still executes (creds
      // are derived fresh), but nothing is written to the shared Redis.
      expect(res.status).toBe(200);
      expect(deriveCount).toBe(1);
      const pmKeys = [...redisStore.keys()].filter((key) => key.startsWith("pm:clob-l2:"));
      expect(pmKeys).toHaveLength(0);
    } finally {
      if (prevMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = prevMasterPassword;
      delete process.env.POLYMARKET_CLOB_API_URL;
      getSpy.mockRestore();
      postSpy.mockRestore();
    }
  });
});
