import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";

const checkRateLimitMock = mock(async () => ({
  allowed: true,
  remaining: 1,
  resetMs: 1_000,
}));
const disconnectRedisMock = mock(async () => undefined);
const pingMock = mock(async () => "PONG");
const recordSpendMock = mock(async () => undefined);
const reserveSpendMock = mock(
  async (
    _agentId: string,
    _tenantId: string,
    amountUsd: number,
    _limits: Partial<Record<"day" | "week" | "month", number>>,
  ) => ({
    reservedUsd: amountUsd,
    periods: ["day"],
    buckets: [{ period: "day", dateKey: "2026-08-20", key: "spend:test:day" }],
  }),
);
const settleReservedSpendMock = mock(
  async (
    _agentId: string,
    _tenantId: string,
    _reservedUsd: number,
    _actualUsd: number,
    _host: string,
    _periods: string[],
    _buckets: unknown[],
  ) => undefined,
);

mock.module("@stwd/redis", () => ({
  checkRateLimit: checkRateLimitMock,
  createUpstashIoredisAdapter: () => ({ ping: pingMock }),
  disconnectRedis: disconnectRedisMock,
  estimateCost: () => 0,
  getAggregationSnapshot: async () => null,
  getCachedPolicies: async () => null,
  getPricingTable: () => ({}),
  getRedis: () => ({ ping: pingMock }),
  getRedisDriver: () => "ioredis",
  getSpend: async () => 0,
  getSpendByHost: async () => ({}),
  invalidateCache: async () => undefined,
  invalidateTenantCache: async () => undefined,
  isKnownHost: () => false,
  recordAggregationEvent: async () => undefined,
  recordSpend: recordSpendMock,
  reserveSpend: reserveSpendMock,
  setCachedPolicies: async () => undefined,
  settleReservedSpend: settleReservedSpendMock,
}));

const redisMiddleware = await import("../middleware/redis");

describe("Redis rate-limit wrappers", () => {
  const originalRedisUrl = process.env.REDIS_URL;
  const originalRedisDriver = process.env.REDIS_DRIVER;

  beforeEach(async () => {
    checkRateLimitMock.mockReset();
    checkRateLimitMock.mockImplementation(async () => ({
      allowed: true,
      remaining: 1,
      resetMs: 1_000,
    }));
    disconnectRedisMock.mockReset();
    pingMock.mockReset();
    pingMock.mockImplementation(async () => "PONG");
    recordSpendMock.mockReset();
    process.env.REDIS_DRIVER = "ioredis";
    process.env.REDIS_URL = "redis://rate-limit-wrapper.test:6379";
    await redisMiddleware.shutdownRedis();
  });

  afterEach(async () => {
    await redisMiddleware.shutdownRedis();
    if (originalRedisUrl === undefined) {
      delete process.env.REDIS_URL;
    } else {
      process.env.REDIS_URL = originalRedisUrl;
    }
    if (originalRedisDriver === undefined) {
      delete process.env.REDIS_DRIVER;
    } else {
      process.env.REDIS_DRIVER = originalRedisDriver;
    }
  });

  it("fails closed when configured proxy rate-limit checks throw", async () => {
    expect(await redisMiddleware.initRedis()).toBe(true);
    checkRateLimitMock.mockImplementation(async () => {
      throw new Error("redis eval failed");
    });

    const result = await redisMiddleware.checkProxyRateLimit(
      "agent-proxy",
      "api.example.test",
      60_000,
      10,
    );

    expect(result).toEqual({ allowed: false, remaining: 0, resetMs: 60_000 });
  });

  it("keeps the unconfigured local-development proxy path permissive", async () => {
    delete process.env.REDIS_URL;
    await redisMiddleware.shutdownRedis();

    const result = await redisMiddleware.checkProxyRateLimit(
      "agent-proxy",
      "api.example.test",
      60_000,
      10,
    );

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(Infinity);
    expect(checkRateLimitMock).not.toHaveBeenCalled();
  });

  it("SEC-016: fails closed when Redis is configured but unavailable at boot", async () => {
    // REDIS_URL set (production posture) but the connection fails: the helpers
    // must NOT silently disable rate limiting.
    pingMock.mockImplementation(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    expect(await redisMiddleware.initRedis()).toBe(false);

    const proxyResult = await redisMiddleware.checkProxyRateLimit(
      "agent-proxy",
      "api.example.test",
      60_000,
      10,
    );
    expect(proxyResult).toEqual({ allowed: false, remaining: 0, resetMs: 60_000 });

    const agentResult = await redisMiddleware.checkAgentRateLimit("agent-vault", 60_000, 10);
    expect(agentResult).toEqual({ allowed: false, remaining: 0, resetMs: 60_000 });
    expect(checkRateLimitMock).not.toHaveBeenCalled();
  });

  it("SEC-016: keeps the unconfigured local-development agent path permissive", async () => {
    delete process.env.REDIS_URL;
    await redisMiddleware.shutdownRedis();

    const result = await redisMiddleware.checkAgentRateLimit("agent-vault", 60_000, 10);

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(Infinity);
  });
});

describe("Redis spend-limit wrapper", () => {
  const originalRedisUrl = process.env.REDIS_URL;

  beforeEach(async () => {
    reserveSpendMock.mockReset();
    reserveSpendMock.mockImplementation(async (_agentId, _tenantId, amountUsd) => ({
      reservedUsd: amountUsd,
      periods: ["day"],
      buckets: [{ period: "day", dateKey: "2026-08-20", key: "spend:test:day" }],
    }));
    settleReservedSpendMock.mockReset();
    settleReservedSpendMock.mockImplementation(async () => undefined);
    pingMock.mockReset();
    pingMock.mockImplementation(async () => "PONG");
    redisMiddleware.__resetAdapterMemorySpendForTests();
    await redisMiddleware.shutdownRedis();
  });

  afterEach(async () => {
    await redisMiddleware.shutdownRedis();
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
  });

  it("fails closed without Redis unless development/test memory posture is explicitly acknowledged", async () => {
    for (const environment of [
      {},
      { NODE_ENV: "production" },
      { NODE_ENV: "staging" },
      { NODE_ENV: "developmnt", STEWARD_ALLOW_MEMORY_ADAPTER_SPEND: "true" },
      {
        NODE_ENV: "test",
        STEWARD_RUNTIME: "workers",
        STEWARD_ALLOW_MEMORY_ADAPTER_SPEND: "true",
      },
    ]) {
      const result = await withRuntimeEnvironment(environment, () =>
        redisMiddleware.reserveAgentSpendLimit("agent-no-redis", "tenant-a", 1, 60),
      );
      expect(result.allowed).toBe(false);
    }
    expect(reserveSpendMock).not.toHaveBeenCalled();
  });

  it("fails closed in production when configured durable spend state is down", async () => {
    pingMock.mockImplementation(async () => {
      throw new Error("connect ECONNREFUSED");
    });
    expect(
      await withRuntimeEnvironment(
        { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
        () => redisMiddleware.initRedis({ REDIS_URL: "redis://spend.test:6379" }),
      ),
    ).toBe(false);

    const result = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        REDIS_URL: "redis://spend.test:6379",
        STEWARD_ADAPTER_DAILY_CAP_USD: "1000",
      },
      () => redisMiddleware.reserveAgentSpendLimit("agent-production", "tenant-a", 1, 1000),
    );

    expect(result.allowed).toBe(false);
    expect(reserveSpendMock).not.toHaveBeenCalled();
  });

  it("does not inherit a stale configured client into a production request with no binding", async () => {
    expect(
      await withRuntimeEnvironment(
        { NODE_ENV: "production", REDIS_URL: "redis://request-a.test:6379" },
        () => redisMiddleware.initRedis({ REDIS_URL: "redis://request-a.test:6379" }),
      ),
    ).toBe(true);
    expect(redisMiddleware.isRedisAvailable()).toBe(true);

    const result = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ADAPTER_DAILY_CAP_USD: "1000",
      },
      () => redisMiddleware.reserveAgentSpendLimit("agent-request-b", "tenant-b", 1, 1000),
    );

    expect(result.allowed).toBe(false);
    expect(reserveSpendMock).not.toHaveBeenCalled();
  });

  it("uses an atomic bounded memory reservation only for explicitly acknowledged development/test", async () => {
    for (const nodeEnv of ["development", "test"] as const) {
      redisMiddleware.__resetAdapterMemorySpendForTests();
      const exactBoundary = await withRuntimeEnvironment(
        {
          NODE_ENV: nodeEnv,
          STEWARD_ALLOW_MEMORY_ADAPTER_SPEND: "true",
        },
        () => redisMiddleware.reserveAgentSpendLimit(`agent-${nodeEnv}`, "tenant-a", 60, 60),
      );
      expect(exactBoundary.allowed).toBe(true);
      const overBoundary = await withRuntimeEnvironment(
        {
          NODE_ENV: nodeEnv,
          STEWARD_ALLOW_MEMORY_ADAPTER_SPEND: "true",
        },
        () => redisMiddleware.reserveAgentSpendLimit(`agent-${nodeEnv}`, "tenant-a", 0.0001, 60),
      );
      expect(overBoundary.allowed).toBe(false);
    }
    expect(reserveSpendMock).not.toHaveBeenCalled();
  });

  it("delegates admission to the atomic Redis reservation and retains durable state across restart", async () => {
    let reserved = 59;
    reserveSpendMock.mockImplementation(async (_agent, _tenant, amount, limits) => {
      const daily = (limits as { day: number }).day;
      await Promise.resolve();
      if (reserved + amount > daily) throw new Error("cap exceeded");
      reserved += amount;
      return {
        reservedUsd: amount,
        periods: ["day"],
        buckets: [{ period: "day", dateKey: "2026-08-20", key: "spend:test:day" }],
      };
    });
    await withRuntimeEnvironment(
      { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
      () => redisMiddleware.initRedis({ REDIS_URL: "redis://spend.test:6379" }),
    );

    const concurrent = await withRuntimeEnvironment(
      { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
      () =>
        Promise.all([
          redisMiddleware.reserveAgentSpendLimit("agent-race", "tenant-a", 1, 60),
          redisMiddleware.reserveAgentSpendLimit("agent-race", "tenant-a", 1, 60),
        ]),
    );
    expect(concurrent.filter((entry) => entry.allowed)).toHaveLength(1);

    await redisMiddleware.shutdownRedis();
    await withRuntimeEnvironment(
      { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
      () => redisMiddleware.initRedis({ REDIS_URL: "redis://spend.test:6379" }),
    );
    const afterRestart = await withRuntimeEnvironment(
      { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
      () => redisMiddleware.reserveAgentSpendLimit("agent-race", "tenant-a", 0.0001, 60),
    );
    expect(afterRestart.allowed).toBe(false);
  });

  it("keeps overlapping request postures isolated in AsyncLocalStorage", async () => {
    const [acknowledgedDev, unboundProduction] = await Promise.all([
      withRuntimeEnvironment(
        { NODE_ENV: "development", STEWARD_ALLOW_MEMORY_ADAPTER_SPEND: "true" },
        async () => {
          await Promise.resolve();
          return redisMiddleware.reserveAgentSpendLimit("agent-dev", "tenant-a", 1, 60);
        },
      ),
      withRuntimeEnvironment({ NODE_ENV: "production" }, async () => {
        await Promise.resolve();
        return redisMiddleware.reserveAgentSpendLimit("agent-prod", "tenant-b", 1, 60);
      }),
    ]);
    expect(acknowledgedDev.allowed).toBe(true);
    expect(unboundProduction.allowed).toBe(false);
  });

  it("denies Redis reservation errors without logging raw diagnostics", async () => {
    const secret = "redis://user:super-secret@example.test/private";
    reserveSpendMock.mockImplementation(async () => {
      throw new Error(secret);
    });
    await withRuntimeEnvironment(
      { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
      () => redisMiddleware.initRedis({ REDIS_URL: "redis://spend.test:6379" }),
    );
    const originalConsoleError = console.error;
    const logged: unknown[][] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args);
    };
    try {
      const result = await withRuntimeEnvironment(
        { NODE_ENV: "production", REDIS_URL: "redis://spend.test:6379" },
        () => redisMiddleware.reserveAgentSpendLimit("agent-secret", "tenant-a", 1, 60),
      );
      expect(result.allowed).toBe(false);
      expect(JSON.stringify(logged)).not.toContain(secret);
      expect(JSON.stringify(logged)).not.toContain("super-secret");
    } finally {
      console.error = originalConsoleError;
    }
  });
});
