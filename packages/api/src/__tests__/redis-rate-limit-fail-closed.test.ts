import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";

const checkRateLimitMock = mock(async () => ({
  allowed: true,
  remaining: 1,
  resetMs: 1_000,
}));
const checkSpendLimitMock = mock(async () => ({
  allowed: true,
  spent: 0,
  remaining: 1,
}));
const disconnectRedisMock = mock(async () => undefined);
const pingMock = mock(async () => "PONG");
const recordSpendMock = mock(async () => undefined);

mock.module("@stwd/redis", () => ({
  checkRateLimit: checkRateLimitMock,
  checkSpendLimit: checkSpendLimitMock,
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
  reserveSpend: async () => ({ allowed: true, reservationId: "reservation-test" }),
  setCachedPolicies: async () => undefined,
  settleReservedSpend: async () => undefined,
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
    checkSpendLimitMock.mockReset();
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
    checkSpendLimitMock.mockReset();
    checkSpendLimitMock.mockImplementation(async () => ({
      allowed: true,
      spent: 0,
      remaining: 1,
    }));
    pingMock.mockReset();
    pingMock.mockImplementation(async () => "PONG");
    await redisMiddleware.shutdownRedis();
  });

  afterEach(async () => {
    await redisMiddleware.shutdownRedis();
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
  });

  it("fails closed in production when durable spend state is absent", async () => {
    const result = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ADAPTER_DAILY_CAP_USD: "1000",
      },
      () => redisMiddleware.checkAgentSpendLimit("agent-production", 1000, "day"),
    );

    expect(result).toEqual({ allowed: false, spent: 0, remaining: 0 });
    expect(checkSpendLimitMock).not.toHaveBeenCalled();
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
      () => redisMiddleware.checkAgentSpendLimit("agent-production", 1000, "day"),
    );

    expect(result).toEqual({ allowed: false, spent: 0, remaining: 0 });
    expect(checkSpendLimitMock).not.toHaveBeenCalled();
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
      () => redisMiddleware.checkAgentSpendLimit("agent-request-b", 1000, "day"),
    );

    expect(result).toEqual({ allowed: false, spent: 0, remaining: 0 });
    expect(checkSpendLimitMock).not.toHaveBeenCalled();
  });

  it("keeps explicit unconfigured development and test postures permissive", async () => {
    for (const nodeEnv of ["development", "test"] as const) {
      const result = await withRuntimeEnvironment(
        {
          NODE_ENV: nodeEnv,
          STEWARD_ADAPTER_DAILY_CAP_USD: "1000",
        },
        () => redisMiddleware.checkAgentSpendLimit(`agent-${nodeEnv}`, 1000, "day"),
      );

      expect(result).toEqual({ allowed: true, spent: 0, remaining: 1000 });
      expect(checkSpendLimitMock).not.toHaveBeenCalled();
    }
  });
});
