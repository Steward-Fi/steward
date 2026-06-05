import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";

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
});
