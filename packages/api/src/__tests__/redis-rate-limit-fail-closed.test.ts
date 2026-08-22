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
  createRedisClient: (env: Record<string, string | undefined>) => ({
    generation: env.REDIS_URL ?? env.KV_REST_API_URL,
    ping: pingMock,
    quit: async () => undefined,
  }),
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
  reserveDailySpendIdempotently: async () => ({
    allowed: true,
    replayed: false,
    remainingUsd: 1,
  }),
  setRedisClientResolverForRuntime: () => undefined,
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
    // Outside request A's immutable snapshot, that client is deliberately not
    // authoritative even though its generation remains initialized.
    expect(redisMiddleware.isRedisAvailable()).toBe(false);

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

  it("binds configured A and configured B to distinct request generations", async () => {
    const a = { NODE_ENV: "production", REDIS_URL: "redis://request-a.test:6379" };
    const b = { NODE_ENV: "production", REDIS_URL: "redis://request-b.test:6379" };
    await Promise.all([
      withRuntimeEnvironment(a, () => redisMiddleware.initRedis(a)),
      withRuntimeEnvironment(b, () => redisMiddleware.initRedis(b)),
    ]);

    const clientA = withRuntimeEnvironment(a, () => redisMiddleware.getRedisClient()) as
      | ({ generation?: string } & object)
      | null;
    const clientB = withRuntimeEnvironment(b, () => redisMiddleware.getRedisClient()) as
      | ({ generation?: string } & object)
      | null;
    expect(clientA?.generation).toBe(a.REDIS_URL);
    expect(clientB?.generation).toBe(b.REDIS_URL);
    expect(clientA).not.toBe(clientB);

    const absent = withRuntimeEnvironment(
      { NODE_ENV: "production", STEWARD_RUNTIME: "workers" },
      () => redisMiddleware.getRedisClient(),
    );
    expect(absent).toBeNull();
  });

  it("does not let overlapping Worker generations use each other's client", async () => {
    const a = {
      NODE_ENV: "test",
      STEWARD_RUNTIME: "workers",
      REDIS_URL: "redis://overlap-a.test:6379",
    };
    const b = {
      NODE_ENV: "test",
      STEWARD_RUNTIME: "workers",
      REDIS_URL: "redis://overlap-b.test:6379",
    };
    await Promise.all([
      withRuntimeEnvironment(a, async () => {
        await redisMiddleware.initRedis(a);
        await Promise.resolve();
        expect(
          (redisMiddleware.getRedisClient() as unknown as { generation: string }).generation,
        ).toBe(a.REDIS_URL);
      }),
      withRuntimeEnvironment(b, async () => {
        await redisMiddleware.initRedis(b);
        await Promise.resolve();
        expect(
          (redisMiddleware.getRedisClient() as unknown as { generation: string }).generation,
        ).toBe(b.REDIS_URL);
      }),
    ]);
  });

  it("bounds retained binding generations and fails a new generation closed", async () => {
    for (let index = 0; index < 8; index += 1) {
      const environment = {
        NODE_ENV: "test",
        STEWARD_RUNTIME: "workers",
        REDIS_URL: `redis://bounded-${index}.test:6379`,
      };
      expect(
        await withRuntimeEnvironment(environment, () => redisMiddleware.initRedis(environment)),
      ).toBe(true);
    }
    const overflow = {
      NODE_ENV: "test",
      STEWARD_RUNTIME: "workers",
      REDIS_URL: "redis://bounded-overflow.test:6379",
    };
    expect(await withRuntimeEnvironment(overflow, () => redisMiddleware.initRedis(overflow))).toBe(
      false,
    );
    expect(withRuntimeEnvironment(overflow, () => redisMiddleware.getRedisClient())).toBeNull();
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

  it("keeps development adapter reservations capped and idempotent", async () => {
    const environment = { NODE_ENV: "development" };
    const reserve = (reservationId: string, requestDigest: string, amountUsd = 60) =>
      withRuntimeEnvironment(environment, () =>
        redisMiddleware.reserveAgentDailySpend({
          agentId: "memory-agent",
          tenantId: "memory-tenant",
          amountUsd,
          limitUsd: 100,
          reservationId,
          requestDigest,
        }),
      );
    expect(await reserve("a".repeat(64), "1".repeat(64))).toMatchObject({
      allowed: true,
      replayed: false,
    });
    expect(await reserve("a".repeat(64), "1".repeat(64))).toMatchObject({
      allowed: true,
      replayed: true,
    });
    expect(await reserve("a".repeat(64), "2".repeat(64))).toMatchObject({
      allowed: false,
      conflict: true,
    });
    expect(await reserve("b".repeat(64), "3".repeat(64))).toMatchObject({ allowed: false });
  });

  it("fails the bounded development reservation ledger closed when saturated", async () => {
    const environment = { NODE_ENV: "test" };
    for (let index = 0; index < 1_000; index += 1) {
      const digest = index.toString(16).padStart(64, "0");
      const result = await withRuntimeEnvironment(environment, () =>
        redisMiddleware.reserveAgentDailySpend({
          agentId: "bounded-memory-agent",
          tenantId: "bounded-memory-tenant",
          amountUsd: 0.0001,
          limitUsd: 1_000,
          reservationId: digest,
          requestDigest: digest,
        }),
      );
      expect(result.allowed).toBe(true);
    }
    const overflow = "f".repeat(64);
    expect(
      await withRuntimeEnvironment(environment, () =>
        redisMiddleware.reserveAgentDailySpend({
          agentId: "bounded-memory-agent",
          tenantId: "bounded-memory-tenant",
          amountUsd: 0.0001,
          limitUsd: 1_000,
          reservationId: overflow,
          requestDigest: overflow,
        }),
      ),
    ).toMatchObject({ allowed: false });
  });
});
