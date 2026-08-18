import { afterEach, describe, expect, it, mock } from "bun:test";

const redisSetMock = mock(async () => "OK");
const redisGetMock = mock(async () => null as string | null);
const redisGetdelMock = mock(async () => null as string | null);
const redisDelMock = mock(async () => 1);
let redisClient: {
  set: typeof redisSetMock;
  get: typeof redisGetMock;
  getdel: typeof redisGetdelMock;
  del: typeof redisDelMock;
} | null = null;

mock.module("../middleware/redis.js", () => ({
  checkAgentRateLimit: async () => ({ allowed: true, remaining: Infinity, resetMs: 0 }),
  checkAgentSpendLimit: async (_agentId: string, limitUsd: number) => ({
    allowed: true,
    spent: 0,
    remaining: limitUsd,
  }),
  checkProxyRateLimit: async () => ({ allowed: true, remaining: Infinity, resetMs: 0 }),
  estimateCost: () => 0,
  getRedisClient: () => redisClient,
  initRedis: async () => redisClient !== null,
  isRedisAvailable: () => redisClient !== null,
  isRedisConfigured: () => redisClient !== null,
  recordAgentSpend: async () => undefined,
  shutdownRedis: async () => {
    redisClient = null;
  },
}));

process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = "postgres://auth-import-session-store-sources.invalid/steward";
process.env.STEWARD_MASTER_PASSWORD = "auth-import-session-store-sources-master-password";
process.env.STEWARD_SESSION_SECRET =
  "auth-import-session-store-sources-session-secret-with-enough-entropy";

const { assertAuthStoresAreSafe, getAuthStoreSources, initAuthStores } = await import(
  "../routes/auth"
);

describe("auth import-session store source tracking", () => {
  afterEach(() => {
    redisClient = null;
    redisSetMock.mockClear();
    redisGetMock.mockClear();
    redisGetdelMock.mockClear();
    redisDelMock.mockClear();
  });

  it("defaults import-session store source to memory before startup initialization", () => {
    expect(getAuthStoreSources()).toEqual({
      challenge: "memory",
      token: "memory",
      siweNonce: "memory",
      mfa: "memory",
      importSession: "memory",
    });
  });

  it("keeps import-session source as memory when no shared backend is available", async () => {
    await initAuthStores(false);

    expect(getAuthStoreSources().importSession).toBe("memory");
    expect(redisSetMock).not.toHaveBeenCalled();
  });

  it("updates import-session source when startup initializes a Redis-backed store", async () => {
    redisClient = {
      set: redisSetMock,
      get: redisGetMock,
      getdel: redisGetdelMock,
      del: redisDelMock,
    };

    await initAuthStores(false);

    expect(getAuthStoreSources()).toEqual({
      challenge: "redis",
      token: "redis",
      siweNonce: "redis",
      mfa: "redis",
      importSession: "redis",
    });
    expect(redisSetMock).toHaveBeenCalledWith("auth:import-session:__ping__", "1", "PX", 1000);
  });
});

describe("production auth-store startup gate", () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const originalRuntime = process.env.STEWARD_RUNTIME;
  const originalAcknowledgement = process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES;

  afterEach(() => {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (originalRuntime === undefined) delete process.env.STEWARD_RUNTIME;
    else process.env.STEWARD_RUNTIME = originalRuntime;
    if (originalAcknowledgement === undefined) delete process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES;
    else process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES = originalAcknowledgement;
  });

  it("fails closed when any production auth store is process-local", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES;

    expect(() =>
      assertAuthStoresAreSafe({
        challenge: "postgres",
        token: "postgres",
        siweNonce: "memory",
        mfa: "postgres",
        importSession: "postgres",
      }),
    ).toThrow("memory-backed stores: siweNonce");
  });

  it("requires durable stores on Workers even when NODE_ENV is unset", () => {
    delete process.env.NODE_ENV;
    process.env.STEWARD_RUNTIME = "workers";
    delete process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES;

    expect(() =>
      assertAuthStoresAreSafe({
        challenge: "memory",
        token: "memory",
        siweNonce: "memory",
        mfa: "memory",
        importSession: "memory",
      }),
    ).toThrow("Durable auth storage is required");
  });

  it("accepts all-durable stores and an explicit single-instance acknowledgement", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES;
    expect(() =>
      assertAuthStoresAreSafe({
        challenge: "redis",
        token: "redis",
        siweNonce: "redis",
        mfa: "redis",
        importSession: "redis",
      }),
    ).not.toThrow();

    process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES = "true";
    expect(() =>
      assertAuthStoresAreSafe({
        challenge: "memory",
        token: "memory",
        siweNonce: "memory",
        mfa: "memory",
        importSession: "memory",
      }),
    ).not.toThrow();
  });
});
