import { afterEach, describe, expect, it, mock } from "bun:test";
import { Hono } from "hono";
import {
  createReadinessHandler,
  type ReadinessDependencies,
  type ReadinessEnvironment,
} from "../readiness";
import type { AuthStoreSources } from "../routes/auth";
import type { AppVariables } from "../services/context";

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

const durableSources = {
  challenge: "postgres",
  token: "redis",
  siweNonce: "postgres",
  mfa: "redis",
  importSession: "postgres",
} satisfies AuthStoreSources;

function mountReadiness(
  overrides: Partial<ReadinessDependencies> = {},
  environmentOverrides: Partial<ReadinessEnvironment> = {},
) {
  const dependencies: ReadinessDependencies = {
    apiVersion: "test-version",
    startedAt: 1_000,
    now: () => 6_000,
    environment: () => ({
      allowMemoryAuthStores: false,
      probeToken: "readiness-probe-secret",
      requiresDurableAuthStores: true,
      ...environmentOverrides,
    }),
    checkDatabase: async () => ({
      database: { ok: true, detail: { clockSkewMs: 3 } },
      migrations: { ok: true, detail: { expected: "0113" } },
    }),
    checkRedis: async () => ({ ok: true, source: "redis" }),
    checkProxyClock: async () => ({ ok: true, detail: { clockSkewMs: 4 } }),
    getAuthStoreSources: () => durableSources,
    isVaultConfigured: () => true,
    ...overrides,
  };
  const app = new Hono<{ Variables: AppVariables }>();
  app.get("/ready", createReadinessHandler(dependencies));
  return app;
}

describe("mounted Bun readiness auth-store boundary", () => {
  for (const storeName of Object.keys(durableSources)) {
    it(`returns exactly 503 when production ${storeName} storage is memory-backed`, async () => {
      const app = mountReadiness({
        getAuthStoreSources: () => ({ ...durableSources, [storeName]: "memory" }),
      });
      const response = await app.request("/ready");
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        status: "not_ready",
        version: "test-version",
        uptime: 5,
        checks: {
          database: { ok: true },
          migrations: { ok: true },
          redis: { ok: true },
          proxyClock: { ok: true },
          vault: { ok: true },
          authStores: { ok: false },
        },
      });
    });
  }

  it("returns 200 for durable stores and for an explicit single-instance acknowledgement", async () => {
    const durableResponse = await mountReadiness().request("/ready");
    expect(durableResponse.status).toBe(200);
    expect((await durableResponse.json()).status).toBe("ready");

    const acknowledgedResponse = await mountReadiness(
      {
        getAuthStoreSources: () =>
          Object.fromEntries(Object.keys(durableSources).map((key) => [key, "memory"])),
      },
      { allowMemoryAuthStores: true },
    ).request("/ready");
    expect(acknowledgedResponse.status).toBe(200);
    expect((await acknowledgedResponse.json()).status).toBe("ready");
  });

  it("maps rejected DB, Redis, and proxy checks to stable 503 responses", async () => {
    const cases: Array<{
      name: string;
      overrides: Partial<ReadinessDependencies>;
      failedChecks: string[];
    }> = [
      {
        name: "database",
        overrides: { checkDatabase: async () => Promise.reject(new Error("database token leak")) },
        failedChecks: ["database", "migrations"],
      },
      {
        name: "redis",
        overrides: { checkRedis: async () => Promise.reject(new Error("redis endpoint leak")) },
        failedChecks: ["redis"],
      },
      {
        name: "proxy",
        overrides: { checkProxyClock: async () => Promise.reject(new Error("proxy token leak")) },
        failedChecks: ["proxyClock"],
      },
      {
        name: "vault",
        overrides: { isVaultConfigured: () => false },
        failedChecks: ["vault"],
      },
    ];

    for (const testCase of cases) {
      const response = await mountReadiness(testCase.overrides).request("/ready");
      expect(response.status, testCase.name).toBe(503);
      const body = (await response.json()) as {
        status: string;
        checks: Record<string, { ok: boolean }>;
      };
      expect(body.status, testCase.name).toBe("not_ready");
      for (const check of testCase.failedChecks) expect(body.checks[check]).toEqual({ ok: false });
      expect(JSON.stringify(body), testCase.name).not.toMatch(/token leak|endpoint leak/i);
    }
  });

  it("returns 200 when unconfigured Redis and proxy checks are explicitly optional", async () => {
    const response = await mountReadiness({
      checkRedis: async () => ({ ok: false, required: false, error: "optional" }),
      checkProxyClock: async () => ({ ok: false, required: false, error: "optional" }),
    }).request("/ready");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      status: "ready",
      checks: {
        redis: { ok: false, required: false },
        proxyClock: { ok: false, required: false },
      },
    });
  });

  it("redacts public backend diagnostics and exposes bounded detail only to the probe token", async () => {
    const app = mountReadiness({
      checkRedis: async () => ({
        ok: false,
        error: "Redis is configured but not connected",
        source: "redis",
      }),
      getAuthStoreSources: () => ({ ...durableSources, importSession: "memory" }),
    });

    const publicResponse = await app.request("/ready");
    expect(publicResponse.status).toBe(503);
    expect(publicResponse.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(publicResponse.headers.get("pragma")).toBe("no-cache");
    expect(publicResponse.headers.get("expires")).toBe("0");
    const publicText = await publicResponse.text();
    expect(publicText).not.toContain('"source"');
    expect(publicText).not.toContain('"error"');
    expect(publicText).not.toMatch(
      /challenge:|importSession:|configured but|readiness-probe-secret/i,
    );

    const wrongTokenResponse = await app.request("/ready", {
      headers: { "x-steward-probe-token": "wrong-token" },
    });
    expect(wrongTokenResponse.headers.get("cache-control")).toBe("no-store, max-age=0");
    expect(await wrongTokenResponse.json()).toEqual(JSON.parse(publicText));

    const authorizedResponse = await app.request("/ready", {
      headers: { "x-steward-probe-token": "readiness-probe-secret" },
    });
    expect(authorizedResponse.status).toBe(503);
    expect(authorizedResponse.headers.get("cache-control")).toBe("no-store, max-age=0");
    const authorized = (await authorizedResponse.json()) as {
      checks: Record<string, { detail?: unknown; error?: string; source?: string }>;
    };
    expect(authorized.checks.database.detail).toEqual({ clockSkewMs: 3 });
    expect(authorized.checks.redis).toEqual({
      ok: false,
      error: "Redis is configured but not connected",
      source: "redis",
    });
    expect(authorized.checks.authStores.error).toBe(
      "Production auth stores using memory: importSession",
    );
    expect(JSON.stringify(authorized)).not.toContain("readiness-probe-secret");
  });
});
