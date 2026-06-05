import { afterEach, describe, expect, it, mock } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

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

const apiRoot = join(import.meta.dir, "..");
const indexSource = readFileSync(join(apiRoot, "index.ts"), "utf8");
const testSource = readFileSync(import.meta.path, "utf8");

process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = "postgres://auth-import-session-store-sources.invalid/steward";
process.env.STEWARD_MASTER_PASSWORD = "auth-import-session-store-sources-master-password";
process.env.STEWARD_SESSION_SECRET =
  "auth-import-session-store-sources-session-secret-with-enough-entropy";

const { getAuthStoreSources, initAuthStores } = await import("../routes/auth");

describe("auth import-session store source tracking", () => {
  const originalAllowMemoryImportSessionStore =
    process.env.STEWARD_ALLOW_MEMORY_IMPORT_SESSION_STORE;

  afterEach(() => {
    redisClient = null;
    redisSetMock.mockClear();
    redisGetMock.mockClear();
    redisGetdelMock.mockClear();
    redisDelMock.mockClear();

    if (originalAllowMemoryImportSessionStore === undefined) {
      delete process.env.STEWARD_ALLOW_MEMORY_IMPORT_SESSION_STORE;
    } else {
      process.env.STEWARD_ALLOW_MEMORY_IMPORT_SESSION_STORE = originalAllowMemoryImportSessionStore;
    }
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
    expect(redisSetMock).toHaveBeenCalledWith("__ping__import-session", "1", "PX", 1000);
  });
});

describe("readiness import-session memory gate", () => {
  it("keeps this readiness coverage source-only so importing the test does not start the server", () => {
    expect(testSource).toContain('readFileSync(join(apiRoot, "index.ts"), "utf8")');
    expect(testSource).not.toContain(`await ${"import"}("../index")`);
    expect(testSource).not.toContain(`${"from"} "../index"`);
  });

  it("keeps /ready wired to fail production memory import-session storage unless explicitly allowed", () => {
    // Importing src/index.ts starts migrations, schedulers, and Bun.serve at module load,
    // so keep this as a focused wiring check around the readiness boundary.
    const readyRouteStart = indexSource.indexOf('app.get("/ready"');
    expect(readyRouteStart).toBeGreaterThanOrEqual(0);
    const readyRouteEnd = indexSource.indexOf("\n// ─── Database migrations", readyRouteStart);
    const readyRoute = indexSource.slice(
      readyRouteStart,
      readyRouteEnd === -1 ? undefined : readyRouteEnd,
    );

    expect(readyRoute).toContain("getAuthStoreSources()");
    expect(readyRoute).toContain("checks.importSessionStore");
    expect(readyRoute).toContain("STEWARD_ALLOW_MEMORY_IMPORT_SESSION_STORE");
    expect(readyRoute).toContain('process.env.NODE_ENV !== "production"');
    expect(readyRoute).toContain('storeSources.importSession !== "memory"');
    expect(readyRoute).toContain(
      "Encrypted import sessions are using memory storage in production",
    );
  });
});
