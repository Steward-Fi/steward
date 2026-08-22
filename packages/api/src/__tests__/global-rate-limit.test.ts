import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import { SOCKET_PEER_ENV_KEY } from "../services/runtime-gate";

process.env.NODE_ENV = "test";
process.env.STEWARD_PGLITE_MEMORY = "true";
const { createPGLiteDb, setPGLiteOverride } = await import("@stwd/db/pglite");
const { closeDb } = await import("@stwd/db");
const { db: pgliteDb, client: pgliteClient } = await createPGLiteDb("memory://");
setPGLiteOverride(pgliteDb, async () => pgliteClient.close());
const {
  createGlobalRateLimitMiddleware,
  globalRateLimit,
  globalRateLimitPosture,
  globalRateLimitRequiresRedis,
} = await import("../middleware/global-rate-limit");

afterAll(async () => {
  await closeDb();
});

/**
 * SEC-068: app.ts mounts one global limiter across Bun and Workers. Production
 * uses shared Redis state unless a guaranteed single-instance Bun deployment
 * explicitly acknowledges memory; these tests exercise mounted requests and
 * deterministic Redis-unavailable/injected durable-store branches.
 */

const ENV_VARS = [
  "NODE_ENV",
  "REDIS_URL",
  "REDIS_DRIVER",
  "KV_REST_API_URL",
  "KV_REST_API_TOKEN",
  "UPSTASH_REDIS_REST_URL",
  "UPSTASH_REDIS_REST_TOKEN",
  "STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL",
  "STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX",
] as const;
const saved = new Map<string, string | undefined>();

function saveEnv() {
  for (const name of ENV_VARS) saved.set(name, process.env[name]);
}

function restoreEnv() {
  for (const name of ENV_VARS) {
    const value = saved.get(name);
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

function redisUnconfigured() {
  delete process.env.REDIS_URL;
  delete process.env.REDIS_DRIVER;
  delete process.env.KV_REST_API_URL;
  delete process.env.KV_REST_API_TOKEN;
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
  process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX = "0";
}

saveEnv();
afterEach(restoreEnv);

function probeApp() {
  const app = new Hono();
  app.use("*", globalRateLimit);
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/thing", (c) => c.json({ ok: true }));
  return app;
}

function mountedApp(middleware: ReturnType<typeof createGlobalRateLimitMiddleware>) {
  const app = new Hono();
  app.use("*", middleware);
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/ready", (c) => c.json({ status: "ready" }));
  app.get("/thing", (c) => c.json({ ok: true }));
  return app;
}

function mountedRequest(app: Hono, path = "/thing", peer = "192.0.2.10", headers?: HeadersInit) {
  return app.fetch(new Request(`http://steward.test${path}`, { headers }), {
    [SOCKET_PEER_ENV_KEY]: peer,
  });
}

describe("globalRateLimit (SEC-068)", () => {
  test("fails closed in production when Redis was never configured", async () => {
    redisUnconfigured();
    process.env.NODE_ENV = "production";
    const app = probeApp();

    const res = await app.request("/thing");
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("60");
    const body = await res.json();
    expect(body.error).toBe("Rate limit exceeded");
  });

  test("/health bypasses the limiter even when it would deny", async () => {
    redisUnconfigured();
    process.env.NODE_ENV = "production";
    const app = probeApp();

    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });

  test("passes through outside production without Redis (documented dev path)", async () => {
    redisUnconfigured();
    process.env.NODE_ENV = "test";
    const app = probeApp();

    const res = await app.request("/thing");
    expect(res.status).toBe(200);
  });

  test("unset, staging, typo, and Workers-test postures require durable state", async () => {
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        checkDurable: async () => ({ allowed: false, retryAfterSecs: 60 }),
      }),
    );
    for (const environment of [
      {},
      { NODE_ENV: "staging" },
      {
        NODE_ENV: "staging",
        STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT: "true",
      },
      { NODE_ENV: "developmnt" },
      { NODE_ENV: "test", STEWARD_RUNTIME: "workers" },
    ]) {
      await withRuntimeEnvironment(environment, async () => {
        expect(globalRateLimitPosture()).toBe("durable");
        expect((await mountedRequest(app)).status).toBe(429);
      });
    }
  });

  test("two independent Bun contexts and a restarted context share the durable boundary", async () => {
    const counts = new Map<string, number>();
    const sharedDurableCheck = async () => {
      const count = (counts.get("shared-client") ?? 0) + 1;
      counts.set("shared-client", count);
      return count <= 2 ? { allowed: true } : { allowed: false, retryAfterSecs: 60 };
    };
    const options = { maxRequests: 2, checkDurable: sharedDurableCheck };
    const firstReplica = mountedApp(createGlobalRateLimitMiddleware(options));
    const secondReplica = mountedApp(createGlobalRateLimitMiddleware(options));

    await withRuntimeEnvironment({ NODE_ENV: "production" }, async () => {
      expect((await mountedRequest(firstReplica)).status).toBe(200);
      expect((await mountedRequest(secondReplica)).status).toBe(200);

      // A newly constructed middleware represents a restarted Bun process. Its
      // empty memory cannot reset the shared durable count.
      const restartedReplica = mountedApp(createGlobalRateLimitMiddleware(options));
      expect((await mountedRequest(restartedReplica)).status).toBe(429);
    });
  });

  test("fails closed when the configured durable checker throws", async () => {
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        checkDurable: async () => {
          throw new Error("Redis outage");
        },
      }),
    );
    await withRuntimeEnvironment({ NODE_ENV: "production" }, async () => {
      const res = await mountedRequest(app);
      expect(res.status).toBe(429);
      expect(res.headers.get("Retry-After")).toBe("60");
    });
  });

  test("memory is limited to development or exact acknowledged single-instance Bun", async () => {
    const dev = mountedApp(createGlobalRateLimitMiddleware({ maxRequests: 1 }));
    await withRuntimeEnvironment({ NODE_ENV: "development" }, async () => {
      expect((await mountedRequest(dev)).status).toBe(200);
      expect((await mountedRequest(dev)).status).toBe(429);
      // Restart-resetting behavior is explicit and confined to memory posture.
      const restarted = mountedApp(createGlobalRateLimitMiddleware({ maxRequests: 1 }));
      expect((await mountedRequest(restarted)).status).toBe(200);
    });

    const acknowledged = mountedApp(createGlobalRateLimitMiddleware({ maxRequests: 1 }));
    await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT: "true",
      },
      async () => {
        expect(globalRateLimitPosture()).toBe("memory-acknowledged");
        expect(globalRateLimitRequiresRedis()).toBe(false);
        expect((await mountedRequest(acknowledged)).status).toBe(200);
        expect((await mountedRequest(acknowledged)).status).toBe(429);
      },
    );
  });

  test("memory posture preserves trusted-proxy identities from the immutable request config", async () => {
    const app = mountedApp(createGlobalRateLimitMiddleware({ maxRequests: 1 }));
    await withRuntimeEnvironment(
      { NODE_ENV: "development", STEWARD_TRUSTED_PROXY_HOPS: "1" },
      async () => {
        const proxy = "192.0.2.50";
        expect(
          (await mountedRequest(app, "/thing", proxy, { "x-forwarded-for": "198.51.100.1" }))
            .status,
        ).toBe(200);
        expect(
          (await mountedRequest(app, "/thing", proxy, { "x-forwarded-for": "198.51.100.2" }))
            .status,
        ).toBe(200);
        expect(
          (await mountedRequest(app, "/thing", proxy, { "x-forwarded-for": "198.51.100.1" }))
            .status,
        ).toBe(429);
      },
    );
  });

  test("memory posture preserves the configured key-space fail-closed bound", async () => {
    const app = mountedApp(createGlobalRateLimitMiddleware({ maxRequests: 100 }));
    await withRuntimeEnvironment(
      { NODE_ENV: "development", STEWARD_RATE_LIMIT_MAX_KEYS: "1" },
      async () => {
        expect((await mountedRequest(app, "/thing", "192.0.2.1")).status).toBe(200);
        expect((await mountedRequest(app, "/thing", "192.0.2.2")).status).toBe(429);
      },
    );
  });

  test("request-limit overrides come from each immutable runtime snapshot", async () => {
    const app = mountedApp(createGlobalRateLimitMiddleware());
    const samePeer = "192.0.2.11";
    await withRuntimeEnvironment(
      { NODE_ENV: "development", STEWARD_RATE_LIMIT_MAX_REQUESTS: "1" },
      async () => {
        expect((await mountedRequest(app, "/thing", samePeer)).status).toBe(200);
        expect((await mountedRequest(app, "/thing", samePeer)).status).toBe(429);
      },
    );
    // A later binding generation that omits the override returns to the literal
    // default instead of inheriting the first module-generation value.
    await withRuntimeEnvironment({ NODE_ENV: "development" }, async () => {
      expect((await mountedRequest(app, "/thing", samePeer)).status).toBe(200);
    });
    await withRuntimeEnvironment(
      { NODE_ENV: "development", STEWARD_RATE_LIMIT_MAX_REQUESTS: "2" },
      async () => {
        expect((await mountedRequest(app, "/thing", "192.0.2.12")).status).toBe(200);
        expect((await mountedRequest(app, "/thing", "192.0.2.12")).status).toBe(200);
        expect((await mountedRequest(app, "/thing", "192.0.2.12")).status).toBe(429);
      },
    );
  });

  test("single-instance acknowledgement must be exact and is request-isolated", async () => {
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        checkDurable: async () => ({ allowed: false, retryAfterSecs: 60 }),
      }),
    );
    await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT: " true ",
      },
      async () => {
        expect(globalRateLimitPosture()).toBe("durable");
        expect((await mountedRequest(app)).status).toBe(429);
      },
    );
  });

  test("acknowledged Bun still prefers the durable limiter when Redis is available", async () => {
    let durableCalls = 0;
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        durableAvailable: () => true,
        checkDurable: async () => {
          durableCalls += 1;
          return { allowed: true };
        },
      }),
    );
    await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT: "true",
      },
      async () => {
        expect(globalRateLimitPosture(() => true)).toBe("durable");
        expect((await mountedRequest(app)).status).toBe(200);
        expect(durableCalls).toBe(1);
      },
    );
  });

  test("Workers ignore the Bun single-instance acknowledgement", async () => {
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        checkDurable: async () => ({ allowed: false, retryAfterSecs: 60 }),
      }),
    );
    await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_RUNTIME: "workers",
        STEWARD_ACKNOWLEDGE_SINGLE_INSTANCE_GLOBAL_RATE_LIMIT: "true",
      },
      async () => {
        expect(globalRateLimitPosture()).toBe("durable");
        expect(globalRateLimitRequiresRedis()).toBe(true);
        expect((await mountedRequest(app)).status).toBe(429);
      },
    );
  });

  test("health and readiness remain mounted and observable during durable outage", async () => {
    const app = mountedApp(
      createGlobalRateLimitMiddleware({
        checkDurable: async () => {
          throw new Error("Redis outage");
        },
      }),
    );
    await withRuntimeEnvironment({ NODE_ENV: "production" }, async () => {
      expect((await mountedRequest(app, "/health")).status).toBe(200);
      expect((await mountedRequest(app, "/ready")).status).toBe(200);
    });
  });
});
