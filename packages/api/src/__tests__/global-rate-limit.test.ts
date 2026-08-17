import { afterEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { workersGlobalRateLimit } from "../middleware/global-rate-limit";

/**
 * SEC-068: the Workers entry has no in-memory global limiter (no cross-isolate
 * state), so app.ts mounts workersGlobalRateLimit across all routes on that
 * runtime. These tests exercise the middleware directly; the Redis-unavailable
 * branches are deterministic without a live Redis.
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
  app.use("*", workersGlobalRateLimit);
  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/thing", (c) => c.json({ ok: true }));
  return app;
}

describe("workersGlobalRateLimit (SEC-068)", () => {
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
});
