/**
 * Per-client auth rate limiting (#268): trusted-client-IP derivation, IPv6
 * bucketing, spoof resistance, hashed Redis subjects, per-endpoint budgets,
 * the coarse per-host fallback, and the bounded Redis-outage valve.
 *
 * Harness notes:
 *   - "@stwd/redis" is mocked with an in-memory counting checkRateLimit so
 *     budget exhaustion is real and every Redis key is captured for
 *     inspection (pattern: redis-rate-limit-fail-closed.test.ts).
 *   - Route-level requests go through authRoutes.request(...) with crafted
 *     headers (pattern: auth-abuse-controls.test.ts).
 *   - Env is saved/restored around every test (pattern:
 *     auth-rate-limit-headers.test.ts).
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, mock } from "bun:test";
import { hashSha256Hex } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

// ─── @stwd/redis counting mock ───────────────────────────────────────────────

const rateLimitCalls: Array<{ key: string; windowMs: number; max: number }> = [];
const rateLimitCounts = new Map<string, number>();
let forceDenyAll = false;

const checkRateLimitMock = mock(async (key: string, windowMs: number, max: number) => {
  rateLimitCalls.push({ key, windowMs, max });
  if (forceDenyAll) return { allowed: false, remaining: 0, resetMs: windowMs };
  const count = (rateLimitCounts.get(key) ?? 0) + 1;
  rateLimitCounts.set(key, count);
  return { allowed: count <= max, remaining: Math.max(max - count, 0), resetMs: windowMs };
});
const pingMock = mock(async () => "PONG");

mock.module("@stwd/redis", () => ({
  checkRateLimit: checkRateLimitMock,
  checkSpendLimit: async () => ({ allowed: true, spent: 0, remaining: 1 }),
  createUpstashIoredisAdapter: () => ({ ping: pingMock }),
  disconnectRedis: async () => undefined,
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
  recordSpend: async () => undefined,
  reserveSpend: async () => ({ allowed: true, reservationId: "reservation-test" }),
  setCachedPolicies: async () => undefined,
  settleReservedSpend: async () => undefined,
}));

// ─── Env save/restore ────────────────────────────────────────────────────────

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  STEWARD_TRUSTED_PROXY_HOPS: process.env.STEWARD_TRUSTED_PROXY_HOPS,
  STEWARD_TRUST_PROXY_HEADERS: process.env.STEWARD_TRUST_PROXY_HEADERS,
  STEWARD_TRUST_CLOUDFLARE: process.env.STEWARD_TRUST_CLOUDFLARE,
  STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX: process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX,
  STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL,
  REDIS_URL: process.env.REDIS_URL,
  REDIS_DRIVER: process.env.REDIS_DRIVER,
} as const;

function restoreEnv(key: keyof typeof ORIGINAL_ENV) {
  const value = ORIGINAL_ENV[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

function restoreAllEnv() {
  for (const key of Object.keys(ORIGINAL_ENV) as Array<keyof typeof ORIGINAL_ENV>) {
    restoreEnv(key);
  }
}

// ─── Module handles (loaded once in beforeAll) ───────────────────────────────

let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
let trustedClientIp: Awaited<typeof import("../routes/auth")>["trustedClientIp"];
let clientIpBucket: Awaited<typeof import("../routes/auth")>["clientIpBucket"];
let redisMiddleware: Awaited<typeof import("../middleware/redis")>;

/** Tiny probe app so trustedClientIp can be exercised with crafted headers. */
let probe: Hono;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "auth-client-ip-master-password";
  process.env.STEWARD_JWT_SECRET ??= "auth-client-ip-jwt-secret-with-enough-entropy-0123";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  ({ authRoutes, trustedClientIp, clientIpBucket } = await import("../routes/auth"));
  redisMiddleware = await import("../middleware/redis");

  probe = new Hono();
  probe.get("/ip", (c) => c.json({ ip: trustedClientIp(c) ?? null }));
});

afterAll(async () => {
  await closeDb();
  restoreAllEnv();
  delete process.env.STEWARD_PGLITE_MEMORY;
});

afterEach(() => {
  restoreAllEnv();
  forceDenyAll = false;
  rateLimitCalls.length = 0;
  rateLimitCounts.clear();
});

async function probeIp(headers: Record<string, string>): Promise<string | null> {
  const res = await probe.request("/ip", { headers });
  return ((await res.json()) as { ip: string | null }).ip;
}

/** Make Redis "available" via the mocked client so checkRateLimit is reached. */
async function connectMockRedis(): Promise<void> {
  process.env.REDIS_DRIVER = "ioredis";
  process.env.REDIS_URL = "redis://auth-client-ip.test:6379";
  expect(await redisMiddleware.initRedis()).toBe(true);
}

function capturedKeys(endpoint: string): string[] {
  return rateLimitCalls
    .filter((call) => call.key.startsWith(`ratelimit:auth:${endpoint}:`))
    .map((call) => call.key);
}

describe("trustedClientIp", () => {
  it("trusts no forwarded header when no hops are configured (safe default)", async () => {
    delete process.env.STEWARD_TRUSTED_PROXY_HOPS;
    delete process.env.STEWARD_TRUST_PROXY_HEADERS;
    expect(
      await probeIp({ "x-forwarded-for": "203.0.113.5", "x-real-ip": "203.0.113.5" }),
    ).toBeNull();
  });

  it("hops=1 reads the RIGHT-most x-forwarded-for entry; prepended spoofs are ignored", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, 198.51.100.7" })).toBe("198.51.100.7");
    // Attacker prepends garbage and extra fake IPs — right-most still wins.
    expect(await probeIp({ "x-forwarded-for": "1.1.1.1, 2.2.2.2, evil, 198.51.100.7" })).toBe(
      "198.51.100.7",
    );
  });

  it("hops=2 selects the 2nd entry from the right; too-short lists yield undefined", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "2";
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, 198.51.100.7, 10.0.0.9" })).toBe(
      "198.51.100.7",
    );
    // Only one entry with two trusted hops: never fall back to the left-most.
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5" })).toBeNull();
  });

  it("rejects non-IP garbage in the trusted position", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, not-an-ip" })).toBeNull();
  });

  it("invalid hop counts disable trust instead of widening it", async () => {
    for (const bad of ["abc", "-1", "0", "99", "1.5"]) {
      process.env.STEWARD_TRUSTED_PROXY_HOPS = bad;
      expect(await probeIp({ "x-forwarded-for": "203.0.113.5, 198.51.100.7" })).toBeNull();
    }
  });

  it("legacy STEWARD_TRUST_PROXY_HEADERS=true maps to hops=1 with RIGHT-most semantics", async () => {
    delete process.env.STEWARD_TRUSTED_PROXY_HOPS;
    process.env.STEWARD_TRUST_PROXY_HEADERS = "true";
    expect(await probeIp({ "x-forwarded-for": "6.6.6.6, 198.51.100.7" })).toBe("198.51.100.7");
  });

  it("x-real-ip is never consulted", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await probeIp({ "x-real-ip": "203.0.113.5" })).toBeNull();
  });

  it("x-envoy-external-address is honored when a trusted edge is configured, with :port stripped", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    expect(await probeIp({ "x-envoy-external-address": "203.0.113.9" })).toBe("203.0.113.9");
    // Railway's Envoy edge may append the observed source port.
    expect(await probeIp({ "x-envoy-external-address": "203.0.113.9:41234" })).toBe("203.0.113.9");
    expect(await probeIp({ "x-envoy-external-address": "[2001:db8::9]:443" })).toBe("2001:db8::9");
    // Envoy's single trusted value wins over the XFF fallback at hops=1.
    expect(
      await probeIp({
        "x-envoy-external-address": "203.0.113.9",
        "x-forwarded-for": "198.51.100.7",
      }),
    ).toBe("203.0.113.9");
    // Garbage still falls through to the XFF path, never becomes a key.
    expect(
      await probeIp({
        "x-envoy-external-address": "not-an-ip:80",
        "x-forwarded-for": "198.51.100.7",
      }),
    ).toBe("198.51.100.7");
  });

  it("x-envoy-external-address is NEVER trusted with zero trusted hops (client-forgeable)", async () => {
    delete process.env.STEWARD_TRUSTED_PROXY_HOPS;
    delete process.env.STEWARD_TRUST_PROXY_HEADERS;
    delete process.env.STEWARD_TRUST_CLOUDFLARE;
    expect(await probeIp({ "x-envoy-external-address": "203.0.113.9" })).toBeNull();
  });

  it("with hops >= 2 the positional XFF read stays authoritative over x-envoy-external-address", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "2";
    // Envoy names the intermediate proxy here, not the client — XFF wins.
    expect(
      await probeIp({
        "x-envoy-external-address": "10.0.0.9",
        "x-forwarded-for": "203.0.113.5, 198.51.100.7, 10.0.0.9",
      }),
    ).toBe("198.51.100.7");
    // A missing positional entry is a topology failure. Envoy names the
    // adjacent proxy here and must not be accepted as the external client.
    expect(
      await probeIp({
        "x-envoy-external-address": "10.0.0.9",
        "x-forwarded-for": "203.0.113.5",
      }),
    ).toBeNull();
  });

  it("parses ip:port and [ipv6]:port in the trusted XFF position; bare IPv6 is never mangled", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    // Envoy-style ip:port right-most entry (the Railway prod shape).
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, 198.51.100.7:52801" })).toBe(
      "198.51.100.7",
    );
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, [2001:db8::7]:443" })).toBe(
      "2001:db8::7",
    );
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, [2001:db8::7]" })).toBe("2001:db8::7");
    // Bare IPv6 has >= 2 colons and must not be truncated at its last group.
    expect(await probeIp({ "x-forwarded-for": "203.0.113.5, 2001:db8::7" })).toBe("2001:db8::7");
    expect(await probeIp({ "x-forwarded-for": "::1" })).toBe("::1");
    // ip:garbage-port is not silently repaired into an IP.
    expect(await probeIp({ "x-forwarded-for": "198.51.100.7:notaport" })).toBeNull();
  });

  it("cf-connecting-ip is honored only behind STEWARD_TRUST_CLOUDFLARE=true", async () => {
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    delete process.env.STEWARD_TRUST_CLOUDFLARE;
    // Flag unset: forged CF header is ignored; XFF path is used instead.
    expect(
      await probeIp({ "cf-connecting-ip": "9.9.9.9", "x-forwarded-for": "198.51.100.7" }),
    ).toBe("198.51.100.7");

    process.env.STEWARD_TRUST_CLOUDFLARE = "true";
    expect(
      await probeIp({ "cf-connecting-ip": "9.9.9.9", "x-forwarded-for": "198.51.100.7" }),
    ).toBe("9.9.9.9");
    // Flag on makes CF authoritative. Missing/invalid values fail closed and
    // cannot fall through to client-controlled proxy headers.
    expect(
      await probeIp({
        "cf-connecting-ip": "junk",
        "x-forwarded-for": "198.51.100.7",
        "x-envoy-external-address": "203.0.113.9",
      }),
    ).toBeNull();
    expect(await probeIp({ "x-envoy-external-address": "203.0.113.9" })).toBeNull();
  });
});

describe("clientIpBucket", () => {
  it("keys IPv4 as itself", () => {
    expect(clientIpBucket("198.51.100.7")).toBe("198.51.100.7");
  });

  it("unwraps IPv4-mapped IPv6 to the embedded IPv4", () => {
    expect(clientIpBucket("::ffff:1.2.3.4")).toBe("1.2.3.4");
  });

  it("unwraps the hex spelling of IPv4-mapped IPv6 to the same bucket as the dotted form", () => {
    expect(clientIpBucket("::ffff:0102:0304")).toBe("1.2.3.4");
    // Leading zeros stripped and full form: still the same mapped address.
    expect(clientIpBucket("::ffff:102:304")).toBe("1.2.3.4");
    expect(clientIpBucket("0:0:0:0:0:ffff:0102:0304")).toBe("1.2.3.4");
    expect(clientIpBucket("::ffff:0102:0304")).toBe(clientIpBucket("::ffff:1.2.3.4"));
  });

  it("buckets native IPv6 by /64 so one host cannot mint 2^64 budgets", () => {
    expect(clientIpBucket("2001:db8:abcd:12:1::1")).toBe("2001:db8:abcd:12::/64");
    expect(clientIpBucket("2001:db8:abcd:12:ffff:ffff:ffff:2")).toBe("2001:db8:abcd:12::/64");
    // Different /64 → different bucket.
    expect(clientIpBucket("2001:db8:abcd:13::1")).not.toBe(clientIpBucket("2001:db8:abcd:12::1"));
  });

  it("normalizes full-form and ::-compressed spellings to the same bucket", () => {
    expect(clientIpBucket("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(
      clientIpBucket("2001:db8::1"),
    );
  });
});

describe("auth rate-limit keying (route harness)", () => {
  it("keys per trusted client IP: spoofed prefixes share a bucket, real clients get independent budgets", async () => {
    await connectMockRedis();
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";

    // siwe-nonce budget is 30/min. Rotating attacker-prepended entries with a
    // fixed right-most IP must all land in ONE bucket and exhaust it.
    let denied: Response | null = null;
    for (let i = 0; i < 31; i++) {
      const res = await authRoutes.request("/nonce", {
        headers: { "x-forwarded-for": `10.66.${i}.1, 198.51.100.7` },
      });
      if (res.status === 429) denied = res;
    }
    const nonceKeys = capturedKeys("siwe-nonce");
    const expectedKey = `ratelimit:auth:siwe-nonce:${hashSha256Hex("ip:198.51.100.7")}:60000`;
    expect(new Set(nonceKeys)).toEqual(new Set([expectedKey]));
    expect(denied).not.toBeNull();
    expect(denied?.headers.get("retry-after")).toBe("60");

    // A different (unspoofed) client is unaffected by the exhausted bucket.
    // (400 = admitted past the limiter but no allowed Origin header; the
    // limiter outcome is all this test cares about.)
    const other = await authRoutes.request("/nonce", {
      headers: { "x-forwarded-for": "203.0.113.99" },
    });
    expect(other.status).toBe(400);
    expect(capturedKeys("siwe-nonce")).toContain(
      `ratelimit:auth:siwe-nonce:${hashSha256Hex("ip:203.0.113.99")}:60000`,
    );
  });

  it("multi-hop depth keys on the Nth-from-right entry", async () => {
    await connectMockRedis();
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "2";
    const res = await authRoutes.request("/nonce", {
      headers: { "x-forwarded-for": "203.0.113.5, 198.51.100.7, 10.0.0.9" },
    });
    expect(res.status).not.toBe(429);
    expect(capturedKeys("siwe-nonce")).toContain(
      `ratelimit:auth:siwe-nonce:${hashSha256Hex("ip:198.51.100.7")}:60000`,
    );
  });

  it("without a trusted IP, falls back to coarse per-host subjects (distinct per Host, never the old global) with x5 headroom", async () => {
    await connectMockRedis();
    delete process.env.STEWARD_TRUSTED_PROXY_HOPS;
    delete process.env.STEWARD_TRUST_PROXY_HEADERS;
    forceDenyAll = true;

    const res = await authRoutes.request("/nonce", {
      headers: {
        host: "api.steward.example",
        "x-forwarded-for": "203.0.113.5",
        // Forged Envoy header without a trusted edge must not mint an ip: bucket.
        "x-envoy-external-address": "203.0.113.5",
      },
    });
    expect(res.status).toBe(429);
    // Base 30/min widened x5 for the shared coarse bucket.
    expect(res.headers.get("ratelimit-limit")).toBe("150");
    expect(res.headers.get("ratelimit-policy")).toBe("150;w=60");
    await authRoutes.request("/nonce", {
      headers: { host: "staging.steward.example", "x-forwarded-for": "203.0.113.5" },
    });

    const calls = rateLimitCalls.filter((entry) => entry.key.includes("siwe-nonce"));
    expect(calls.map((entry) => entry.max)).toEqual([150, 150]);
    // The subject is exactly `host:<lowercased Host>` hashed — so each served
    // Host gets its own bucket, and no request ever lands in the legacy
    // "global" chokepoint or puts raw client-controlled bytes in the key.
    expect(calls.map((entry) => entry.key)).toEqual([
      `ratelimit:auth:siwe-nonce:${hashSha256Hex("host:api.steward.example")}:60000`,
      `ratelimit:auth:siwe-nonce:${hashSha256Hex("host:staging.steward.example")}:60000`,
    ]);
    expect(calls[0]?.key).not.toBe(calls[1]?.key);
    for (const call of calls) {
      expect(call.key).not.toContain(hashSha256Hex("global"));
      expect(call.key).not.toContain("global");
    }
  });

  it("hashes subjectOverride subjects: destination emails never reach Redis raw", async () => {
    await connectMockRedis();
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    const email = "pii-probe@example.com";
    await authRoutes.request("/email/send", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": "198.51.100.20",
      },
      body: JSON.stringify({ email }),
    });
    expect(rateLimitCalls.length).toBeGreaterThan(0);
    for (const call of rateLimitCalls) {
      expect(call.key).not.toContain(email);
    }
    // The destination limiter still keys deterministically on the email.
    expect(capturedKeys("email-send-destination")).toContain(
      `ratelimit:auth:email-send-destination:${hashSha256Hex(email)}:600000`,
    );
  });

  it("enforces launch-sized per-endpoint budgets (email-send 30/min, sms-send 5/min per IP)", async () => {
    await connectMockRedis();
    process.env.STEWARD_TRUSTED_PROXY_HOPS = "1";
    const headers = {
      "content-type": "application/json",
      "x-forwarded-for": "198.51.100.30",
    };

    // email-send: 30 allowed (generous per-IP burst for shared NATs — the
    // per-destination limiter is the anti-abuse backstop), 31st denied.
    // Unique destination emails keep the per-email limiter out of the way;
    // the per-IP budget is what trips.
    for (let i = 0; i < 30; i++) {
      const res = await authRoutes.request("/email/send", {
        method: "POST",
        headers,
        body: JSON.stringify({ email: `person-${i}@example.com` }),
      });
      expect(res.status).not.toBe(429);
    }
    const emailDenied = await authRoutes.request("/email/send", {
      method: "POST",
      headers,
      body: JSON.stringify({ email: "person-30@example.com" }),
    });
    expect(emailDenied.status).toBe(429);
    expect(emailDenied.headers.get("ratelimit-policy")).toBe("30;w=60");

    // sms-send: 5 allowed (invalid body → 400 AFTER the limiter), 6th denied.
    for (let i = 0; i < 5; i++) {
      const res = await authRoutes.request("/sms/send", {
        method: "POST",
        headers,
        body: JSON.stringify({ phone: "not-a-phone" }),
      });
      expect(res.status).toBe(400);
    }
    const smsDenied = await authRoutes.request("/sms/send", {
      method: "POST",
      headers,
      body: JSON.stringify({ phone: "not-a-phone" }),
    });
    expect(smsDenied.status).toBe(429);
    expect(smsDenied.headers.get("ratelimit-policy")).toBe("5;w=60");
  });

  it("bounded outage valve: configured-but-down Redis admits a small budget, then denies; 0 restores strict fail-closed", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    process.env.REDIS_DRIVER = "ioredis";
    process.env.REDIS_URL = "redis://auth-client-ip.test:6379"; // configured...
    await redisMiddleware.shutdownRedis(); // ...but unavailable
    process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX = "3";

    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await authRoutes.request("/nonce", {
        headers: { "x-forwarded-for": "198.51.100.40" },
      });
      statuses.push(res.status);
    }
    // Admitted requests reach the handler (400: no allowed Origin header);
    // once the valve budget is spent, the limiter itself denies with 429.
    expect(statuses.slice(0, 3)).toEqual([400, 400, 400]);
    expect(statuses[3]).toBe(429);
    // The Redis-backed limiter was never reached during the outage.
    expect(rateLimitCalls.length).toBe(0);

    // Valve max 0 → strict fail-closed.
    process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX = "0";
    const strict = await authRoutes.request("/nonce", {
      headers: { "x-forwarded-for": "198.51.100.40" },
    });
    expect(strict.status).toBe(429);
    expect(strict.headers.get("retry-after")).toBe("60");
  });

  it("never-configured Redis in production stays hard fail-closed (valve does not apply)", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    delete process.env.REDIS_URL;
    delete process.env.REDIS_DRIVER;
    await redisMiddleware.shutdownRedis();

    const res = await authRoutes.request("/nonce", {
      headers: { "x-forwarded-for": "198.51.100.50" },
    });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(rateLimitCalls.length).toBe(0);
  });
});
