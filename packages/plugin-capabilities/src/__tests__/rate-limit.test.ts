import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { agents, tenants } from "@stwd/db";
import type { IoredisLike } from "@stwd/redis";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { createInvokeRoutes } from "../invoke";
import {
  CAPABILITY_INVOKE_RATE_LIMIT,
  CAPABILITY_ISSUE_RATE_LIMIT,
  type CapabilityRateResult,
  enforceCapabilityRateLimit,
} from "../rate-limit";
import { capabilityInvocations, capabilityRateLimitBuckets } from "../schema";
import { type Harness, makeHarness } from "./_harness";

const savedEnvironment = {
  NODE_ENV: process.env.NODE_ENV,
  REDIS_DRIVER: process.env.REDIS_DRIVER,
  REDIS_URL: process.env.REDIS_URL,
  KV_REST_API_URL: process.env.KV_REST_API_URL,
  KV_REST_API_TOKEN: process.env.KV_REST_API_TOKEN,
  UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
};

let harness: Harness | null = null;

function restoreEnvironment() {
  for (const [name, value] of Object.entries(savedEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
}

beforeEach(() => {
  process.env.NODE_ENV = "test";
  delete process.env.REDIS_DRIVER;
  delete process.env.REDIS_URL;
  delete process.env.KV_REST_API_URL;
  delete process.env.KV_REST_API_TOKEN;
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
});

afterEach(async () => {
  await harness?.close();
  harness = null;
  restoreEnvironment();
});

const memoryContext = {
  db: null as never,
  getRedisClient: () => null,
  isRedisConfigured: () => false,
};

async function seedRateAgent(tenantId: string, agentId: string): Promise<void> {
  await harness!.db.insert(tenants).values({
    id: tenantId,
    name: tenantId,
    apiKeyHash: `rate-key-${tenantId}`,
  });
  await harness!.db.insert(agents).values({
    id: agentId,
    tenantId,
    name: agentId,
    walletAddress: "0x1234567890123456789012345678901234567890",
  });
}

describe("enforceCapabilityRateLimit", () => {
  test("reserves on the exact Redis client supplied by the request context", async () => {
    function countingClient(label: string) {
      const counts = new Map<string, number>();
      const calls: string[] = [];
      const client = {
        async eval(script: string, _keyCount: number, ...args: Array<string | number>) {
          const key = String(args[0]);
          const windowMs = Number(args[1]);
          const max = Number(args[2]);
          calls.push(`${label}:${key}`);
          const prior = counts.get(key) ?? 0;
          const allowed = prior < max;
          const count = allowed ? prior + 1 : prior;
          counts.set(key, count);
          expect(script).toContain("redis.call('TIME')");
          return [allowed ? 1 : 0, count, "1000000", 1000000, windowMs];
        },
      } as unknown as IoredisLike;
      return { client, calls };
    }

    const authorityA = countingClient("A");
    const authorityB = countingClient("B");
    const tenantId = `tenant-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    const context = (client: IoredisLike) => ({
      db: null as never,
      getRedisClient: () => client,
      isRedisConfigured: () => true,
    });

    for (let i = 0; i < CAPABILITY_ISSUE_RATE_LIMIT.maxRequests; i++) {
      expect(
        (await enforceCapabilityRateLimit(context(authorityA.client), "issue", tenantId, agentId))
          .allowed,
      ).toBe(true);
    }
    expect(
      (await enforceCapabilityRateLimit(context(authorityB.client), "issue", tenantId, agentId))
        .allowed,
    ).toBe(true);
    expect(
      (await enforceCapabilityRateLimit(context(authorityA.client), "issue", tenantId, agentId))
        .allowed,
    ).toBe(false);
    expect(authorityA.calls).toHaveLength(CAPABILITY_ISSUE_RATE_LIMIT.maxRequests + 1);
    expect(authorityB.calls).toHaveLength(1);
  });

  test("uses one Redis clock across skewed independent application contexts", async () => {
    const reservations = new Map<string, number[]>();
    const serverNow = 1_900_000_000_000;
    function skewHostClient(localNow: number) {
      return {
        async eval(script: string, _keyCount: number, ...args: Array<string | number>) {
          expect(script).toContain("redis.call('TIME')");
          const key = String(args[0]);
          const windowMs = Number(args[1]);
          const max = Number(args[2]);
          // No caller timestamp/window boundary is accepted by the script.
          expect(args).toHaveLength(5);
          expect(args.map(String)).not.toContain(String(localNow));
          const live = (reservations.get(key) ?? []).filter(
            (reservedAt) => reservedAt > serverNow - windowMs,
          );
          const allowed = live.length < max;
          if (allowed) live.push(serverNow);
          reservations.set(key, live);
          return [allowed ? 1 : 0, live.length, String(serverNow), serverNow, windowMs];
        },
      } as unknown as IoredisLike;
    }

    const tenantId = `tenant-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    const farBehindNow = serverNow - 365 * 24 * 60 * 60_000;
    const farAheadNow = serverNow + 365 * 24 * 60 * 60_000;
    const farBehind = skewHostClient(farBehindNow);
    const farAhead = skewHostClient(farAheadNow);
    const context = (client: IoredisLike) => ({
      db: null as never,
      getRedisClient: () => client,
      isRedisConfigured: () => true,
    });

    const originalDateNow = Date.now;
    const attempts: CapabilityRateResult[] = [];
    try {
      Date.now = () => farBehindNow;
      for (let index = 0; index < CAPABILITY_INVOKE_RATE_LIMIT.maxRequests / 2; index += 1) {
        attempts.push(
          await enforceCapabilityRateLimit(context(farBehind), "invoke", tenantId, agentId),
        );
      }
      Date.now = () => farAheadNow;
      for (
        let index = CAPABILITY_INVOKE_RATE_LIMIT.maxRequests / 2;
        index <= CAPABILITY_INVOKE_RATE_LIMIT.maxRequests;
        index += 1
      ) {
        attempts.push(
          await enforceCapabilityRateLimit(context(farAhead), "invoke", tenantId, agentId),
        );
      }
    } finally {
      Date.now = originalDateNow;
    }
    expect(attempts.filter((attempt) => attempt.allowed)).toHaveLength(
      CAPABILITY_INVOKE_RATE_LIMIT.maxRequests,
    );
    expect(attempts.filter((attempt) => !attempt.allowed)).toHaveLength(1);
    expect(new Set(attempts.map((attempt) => attempt.resetMs))).toEqual(
      new Set([CAPABILITY_INVOKE_RATE_LIMIT.windowMs]),
    );
  });

  test("permits memory only in explicit test/development posture", async () => {
    const tenant = `tenant-cap-rl-${crypto.randomUUID()}`;
    const agent = `agent-cap-rl-${crypto.randomUUID()}`;
    for (let i = 0; i < CAPABILITY_INVOKE_RATE_LIMIT.maxRequests; i++) {
      expect(
        (await enforceCapabilityRateLimit(memoryContext, "invoke", tenant, agent)).allowed,
      ).toBe(true);
    }
    expect((await enforceCapabilityRateLimit(memoryContext, "invoke", tenant, agent)).allowed).toBe(
      false,
    );

    process.env.NODE_ENV = "production";
    expect(
      (await enforceCapabilityRateLimit(memoryContext, "invoke", tenant, crypto.randomUUID()))
        .allowed,
    ).toBe(false);
  });

  test("keeps development buckets isolated by tenant, agent, and surface", async () => {
    process.env.NODE_ENV = "development";
    const tenant = `tenant-cap-rl-${crypto.randomUUID()}`;
    const otherTenant = `tenant-cap-rl-${crypto.randomUUID()}`;
    const flooded = `agent-cap-rl-${crypto.randomUUID()}`;
    for (let i = 0; i < CAPABILITY_ISSUE_RATE_LIMIT.maxRequests; i++) {
      await enforceCapabilityRateLimit(memoryContext, "issue", tenant, flooded);
    }
    expect(
      (await enforceCapabilityRateLimit(memoryContext, "issue", tenant, flooded)).allowed,
    ).toBe(false);
    expect(
      (await enforceCapabilityRateLimit(memoryContext, "issue", otherTenant, flooded)).allowed,
    ).toBe(true);
    expect(
      (await enforceCapabilityRateLimit(memoryContext, "invoke", tenant, flooded)).allowed,
    ).toBe(true);
  });

  test("configured-but-unavailable Redis fails closed before database fallback", async () => {
    process.env.NODE_ENV = "production";
    harness = await makeHarness();
    const result = await enforceCapabilityRateLimit(
      {
        db: harness.db,
        getRedisClient: () => null,
        isRedisConfigured: () => true,
      },
      "invoke",
      `tenant-${crypto.randomUUID()}`,
      `agent-${crypto.randomUUID()}`,
    );
    expect(result.allowed).toBe(false);
    expect(await harness.db.select().from(capabilityRateLimitBuckets)).toEqual([]);
  });

  test("absent Redis in production uses durable state across fresh service contexts and expiry", async () => {
    process.env.NODE_ENV = "production";
    harness = await makeHarness();
    const tenantId = `tenant-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await seedRateAgent(tenantId, agentId);
    const firstContext = {
      db: harness.db,
      getRedisClient: () => null,
      isRedisConfigured: () => false,
      withCapabilityTenantDatabase: (
        _tenantId: string,
        use: (db: typeof harness.db) => Promise<unknown>,
      ) => use(harness!.db),
    };
    for (let i = 0; i < CAPABILITY_ISSUE_RATE_LIMIT.maxRequests; i++) {
      expect(
        (await enforceCapabilityRateLimit(firstContext, "issue", tenantId, agentId)).allowed,
      ).toBe(true);
    }

    // A newly constructed context models a restarted service process. The next
    // request still observes the durable full bucket.
    const restartedContext = { ...firstContext };
    expect(
      (await enforceCapabilityRateLimit(restartedContext, "issue", tenantId, agentId)).allowed,
    ).toBe(false);

    const expired = new Date(Date.now() - CAPABILITY_ISSUE_RATE_LIMIT.windowMs - 1_000);
    await harness.db
      .update(capabilityRateLimitBuckets)
      .set({ reservations: Array(CAPABILITY_ISSUE_RATE_LIMIT.maxRequests).fill(expired) })
      .where(
        and(
          eq(capabilityRateLimitBuckets.tenantId, tenantId),
          eq(capabilityRateLimitBuckets.agentId, agentId),
          eq(capabilityRateLimitBuckets.surface, "issue"),
        ),
      );
    expect(
      (await enforceCapabilityRateLimit(restartedContext, "issue", tenantId, agentId)).allowed,
    ).toBe(true);
  });

  test("reachable 429 boundary writes no invocation row for the rejected attempt", async () => {
    process.env.NODE_ENV = "production";
    harness = await makeHarness();
    const tenantId = `tenant-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await seedRateAgent(tenantId, agentId);
    const rateContext = {
      db: harness.db,
      getRedisClient: () => null,
      isRedisConfigured: () => false,
      withCapabilityTenantDatabase: (
        _tenantId: string,
        use: (db: typeof harness.db) => Promise<unknown>,
      ) => use(harness!.db),
    };
    const app = new Hono();
    app.use("*", async (c, next) => {
      c.set("tenantId" as never, tenantId as never);
      c.set("agentScope" as never, agentId as never);
      await next();
    });
    app.route("/capabilities", createInvokeRoutes(rateContext as never));

    for (let i = 0; i < CAPABILITY_INVOKE_RATE_LIMIT.maxRequests; i++) {
      const response = await app.request("/capabilities/not-granted/invoke", { method: "POST" });
      expect(response.status).toBe(403);
    }
    const rejected = await app.request("/capabilities/not-granted/invoke", { method: "POST" });
    expect(rejected.status).toBe(429);
    expect(rejected.headers.get("retry-after")).toBeTruthy();

    const rows = await harness.db
      .select()
      .from(capabilityInvocations)
      .where(
        and(
          eq(capabilityInvocations.tenantId, tenantId),
          eq(capabilityInvocations.agentId, agentId),
        ),
      );
    expect(rows).toHaveLength(CAPABILITY_INVOKE_RATE_LIMIT.maxRequests);
  });
});
