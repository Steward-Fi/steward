import { afterAll, describe, expect, it } from "bun:test";
import { checkRateLimit, disconnectRedis, getRedis, rateLimitBucketKey } from "@stwd/redis";
import type { StewardAppContext } from "../context";
import { CAPABILITY_INVOKE_RATE_LIMIT, enforceCapabilityRateLimit } from "../rate-limit";

const describeRedis = process.env.STEWARD_REDIS_TESTS === "1" ? describe : describe.skip;

afterAll(async () => {
  await disconnectRedis();
});

describeRedis("capability rate limiting with real Redis", () => {
  it("serializes independent callers at the exact boundary and survives reconnect", async () => {
    const tenantId = `redis-rate-tenant-${crypto.randomUUID()}`;
    const agentId = `redis-rate-agent-${crypto.randomUUID()}`;
    const key = `ratelimit:capability:invoke:${tenantId}:${agentId}:${CAPABILITY_INVOKE_RATE_LIMIT.windowMs}`;
    const physicalKey = rateLimitBucketKey(
      key,
      CAPABILITY_INVOKE_RATE_LIMIT.windowMs,
      CAPABILITY_INVOKE_RATE_LIMIT.maxRequests,
    );
    const alternateMax = CAPABILITY_INVOKE_RATE_LIMIT.maxRequests + 1;
    const alternatePhysicalKey = rateLimitBucketKey(
      key,
      CAPABILITY_INVOKE_RATE_LIMIT.windowMs,
      alternateMax,
    );
    const context = (): Pick<StewardAppContext, "db" | "getRedisClient" | "isRedisConfigured"> => ({
      db: {} as StewardAppContext["db"],
      getRedisClient: () => getRedis(),
      isRedisConfigured: () => true,
    });

    try {
      const firstReplica = context();
      const secondReplica = context();
      const results = await Promise.all(
        Array.from({ length: CAPABILITY_INVOKE_RATE_LIMIT.maxRequests + 1 }, (_, index) =>
          enforceCapabilityRateLimit(
            index % 2 === 0 ? firstReplica : secondReplica,
            "invoke",
            tenantId,
            agentId,
          ),
        ),
      );
      expect(results.filter((result) => result.allowed)).toHaveLength(
        CAPABILITY_INVOKE_RATE_LIMIT.maxRequests,
      );
      expect(results.filter((result) => !result.allowed)).toHaveLength(1);
      expect(await getRedis().zcard(physicalKey)).toBe(CAPABILITY_INVOKE_RATE_LIMIT.maxRequests);
      expect(
        await checkRateLimit(key, CAPABILITY_INVOKE_RATE_LIMIT.windowMs, alternateMax, getRedis()),
      ).toMatchObject({ allowed: true, remaining: alternateMax - 1 });
      expect(await getRedis().zcard(alternatePhysicalKey)).toBe(1);
      expect(await getRedis().zcard(physicalKey)).toBe(CAPABILITY_INVOKE_RATE_LIMIT.maxRequests);

      await disconnectRedis();
      expect(
        await enforceCapabilityRateLimit(context(), "invoke", tenantId, agentId),
      ).toMatchObject({ allowed: false });
    } finally {
      await getRedis().del(physicalKey, alternatePhysicalKey);
    }
  });
});
