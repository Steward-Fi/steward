import { afterAll, describe, expect, test } from "bun:test";
import { Redis } from "ioredis";
import { MONOTONIC_REVOCATION_SCRIPT } from "../revocation";

const redisUrl = process.env.REDIS_URL;
const redisTest = redisUrl ? test : test.skip;
const redis = redisUrl
  ? new Redis(redisUrl, { enableReadyCheck: true, maxRetriesPerRequest: 1 })
  : null;

afterAll(async () => {
  if (redis) await redis.quit();
});

describe("Redis revocation line monotonicity", () => {
  redisTest("never lowers the latest value or shortens its TTL", async () => {
    if (!redis) throw new Error("REDIS_URL is required");

    const suffix = crypto.randomUUID();
    const latestKey = `test:revocation:${suffix}:latest`;
    const markerKey = `test:revocation:${suffix}:marker`;

    try {
      await redis.set(latestKey, "200", "PX", 10_000);
      await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey, latestKey, 100, 100);

      expect(await redis.get(latestKey)).toBe("200");
      expect(await redis.pttl(latestKey)).toBeGreaterThan(8_000);

      await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey, latestKey, 300, 1_000);
      expect(await redis.get(latestKey)).toBe("300");
      expect(await redis.pttl(latestKey)).toBeGreaterThan(8_000);

      await redis.persist(latestKey);
      await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey, latestKey, 400, 100);
      expect(await redis.get(latestKey)).toBe("400");
      expect(await redis.pttl(latestKey)).toBe(-1);
    } finally {
      await redis.del(markerKey, latestKey);
    }
  });
});
