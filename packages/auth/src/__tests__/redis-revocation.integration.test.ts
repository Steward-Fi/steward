import { afterAll, describe, expect, test } from "bun:test";
import { Redis } from "ioredis";
import { MONOTONIC_REVOCATION_SCRIPT } from "../revocation-script";

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
    const markerKey = (line: number) => `test:revocation:${suffix}:marker:${line}`;

    try {
      expect(
        await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey(200), latestKey, 200, 10_000),
      ).toBe(200);
      expect(
        await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey(100), latestKey, 100, 100),
      ).toBe(200);

      expect(await redis.get(latestKey)).toBe("200");
      expect(await redis.pttl(latestKey)).toBeGreaterThan(8_000);
      expect(await redis.pttl(markerKey(100))).toBeGreaterThan(8_000);

      expect(
        await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey(300), latestKey, 300, 1_000),
      ).toBe(300);
      expect(await redis.get(latestKey)).toBe("300");
      expect(await redis.pttl(latestKey)).toBeGreaterThan(8_000);
      expect(await redis.pttl(markerKey(300))).toBeGreaterThan(8_000);

      await redis.persist(latestKey);
      expect(
        await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey(400), latestKey, 400, 100),
      ).toBe(400);
      expect(await redis.get(latestKey)).toBe("400");
      expect(await redis.pttl(latestKey)).toBe(-1);
      expect(await redis.pttl(markerKey(400))).toBe(-1);
    } finally {
      await redis.del(markerKey(100), markerKey(200), markerKey(300), markerKey(400), latestKey);
    }
  });
});
