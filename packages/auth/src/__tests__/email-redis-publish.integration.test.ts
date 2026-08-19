import { afterAll, describe, expect, it } from "bun:test";
import { Redis } from "ioredis";

import { RedisBackend } from "../store-backends";

const redisUrl = process.env.REDIS_URL;
const integration = describe.skipIf(!redisUrl);
const redis = redisUrl ? new Redis(redisUrl, { lazyConnect: true }) : null;

integration("Redis email challenge publication", () => {
  afterAll(async () => {
    if (redis) await redis.quit();
  });

  it("rejects an expired absolute deadline before applying any write", async () => {
    if (!redis) throw new Error("REDIS_URL is required");
    await redis.connect();
    const prefix = `auth-email-publish-${crypto.randomUUID()}:`;
    const backend = new RedisBackend(redis, prefix);
    const guardKey = "reservation";
    const credentialKey = "credential";
    await backend.set(guardKey, "reserved", 60_000);

    expect(
      await backend.publish([
        { key: credentialKey, value: "active", expiresAt: Date.now() - 1 },
        {
          key: guardKey,
          value: "published",
          expiresAt: Date.now() - 1,
          expected: "reserved",
        },
      ]),
    ).toBe(false);
    expect(await backend.get(credentialKey)).toBeNull();
    expect(await backend.get(guardKey)).toBe("reserved");

    await backend.delete(guardKey);
    await backend.delete(credentialKey);
  });

  it("expires a publication at the supplied deadline rather than write time plus TTL", async () => {
    if (!redis) throw new Error("REDIS_URL is required");
    if (redis.status !== "ready") await redis.connect();
    const prefix = `auth-email-publish-${crypto.randomUUID()}:`;
    const backend = new RedisBackend(redis, prefix);
    const expiresAt = Date.now() + 100;

    expect(await backend.publish([{ key: "credential", value: "active", expiresAt }])).toBe(true);
    await Bun.sleep(130);
    expect(await backend.get("credential")).toBeNull();
    await backend.delete("credential");
  });
});
