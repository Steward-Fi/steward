import { describe, expect, it } from "bun:test";
import type { IoredisLike } from "@stwd/redis";
import { checkRedisConnectionReadiness } from "../middleware/redis";

describe("Redis connection readiness", () => {
  it("bounds a stalled ping, discards the stale client, and single-flights the ping", async () => {
    let pingCalls = 0;
    let discardCalls = 0;
    let refreshCalls = 0;
    const client = {
      async ping() {
        pingCalls += 1;
        return await new Promise<string>(() => undefined);
      },
    } as unknown as IoredisLike;
    const options = {
      timeoutMs: 10,
      getClient: () => client,
      discardClient: () => {
        discardCalls += 1;
      },
      refreshClient: async () => {
        refreshCalls += 1;
        return false;
      },
    };

    const startedAt = performance.now();
    const results = await Promise.all([
      checkRedisConnectionReadiness(options),
      checkRedisConnectionReadiness(options),
    ]);

    expect(performance.now() - startedAt).toBeLessThan(500);
    expect(results).toEqual([false, false]);
    expect(pingCalls).toBe(1);
    expect(discardCalls).toBe(2);
    expect(refreshCalls).toBe(2);
  });

  it("bounds and shares a replacement initialization supplied by middleware", async () => {
    let refreshCalls = 0;
    const refresh = async () => {
      refreshCalls += 1;
      return await new Promise<boolean>(() => undefined);
    };
    const startedAt = performance.now();
    const results = await Promise.all([
      checkRedisConnectionReadiness({
        timeoutMs: 10,
        getClient: () => null,
        refreshClient: refresh,
      }),
      checkRedisConnectionReadiness({
        timeoutMs: 10,
        getClient: () => null,
        refreshClient: refresh,
      }),
    ]);

    expect(performance.now() - startedAt).toBeLessThan(500);
    expect(results).toEqual([false, false]);
    // Production's initRedis owns the replacement single-flight. This injected
    // seam intentionally does not invent sharing outside that authority.
    expect(refreshCalls).toBe(2);
  });

  it("accepts a healthy client without replacement", async () => {
    let refreshCalls = 0;
    const client = { ping: async () => "PONG" } as unknown as IoredisLike;
    await expect(
      checkRedisConnectionReadiness({
        getClient: () => client,
        refreshClient: async () => {
          refreshCalls += 1;
          return false;
        },
      }),
    ).resolves.toBe(true);
    expect(refreshCalls).toBe(0);
  });
});
