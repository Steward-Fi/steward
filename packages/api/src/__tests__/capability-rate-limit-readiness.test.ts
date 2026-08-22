import { describe, expect, it } from "bun:test";
import type { IoredisLike } from "@stwd/redis";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { checkCapabilityRateLimitReadiness } from "../services/capability-rate-limit-readiness";

describe("capability rate-limit Redis readiness", () => {
  it("uses the immutable request posture instead of an ambient production value", async () => {
    const priorNodeEnvironment = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      await expect(
        withRuntimeEnvironment({ NODE_ENV: "development" }, () =>
          checkCapabilityRateLimitReadiness({
            getRedisClient: () => null,
            isRedisConfigured: () => false,
          }),
        ),
      ).resolves.toEqual({ ok: true, source: "memory" });
    } finally {
      if (priorNodeEnvironment === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = priorNodeEnvironment;
    }
  });
  it("executes a bounded physical-generation reservation and cleans it up", async () => {
    const evaluatedKeys: string[] = [];
    const deletedKeys: string[] = [];
    const client = {
      async eval(_script: string, _keyCount: number, ...args: Array<string | number>) {
        evaluatedKeys.push(String(args[0]));
        return [1, 1, "1000000", 1_000_000, 1_000];
      },
      async del(...keys: string[]) {
        deletedKeys.push(...keys);
        return keys.length;
      },
    } as unknown as IoredisLike;

    await expect(
      checkCapabilityRateLimitReadiness({
        getRedisClient: () => client,
        isRedisConfigured: () => true,
      }),
    ).resolves.toEqual({ ok: true, source: "redis" });

    expect(evaluatedKeys).toHaveLength(1);
    expect(evaluatedKeys[0]).toMatch(/^ratelimit:capability-readiness:[^:]+:policy:1000:1$/);
    expect(deletedKeys).toEqual(evaluatedKeys);
  });

  it("reports not-ready when a stale cached client cannot execute the probe", async () => {
    const deletedKeys: string[] = [];
    const staleClient = {
      async eval() {
        throw new Error("connection closed");
      },
      async del(...keys: string[]) {
        deletedKeys.push(...keys);
        return keys.length;
      },
    } as unknown as IoredisLike;

    const result = await checkCapabilityRateLimitReadiness({
      getRedisClient: () => staleClient,
      isRedisConfigured: () => true,
    });

    expect(result).toEqual({
      ok: false,
      source: "redis",
      error: "Configured Redis capability rate-limit backend exercise failed",
    });
    expect(deletedKeys).toHaveLength(1);
    expect(deletedKeys[0]).toEndWith(":policy:1000:1");
  });

  it("bounds a stalled cached client and still attempts isolated-key cleanup", async () => {
    const deletedKeys: string[] = [];
    const stalledClient = {
      async eval() {
        return await new Promise<never>(() => undefined);
      },
      async del(...keys: string[]) {
        deletedKeys.push(...keys);
        return keys.length;
      },
    } as unknown as IoredisLike;

    const startedAt = performance.now();
    const result = await checkCapabilityRateLimitReadiness({
      getRedisClient: () => stalledClient,
      isRedisConfigured: () => true,
      redisProbeTimeoutMs: 10,
    });

    expect(performance.now() - startedAt).toBeLessThan(500);
    expect(result).toEqual({
      ok: false,
      source: "redis",
      error: "Configured Redis capability rate-limit backend exercise failed",
    });
    expect(deletedKeys).toHaveLength(1);
    expect(deletedKeys[0]).toEndWith(":policy:1000:1");
  });
});
