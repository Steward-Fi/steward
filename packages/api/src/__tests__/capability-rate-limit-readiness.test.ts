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

  it("executes and cleans an isolated physical-generation reservation atomically", async () => {
    const evaluatedKeys: string[] = [];
    const scripts: string[] = [];
    const client = {
      async eval(script: string, _keyCount: number, ...args: Array<string | number>) {
        scripts.push(script);
        evaluatedKeys.push(String(args[0]));
        return [1, 1, "1000000", 1_000_000, 1_000];
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
    expect(scripts[0]).toContain("redis.call('DEL', KEYS[1])");
  });

  it("reports not-ready when a stale cached client cannot execute the probe", async () => {
    const staleClient = {
      async eval() {
        throw new Error("connection closed");
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
  });

  it("bounds and single-flights a stalled cached client", async () => {
    let evalCalls = 0;
    const stalledClient = {
      async eval() {
        evalCalls += 1;
        return await new Promise<never>(() => undefined);
      },
    } as unknown as IoredisLike;

    const startedAt = performance.now();
    const options = {
      getRedisClient: () => stalledClient,
      isRedisConfigured: () => true,
      redisProbeTimeoutMs: 10,
    };
    const [result, repeated] = await Promise.all([
      checkCapabilityRateLimitReadiness(options),
      checkCapabilityRateLimitReadiness(options),
    ]);

    expect(performance.now() - startedAt).toBeLessThan(500);
    expect(result).toEqual({
      ok: false,
      source: "redis",
      error: "Configured Redis capability rate-limit backend exercise failed",
    });
    expect(repeated).toEqual(result);
    expect(evalCalls).toBe(1);
  });

  it("cannot recreate a probe bucket after a caller deadline", async () => {
    let release: ((value: unknown) => void) | undefined;
    let script = "";
    const keys = new Set<string>();
    const client = {
      async eval(source: string, _keyCount: number, key: string) {
        script = source;
        await new Promise<unknown>((resolve) => {
          release = resolve;
        });
        // Model the atomic script's externally visible effect: its temporary
        // write and delete commit together, so no bucket can survive late EVAL.
        keys.add(key);
        if (source.includes("redis.call('DEL', KEYS[1])")) keys.delete(key);
        return [1, 1, "1000000", 1_000_000, 1_000];
      },
    } as unknown as IoredisLike;

    const result = await checkCapabilityRateLimitReadiness({
      getRedisClient: () => client,
      isRedisConfigured: () => true,
      redisProbeTimeoutMs: 10,
    });
    expect(result.ok).toBe(false);
    expect(script).toContain("redis.call('DEL', KEYS[1])");
    release?.(undefined);
    await Bun.sleep(0);
    expect(keys.size).toBe(0);
  });
});
