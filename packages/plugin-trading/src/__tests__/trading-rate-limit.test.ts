import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { enforceTradingRateLimit, MemoryTradingRateLimiter } from "../routes/trading-rate-limit";

function consumeWithoutRedis(memory: MemoryTradingRateLimiter, memoryKey = "agent-1") {
  return enforceTradingRateLimit({
    redisAvailable: false,
    checkRedis: async () => ({ allowed: true, resetMs: 0 }),
    memoryKey,
    windowMs: 1_000,
    maxRequests: 10,
    memory,
  });
}

describe("trading rate-limit fallback boundary", () => {
  it("fails closed when the durable limiter errors without consuming memory", async () => {
    const memory = new MemoryTradingRateLimiter();
    const result = await enforceTradingRateLimit({
      redisAvailable: true,
      checkRedis: async () => {
        throw new Error("redis unavailable");
      },
      memoryKey: "agent-1",
      windowMs: 1_000,
      maxRequests: 10,
      memory,
    });

    expect(result).toEqual({ allowed: false, resetMs: 1_000, unavailable: true });
    expect(memory.entryCount()).toBe(0);
  });

  it("fails closed in production across independent replicas and restarts", async () => {
    await withRuntimeEnvironment({ NODE_ENV: "production" }, async () => {
      const firstReplica = new MemoryTradingRateLimiter();
      const secondReplica = new MemoryTradingRateLimiter();
      const results = await Promise.all([
        consumeWithoutRedis(firstReplica),
        consumeWithoutRedis(secondReplica),
        consumeWithoutRedis(new MemoryTradingRateLimiter()),
      ]);

      expect(results).toEqual([
        { allowed: false, resetMs: 1_000, unavailable: true },
        { allowed: false, resetMs: 1_000, unavailable: true },
        { allowed: false, resetMs: 1_000, unavailable: true },
      ]);
      expect(firstReplica.entryCount()).toBe(0);
      expect(secondReplica.entryCount()).toBe(0);
    });
  });

  it("requires the exact single-instance acknowledgement in production and Workers", async () => {
    const denied = await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS: "TRUE",
      },
      () => consumeWithoutRedis(new MemoryTradingRateLimiter()),
    );
    expect(denied.unavailable).toBe(true);

    const memory = new MemoryTradingRateLimiter();
    const admitted = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS: "true",
      },
      () => consumeWithoutRedis(memory),
    );
    expect(admitted).toEqual({ allowed: true, resetMs: 1_000 });
    expect(memory.entryCount()).toBe(1);
  });

  it("keeps overlapping request environments isolated", async () => {
    let releaseAcknowledged!: () => void;
    const acknowledgedPaused = new Promise<void>((resolve) => {
      releaseAcknowledged = resolve;
    });
    let acknowledgedStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      acknowledgedStarted = resolve;
    });

    const acknowledged = withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS: "true",
      },
      async () => {
        acknowledgedStarted();
        await acknowledgedPaused;
        return consumeWithoutRedis(new MemoryTradingRateLimiter(), "acknowledged");
      },
    );
    await started;
    const denied = await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
      consumeWithoutRedis(new MemoryTradingRateLimiter(), "denied"),
    );
    releaseAcknowledged();

    expect(denied.unavailable).toBe(true);
    expect(await acknowledged).toEqual({ allowed: true, resetMs: 1_000 });
  });

  it("bounds development memory and reclaims only expired windows", () => {
    const memory = new MemoryTradingRateLimiter(2);
    expect(memory.consume("a", 1_000, 1, 1)).toEqual({ allowed: true, resetMs: 1_000 });
    expect(memory.consume("b", 1_000, 1, 1)).toEqual({ allowed: true, resetMs: 1_000 });
    expect(memory.consume("c", 1_000, 1, 1)).toEqual({ allowed: false, resetMs: 1_000 });
    expect(memory.entryCount()).toBe(2);
    expect(memory.consume("c", 1_000, 1, 1_001)).toEqual({
      allowed: true,
      resetMs: 1_000,
    });
    expect(memory.entryCount()).toBe(1);
  });
});
