import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export interface TradingRateLimitResult {
  allowed: boolean;
  resetMs: number;
  unavailable?: boolean;
}

type MemoryWindow = { count: number; resetAt: number };

/** Bounded fixed-window fallback for development or acknowledged single-instance use. */
export class MemoryTradingRateLimiter {
  private readonly windows = new Map<string, MemoryWindow>();

  constructor(private readonly maxEntries = 1_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0) {
      throw new RangeError("maxEntries must be a positive safe integer");
    }
  }

  consume(
    key: string,
    windowMs: number,
    maxRequests: number,
    now = Date.now(),
  ): TradingRateLimitResult {
    const current = this.windows.get(key);
    if (current && current.resetAt > now) {
      if (current.count >= maxRequests) {
        return { allowed: false, resetMs: current.resetAt - now };
      }
      current.count += 1;
      return { allowed: true, resetMs: current.resetAt - now };
    }
    if (current) this.windows.delete(key);

    if (this.windows.size >= this.maxEntries) {
      for (const [candidate, window] of this.windows) {
        if (window.resetAt <= now) this.windows.delete(candidate);
      }
      if (this.windows.size >= this.maxEntries) {
        return { allowed: false, resetMs: windowMs };
      }
    }

    this.windows.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, resetMs: windowMs };
  }

  /** Test-only observation of the bounded fallback; not used for enforcement. */
  entryCount(): number {
    return this.windows.size;
  }
}

function allowsMemoryFallback(): boolean {
  if (
    runtimeEnvironmentValue("STEWARD_RUNTIME") === "workers" ||
    runtimeEnvironmentValue("CF_PAGES") === "1"
  ) {
    return false;
  }
  const nodeEnv = runtimeEnvironmentValue("NODE_ENV");
  return (
    nodeEnv === "development" ||
    nodeEnv === "test" ||
    (nodeEnv === "production" &&
      runtimeEnvironmentValue("STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS") === "true")
  );
}

export async function enforceTradingRateLimit(input: {
  redisAvailable: boolean;
  checkRedis: () => Promise<{ allowed: boolean; resetMs: number }>;
  memoryKey: string;
  windowMs: number;
  maxRequests: number;
  memory: MemoryTradingRateLimiter;
}): Promise<TradingRateLimitResult> {
  if (input.redisAvailable) {
    try {
      const result = await input.checkRedis();
      return { allowed: result.allowed, resetMs: result.resetMs };
    } catch {
      return { allowed: false, resetMs: input.windowMs, unavailable: true };
    }
  }

  if (!allowsMemoryFallback()) {
    return { allowed: false, resetMs: input.windowMs, unavailable: true };
  }

  return input.memory.consume(input.memoryKey, input.windowMs, input.maxRequests);
}
