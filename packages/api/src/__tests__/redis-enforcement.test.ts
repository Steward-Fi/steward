/**
 * Tests for Redis enforcement middleware.
 *
 * These tests verify the rate-limit and spend-tracking extraction
 * and enforcement logic WITHOUT requiring a live Redis connection.
 * Redis helpers degrade gracefully when unavailable.
 */

import { describe, expect, it } from "bun:test";
import type { PolicyRule } from "@stwd/shared";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import {
  conservativeNativeSpendUsd,
  enforceRateLimit,
  extractRateLimitPolicy,
  extractSpendLimitPolicy,
  formatRateLimitHeaders,
  nativePriceFallbackUsd,
  recordVaultSpend,
} from "../middleware/redis-enforcement";

// ─── Policy extraction tests ─────────────────────────────────────────────────

describe("extractRateLimitPolicy", () => {
  it("returns null when no rate-limit policy exists", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "spending-limit",
        enabled: true,
        config: {
          maxPerDay: "1000000",
          maxPerWeek: "5000000",
          maxPerTx: "100000",
        },
      },
    ];
    expect(extractRateLimitPolicy(policies)).toBeNull();
  });

  it("returns null when rate-limit policy is disabled", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "rate-limit",
        enabled: false,
        config: { maxTxPerHour: 10, maxTxPerDay: 100 },
      },
    ];
    expect(extractRateLimitPolicy(policies)).toBeNull();
  });

  it("extracts rate-limit config from enabled policy", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerHour: 25, maxTxPerDay: 200 },
      },
    ];
    const result = extractRateLimitPolicy(policies);
    expect(result).toEqual({ maxTxPerHour: 25, maxTxPerDay: 200 });
  });

  it("uses defaults for missing config fields", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "rate-limit",
        enabled: true,
        config: {},
      },
    ];
    const result = extractRateLimitPolicy(policies);
    expect(result).toEqual({ maxTxPerHour: 100, maxTxPerDay: 1000 });
  });
});

describe("extractSpendLimitPolicy", () => {
  it("returns null when no spending-limit policy exists", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerHour: 10, maxTxPerDay: 100 },
      },
    ];
    expect(extractSpendLimitPolicy(policies)).toBeNull();
  });

  it("extracts canonical format spend limits", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "spending-limit",
        enabled: true,
        config: {
          maxPerDay: "1000000",
          maxPerWeek: "5000000",
          maxPerTx: "100000",
        },
      },
    ];
    const result = extractSpendLimitPolicy(policies);
    expect(result).toEqual({ maxPerDay: "1000000", maxPerWeek: "5000000" });
  });

  it("extracts a weekly-only canonical cap without inventing a zero daily cap", () => {
    const result = extractSpendLimitPolicy([
      {
        id: "p1",
        type: "spending-limit",
        enabled: true,
        config: { maxPerWeek: "5000000" },
      },
    ]);
    expect(result).toEqual({
      maxPerDay: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
      maxPerWeek: "5000000",
    });
  });

  it("returns null for a pure-USD policy because it has no rolling wei cap", () => {
    expect(
      extractSpendLimitPolicy([
        {
          id: "p1",
          type: "spending-limit",
          enabled: true,
          config: { maxPerDayUsd: 100 },
        },
      ]),
    ).toBeNull();
  });

  it("handles simplified period format (day)", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "spending-limit",
        enabled: true,
        config: { maxAmount: "500000", period: "day" },
      },
    ];
    const result = extractSpendLimitPolicy(policies);
    expect(result).not.toBeNull();
    if (!result) throw new Error("Expected spend-limit policy");
    expect(result.maxPerDay).toBe("500000");
  });

  it("handles simplified period format (week)", () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "spending-limit",
        enabled: true,
        config: { maxAmount: "2000000", period: "week" },
      },
    ];
    const result = extractSpendLimitPolicy(policies);
    expect(result).not.toBeNull();
    if (!result) throw new Error("Expected spend-limit policy");
    expect(result.maxPerWeek).toBe("2000000");
  });
});

// ─── Graceful degradation tests (no Redis) ───────────────────────────────────

describe("enforceRateLimit (no Redis)", () => {
  it("allows requests when Redis is not available", async () => {
    const policies: PolicyRule[] = [
      {
        id: "p1",
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerHour: 100, maxTxPerDay: 100 },
      },
    ];

    const result = await enforceRateLimit(`test-agent-${crypto.randomUUID()}`, policies);
    expect(result.allowed).toBe(!process.env.REDIS_URL);
  });

  it("allows requests when no rate-limit policy exists", async () => {
    const policies: PolicyRule[] = [];
    const result = await enforceRateLimit("test-agent", policies);
    expect(result.allowed).toBe(true);
  });
});

describe("formatRateLimitHeaders", () => {
  it("emits standard and legacy rate-limit headers", () => {
    const headers = formatRateLimitHeaders({
      limit: 10,
      remaining: 2,
      resetMs: 12_001,
      retryAfterMs: 12_001,
    });

    expect(headers["RateLimit-Limit"]).toBe("10");
    expect(headers["RateLimit-Remaining"]).toBe("2");
    expect(headers["RateLimit-Reset"]).toBe("13");
    expect(headers["Retry-After"]).toBe("13");
    expect(headers["X-RateLimit-Limit"]).toBe("10");
    expect(headers["X-RateLimit-Remaining"]).toBe("2");
    expect(headers["X-RateLimit-Reset"]).toBe("13");
  });

  it("does not emit Retry-After for allowed responses", () => {
    const headers = formatRateLimitHeaders({ limit: 5, remaining: 4, resetMs: 1_000 });
    expect(headers["Retry-After"]).toBeUndefined();
    expect(headers["RateLimit-Remaining"]).toBe("4");
  });
});

describe("nativePriceFallbackUsd", () => {
  it("isolates hostile overlapping Worker request bindings", async () => {
    let releaseHigh!: () => void;
    const highCanFinish = new Promise<void>((resolve) => {
      releaseHigh = resolve;
    });
    let highStarted!: () => void;
    const highDidStart = new Promise<void>((resolve) => {
      highStarted = resolve;
    });

    const high = withRuntimeEnvironment(
      { STEWARD_NATIVE_PRICE_FALLBACK_USD: "25000" },
      async () => {
        highStarted();
        await highCanFinish;
        return nativePriceFallbackUsd();
      },
    );
    await highDidStart;

    const hostileLow = withRuntimeEnvironment(
      { STEWARD_NATIVE_PRICE_FALLBACK_USD: "1" },
      async () => {
        expect(nativePriceFallbackUsd()).toBe(1);
        releaseHigh();
        return nativePriceFallbackUsd();
      },
    );

    expect(await Promise.all([high, hostileLow])).toEqual([25_000, 1]);
  });

  it("uses the conservative default for absent or invalid request bindings", () => {
    expect(withRuntimeEnvironment({}, () => nativePriceFallbackUsd())).toBe(10_000);
    expect(
      withRuntimeEnvironment({ STEWARD_NATIVE_PRICE_FALLBACK_USD: "Infinity" }, () =>
        nativePriceFallbackUsd(),
      ),
    ).toBe(10_000);
    expect(
      withRuntimeEnvironment({ STEWARD_NATIVE_PRICE_FALLBACK_USD: "0" }, () =>
        nativePriceFallbackUsd(),
      ),
    ).toBe(10_000);
  });
});

describe("conservativeNativeSpendUsd", () => {
  it("uses Solana's 9-decimal base units when no oracle price is available", () => {
    expect(
      withRuntimeEnvironment({ STEWARD_NATIVE_PRICE_FALLBACK_USD: "10000" }, () =>
        conservativeNativeSpendUsd(1_000_000_000n, 101),
      ),
    ).toBe(10_000);
    expect(
      withRuntimeEnvironment({ STEWARD_NATIVE_PRICE_FALLBACK_USD: "10000" }, () =>
        conservativeNativeSpendUsd(1_500_000_000n, 102),
      ),
    ).toBe(15_000);
  });

  it("fails closed when native decimals are unknown", () => {
    expect(() => conservativeNativeSpendUsd(1n, 999_999)).toThrow(
      "Native-token decimals are not configured",
    );
  });
});

describe("recordVaultSpend (no Redis)", () => {
  it("does not throw when Redis is not available", async () => {
    // Should silently succeed (no-op)
    await recordVaultSpend("test-agent", "test-tenant", "1000000000000000000", 8453);
  });

  it("does not throw for zero value", async () => {
    await recordVaultSpend("test-agent", "test-tenant", "0", 8453);
  });
});
