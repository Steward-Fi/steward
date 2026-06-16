import { describe, expect, it } from "bun:test";
import {
  assetAllowlistEvaluator,
  dailySpendCapEvaluator,
  evaluateTradeOrder,
  leverageCapEvaluator,
  perOrderCapEvaluator,
  venueAllowlistEvaluator,
} from "../trade-order";

const session = {
  venue: "hyperliquid",
  allowedVenues: ["hyperliquid"],
  allowedAssets: ["BTC", "ETH"],
  leverageCap: 2,
  dailySpendUsd: 25,
  dailyCapUsd: 100,
  perOrderCapUsd: 50,
};

const order = {
  venue: "hyperliquid",
  asset: "BTC",
  leverage: 2,
  estimatedOrderUsd: 25,
};

describe("trade-order evaluators", () => {
  it("venue-allowlist blocks venues outside the session allowlist", () => {
    expect(venueAllowlistEvaluator(session, { ...order, venue: "polymarket" })).toEqual({
      allow: false,
      reason: "venue-allowlist: venue polymarket is not allowed for this session",
    });
  });

  it("leverage-cap blocks leverage above the session cap and defaults to 2x", () => {
    expect(leverageCapEvaluator({}, { ...order, leverage: 3 })).toEqual({
      allow: false,
      reason: "leverage-cap: leverage 3 exceeds cap 2",
    });
  });

  it("asset-allowlist blocks assets outside the session allowlist and defaults to BTC/ETH", () => {
    expect(assetAllowlistEvaluator({}, { ...order, asset: "SOL" })).toEqual({
      allow: false,
      reason: "asset-allowlist: asset SOL is not allowed for this session",
    });
  });

  it("daily-spend-cap blocks orders that would exceed the session daily cap", () => {
    expect(dailySpendCapEvaluator(session, { ...order, estimatedOrderUsd: 80 })).toEqual({
      allow: false,
      reason: "daily-spend-cap: $105 would exceed daily cap $100",
    });
  });

  it("daily-spend-cap fails closed when order notional is missing or invalid", () => {
    for (const estimatedOrderUsd of [undefined, Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
      expect(dailySpendCapEvaluator(session, { ...order, estimatedOrderUsd })).toEqual({
        allow: false,
        reason: "daily-spend-cap: estimated order USD is required when a daily cap is configured",
      });
    }
  });

  it("per-order-cap blocks orders above the session per-order cap and defaults to $50", () => {
    expect(perOrderCapEvaluator({}, { ...order, estimatedOrderUsd: 51 })).toEqual({
      allow: false,
      reason: "per-order-cap: order $51 exceeds cap $50",
    });
  });

  it("per-order-cap fails closed when order notional is missing or invalid", () => {
    for (const estimatedOrderUsd of [undefined, Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
      expect(perOrderCapEvaluator(session, { ...order, estimatedOrderUsd })).toEqual({
        allow: false,
        reason: "per-order-cap: estimated order USD is required when a per-order cap is configured",
      });
    }
  });

  it("adapter gate composition (per-order + daily) denies an under-per-order order once rolling daily spend is counted", () => {
    // Mirrors routes/adapters.ts `enforceFundMovingPolicy`, which runs ONLY the
    // USD-cap evaluators. Regression guard for the bug where the route passed a
    // hardcoded dailySpendUsd:0, making the daily cap a no-op: an order UNDER the
    // per-order cap must still be DENIED when the agent's REAL rolling daily
    // spend would push the day's total over the daily cap.
    const adapterSession = { perOrderCapUsd: 100, dailyCapUsd: 1000, dailySpendUsd: 950 };
    const adapterEvaluators = [perOrderCapEvaluator, dailySpendCapEvaluator];

    // $80 is under the $100 per-order cap, but 950 + 80 = 1030 > 1000 daily cap.
    expect(
      evaluateTradeOrder(adapterSession, { estimatedOrderUsd: 80 }, adapterEvaluators),
    ).toEqual({
      allow: false,
      reason: "daily-spend-cap: $1030 would exceed daily cap $1000",
      failedEvaluator: "dailySpendCapEvaluator",
    });

    // With the previous (buggy) dailySpendUsd:0 baseline the SAME order is allowed,
    // proving the rolling spend is what binds the cap.
    expect(
      evaluateTradeOrder(
        { perOrderCapUsd: 100, dailyCapUsd: 1000, dailySpendUsd: 0 },
        { estimatedOrderUsd: 80 },
        adapterEvaluators,
      ),
    ).toEqual({ allow: true });
  });

  it("compose returns the first failure for an ETH buy 3x at $200", () => {
    const result = evaluateTradeOrder(session, {
      venue: "hyperliquid",
      asset: "ETH",
      leverage: 3,
      estimatedOrderUsd: 200,
    });

    expect(result).toEqual({
      allow: false,
      reason: "leverage-cap: leverage 3 exceeds cap 2",
      failedEvaluator: "leverageCapEvaluator",
    });
    expect(
      perOrderCapEvaluator(session, { ...order, asset: "ETH", leverage: 3, estimatedOrderUsd: 200 })
        .allow,
    ).toBe(false);
  });
});

it("requires explicit builder-perp opt-in and clamps builder leverage to 3x", () => {
  expect(
    evaluateTradeOrder(
      {
        venue: "hyperliquid",
        allowedVenues: ["hyperliquid"],
        allowedAssets: ["xyz:SPCX"],
        leverageCap: 10,
        perOrderCapUsd: 500,
      },
      { venue: "hyperliquid", asset: "xyz:SPCX", leverage: 1, estimatedOrderUsd: 100 },
    ),
  ).toEqual({
    allow: false,
    reason: "builder-perp: builder perp xyz:SPCX requires allowBuilderPerps policy opt-in",
    failedEvaluator: "assetAllowlistEvaluator",
  });
  expect(
    evaluateTradeOrder(
      {
        venue: "hyperliquid",
        allowedVenues: ["hyperliquid"],
        allowedAssets: ["xyz:SPCX"],
        allowBuilderPerps: true,
        leverageCap: 10,
        perOrderCapUsd: 500,
      },
      { venue: "hyperliquid", asset: "xyz:SPCX", leverage: 4, estimatedOrderUsd: 100 },
    ),
  ).toEqual({
    allow: false,
    reason: "leverage-cap: leverage 4 exceeds cap 3",
    failedEvaluator: "leverageCapEvaluator",
  });
});
