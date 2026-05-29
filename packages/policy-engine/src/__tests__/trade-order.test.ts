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
