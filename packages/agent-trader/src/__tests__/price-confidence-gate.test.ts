import { describe, expect, it } from "bun:test";
import { DCAStrategy } from "../strategies/dca.js";
import { RebalanceStrategy } from "../strategies/rebalance.js";
import { ThresholdStrategy } from "../strategies/threshold.js";
import type { AgentState } from "../strategies/types.js";

/**
 * Build an AgentState whose token price WOULD trigger a buy/sell, varying only
 * the price-confidence tag so we can prove the low-confidence gate.
 */
function stateWith(overrides: Partial<AgentState>): AgentState {
  return {
    nativeBalance: 10n ** 19n, // 10 native
    tokenBalance: 10n ** 21n, // plenty of token to sell
    tokenPrice: 10n ** 15n, // 0.001 native/token
    priceConfidence: "high",
    lastTradeAge: 100_000,
    dailyVolume: 0n,
    treasuryValue: 10n ** 19n,
    ...overrides,
  };
}

describe("low-confidence price gate — strategy self-guard (LOW fix)", () => {
  it("threshold BUYS on a high-confidence dip price", async () => {
    const strat = new ThresholdStrategy({
      buyBelowPrice: (10n ** 16n).toString(), // price (1e15) is below → buy
      buyAmountWei: (10n ** 18n).toString(),
    });
    const decision = await strat.evaluate(stateWith({ priceConfidence: "high" }));
    expect(decision.action).toBe("buy");
  });

  it("threshold HOLDS on the same dip when the price is low-confidence", async () => {
    const strat = new ThresholdStrategy({
      buyBelowPrice: (10n ** 16n).toString(),
      buyAmountWei: (10n ** 18n).toString(),
    });
    const decision = await strat.evaluate(stateWith({ priceConfidence: "low" }));
    expect(decision.action).toBe("hold");
    expect(decision.confidence).toBe(0);
  });

  it("threshold HOLDS when price confidence is none", async () => {
    const strat = new ThresholdStrategy({
      buyBelowPrice: (10n ** 16n).toString(),
      buyAmountWei: (10n ** 18n).toString(),
    });
    const decision = await strat.evaluate(stateWith({ tokenPrice: 0n, priceConfidence: "none" }));
    expect(decision.action).toBe("hold");
  });

  it("rebalance ACTS on a high-confidence price but HOLDS on low-confidence", async () => {
    // Treasury skewed all into token → high confidence should sell to rebalance.
    const skewed = stateWith({
      nativeBalance: 0n,
      tokenBalance: 10n ** 22n,
      treasuryValue: (10n ** 22n * 10n ** 15n) / 10n ** 18n,
    });
    const strat = new RebalanceStrategy({ targetNativePercent: 50, targetTokenPercent: 50 });

    const high = await strat.evaluate({ ...skewed, priceConfidence: "high" });
    expect(high.action).toBe("sell");

    const low = await strat.evaluate({ ...skewed, priceConfidence: "low" });
    expect(low.action).toBe("hold");
  });

  it("strategies expose requiresPriceConfidence correctly", () => {
    expect(new ThresholdStrategy({ buyBelowPrice: "1" }).requiresPriceConfidence).toBe(true);
    expect(
      new RebalanceStrategy({ targetNativePercent: 30, targetTokenPercent: 70 })
        .requiresPriceConfidence,
    ).toBe(true);
    // DCA is price-agnostic — a low-confidence feed must NOT block scheduled buys.
    expect(new DCAStrategy({ buyAmountWei: "1" }).requiresPriceConfidence).toBe(false);
  });

  it("DCA still buys regardless of price confidence (price-agnostic)", async () => {
    const strat = new DCAStrategy({ buyAmountWei: (10n ** 18n).toString() });
    const decision = await strat.evaluate(stateWith({ priceConfidence: "low" }));
    expect(decision.action).toBe("buy");
  });
});
