import { describe, expect, test } from "bun:test";
import { MockSwapAdapter } from "../adapters/swap.js";
import { AdapterValidationError } from "../types.js";

const USDC = { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 };
const WETH = {
  address: "0x4200000000000000000000000000000000000006",
  symbol: "WETH",
  decimals: 18,
};

function fixedClock(ms: number): { now: () => number } {
  return { now: () => ms };
}

describe("MockSwapAdapter.getQuote", () => {
  test("returns a deterministic quote with 0.3% fee and slippage-adjusted minimum", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000000",
      chainId: 8453,
      slippageBps: 50,
    });

    expect(quote.provider).toBe("mock");
    expect(quote.amountIn).toBe("1000000");
    // fee = 1_000_000 * 30 / 10_000 = 3_000; out = 997_000
    expect(quote.feeAmount).toBe("3000");
    expect(quote.amountOut).toBe("997000");
    // minOut = 997_000 * (10_000-50)/10_000 = 992_015
    expect(quote.minAmountOut).toBe("992015");
    expect(quote.slippageBps).toBe(50);
    expect(quote.expiresAt).toBe(1_000 + 60_000);
    expect(quote.route).toHaveLength(1);
  });

  test("is deterministic across calls (same inputs -> same quoteId/output)", async () => {
    const swap = new MockSwapAdapter(fixedClock(42));
    const a = await swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "500", chainId: 8453 });
    const b = await swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "500", chainId: 8453 });
    expect(a.quoteId).toBe(b.quoteId);
    expect(a.amountOut).toBe(b.amountOut);
  });

  test("rejects zero amount (assertUint256 default disallows zero)", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "0", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects negative amount", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "-5", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects non-integer / non-numeric amount", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "1.5", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects identical from/to token", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: USDC, amount: "100", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects slippage above 10000 bps", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({
        fromToken: USDC,
        toToken: WETH,
        amount: "100",
        chainId: 8453,
        slippageBps: 10_001,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects invalid chainId", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "100", chainId: 0 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

describe("MockSwapAdapter.buildSwap", () => {
  test("produces an UNSIGNED intent for a fresh quote", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    const intent = await swap.buildSwap(quote, "0x1111111111111111111111111111111111111111");

    expect(intent.signed).toBe(false);
    expect(intent.kind).toBe("evm-tx");
    expect(intent.category).toBe("swap");
    expect(intent.owner).toBe("0x1111111111111111111111111111111111111111");
    // No signature-bearing fields.
    expect((intent as Record<string, unknown>).signature).toBeUndefined();
    expect((intent as Record<string, unknown>).rawTransaction).toBeUndefined();
  });

  test("rejects an expired quote", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    // Advance the clock past expiry by building with a later-now adapter.
    const later = new MockSwapAdapter(fixedClock(quote.expiresAt + 1));
    await expect(
      later.buildSwap(quote, "0x1111111111111111111111111111111111111111"),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects a malformed agent address", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    await expect(swap.buildSwap(quote, "not-an-address")).rejects.toBeInstanceOf(
      AdapterValidationError,
    );
  });
});
