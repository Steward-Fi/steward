import { describe, expect, it } from "bun:test";
import { decodeFunctionData } from "viem";
import {
  buildSwapTx,
  computeAmountOutMin,
  computeExpectedOut,
  MAX_SLIPPAGE_BPS,
  NATIVE_TOKEN_ADDRESS,
  PORTAL_ABI,
  UnsafeSwapError,
} from "../trade-builder";

const TOKEN = "0x1111111111111111111111111111111111111111";
const PORTAL = "0x2222222222222222222222222222222222222222";
const RECIPIENT = "0x3333333333333333333333333333333333333333";
const CHAIN = 8453;

/** Pull the decoded swapExactInput args out of built calldata. */
function decodeSwap(data: string) {
  const { args } = decodeFunctionData({ abi: PORTAL_ABI, data: data as `0x${string}` });
  const [tokenIn, tokenOut, amountIn, amountOutMin, recipient] = args as readonly [
    string,
    string,
    bigint,
    bigint,
    string,
  ];
  return { tokenIn, tokenOut, amountIn, amountOutMin, recipient };
}

describe("computeExpectedOut", () => {
  it("buy: native-in → expected token-out = amountIn * 1e18 / price", () => {
    // price = 1e15 native-wei per token (1 token = 0.001 native)
    // spend 1e18 native → expect 1e18 * 1e18 / 1e15 = 1e21 token-wei
    const out = computeExpectedOut("buy", 10n ** 18n, 10n ** 15n);
    expect(out).toBe(10n ** 21n);
  });

  it("sell: token-in → expected native-out = amountIn * price / 1e18", () => {
    // sell 1e21 token-wei at price 1e15 → 1e21 * 1e15 / 1e18 = 1e18 native-wei
    const out = computeExpectedOut("sell", 10n ** 21n, 10n ** 15n);
    expect(out).toBe(10n ** 18n);
  });

  it("returns null for a non-positive price (no usable quote)", () => {
    expect(computeExpectedOut("buy", 10n ** 18n, 0n)).toBeNull();
  });

  it("returns null for a non-positive amount", () => {
    expect(computeExpectedOut("buy", 0n, 10n ** 15n)).toBeNull();
  });
});

describe("computeAmountOutMin", () => {
  it("applies slippageBps: out = expectedOut * (10000 - bps) / 10000", () => {
    // 100 bps = 1% off 1e21 → 0.99e21
    expect(computeAmountOutMin(10n ** 21n, 100)).toBe((10n ** 21n * 9900n) / 10000n);
    // 50 bps = 0.5%
    expect(computeAmountOutMin(10n ** 21n, 50)).toBe((10n ** 21n * 9950n) / 10000n);
  });

  it("0 bps yields the full expected output (still a real, non-zero floor)", () => {
    expect(computeAmountOutMin(10n ** 21n, 0)).toBe(10n ** 21n);
  });

  it("THROWS (fail-closed) when there is no quote — never returns 0", () => {
    expect(() => computeAmountOutMin(null, 100)).toThrow(UnsafeSwapError);
    expect(() => computeAmountOutMin(0n, 100)).toThrow(UnsafeSwapError);
  });

  it("THROWS for out-of-range slippage (negative, >=MAX, non-integer)", () => {
    expect(() => computeAmountOutMin(10n ** 21n, -1)).toThrow(UnsafeSwapError);
    expect(() => computeAmountOutMin(10n ** 21n, MAX_SLIPPAGE_BPS)).toThrow(UnsafeSwapError);
    expect(() => computeAmountOutMin(10n ** 21n, 1.5)).toThrow(UnsafeSwapError);
  });

  it("THROWS when the computed floor rounds to zero (would be 'accept any output')", () => {
    // expectedOut = 1 token-wei, 1 bps off → floor(1 * 9999 / 10000) = 0 → refuse
    expect(() => computeAmountOutMin(1n, 1)).toThrow(UnsafeSwapError);
  });
});

describe("buildSwapTx — slippage protection (HIGH fix)", () => {
  it("(a) encodes a NON-ZERO amountOutMin derived from slippageBps for a normal quote", () => {
    const amountIn = 10n ** 18n; // 1 native
    const price = 10n ** 15n; // 1 token = 0.001 native
    const expectedOut = computeExpectedOut("buy", amountIn, price);
    expect(expectedOut).not.toBeNull();

    const tx = buildSwapTx(
      "buy",
      TOKEN,
      amountIn.toString(),
      PORTAL,
      RECIPIENT,
      CHAIN,
      expectedOut,
      100, // 1%
    );

    const decoded = decodeSwap(tx.data);
    expect(decoded.amountOutMin).toBeGreaterThan(0n);
    expect(decoded.amountOutMin).toBe((expectedOut! * 9900n) / 10000n);
    // buy: native in attached as msg.value, tokenIn is the native sentinel
    expect(decoded.tokenIn.toLowerCase()).toBe(NATIVE_TOKEN_ADDRESS.toLowerCase());
    expect(decoded.tokenOut.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(tx.value).toBe(amountIn.toString());
    expect(tx.to).toBe(PORTAL);
  });

  it("(b) THROWS (refuses to build) when no quote is available — no unprotected swap", () => {
    expect(() =>
      buildSwapTx("buy", TOKEN, (10n ** 18n).toString(), PORTAL, RECIPIENT, CHAIN, null, 100),
    ).toThrow(UnsafeSwapError);
  });

  it("sell path encodes native sentinel as tokenOut with a non-zero floor", () => {
    const amountIn = 10n ** 21n; // token-wei
    const price = 10n ** 15n;
    const expectedOut = computeExpectedOut("sell", amountIn, price);

    const tx = buildSwapTx(
      "sell",
      TOKEN,
      amountIn.toString(),
      PORTAL,
      RECIPIENT,
      CHAIN,
      expectedOut,
      250,
    );

    const decoded = decodeSwap(tx.data);
    expect(decoded.tokenIn.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(decoded.tokenOut.toLowerCase()).toBe(NATIVE_TOKEN_ADDRESS.toLowerCase());
    expect(decoded.amountOutMin).toBe((expectedOut! * 9750n) / 10000n);
    expect(decoded.amountOutMin).toBeGreaterThan(0n);
    expect(tx.value).toBe("0"); // no native attached on sell
  });

  it("refuses out-of-range slippage even with a valid quote", () => {
    const expectedOut = computeExpectedOut("buy", 10n ** 18n, 10n ** 15n);
    expect(() =>
      buildSwapTx(
        "buy",
        TOKEN,
        (10n ** 18n).toString(),
        PORTAL,
        RECIPIENT,
        CHAIN,
        expectedOut,
        MAX_SLIPPAGE_BPS + 1,
      ),
    ).toThrow(UnsafeSwapError);
  });

  it("refuses a non-positive amountIn", () => {
    expect(() => buildSwapTx("buy", TOKEN, "0", PORTAL, RECIPIENT, CHAIN, 10n ** 21n, 100)).toThrow(
      UnsafeSwapError,
    );
  });
});
