/**
 * Transaction builder.
 *
 * Produces a raw transaction object (to / value / data / chainId) that can be
 * handed directly to StewardClient.signTransaction().
 *
 * Two build paths:
 *   1. buildNativeTransfer  — simple ETH/BNB send
 *   2. buildSwapTx          — DEX swap using a Uniswap V2-compatible portal
 *
 * The portal ABI targets a single `swapExactInput` entry point.  Waifu.fun
 * portals are expected to implement the same interface.
 */

import type { SignTransactionInput } from "@stwd/sdk";
import { encodeFunctionData } from "viem";

// ─── Portal ABI ───────────────────────────────────────────────────────────────

/**
 * Simplified portal ABI.  The portal receives ETH (via msg.value) for buys and
 * token allowance for sells, then routes through the underlying DEX.
 *
 * function swapExactInput(
 *   address tokenIn,
 *   address tokenOut,
 *   uint256 amountIn,
 *   uint256 amountOutMin,
 *   address recipient
 * ) external payable returns (uint256 amountOut)
 */
export const PORTAL_ABI = [
  {
    name: "swapExactInput",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "tokenIn", type: "address" },
      { name: "tokenOut", type: "address" },
      { name: "amountIn", type: "uint256" },
      { name: "amountOutMin", type: "uint256" },
      { name: "recipient", type: "address" },
    ],
    outputs: [{ name: "amountOut", type: "uint256" }],
  },
] as const;

// Sentinel used when the input currency is native (ETH/BNB)
export const NATIVE_TOKEN_ADDRESS = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE" as const;

/**
 * Hard upper bound on the slippage a caller may request, in basis points.
 * 50% (5000 bps) is already absurdly loose for any honest trade; anything at
 * or above this is treated as a misconfiguration and refused. This is a sanity
 * clamp, NOT a substitute for a tight per-strategy slippage setting.
 */
export const MAX_SLIPPAGE_BPS = 5_000;

const BPS_DENOMINATOR = 10_000n;

/**
 * Thrown when a swap cannot be built with a safe, enforceable minimum-output
 * bound. The trade builder fails CLOSED: callers must NOT fall back to an
 * unprotected (amountOutMin = 0) swap when this is raised — they must skip the
 * trade. Submitting a swap with no slippage floor exposes the full trade value
 * to sandwich/MEV extraction.
 */
export class UnsafeSwapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeSwapError";
  }
}

/**
 * Compute the expected output amount (in output-token wei) for a swap, given
 * the current token price expressed as native-wei per single token-unit
 * (the same convention as {@link AgentState.tokenPrice}).
 *
 *   buy  (native → token):  expectedOut[token]  = amountIn[native] * 1e18 / price
 *   sell (token  → native): expectedOut[native] = amountIn[token]  * price / 1e18
 *
 * Returns null when no usable quote can be derived (non-positive price or
 * amount). Callers MUST treat null as "no quote available" and refuse to build
 * the swap rather than defaulting to an unprotected one.
 */
export function computeExpectedOut(
  side: "buy" | "sell",
  amountIn: bigint,
  tokenPriceNativePerToken: bigint,
): bigint | null {
  if (amountIn <= 0n || tokenPriceNativePerToken <= 0n) return null;

  const ONE = 10n ** 18n;
  const expectedOut =
    side === "buy"
      ? (amountIn * ONE) / tokenPriceNativePerToken
      : (amountIn * tokenPriceNativePerToken) / ONE;

  return expectedOut > 0n ? expectedOut : null;
}

/**
 * Derive a slippage-protected `amountOutMin` from an expected-output quote.
 *
 *   amountOutMin = expectedOut * (10_000 - slippageBps) / 10_000
 *
 * Fails CLOSED via {@link UnsafeSwapError} when the inputs cannot produce a
 * meaningful floor: missing/non-positive quote, out-of-range slippage, or a
 * computed floor of zero (which would be indistinguishable from "accept any
 * output"). NEVER returns 0n.
 */
export function computeAmountOutMin(expectedOut: bigint | null, slippageBps: number): bigint {
  if (!Number.isInteger(slippageBps) || slippageBps < 0 || slippageBps >= MAX_SLIPPAGE_BPS) {
    throw new UnsafeSwapError(
      `Refusing to build swap: slippageBps must be an integer in [0, ${MAX_SLIPPAGE_BPS}) — got ${slippageBps}`,
    );
  }

  if (expectedOut === null || expectedOut <= 0n) {
    throw new UnsafeSwapError(
      "Refusing to build swap: no reliable output quote available — cannot compute a safe amountOutMin (would otherwise leave the swap fully exposed to MEV/sandwich extraction).",
    );
  }

  const amountOutMin = (expectedOut * (BPS_DENOMINATOR - BigInt(slippageBps))) / BPS_DENOMINATOR;

  if (amountOutMin <= 0n) {
    throw new UnsafeSwapError(
      `Refusing to build swap: computed amountOutMin floored to zero (expectedOut=${expectedOut.toString()}, slippageBps=${slippageBps}); an unprotected swap will not be submitted.`,
    );
  }

  return amountOutMin;
}

// ─── Built transaction type ────────────────────────────────────────────────────

export interface BuiltTx {
  to: string;
  /** Native value attached (wei) */
  value: string;
  /** Hex-encoded calldata, or "0x" for pure transfers */
  data: string;
  chainId: number;
}

// ─── Builders ─────────────────────────────────────────────────────────────────

export function buildNativeTransfer(to: string, amountWei: string, chainId: number): BuiltTx {
  return {
    to,
    value: amountWei,
    data: "0x",
    chainId,
  };
}

/**
 * Build a swap transaction through a Uniswap V2-compatible portal.
 *
 * @param side          "buy"  → spend native, receive token
 *                      "sell" → spend token, receive native
 * @param tokenAddress  ERC-20 address of the agent token
 * @param amount        For buy: native wei to spend.
 *                      For sell: token-unit amount to sell.
 * @param portalAddress DEX portal / router address
 * @param recipient     Address to receive the output tokens (usually the agent wallet)
 * @param chainId       Chain to submit on
 * @param expectedOut   Expected output amount in output-token wei, from a price
 *                      quote/oracle (see {@link computeExpectedOut}). REQUIRED:
 *                      pass `null` only to force a fail-closed refusal. There is
 *                      no unprotected (amountOutMin = 0) path.
 * @param slippageBps   Acceptable slippage in basis points (default 100 = 1%)
 *
 * @throws {UnsafeSwapError} when a safe `amountOutMin` cannot be computed
 *   (no quote, out-of-range slippage, or a floor that rounds to zero). The
 *   caller MUST skip the trade — it must NOT retry with a looser bound.
 */
export function buildSwapTx(
  side: "buy" | "sell",
  tokenAddress: string,
  amount: string,
  portalAddress: string,
  recipient: string,
  chainId: number,
  expectedOut: bigint | null,
  slippageBps = 100,
): BuiltTx {
  const amountBig = BigInt(amount);

  if (amountBig <= 0n) {
    throw new UnsafeSwapError(`Refusing to build swap: amountIn must be positive — got ${amount}`);
  }

  // Derive a real, enforceable minimum-output floor from the quote. This THROWS
  // (fail-closed) rather than ever emitting amountOutMin = 0, so a swap with no
  // slippage protection can never be signed.
  const amountOutMin = computeAmountOutMin(expectedOut, slippageBps);

  let tokenIn: string;
  let tokenOut: string;
  let nativeValue: string;

  if (side === "buy") {
    // Native → token
    tokenIn = NATIVE_TOKEN_ADDRESS;
    tokenOut = tokenAddress;
    nativeValue = amount; // attach ETH as msg.value
  } else {
    // Token → native
    tokenIn = tokenAddress;
    tokenOut = NATIVE_TOKEN_ADDRESS;
    nativeValue = "0"; // no native attached; portal pulls token via transferFrom
  }

  const data = encodeFunctionData({
    abi: PORTAL_ABI,
    functionName: "swapExactInput",
    args: [
      tokenIn as `0x${string}`,
      tokenOut as `0x${string}`,
      amountBig,
      amountOutMin,
      recipient as `0x${string}`,
    ],
  });

  return {
    to: portalAddress,
    value: nativeValue,
    data,
    chainId,
  };
}

/**
 * Convenience: produce a SignTransactionInput from a BuiltTx.
 */
export function toSignInput(tx: BuiltTx): SignTransactionInput {
  return {
    to: tx.to,
    value: tx.value,
    data: tx.data !== "0x" ? tx.data : undefined,
    chainId: tx.chainId,
  };
}
