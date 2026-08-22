/**
 * SwapAdapter — DEX-aggregation seam.
 *
 * `getQuote` returns a price quote; `buildSwap` turns a quote into an
 * {@link UnsignedTxIntent} that the existing signing+policy path consumes. The
 * mock NEVER signs and NEVER broadcasts.
 */

import {
  AdapterValidationError,
  type BaseAdapter,
  type TokenRef,
  type UnsignedTxIntent,
} from "../types.js";
import {
  assertChainId,
  assertEvmAddress,
  assertSlippageBps,
  assertUint256,
} from "../validation.js";

export interface SwapQuoteRequest {
  fromToken: TokenRef;
  toToken: TokenRef;
  /** Input amount in base units (wei) of `fromToken`. */
  amount: string;
  chainId: number;
  /** Max slippage in basis points (0–10000). Defaults to 50 (0.5%). */
  slippageBps?: number;
}

export interface SwapQuote {
  readonly provider: string;
  readonly fromToken: TokenRef;
  readonly toToken: TokenRef;
  readonly chainId: number;
  readonly amountIn: string;
  /** Expected output in base units of `toToken`. */
  readonly amountOut: string;
  /** Minimum output after slippage tolerance (base units of `toToken`). */
  readonly minAmountOut: string;
  /** Opaque route description (hops/venues). Non-secret. */
  readonly route: ReadonlyArray<{ venue: string; fromToken: string; toToken: string }>;
  /** Protocol fee in base units of `fromToken`. */
  readonly feeAmount: string;
  readonly slippageBps: number;
  /** Epoch ms after which the quote is no longer valid. */
  readonly expiresAt: number;
  /** Opaque quote id (used to bind buildSwap to this quote). */
  readonly quoteId: string;
}

export interface SwapAdapter extends BaseAdapter {
  readonly category: "swap";
  getQuote(request: SwapQuoteRequest): Promise<SwapQuote>;
  /**
   * Produce an unsigned swap transaction for `agentAddress` to sign via the
   * existing vault/policy path. MUST NOT sign or broadcast. The returned
   * intent MUST bind its validated input amount, chain, and source-token
   * address in metadata so policy code never has to trust the echoed quote.
   */
  buildSwap(quote: SwapQuote, agentAddress: string): Promise<UnsignedTxIntent>;
}

const MOCK_QUOTE_TTL_MS = 60_000;
const MAX_MOCK_QUOTE_RECEIPTS = 4_096;
// Deterministic mock pricing: 0.3% fee, 1:1 nominal rate. No external calls.
const MOCK_FEE_BPS = 30n;

function mockQuoteId(
  chainId: number,
  amountIn: string,
  slippageBps: number,
  fromToken: string,
  toToken: string,
  expiresAt: number,
): string {
  return `mock-swap-${chainId}-${amountIn}-${slippageBps}-${fromToken.toLowerCase()}-${toToken.toLowerCase()}-${expiresAt}`;
}

export class MockSwapAdapter implements SwapAdapter {
  readonly category = "swap" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private now: () => number;
  private readonly issuedQuotes = new Map<string, number>();

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async getQuote(request: SwapQuoteRequest): Promise<SwapQuote> {
    const chainId = assertChainId(request.chainId);
    const amountIn = assertUint256(request.amount, "amount");
    const slippageBps = assertSlippageBps(request.slippageBps);
    const fromTokenAddress = assertEvmAddress(request.fromToken?.address, "fromToken.address");
    const toTokenAddress = assertEvmAddress(request.toToken?.address, "toToken.address");
    if (fromTokenAddress.toLowerCase() === toTokenAddress.toLowerCase()) {
      throw new AdapterValidationError("fromToken and toToken must differ");
    }

    const amount = BigInt(amountIn);
    const feeAmount = (amount * MOCK_FEE_BPS) / 10_000n;
    const amountOut = amount - feeAmount; // deterministic 1:1 minus fee
    const minAmountOut = (amountOut * BigInt(10_000 - slippageBps)) / 10_000n;

    const now = this.now();
    const expiresAt = now + MOCK_QUOTE_TTL_MS;
    const quoteId = mockQuoteId(
      chainId,
      amountIn,
      slippageBps,
      fromTokenAddress,
      toTokenAddress,
      expiresAt,
    );
    for (const [issuedId, issuedExpiry] of this.issuedQuotes) {
      if (issuedExpiry <= now) this.issuedQuotes.delete(issuedId);
    }
    if (!this.issuedQuotes.has(quoteId) && this.issuedQuotes.size >= MAX_MOCK_QUOTE_RECEIPTS) {
      throw new AdapterValidationError("mock quote receipt capacity reached; retry later");
    }
    this.issuedQuotes.set(quoteId, expiresAt);
    return {
      provider: this.provider,
      fromToken: request.fromToken,
      toToken: request.toToken,
      chainId,
      amountIn,
      amountOut: amountOut.toString(),
      minAmountOut: minAmountOut.toString(),
      route: [
        {
          venue: "mock-dex",
          fromToken: request.fromToken.address,
          toToken: request.toToken.address,
        },
      ],
      feeAmount: feeAmount.toString(),
      slippageBps,
      expiresAt,
      quoteId,
    };
  }

  async buildSwap(quote: SwapQuote, agentAddress: string): Promise<UnsignedTxIntent> {
    const owner = assertEvmAddress(agentAddress, "agentAddress");
    if (!quote || typeof quote.expiresAt !== "number") {
      throw new AdapterValidationError("a valid quote is required");
    }
    if (quote.expiresAt <= this.now()) {
      throw new AdapterValidationError("quote has expired; request a fresh quote");
    }
    // Re-validate quote internals and their immutable receipt binding. The
    // caller round-trips this object and may mutate any field before build.
    const chainId = assertChainId(quote.chainId);
    const amountIn = assertUint256(quote.amountIn, "quote.amountIn");
    assertUint256(quote.minAmountOut, "quote.minAmountOut", true);
    const slippageBps = assertSlippageBps(quote.slippageBps);
    const fromTokenAddress = assertEvmAddress(quote.fromToken?.address, "quote.fromToken.address");
    const to = assertEvmAddress(quote.toToken.address, "quote.toToken.address");
    if (
      quote.provider !== this.provider ||
      this.issuedQuotes.get(quote.quoteId) !== quote.expiresAt ||
      quote.quoteId !==
        mockQuoteId(chainId, amountIn, slippageBps, fromTokenAddress, to, quote.expiresAt)
    ) {
      throw new AdapterValidationError("quote binding is invalid; request a fresh quote");
    }

    // The mock targets the toToken contract as a stand-in router. A real adapter
    // would encode the aggregator's calldata. Crucially: this is UNSIGNED.
    return {
      signed: false,
      kind: "evm-tx",
      chainId,
      to,
      value: "0",
      data: "0x",
      owner,
      category: "swap",
      provider: this.provider,
      metadata: {
        quoteId: quote.quoteId,
        amountIn,
        sourceChainId: chainId,
        sourceTokenAddress: fromTokenAddress,
        minAmountOut: quote.minAmountOut,
        slippageBps: quote.slippageBps,
      },
    };
  }
}
