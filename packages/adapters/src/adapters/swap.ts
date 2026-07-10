/**
 * SwapAdapter — DEX-aggregation seam.
 *
 * `getQuote` returns a price quote; `buildSwap` turns a quote into an
 * {@link UnsignedTxIntent} that the existing signing+policy path consumes.
 * Adapters NEVER sign and NEVER broadcast.
 */

import {
  AdapterUnavailableError,
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
  /** EVM address bound as taker/owner for providers that require it. */
  taker?: string;
  /** Max slippage in basis points (0-10000). Defaults to 50 (0.5%). */
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
   * existing vault/policy path. MUST NOT sign or broadcast.
   */
  buildSwap(quote: SwapQuote, agentAddress: string): Promise<UnsignedTxIntent>;
}

export interface ZeroExChainConfig {
  /** 0x AllowanceHolder spender for this chain. Never the Settler. */
  allowanceTarget: string;
  /** Explicit allowlist of transaction.to targets returned by 0x quotes. */
  transactionTargets: readonly string[];
}

export interface ZeroExAffiliateFeeConfig {
  recipient: string;
  bps: number;
  /** Must resolve to either the buy token or sell token. Defaults to buy. */
  token?: "buy" | "sell" | string;
}

export interface ZeroExSwapAdapterOptions {
  apiKey: string;
  supportedChains: Readonly<Record<number, ZeroExChainConfig>>;
  baseUrl?: string;
  timeoutMs?: number;
  quoteTtlMs?: number;
  now?: () => number;
  fetch?: typeof fetch;
  affiliateFee?: ZeroExAffiliateFeeConfig;
}

const MOCK_QUOTE_TTL_MS = 60_000;
const MOCK_FEE_BPS = 30n;
const ZEROEX_PROVIDER = "zeroex";
const ZEROEX_DEFAULT_BASE_URL = "https://api.0x.org";
const ZEROEX_DEFAULT_TIMEOUT_MS = 3_000;
const ZEROEX_DEFAULT_QUOTE_TTL_MS = 30_000;
const HEX_DATA_RE = /^0x(?:[a-fA-F0-9]{2})+$/;

type ZeroExResponse = Record<string, unknown>;
type NormalizedZeroExChainConfig = {
  allowanceTarget: string;
  transactionTargets: ReadonlySet<string>;
};
type ZeroExRequestParams = {
  chainId: number;
  sellToken: string;
  buyToken: string;
  sellAmount: string;
  taker: string;
  slippageBps: number;
};
type ZeroExQuote = SwapQuote & {
  readonly zeroEx: {
    readonly taker: string;
    readonly allowanceTarget: string;
    readonly request: ZeroExRequestParams;
  };
};

function normalizeAddress(value: string): string {
  return value.toLowerCase();
}

function assertDifferentTokens(fromToken: TokenRef, toToken: TokenRef): void {
  if (!fromToken?.address || !toToken?.address) {
    throw new AdapterValidationError("fromToken and toToken addresses are required");
  }
  if (normalizeAddress(fromToken.address) === normalizeAddress(toToken.address)) {
    throw new AdapterValidationError("fromToken and toToken must differ");
  }
}

function assertHexData(value: unknown, field: string): string {
  if (typeof value !== "string" || !HEX_DATA_RE.test(value)) {
    throw new AdapterValidationError(`${field} must be non-empty 0x hex calldata`);
  }
  return value;
}

function responseObject(value: unknown): ZeroExResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AdapterValidationError("0x response must be an object");
  }
  return value as ZeroExResponse;
}

function responseString(response: ZeroExResponse, field: string): string {
  const value = response[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new AdapterValidationError(`0x response ${field} is required`);
  }
  return value;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`)
    .join(",")}}`;
}

function quoteIdFrom(value: unknown): string {
  let hash = 0xcbf29ce484222325n;
  for (const char of stableStringify(value)) {
    hash ^= BigInt(char.charCodeAt(0));
    hash = (hash * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return `zeroex-v2:${hash.toString(16).padStart(16, "0")}`;
}

function feeTokenAddress(
  fee: ZeroExAffiliateFeeConfig,
  sellToken: string,
  buyToken: string,
): string {
  const token = fee.token ?? "buy";
  if (token === "buy") return buyToken;
  if (token === "sell") return sellToken;
  const address = normalizeAddress(assertEvmAddress(token, "swapFeeToken"));
  if (address !== sellToken && address !== buyToken) {
    throw new AdapterValidationError("swapFeeToken must be the buy token or sell token");
  }
  return address;
}

export class MockSwapAdapter implements SwapAdapter {
  readonly category = "swap" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async getQuote(request: SwapQuoteRequest): Promise<SwapQuote> {
    const chainId = assertChainId(request.chainId);
    const amountIn = assertUint256(request.amount, "amount");
    const slippageBps = assertSlippageBps(request.slippageBps);
    assertDifferentTokens(request.fromToken, request.toToken);

    const amount = BigInt(amountIn);
    const feeAmount = (amount * MOCK_FEE_BPS) / 10_000n;
    const amountOut = amount - feeAmount;
    const minAmountOut = (amountOut * BigInt(10_000 - slippageBps)) / 10_000n;

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
      expiresAt: this.now() + MOCK_QUOTE_TTL_MS,
      quoteId: `mock-swap-${chainId}-${amountIn}-${slippageBps}`,
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
    assertUint256(quote.amountIn, "quote.amountIn");
    assertUint256(quote.minAmountOut, "quote.minAmountOut", true);
    const to = assertEvmAddress(quote.toToken.address, "quote.toToken.address");

    return {
      signed: false,
      kind: "evm-tx",
      chainId: quote.chainId,
      to,
      value: "0",
      data: "0x",
      owner,
      category: "swap",
      provider: this.provider,
      metadata: {
        quoteId: quote.quoteId,
        amountIn: quote.amountIn,
        minAmountOut: quote.minAmountOut,
        slippageBps: quote.slippageBps,
      },
    };
  }
}

export class ZeroExSwapAdapter implements SwapAdapter {
  readonly category = "swap" as const;
  readonly provider = ZEROEX_PROVIDER;
  readonly enabled = true;

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly quoteTtlMs: number;
  private readonly now: () => number;
  private readonly fetchImpl: typeof fetch;
  private readonly supportedChains: ReadonlyMap<number, NormalizedZeroExChainConfig>;
  private readonly affiliateFee?: ZeroExAffiliateFeeConfig;

  constructor(options: ZeroExSwapAdapterOptions) {
    const apiKey = options.apiKey.trim();
    if (!apiKey) throw new AdapterValidationError("0x api key is required");
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? ZEROEX_DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? ZEROEX_DEFAULT_TIMEOUT_MS;
    this.quoteTtlMs = options.quoteTtlMs ?? ZEROEX_DEFAULT_QUOTE_TTL_MS;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs <= 0 || this.timeoutMs > 10_000) {
      throw new AdapterValidationError("0x timeoutMs must be an integer between 1 and 10000");
    }
    if (!Number.isInteger(this.quoteTtlMs) || this.quoteTtlMs <= 0 || this.quoteTtlMs > 120_000) {
      throw new AdapterValidationError("0x quoteTtlMs must be an integer between 1 and 120000");
    }
    this.now = options.now ?? (() => Date.now());
    this.fetchImpl = options.fetch ?? fetch;
    this.affiliateFee = options.affiliateFee;
    this.supportedChains = this.normalizeSupportedChains(options.supportedChains);
  }

  async getQuote(request: SwapQuoteRequest): Promise<SwapQuote> {
    const params = this.normalizeRequest(request);
    const response = await this.fetchAllowanceHolder("price", params);
    return this.parsePriceResponse(response, params);
  }

  async buildSwap(quote: SwapQuote, agentAddress: string): Promise<UnsignedTxIntent> {
    const zeroExQuote = this.assertZeroExQuote(quote);
    const owner = normalizeAddress(assertEvmAddress(agentAddress, "agentAddress"));
    if (owner !== zeroExQuote.zeroEx.taker) {
      throw new AdapterValidationError("agentAddress does not match quote taker");
    }
    if (quote.expiresAt <= this.now()) {
      throw new AdapterValidationError("quote has expired; request a fresh quote");
    }

    const response = await this.fetchAllowanceHolder("quote", zeroExQuote.zeroEx.request);
    const parsed = this.parseQuoteResponse(response, zeroExQuote);
    return {
      signed: false,
      kind: "evm-tx",
      chainId: quote.chainId,
      to: parsed.to,
      value: parsed.value,
      data: parsed.data,
      owner,
      category: "swap",
      provider: this.provider,
      metadata: {
        quoteId: quote.quoteId,
        amountIn: quote.amountIn,
        minAmountOut: quote.minAmountOut,
        slippageBps: quote.slippageBps,
        allowanceTarget: zeroExQuote.zeroEx.allowanceTarget,
      },
    };
  }

  private normalizeSupportedChains(
    supportedChains: Readonly<Record<number, ZeroExChainConfig>>,
  ): ReadonlyMap<number, NormalizedZeroExChainConfig> {
    const entries = Object.entries(supportedChains);
    if (entries.length === 0) {
      throw new AdapterValidationError("0x supportedChains must not be empty");
    }
    const normalized = new Map<number, NormalizedZeroExChainConfig>();
    for (const [rawChainId, rawConfig] of entries) {
      const chainId = assertChainId(Number(rawChainId));
      const allowanceTarget = normalizeAddress(
        assertEvmAddress(
          rawConfig.allowanceTarget,
          `supportedChains.${rawChainId}.allowanceTarget`,
        ),
      );
      const targets = rawConfig.transactionTargets.map((target) =>
        normalizeAddress(
          assertEvmAddress(target, `supportedChains.${rawChainId}.transactionTarget`),
        ),
      );
      if (targets.length === 0) {
        throw new AdapterValidationError(
          `supportedChains.${rawChainId}.transactionTargets must not be empty`,
        );
      }
      if (targets.includes(allowanceTarget)) {
        throw new AdapterValidationError("0x transaction target must not be the AllowanceHolder");
      }
      normalized.set(chainId, { allowanceTarget, transactionTargets: new Set(targets) });
    }
    return normalized;
  }

  private normalizeRequest(request: SwapQuoteRequest): ZeroExRequestParams {
    const chainId = assertChainId(request.chainId);
    if (!this.supportedChains.has(chainId)) {
      throw new AdapterValidationError(`0x does not support chainId ${chainId}`);
    }
    assertDifferentTokens(request.fromToken, request.toToken);
    const sellToken = normalizeAddress(
      assertEvmAddress(request.fromToken.address, "fromToken.address"),
    );
    const buyToken = normalizeAddress(assertEvmAddress(request.toToken.address, "toToken.address"));
    const taker = normalizeAddress(assertEvmAddress(request.taker, "taker"));
    return {
      chainId,
      sellToken,
      buyToken,
      sellAmount: assertUint256(request.amount, "amount"),
      taker,
      slippageBps: assertSlippageBps(request.slippageBps),
    };
  }

  private parsePriceResponse(response: ZeroExResponse, request: ZeroExRequestParams): ZeroExQuote {
    const chain = this.requireChain(request.chainId);
    this.validateSemanticEcho(response, request);
    const buyAmount = assertUint256(responseString(response, "buyAmount"), "buyAmount", true);
    const minBuyAmount =
      typeof response.minBuyAmount === "string"
        ? assertUint256(response.minBuyAmount, "minBuyAmount", true)
        : buyAmount;
    const allowanceTarget = this.validateOptionalAllowanceTarget(response, chain);
    const expiresAt = this.now() + this.quoteTtlMs;
    const quoteId = quoteIdFrom({
      provider: this.provider,
      request,
      buyAmount,
      minBuyAmount,
      allowanceTarget,
      expiresAt,
    });
    return {
      provider: this.provider,
      fromToken: { address: request.sellToken },
      toToken: { address: request.buyToken },
      chainId: request.chainId,
      amountIn: request.sellAmount,
      amountOut: buyAmount,
      minAmountOut: minBuyAmount,
      route: [{ venue: "0x-swap-api-v2", fromToken: request.sellToken, toToken: request.buyToken }],
      feeAmount: "0",
      slippageBps: request.slippageBps,
      expiresAt,
      quoteId,
      zeroEx: { taker: request.taker, allowanceTarget, request },
    };
  }

  private parseQuoteResponse(
    response: ZeroExResponse,
    quote: ZeroExQuote,
  ): { to: string; data: string; value: string } {
    const chain = this.requireChain(quote.chainId);
    this.validateSemanticEcho(response, quote.zeroEx.request);
    const buyAmount = assertUint256(responseString(response, "buyAmount"), "buyAmount", true);
    const minBuyAmount = assertUint256(
      responseString(response, "minBuyAmount"),
      "minBuyAmount",
      true,
    );
    const sellAmount = assertUint256(responseString(response, "sellAmount"), "sellAmount");
    if (
      buyAmount !== quote.amountOut ||
      minBuyAmount !== quote.minAmountOut ||
      sellAmount !== quote.amountIn
    ) {
      throw new AdapterValidationError("0x quote response is not bound to the price quote");
    }
    const allowanceTarget = this.validateOptionalAllowanceTarget(response, chain);
    if (allowanceTarget !== quote.zeroEx.allowanceTarget) {
      throw new AdapterValidationError("0x allowanceTarget is not bound to the price quote");
    }
    const transaction = responseObject(response.transaction);
    const to = normalizeAddress(assertEvmAddress(transaction.to, "transaction.to"));
    if (!chain.transactionTargets.has(to)) {
      throw new AdapterValidationError("0x transaction target is not allowlisted");
    }
    if (transaction.from !== undefined) {
      const from = normalizeAddress(assertEvmAddress(transaction.from, "transaction.from"));
      if (from !== quote.zeroEx.taker) {
        throw new AdapterValidationError("0x transaction.from is not bound to taker");
      }
    }
    const data = assertHexData(transaction.data, "transaction.data");
    const value = assertUint256(responseString(transaction, "value"), "transaction.value", true);
    return { to, data, value };
  }

  private validateSemanticEcho(response: ZeroExResponse, request: ZeroExRequestParams): void {
    this.assertOptionalEchoAddress(response, "sellToken", request.sellToken);
    this.assertOptionalEchoAddress(response, "buyToken", request.buyToken);
    this.assertOptionalEchoAmount(response, "sellAmount", request.sellAmount);
    if (response.chainId !== undefined && response.chainId !== request.chainId) {
      throw new AdapterValidationError("0x response chainId is not bound to the request");
    }
    if (response.taker !== undefined) {
      const taker = normalizeAddress(assertEvmAddress(response.taker, "taker"));
      if (taker !== request.taker) {
        throw new AdapterValidationError("0x response taker is not bound to the request");
      }
    }
  }

  private assertOptionalEchoAddress(
    response: ZeroExResponse,
    field: string,
    expected: string,
  ): void {
    const value = response[field];
    if (value !== undefined && normalizeAddress(assertEvmAddress(value, field)) !== expected) {
      throw new AdapterValidationError(`0x response ${field} is not bound to the request`);
    }
  }

  private assertOptionalEchoAmount(
    response: ZeroExResponse,
    field: string,
    expected: string,
  ): void {
    const value = response[field];
    if (value !== undefined && assertUint256(value, field) !== expected) {
      throw new AdapterValidationError(`0x response ${field} is not bound to the request`);
    }
  }

  private validateAllowanceTarget(
    response: ZeroExResponse,
    chain: NormalizedZeroExChainConfig,
    expected = chain.allowanceTarget,
  ): string {
    const allowanceTarget = normalizeAddress(
      assertEvmAddress(response.allowanceTarget, "allowanceTarget"),
    );
    if (allowanceTarget !== expected || allowanceTarget !== chain.allowanceTarget) {
      throw new AdapterValidationError("0x allowanceTarget is not configured for this chain");
    }
    const issues = response.issues;
    if (issues && typeof issues === "object" && !Array.isArray(issues)) {
      const allowance = (issues as Record<string, unknown>).allowance;
      if (allowance && typeof allowance === "object" && !Array.isArray(allowance)) {
        const spender = (allowance as Record<string, unknown>).spender;
        if (
          spender !== undefined &&
          normalizeAddress(assertEvmAddress(spender, "issues.allowance.spender")) !==
            chain.allowanceTarget
        ) {
          throw new AdapterValidationError("0x allowance spender is not the AllowanceHolder");
        }
      }
    }
    return allowanceTarget;
  }

  private validateOptionalAllowanceTarget(
    response: ZeroExResponse,
    chain: NormalizedZeroExChainConfig,
  ): string {
    if (response.allowanceTarget !== undefined) {
      return this.validateAllowanceTarget(response, chain);
    }
    this.validateAllowanceIssue(response, chain);
    return chain.allowanceTarget;
  }

  private validateAllowanceIssue(
    response: ZeroExResponse,
    chain: NormalizedZeroExChainConfig,
  ): void {
    const issues = response.issues;
    if (!issues || typeof issues !== "object" || Array.isArray(issues)) return;
    const allowance = (issues as Record<string, unknown>).allowance;
    if (!allowance || typeof allowance !== "object" || Array.isArray(allowance)) return;
    const spender = (allowance as Record<string, unknown>).spender;
    if (
      spender !== undefined &&
      normalizeAddress(assertEvmAddress(spender, "issues.allowance.spender")) !==
        chain.allowanceTarget
    ) {
      throw new AdapterValidationError("0x allowance spender is not the AllowanceHolder");
    }
  }

  private requireChain(chainId: number): NormalizedZeroExChainConfig {
    const chain = this.supportedChains.get(chainId);
    if (!chain) throw new AdapterValidationError(`0x does not support chainId ${chainId}`);
    return chain;
  }

  private assertZeroExQuote(quote: SwapQuote): ZeroExQuote {
    if (quote.provider !== this.provider) {
      throw new AdapterValidationError("quote provider is not zeroex");
    }
    const maybe = quote as Partial<ZeroExQuote>;
    if (!maybe.zeroEx?.request || !maybe.zeroEx.taker || !maybe.zeroEx.allowanceTarget) {
      throw new AdapterValidationError("quote is missing zeroex binding metadata");
    }
    const zeroExQuote = quote as ZeroExQuote;
    const request = zeroExQuote.zeroEx.request;
    const chain = this.requireChain(assertChainId(quote.chainId));
    const fromToken = normalizeAddress(
      assertEvmAddress(quote.fromToken.address, "quote.fromToken"),
    );
    const toToken = normalizeAddress(assertEvmAddress(quote.toToken.address, "quote.toToken"));
    const amountIn = assertUint256(quote.amountIn, "quote.amountIn");
    assertUint256(quote.amountOut, "quote.amountOut", true);
    assertUint256(quote.minAmountOut, "quote.minAmountOut", true);
    const slippageBps = assertSlippageBps(quote.slippageBps);
    const taker = normalizeAddress(assertEvmAddress(zeroExQuote.zeroEx.taker, "zeroEx.taker"));
    const allowanceTarget = normalizeAddress(
      assertEvmAddress(zeroExQuote.zeroEx.allowanceTarget, "zeroEx.allowanceTarget"),
    );
    if (
      request.chainId !== quote.chainId ||
      request.sellToken !== fromToken ||
      request.buyToken !== toToken ||
      request.sellAmount !== amountIn ||
      request.slippageBps !== slippageBps ||
      request.taker !== taker ||
      allowanceTarget !== chain.allowanceTarget
    ) {
      throw new AdapterValidationError("quote zeroex metadata is not bound to the quote");
    }
    if (!Number.isSafeInteger(quote.expiresAt)) {
      throw new AdapterValidationError("quote.expiresAt must be an integer timestamp");
    }
    return zeroExQuote;
  }

  private async fetchAllowanceHolder(
    endpoint: "price" | "quote",
    request: ZeroExRequestParams,
  ): Promise<ZeroExResponse> {
    const url = new URL(`/swap/allowance-holder/${endpoint}`, this.baseUrl);
    url.searchParams.set("chainId", String(request.chainId));
    url.searchParams.set("sellToken", request.sellToken);
    url.searchParams.set("buyToken", request.buyToken);
    url.searchParams.set("sellAmount", request.sellAmount);
    url.searchParams.set("taker", request.taker);
    url.searchParams.set("slippageBps", String(request.slippageBps));
    if (this.affiliateFee) {
      if (this.affiliateFee.bps < 0 || this.affiliateFee.bps > 1_000) {
        throw new AdapterValidationError("swapFeeBps must be between 0 and 1000");
      }
      const recipient = normalizeAddress(
        assertEvmAddress(this.affiliateFee.recipient, "swapFeeRecipient"),
      );
      url.searchParams.set("swapFeeRecipient", recipient);
      url.searchParams.set("swapFeeBps", String(this.affiliateFee.bps));
      url.searchParams.set(
        "swapFeeToken",
        feeTokenAddress(this.affiliateFee, request.sellToken, request.buyToken),
      );
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        headers: { "0x-api-key": this.apiKey, "0x-version": "v2" },
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new AdapterUnavailableError("swap", `0x ${endpoint} failed with HTTP ${res.status}`);
      }
      return responseObject(await res.json());
    } catch (error) {
      if (error instanceof AdapterUnavailableError || error instanceof AdapterValidationError) {
        throw error;
      }
      const isAbort =
        error instanceof Error && (error.name === "AbortError" || error.message.includes("abort"));
      throw new AdapterUnavailableError(
        "swap",
        isAbort ? `0x ${endpoint} timed out` : `0x ${endpoint} request failed`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }
}
