/**
 * BridgeAdapter — cross-chain transfer seam.
 *
 * Bridge providers are high-risk money-path dependencies. The mock deliberately
 * models quote/session metadata only and never signs, broadcasts, custody-swaps,
 * or claims settlement. Execution is represented as an unsigned intent routed
 * through the existing policy/signing path.
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
  assertId,
  assertSlippageBps,
  assertUint256,
} from "../validation.js";

export interface BridgeQuoteRequest {
  fromChainId: number;
  toChainId: number;
  fromToken: TokenRef;
  toToken: TokenRef;
  amount: string;
  recipient: string;
  slippageBps?: number;
}

export interface BridgeQuote {
  readonly provider: string;
  readonly quoteId: string;
  readonly fromChainId: number;
  readonly toChainId: number;
  readonly fromToken: TokenRef;
  readonly toToken: TokenRef;
  readonly amountIn: string;
  readonly amountOut: string;
  readonly minAmountOut: string;
  readonly feeAmount: string;
  readonly recipient: string;
  readonly route: ReadonlyArray<{ bridge: string; fromChainId: number; toChainId: number }>;
  readonly slippageBps: number;
  readonly expiresAt: number;
}

export interface BridgeBuildRequest {
  quote: BridgeQuote;
  owner: string;
}

export interface BridgeSession {
  readonly id: string;
  readonly provider: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly quoteId: string;
  readonly status: "created" | "pending" | "completed" | "failed";
  readonly fromChainId: number;
  readonly toChainId: number;
  readonly recipient: string;
  readonly createdAt: number;
}

export interface BridgeAdapter extends BaseAdapter {
  readonly category: "bridge";
  getQuote(request: BridgeQuoteRequest): Promise<BridgeQuote>;
  buildBridge(request: BridgeBuildRequest): Promise<UnsignedTxIntent>;
  createSession(
    quote: BridgeQuote,
    owner: { tenantId: string; userId: string },
  ): Promise<BridgeSession>;
  getSession(id: string): Promise<BridgeSession | null>;
}

const MOCK_QUOTE_TTL_MS = 60_000;
const MOCK_BRIDGE_FEE_BPS = 20n;

export class MockBridgeAdapter implements BridgeAdapter {
  readonly category = "bridge" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private readonly sessions = new Map<string, BridgeSession>();
  private readonly now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async getQuote(request: BridgeQuoteRequest): Promise<BridgeQuote> {
    const fromChainId = assertChainId(request.fromChainId);
    const toChainId = assertChainId(request.toChainId);
    if (fromChainId === toChainId) {
      throw new AdapterValidationError("fromChainId and toChainId must differ");
    }
    const amountIn = assertUint256(request.amount, "amount");
    if (!request.fromToken?.address || !request.toToken?.address) {
      throw new AdapterValidationError("fromToken and toToken addresses are required");
    }
    const recipient = assertEvmAddress(request.recipient, "recipient");
    const slippageBps = assertSlippageBps(request.slippageBps);
    const amount = BigInt(amountIn);
    const feeAmount = (amount * MOCK_BRIDGE_FEE_BPS) / 10_000n;
    const amountOut = amount - feeAmount;
    const minAmountOut = (amountOut * BigInt(10_000 - slippageBps)) / 10_000n;
    return {
      provider: this.provider,
      quoteId: `mock-bridge-${fromChainId}-${toChainId}-${amountIn}-${slippageBps}`,
      fromChainId,
      toChainId,
      fromToken: request.fromToken,
      toToken: request.toToken,
      amountIn,
      amountOut: amountOut.toString(),
      minAmountOut: minAmountOut.toString(),
      feeAmount: feeAmount.toString(),
      recipient,
      route: [{ bridge: "mock-bridge", fromChainId, toChainId }],
      slippageBps,
      expiresAt: this.now() + MOCK_QUOTE_TTL_MS,
    };
  }

  async buildBridge(request: BridgeBuildRequest): Promise<UnsignedTxIntent> {
    const quote = validateQuote(request.quote, this.now());
    const owner = assertEvmAddress(request.owner, "owner");
    const bridgeContract = assertEvmAddress(quote.fromToken.address, "quote.fromToken.address");
    return {
      signed: false,
      kind: "evm-tx",
      chainId: quote.fromChainId,
      to: bridgeContract,
      value: "0",
      data: "0x",
      owner,
      category: "bridge",
      provider: this.provider,
      metadata: {
        quoteId: quote.quoteId,
        fromChainId: quote.fromChainId,
        toChainId: quote.toChainId,
        recipient: quote.recipient,
        amountIn: quote.amountIn,
        minAmountOut: quote.minAmountOut,
        slippageBps: quote.slippageBps,
      },
    };
  }

  async createSession(
    quote: BridgeQuote,
    owner: { tenantId: string; userId: string },
  ): Promise<BridgeSession> {
    const valid = validateQuote(quote, this.now());
    const tenantId = assertId(owner?.tenantId, "tenantId", 128);
    const userId = assertId(owner?.userId, "userId", 128);
    const session: BridgeSession = {
      id: `bridge_${crypto.randomUUID()}`,
      provider: this.provider,
      tenantId,
      userId,
      quoteId: valid.quoteId,
      status: "created",
      fromChainId: valid.fromChainId,
      toChainId: valid.toChainId,
      recipient: valid.recipient,
      createdAt: this.now(),
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async getSession(id: string): Promise<BridgeSession | null> {
    const sessionId = assertId(id, "sessionId", 128);
    return this.sessions.get(sessionId) ?? null;
  }
}

function validateQuote(quote: BridgeQuote, now: number): BridgeQuote {
  if (!quote || typeof quote !== "object") {
    throw new AdapterValidationError("a valid bridge quote is required");
  }
  assertId(quote.quoteId, "quoteId", 256);
  assertChainId(quote.fromChainId);
  assertChainId(quote.toChainId);
  if (quote.fromChainId === quote.toChainId) {
    throw new AdapterValidationError("quote chains must differ");
  }
  assertUint256(quote.amountIn, "quote.amountIn");
  assertUint256(quote.minAmountOut, "quote.minAmountOut", true);
  assertEvmAddress(quote.recipient, "quote.recipient");
  if (typeof quote.expiresAt !== "number" || quote.expiresAt <= now) {
    throw new AdapterValidationError("quote has expired; request a fresh quote");
  }
  return quote;
}
