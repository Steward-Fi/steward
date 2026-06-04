/**
 * OnrampAdapter — fiat → crypto seam (buy crypto with card/bank).
 *
 * The mock advances a session status in memory (pending → completed) and NEVER
 * actually moves money. There is no unsigned-tx artifact here: an onramp is an
 * off-platform fiat settlement, so the adapter only models session lifecycle.
 */

import { AdapterValidationError, type BaseAdapter } from "../types.js";
import {
  assertChainId,
  assertEvmAddress,
  assertFiatCurrency,
  assertId,
  assertPositiveAmount,
} from "../validation.js";

export type OnrampStatus = "pending" | "processing" | "completed" | "failed";

export interface OnrampQuoteRequest {
  fiatCurrency: string;
  fiatAmount: number;
  cryptoAsset: string;
  chainId: number;
}

export interface OnrampQuote {
  readonly provider: string;
  readonly fiatCurrency: string;
  readonly fiatAmount: number;
  readonly cryptoAsset: string;
  readonly chainId: number;
  /** Estimated crypto out in base units. */
  readonly cryptoAmount: string;
  /** Provider fee in fiat. */
  readonly feeFiat: number;
  readonly expiresAt: number;
  readonly quoteId: string;
}

export interface OnrampSession {
  readonly id: string;
  readonly provider: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly status: OnrampStatus;
  readonly fiatCurrency: string;
  readonly fiatAmount: number;
  readonly cryptoAsset: string;
  readonly chainId: number;
  readonly cryptoAmount: string;
  readonly destinationAddress: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface OnrampAdapter extends BaseAdapter {
  readonly category: "onramp";
  getQuote(request: OnrampQuoteRequest): Promise<OnrampQuote>;
  createSession(
    quote: OnrampQuote,
    destinationAddress: string,
    owner: { tenantId: string; userId: string },
  ): Promise<OnrampSession>;
  getSession(id: string): Promise<OnrampSession | null>;
}

const MOCK_QUOTE_TTL_MS = 60_000;
const MOCK_FEE_RATE = 0.01; // 1% flat
// Deterministic mock rate: 1 fiat unit -> 1e15 base units of crypto.
const MOCK_UNITS_PER_FIAT = 10n ** 15n;

export class MockOnrampAdapter implements OnrampAdapter {
  readonly category = "onramp" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private sessions = new Map<string, OnrampSession>();
  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  private cryptoFor(fiatAmount: number): string {
    const net = fiatAmount * (1 - MOCK_FEE_RATE);
    // Scale via integer math on cents to stay deterministic.
    const cents = BigInt(Math.round(net * 100));
    return ((cents * MOCK_UNITS_PER_FIAT) / 100n).toString();
  }

  async getQuote(request: OnrampQuoteRequest): Promise<OnrampQuote> {
    const fiatCurrency = assertFiatCurrency(request.fiatCurrency);
    const fiatAmount = assertPositiveAmount(request.fiatAmount, "fiatAmount");
    const cryptoAsset = assertId(request.cryptoAsset, "cryptoAsset", 64);
    const chainId = assertChainId(request.chainId);

    return {
      provider: this.provider,
      fiatCurrency,
      fiatAmount,
      cryptoAsset,
      chainId,
      cryptoAmount: this.cryptoFor(fiatAmount),
      feeFiat: Number((fiatAmount * MOCK_FEE_RATE).toFixed(2)),
      expiresAt: this.now() + MOCK_QUOTE_TTL_MS,
      quoteId: `mock-onramp-${fiatCurrency}-${fiatAmount}-${cryptoAsset}`,
    };
  }

  async createSession(
    quote: OnrampQuote,
    destinationAddress: string,
    owner: { tenantId: string; userId: string },
  ): Promise<OnrampSession> {
    const destination = assertEvmAddress(destinationAddress, "destinationAddress");
    const tenantId = assertId(owner?.tenantId, "tenantId", 128);
    const userId = assertId(owner?.userId, "userId", 128);
    if (!quote || typeof quote.expiresAt !== "number") {
      throw new AdapterValidationError("a valid quote is required");
    }
    if (quote.expiresAt <= this.now()) {
      throw new AdapterValidationError("quote has expired; request a fresh quote");
    }
    assertPositiveAmount(quote.fiatAmount, "quote.fiatAmount");

    const ts = this.now();
    const session: OnrampSession = {
      id: `onramp_${crypto.randomUUID()}`,
      provider: this.provider,
      tenantId,
      userId,
      status: "pending",
      fiatCurrency: quote.fiatCurrency,
      fiatAmount: quote.fiatAmount,
      cryptoAsset: quote.cryptoAsset,
      chainId: quote.chainId,
      cryptoAmount: quote.cryptoAmount,
      destinationAddress: destination,
      createdAt: ts,
      updatedAt: ts,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async getSession(id: string): Promise<OnrampSession | null> {
    const sessionId = assertId(id, "sessionId", 128);
    const existing = this.sessions.get(sessionId);
    if (!existing) return null;
    // Deterministically advance pending -> completed on read so callers can
    // observe lifecycle progress without any real settlement.
    if (existing.status === "pending") {
      const advanced: OnrampSession = {
        ...existing,
        status: "completed",
        updatedAt: this.now(),
      };
      this.sessions.set(sessionId, advanced);
      return advanced;
    }
    return existing;
  }
}
