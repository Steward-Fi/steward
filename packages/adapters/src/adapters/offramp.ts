/**
 * OfframpAdapter — crypto → fiat seam (sell crypto for a fiat payout).
 *
 * Symmetric to the onramp. A real offramp requires the user to SEND crypto to a
 * provider deposit address, then the provider pays out fiat. The mock therefore
 * exposes the provider-supplied deposit address on the session and advances the
 * payout status in memory (pending → completed). It NEVER moves money and NEVER
 * signs — if the platform later auto-funds the deposit, that transfer would go
 * through the existing signing+policy path, not this adapter.
 */

import { AdapterValidationError, type BaseAdapter } from "../types.js";
import { assertChainId, assertFiatCurrency, assertId, assertUint256 } from "../validation.js";

export type OfframpStatus = "pending" | "processing" | "completed" | "failed";

export interface OfframpQuoteRequest {
  cryptoAsset: string;
  /** Crypto amount to sell in base units. */
  cryptoAmount: string;
  chainId: number;
  fiatCurrency: string;
}

export interface OfframpQuote {
  readonly provider: string;
  readonly cryptoAsset: string;
  readonly cryptoAmount: string;
  readonly chainId: number;
  readonly fiatCurrency: string;
  /** Estimated fiat payout. */
  readonly fiatAmount: number;
  readonly feeFiat: number;
  readonly expiresAt: number;
  readonly quoteId: string;
}

export interface OfframpPayoutDetails {
  /** Opaque, NON-SECRET reference to a pre-registered payout method. */
  readonly payoutMethodId: string;
}

export interface OfframpSession {
  readonly id: string;
  readonly provider: string;
  readonly status: OfframpStatus;
  readonly cryptoAsset: string;
  readonly cryptoAmount: string;
  readonly chainId: number;
  readonly fiatCurrency: string;
  readonly fiatAmount: number;
  /**
   * Provider-controlled deposit address the user must send crypto to. The
   * funding transfer (if platform-initiated) goes through the normal
   * signing+policy path — never through this adapter.
   */
  readonly depositAddress: string;
  readonly payoutMethodId: string;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface OfframpAdapter extends BaseAdapter {
  readonly category: "offramp";
  getQuote(request: OfframpQuoteRequest): Promise<OfframpQuote>;
  createSession(quote: OfframpQuote, payout: OfframpPayoutDetails): Promise<OfframpSession>;
  getSession(id: string): Promise<OfframpSession | null>;
}

const MOCK_QUOTE_TTL_MS = 60_000;
const MOCK_FEE_RATE = 0.01;
// Inverse of the onramp rate: 1e15 base units -> 1 fiat unit.
const MOCK_UNITS_PER_FIAT = 10n ** 15n;
// Deterministic mock deposit address.
const MOCK_DEPOSIT_ADDRESS = "0x0ff7a3000000000000000000000000000000dead";

export class MockOfframpAdapter implements OfframpAdapter {
  readonly category = "offramp" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private sessions = new Map<string, OfframpSession>();
  private now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  private fiatFor(cryptoAmount: string): number {
    const units = BigInt(cryptoAmount);
    const grossCents = (units * 100n) / MOCK_UNITS_PER_FIAT;
    const gross = Number(grossCents) / 100;
    return Number((gross * (1 - MOCK_FEE_RATE)).toFixed(2));
  }

  async getQuote(request: OfframpQuoteRequest): Promise<OfframpQuote> {
    const cryptoAsset = assertId(request.cryptoAsset, "cryptoAsset", 64);
    const cryptoAmount = assertUint256(request.cryptoAmount, "cryptoAmount");
    const chainId = assertChainId(request.chainId);
    const fiatCurrency = assertFiatCurrency(request.fiatCurrency);
    const fiatAmount = this.fiatFor(cryptoAmount);

    return {
      provider: this.provider,
      cryptoAsset,
      cryptoAmount,
      chainId,
      fiatCurrency,
      fiatAmount,
      feeFiat: Number((this.fiatFor(cryptoAmount) * MOCK_FEE_RATE).toFixed(2)),
      expiresAt: this.now() + MOCK_QUOTE_TTL_MS,
      quoteId: `mock-offramp-${cryptoAsset}-${cryptoAmount}-${fiatCurrency}`,
    };
  }

  async createSession(quote: OfframpQuote, payout: OfframpPayoutDetails): Promise<OfframpSession> {
    if (!quote || typeof quote.expiresAt !== "number") {
      throw new AdapterValidationError("a valid quote is required");
    }
    if (quote.expiresAt <= this.now()) {
      throw new AdapterValidationError("quote has expired; request a fresh quote");
    }
    assertUint256(quote.cryptoAmount, "quote.cryptoAmount");
    const payoutMethodId = assertId(payout?.payoutMethodId, "payoutMethodId", 128);

    const ts = this.now();
    const session: OfframpSession = {
      id: `offramp_${crypto.randomUUID()}`,
      provider: this.provider,
      status: "pending",
      cryptoAsset: quote.cryptoAsset,
      cryptoAmount: quote.cryptoAmount,
      chainId: quote.chainId,
      fiatCurrency: quote.fiatCurrency,
      fiatAmount: quote.fiatAmount,
      depositAddress: MOCK_DEPOSIT_ADDRESS,
      payoutMethodId,
      createdAt: ts,
      updatedAt: ts,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  async getSession(id: string): Promise<OfframpSession | null> {
    const sessionId = assertId(id, "sessionId", 128);
    const existing = this.sessions.get(sessionId);
    if (!existing) return null;
    if (existing.status === "pending") {
      const advanced: OfframpSession = {
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
