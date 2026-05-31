/**
 * ExchangeEmbedAdapter — provider-neutral exchange embed seam.
 *
 * This models embedded exchange onboarding/trading sessions such as Kraken
 * Embed without treating the OSS repo as a broker or custodian. The mock never
 * creates real exchange accounts, never executes orders, and never stores API
 * credentials. It only returns deterministic sandbox session metadata for UI
 * and route wiring tests.
 */

import { AdapterUnavailableError, AdapterValidationError, type BaseAdapter } from "../types.js";
import { assertId } from "../validation.js";

export type ExchangeProvider = "kraken" | "coinbase" | "binance" | "mock";

export interface ExchangeEmbedSessionRequest {
  userId: string;
  tenantId: string;
  provider: ExchangeProvider;
  returnUrl: string;
  scopes?: readonly string[];
  locale?: string;
}

export interface ExchangeEmbedSession {
  readonly id: string;
  readonly provider: string;
  readonly userId: string;
  readonly tenantId: string;
  readonly status: "created" | "active" | "expired" | "failed";
  readonly url: string;
  readonly scopes: readonly string[];
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface ExchangeAccountLink {
  readonly id: string;
  readonly provider: string;
  readonly userId: string;
  readonly externalAccountId: string;
  readonly status: "linked" | "revoked";
  readonly createdAt: number;
}

export interface ExchangeEmbedAdapter extends BaseAdapter {
  readonly category: "exchange";
  createEmbedSession(request: ExchangeEmbedSessionRequest): Promise<ExchangeEmbedSession>;
  getEmbedSession(id: string): Promise<ExchangeEmbedSession | null>;
  listLinkedAccounts(userId: string): Promise<ExchangeAccountLink[]>;
  getLinkedAccount(id: string): Promise<ExchangeAccountLink | null>;
  revokeLinkedAccount(id: string): Promise<ExchangeAccountLink>;
  /**
   * A real exchange adapter may expose order placement under strict tenant
   * controls. The mock always fails closed and never fabricates order execution.
   */
  createOrder(request: unknown): Promise<never>;
}

const SESSION_TTL_MS = 10 * 60 * 1000;
const DEFAULT_SCOPES = ["account:read", "trade:read"] as const;

export class MockExchangeEmbedAdapter implements ExchangeEmbedAdapter {
  readonly category = "exchange" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private readonly sessions = new Map<string, ExchangeEmbedSession>();
  private readonly links = new Map<string, ExchangeAccountLink>();
  private readonly now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async createEmbedSession(request: ExchangeEmbedSessionRequest): Promise<ExchangeEmbedSession> {
    const userId = assertId(request.userId, "userId", 128);
    const tenantId = assertId(request.tenantId, "tenantId", 128);
    assertExchangeProvider(request.provider);
    const returnUrl = assertHttpsReturnUrl(request.returnUrl);
    const scopes = validateScopes(request.scopes);
    if (request.locale !== undefined) assertId(request.locale, "locale", 32);

    const id = `exchange_${crypto.randomUUID()}`;
    const createdAt = this.now();
    const session: ExchangeEmbedSession = {
      id,
      provider: this.provider,
      userId,
      tenantId,
      status: "created",
      url: `https://mock.exchange.local/embed/${id}?return_url=${encodeURIComponent(returnUrl)}`,
      scopes,
      createdAt,
      expiresAt: createdAt + SESSION_TTL_MS,
    };
    this.sessions.set(id, session);

    // Seed a deterministic linked-account placeholder so list/revoke flows can
    // be exercised without a real provider relationship or API credential.
    const linkId = `exchange_link_${id}`;
    this.links.set(linkId, {
      id: linkId,
      provider: this.provider,
      userId,
      externalAccountId: `mock-exchange-account-${userId}`,
      status: "linked",
      createdAt,
    });
    return session;
  }

  async getEmbedSession(id: string): Promise<ExchangeEmbedSession | null> {
    const sessionId = assertId(id, "sessionId", 128);
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    if (session.expiresAt <= this.now()) return { ...session, status: "expired" };
    return session;
  }

  async listLinkedAccounts(userId: string): Promise<ExchangeAccountLink[]> {
    const id = assertId(userId, "userId", 128);
    return [...this.links.values()].filter((link) => link.userId === id);
  }

  async getLinkedAccount(id: string): Promise<ExchangeAccountLink | null> {
    const linkId = assertId(id, "linkId", 128);
    return this.links.get(linkId) ?? null;
  }

  async revokeLinkedAccount(id: string): Promise<ExchangeAccountLink> {
    const linkId = assertId(id, "linkId", 128);
    const link = this.links.get(linkId);
    if (!link) throw new AdapterValidationError("unknown exchange account link");
    const revoked: ExchangeAccountLink = { ...link, status: "revoked" };
    this.links.set(linkId, revoked);
    return revoked;
  }

  async createOrder(_request: unknown): Promise<never> {
    throw new AdapterUnavailableError(
      "exchange",
      "Exchange order placement is not available in the mock adapter. Configure a regulated exchange provider before enabling embedded trading.",
    );
  }
}

function assertExchangeProvider(value: unknown): ExchangeProvider {
  if (value === "kraken" || value === "coinbase" || value === "binance" || value === "mock") {
    return value;
  }
  throw new AdapterValidationError("exchange provider must be kraken, coinbase, binance, or mock");
}

function assertHttpsReturnUrl(value: unknown): string {
  const url = assertId(value, "returnUrl", 2048);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new AdapterValidationError("returnUrl must be a valid URL");
  }
  if (parsed.protocol !== "https:" && parsed.hostname !== "localhost") {
    throw new AdapterValidationError("returnUrl must use https outside localhost");
  }
  return parsed.toString();
}

function validateScopes(scopes: readonly string[] | undefined): readonly string[] {
  if (scopes === undefined) return DEFAULT_SCOPES;
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.length > 16) {
    throw new AdapterValidationError("scopes must be a non-empty array of at most 16 entries");
  }
  return scopes.map((scope) => assertId(scope, "scope", 64));
}
