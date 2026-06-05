/**
 * SparkAdapter - BTC/Spark/Lightning seam.
 *
 * The mock models provider-neutral Spark wallet DTOs, static BTC deposits,
 * Lightning invoices/payments, Spark transfers, token transfers, and balance
 * reads. It never holds keys, never signs identity-key payloads, and returns
 * only unsigned abstract intents for fund-moving operations.
 */

import {
  AdapterUnavailableError,
  AdapterValidationError,
  type BaseAdapter,
  type UnsignedTxIntent,
} from "../types.js";
import { assertId } from "../validation.js";

export type SparkWalletStatus = "created" | "active" | "disabled";
export type SparkNetwork = "mainnet" | "testnet" | "signet";
export type SparkTransferStatus = "created" | "pending" | "completed" | "failed";
export type LightningInvoiceStatus = "created" | "paid" | "expired" | "canceled";
export type StaticBtcDepositStatus = "created" | "funded" | "claimed" | "expired";

export interface CreateSparkWalletRequest {
  userId: string;
  network?: SparkNetwork;
  label?: string;
}

export interface SparkWallet {
  readonly id: string;
  readonly provider: string;
  readonly userId: string;
  readonly network: SparkNetwork;
  readonly status: SparkWalletStatus;
  readonly sparkAddress: string;
  readonly identityPublicKey: string;
  readonly createdAt: number;
}

export interface SparkBalance {
  readonly walletId: string;
  readonly provider: string;
  readonly network: SparkNetwork;
  readonly btcSats: string;
  readonly lightningSats: string;
  readonly sparkTokenBalances: ReadonlyArray<{
    tokenId: string;
    amount: string;
  }>;
  readonly updatedAt: number;
}

export interface StaticBtcDepositQuoteRequest {
  walletId: string;
  amountSats?: string;
}

export interface StaticBtcDepositQuote {
  readonly id: string;
  readonly provider: string;
  readonly walletId: string;
  readonly network: SparkNetwork;
  readonly depositAddress: string;
  readonly amountSats?: string;
  readonly status: StaticBtcDepositStatus;
  readonly expiresAt: number;
  readonly createdAt: number;
}

export interface StaticBtcDepositClaimRequest {
  quoteId: string;
  owner: string;
}

export interface LightningInvoiceRequest {
  walletId: string;
  amountSats: string;
  memo?: string;
  expiresInSeconds?: number;
}

export interface LightningInvoice {
  readonly id: string;
  readonly provider: string;
  readonly walletId: string;
  readonly amountSats: string;
  readonly memo?: string;
  readonly paymentRequest: string;
  readonly status: LightningInvoiceStatus;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface LightningPaymentRequest {
  walletId: string;
  paymentRequest: string;
  maxFeeSats?: string;
  owner: string;
}

export interface SparkTransferRequest {
  walletId: string;
  recipient: string;
  amountSats: string;
  memo?: string;
  owner: string;
}

export interface SparkTokenTransferRequest {
  walletId: string;
  recipient: string;
  tokenId: string;
  amount: string;
  memo?: string;
  owner: string;
}

export interface SparkIdentitySignRequest {
  walletId: string;
  payload: string;
}

export interface SparkIdentitySignResult {
  readonly ok: false;
  readonly available: false;
  readonly provider: string;
  readonly reason: string;
}

export interface SparkAdapter extends BaseAdapter {
  readonly category: "spark";
  createWallet(request: CreateSparkWalletRequest): Promise<SparkWallet>;
  getWallet(id: string): Promise<SparkWallet | null>;
  getBalance(walletId: string): Promise<SparkBalance>;
  createStaticBtcDepositQuote(
    request: StaticBtcDepositQuoteRequest,
  ): Promise<StaticBtcDepositQuote>;
  buildStaticBtcDepositClaim(request: StaticBtcDepositClaimRequest): Promise<UnsignedTxIntent>;
  createLightningInvoice(request: LightningInvoiceRequest): Promise<LightningInvoice>;
  getLightningInvoice(id: string): Promise<LightningInvoice | null>;
  buildLightningPayment(request: LightningPaymentRequest): Promise<UnsignedTxIntent>;
  buildSparkTransfer(request: SparkTransferRequest): Promise<UnsignedTxIntent>;
  buildSparkTokenTransfer(request: SparkTokenTransferRequest): Promise<UnsignedTxIntent>;
  requestIdentitySignature(request: SparkIdentitySignRequest): Promise<SparkIdentitySignResult>;
}

const VALID_NETWORKS: ReadonlySet<SparkNetwork> = new Set(["mainnet", "testnet", "signet"]);
const DECIMAL_RE = /^\d+$/;
const HEX_RE = /^0x[0-9a-fA-F]*$/;
const LIGHTNING_INVOICE_RE = /^(lnbc|lntb|lnbcrt)[a-zA-Z0-9]+$/;
const DEFAULT_INVOICE_TTL_SECONDS = 3_600;
const DEFAULT_DEPOSIT_TTL_MS = 24 * 60 * 60 * 1_000;

export class MockSparkAdapter implements SparkAdapter {
  readonly category = "spark" as const;
  readonly provider = "mock";
  readonly enabled = true;

  private readonly wallets = new Map<string, SparkWallet>();
  private readonly deposits = new Map<string, StaticBtcDepositQuote>();
  private readonly invoices = new Map<string, LightningInvoice>();
  private readonly now: () => number;

  constructor(options?: { now?: () => number }) {
    this.now = options?.now ?? (() => Date.now());
  }

  async createWallet(request: CreateSparkWalletRequest): Promise<SparkWallet> {
    const userId = assertId(request.userId, "userId", 128);
    const network = assertNetwork(request.network);
    if (request.label !== undefined) assertId(request.label, "label", 128);
    const id = `spark_wallet_${crypto.randomUUID()}`;
    const suffix = id.replace(/-/g, "").slice(-16);
    const wallet: SparkWallet = {
      id,
      provider: this.provider,
      userId,
      network,
      status: "created",
      sparkAddress: `spk_${network}_${suffix}`,
      identityPublicKey: `spk_identity_${suffix}`,
      createdAt: this.now(),
    };
    this.wallets.set(id, wallet);
    return wallet;
  }

  async getWallet(id: string): Promise<SparkWallet | null> {
    return this.wallets.get(assertId(id, "walletId", 128)) ?? null;
  }

  async getBalance(walletId: string): Promise<SparkBalance> {
    const wallet = this.requireWallet(walletId);
    return {
      walletId: wallet.id,
      provider: this.provider,
      network: wallet.network,
      btcSats: "0",
      lightningSats: "0",
      sparkTokenBalances: [],
      updatedAt: this.now(),
    };
  }

  async createStaticBtcDepositQuote(
    request: StaticBtcDepositQuoteRequest,
  ): Promise<StaticBtcDepositQuote> {
    const wallet = this.requireWallet(request.walletId);
    const amountSats =
      request.amountSats === undefined
        ? undefined
        : assertDecimal(request.amountSats, "amountSats");
    const id = `spark_deposit_${crypto.randomUUID()}`;
    const quote: StaticBtcDepositQuote = {
      id,
      provider: this.provider,
      walletId: wallet.id,
      network: wallet.network,
      depositAddress: mockBtcAddress(wallet.network, id),
      amountSats,
      status: "created",
      createdAt: this.now(),
      expiresAt: this.now() + DEFAULT_DEPOSIT_TTL_MS,
    };
    this.deposits.set(id, quote);
    return quote;
  }

  async buildStaticBtcDepositClaim(
    request: StaticBtcDepositClaimRequest,
  ): Promise<UnsignedTxIntent> {
    const quoteId = assertId(request.quoteId, "quoteId", 128);
    const quote = this.deposits.get(quoteId);
    if (!quote) throw new AdapterValidationError("unknown quoteId");
    if (quote.expiresAt <= this.now()) {
      throw new AdapterValidationError("deposit quote has expired");
    }
    return abstractIntent({
      provider: this.provider,
      operation: "spark.static_btc_deposit.claim",
      owner: assertId(request.owner, "owner", 128),
      to: quote.depositAddress,
      value: quote.amountSats ?? "0",
      metadata: {
        quoteId: quote.id,
        walletId: quote.walletId,
        network: quote.network,
        depositAddress: quote.depositAddress,
      },
    });
  }

  async createLightningInvoice(request: LightningInvoiceRequest): Promise<LightningInvoice> {
    const wallet = this.requireWallet(request.walletId);
    const amountSats = assertDecimal(request.amountSats, "amountSats");
    const memo = request.memo === undefined ? undefined : assertId(request.memo, "memo", 280);
    const ttlSeconds =
      request.expiresInSeconds === undefined
        ? DEFAULT_INVOICE_TTL_SECONDS
        : assertTtlSeconds(request.expiresInSeconds);
    const id = `spark_ln_invoice_${crypto.randomUUID()}`;
    const invoice: LightningInvoice = {
      id,
      provider: this.provider,
      walletId: wallet.id,
      amountSats,
      memo,
      paymentRequest: `${wallet.network === "mainnet" ? "lnbc" : "lntb"}${amountSats}n1${id.replace(
        /[^a-zA-Z0-9]/g,
        "",
      )}`,
      status: "created",
      createdAt: this.now(),
      expiresAt: this.now() + ttlSeconds * 1_000,
    };
    this.invoices.set(id, invoice);
    return invoice;
  }

  async getLightningInvoice(id: string): Promise<LightningInvoice | null> {
    return this.invoices.get(assertId(id, "invoiceId", 128)) ?? null;
  }

  async buildLightningPayment(request: LightningPaymentRequest): Promise<UnsignedTxIntent> {
    const wallet = this.requireWallet(request.walletId);
    const paymentRequest = assertLightningInvoice(request.paymentRequest);
    const maxFeeSats =
      request.maxFeeSats === undefined
        ? undefined
        : assertDecimal(request.maxFeeSats, "maxFeeSats");
    return abstractIntent({
      provider: this.provider,
      operation: "spark.lightning.pay",
      owner: assertId(request.owner, "owner", 128),
      to: paymentRequest,
      value: "0",
      metadata: { walletId: wallet.id, network: wallet.network, maxFeeSats },
    });
  }

  async buildSparkTransfer(request: SparkTransferRequest): Promise<UnsignedTxIntent> {
    const wallet = this.requireWallet(request.walletId);
    const recipient = assertSparkRecipient(request.recipient);
    const amountSats = assertDecimal(request.amountSats, "amountSats");
    return abstractIntent({
      provider: this.provider,
      operation: "spark.transfer",
      owner: assertId(request.owner, "owner", 128),
      to: recipient,
      value: amountSats,
      metadata: {
        walletId: wallet.id,
        network: wallet.network,
        memo: request.memo === undefined ? undefined : assertId(request.memo, "memo", 280),
      },
    });
  }

  async buildSparkTokenTransfer(request: SparkTokenTransferRequest): Promise<UnsignedTxIntent> {
    const wallet = this.requireWallet(request.walletId);
    const recipient = assertSparkRecipient(request.recipient);
    const tokenId = assertId(request.tokenId, "tokenId", 128);
    const amount = assertDecimal(request.amount, "amount");
    return abstractIntent({
      provider: this.provider,
      operation: "spark.token_transfer",
      owner: assertId(request.owner, "owner", 128),
      to: recipient,
      value: "0",
      metadata: {
        walletId: wallet.id,
        network: wallet.network,
        tokenId,
        amount,
        memo: request.memo === undefined ? undefined : assertId(request.memo, "memo", 280),
      },
    });
  }

  async requestIdentitySignature(
    request: SparkIdentitySignRequest,
  ): Promise<SparkIdentitySignResult> {
    this.requireWallet(request.walletId);
    if (typeof request.payload !== "string" || !HEX_RE.test(request.payload)) {
      throw new AdapterValidationError("payload must be a 0x-prefixed hex string");
    }
    return {
      ok: false,
      available: false,
      provider: this.provider,
      reason:
        "Spark identity-key signing is not available in the mock adapter. Configure a real Spark provider; the mock never holds keys or fabricates signatures.",
    };
  }

  async requireIdentitySignature(request: SparkIdentitySignRequest): Promise<never> {
    const result = await this.requestIdentitySignature(request);
    throw new AdapterUnavailableError("spark", result.reason);
  }

  private requireWallet(walletId: string): SparkWallet {
    const id = assertId(walletId, "walletId", 128);
    const wallet = this.wallets.get(id);
    if (!wallet) throw new AdapterValidationError("unknown walletId");
    return wallet;
  }
}

function assertNetwork(value: unknown): SparkNetwork {
  if (value === undefined) return "testnet";
  if (typeof value !== "string" || !VALID_NETWORKS.has(value as SparkNetwork)) {
    throw new AdapterValidationError("network must be mainnet, testnet, or signet");
  }
  return value as SparkNetwork;
}

function assertDecimal(value: unknown, field: string): string {
  if (typeof value !== "string" || !DECIMAL_RE.test(value)) {
    throw new AdapterValidationError(`${field} must be a decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new AdapterValidationError(`${field} must be greater than zero`);
  return value;
}

function assertTtlSeconds(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 60 || value > 86_400) {
    throw new AdapterValidationError("expiresInSeconds must be an integer between 60 and 86400");
  }
  return value;
}

function assertLightningInvoice(value: unknown): string {
  if (typeof value !== "string" || value.length > 4096 || !LIGHTNING_INVOICE_RE.test(value)) {
    throw new AdapterValidationError("paymentRequest must be a Lightning invoice");
  }
  return value;
}

function assertSparkRecipient(value: unknown): string {
  if (typeof value !== "string" || !/^spk_[a-z0-9_]{8,160}$/i.test(value)) {
    throw new AdapterValidationError("recipient must be a Spark address");
  }
  return value;
}

function mockBtcAddress(network: SparkNetwork, id: string): string {
  const suffix = id
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(-24)
    .toLowerCase();
  return `${network === "mainnet" ? "bc1q" : "tb1q"}${suffix.padEnd(24, "0")}`;
}

function abstractIntent(params: {
  provider: string;
  operation: string;
  owner: string;
  to: string;
  value: string;
  metadata: Record<string, unknown>;
}): UnsignedTxIntent {
  return {
    signed: false,
    kind: "abstract-intent",
    chainId: 0,
    to: params.to,
    value: params.value,
    owner: params.owner,
    category: "spark",
    provider: params.provider,
    metadata: { operation: params.operation, ...params.metadata },
  };
}
