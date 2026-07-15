import { ed25519 } from "@noble/curves/ed25519";
import { keccak_256 } from "@noble/hashes/sha3";
import { PublicKey } from "@solana/web3.js";
import {
  AdapterProviderError,
  AdapterValidationError,
  assertId,
  type BridgeAdapter,
  type BridgeBuildRequest,
  type BridgeHandoff,
  type BridgeQuote,
  type BridgeQuoteRequest,
  type BridgeSession,
  type TokenRef,
} from "@stwd/adapters";
import { MONERO_ON_SOLANA } from "@stwd/shared";
import bs58 from "bs58";

export const WXMR_PROVIDER = "wxmr";
export const WXMR_BRIDGE_URL = "https://wxmr.io/";
export const WXMR_BRIDGE_PROGRAM_ID = "EzBkC8P5wxab9kwrtV5hRdynHAfB5w3UPcPXNgMseVA8";
export const WXMR_BRIDGE_CONFIG_ACCOUNT = "2yy692W8JX511d63i5BdKHqULJCnQyBYrfnkavnzjZuE";
export const WXMR_SOLANA_CHAIN_ID = 101;
// Matches the native-Monero provider convention in Steward's separate Monero
// support work. It is usable here as an external bridge network identifier even
// when that optional wallet backend is not installed.
export const WXMR_MONERO_CHAIN_ID = 301;
/** Current bridge-program minimum: 0.1 XMR at 12 decimal places. */
export const WXMR_MIN_AMOUNT_ATOMIC = 100_000_000_000n;

export type WxmrBridgeDirection = "monero-to-solana" | "solana-to-monero";

const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";
const QUOTE_TTL_MS = 60_000;
const DEFAULT_RPC_TIMEOUT_MS = 5_000;
const KRAKEN_XMR_USD_URL = "https://api.kraken.com/0/public/Ticker?pair=XMRUSD&assetVersion=1";
const COINGECKO_XMR_USD_URL =
  "https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies=usd&include_last_updated_at=true";
const PRICE_MAX_AGE_MS = 5 * 60_000;
const PRICE_FUTURE_TOLERANCE_MS = 60_000;
const PRICE_MAX_DIVERGENCE_RATIO = 0.1;
const FEE_DENOMINATOR = 10_000n;
const MAX_U64 = 18_446_744_073_709_551_615n;
const XMR_ATOMIC_UNITS = 1_000_000_000_000;
const MAX_SESSIONS = 1_000;
const BRIDGE_CONFIG_DISCRIMINATOR = new Uint8Array([
  0x28, 0xce, 0x33, 0xe9, 0xf6, 0x28, 0xb2, 0x55,
]);
const BRIDGE_CONFIG_MINT_OFFSET = 8 + 32;
const BRIDGE_CONFIG_LEGACY_LENGTH = 8 + 32 + 32 + 8 + 8 + 1;
const BRIDGE_CONFIG_FEE_OFFSET = BRIDGE_CONFIG_LEGACY_LENGTH;
const FEE_OVERRIDE_SEED = "fee_override";
const FEE_OVERRIDE_DISCRIMINATOR = new Uint8Array([45, 33, 41, 248, 253, 236, 239, 85]);
const FEE_OVERRIDE_USER_OFFSET = 8;
const FEE_OVERRIDE_FEE_OFFSET = 40;
const FEE_OVERRIDE_BUMP_OFFSET = 42;
const FEE_OVERRIDE_LENGTH = 43;

const NATIVE_XMR: TokenRef = Object.freeze({ address: "native", symbol: "XMR", decimals: 12 });
const SOLANA_XMR: TokenRef = Object.freeze({
  address: MONERO_ON_SOLANA.address,
  symbol: MONERO_ON_SOLANA.symbol,
  decimals: MONERO_ON_SOLANA.decimals,
});

const HANDOFF_NOTICES = Object.freeze([
  "wxmr.io requires an interactive Solana wallet; Steward does not sign or submit the bridge operation.",
  "Check wxmr.io for the live minimum, final fee, confirmations, and settlement status before approving.",
  "The Solana-to-Monero quote amount is indicative from the global fee; build checks the connected wallet's on-chain fee override.",
  "Monero on Solana uses Solana's public ledger and does not inherit native Monero transaction privacy.",
]);

interface WxmrBridgeQuote extends BridgeQuote {
  readonly provider: typeof WXMR_PROVIDER;
  readonly direction: WxmrBridgeDirection;
  readonly executionMode: "external-handoff";
  readonly handoffUrl: typeof WXMR_BRIDGE_URL;
  readonly feeBps: number;
  readonly feeScope: "global-estimate" | "not-applicable";
  readonly feeObservedSlot?: number;
  readonly feeObservedAt: number;
  readonly notices: readonly string[];
}

interface FeeObservation {
  feeBps: number;
  slot?: number;
  observedAt: number;
}

interface RpcAccountValue {
  data?: [string, string] | string;
  owner?: string;
}

interface RpcAccountInfoResponse {
  result?: {
    context?: { slot?: number };
    value?: RpcAccountValue | null;
  };
  error?: { message?: string };
}

interface RpcMultipleAccountsResponse {
  result?: {
    context?: { slot?: number };
    value?: Array<RpcAccountValue | null>;
  };
  error?: { message?: string };
}

export interface WxmrBridgeAdapterOptions {
  rpcUrl?: string;
  fetch?: typeof fetch;
  now?: () => number;
  randomId?: () => string;
  rpcTimeoutMs?: number;
  getTrustedXmrUsdPrice?: () => Promise<number | null>;
}

function assertRpcUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("WXMR_SOLANA_RPC_URL must be a valid HTTP(S) URL");
  }
  const loopback =
    url.hostname === "localhost" ||
    url.hostname === "::1" ||
    url.hostname === "[::1]" ||
    url.hostname === "127.0.0.1";
  if (url.username !== "" || url.password !== "") {
    throw new Error("WXMR_SOLANA_RPC_URL must not include credentials");
  }
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error(
      "WXMR_SOLANA_RPC_URL must use HTTPS (plain HTTP is allowed only for loopback RPCs)",
    );
  }
  return url.toString();
}

function directionFor(fromChainId: number, toChainId: number): WxmrBridgeDirection {
  if (fromChainId === WXMR_MONERO_CHAIN_ID && toChainId === WXMR_SOLANA_CHAIN_ID) {
    return "monero-to-solana";
  }
  if (fromChainId === WXMR_SOLANA_CHAIN_ID && toChainId === WXMR_MONERO_CHAIN_ID) {
    return "solana-to-monero";
  }
  throw new AdapterValidationError(
    `wxmr supports only Monero mainnet (${WXMR_MONERO_CHAIN_ID}) <-> Solana mainnet (${WXMR_SOLANA_CHAIN_ID})`,
  );
}

function assertBaseUnitAmount(value: unknown, field = "amount"): string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw new AdapterValidationError(`${field} must be a base-unit decimal string`);
  }
  const amount = BigInt(value);
  if (amount <= 0n) throw new AdapterValidationError(`${field} must be greater than zero`);
  if (amount < WXMR_MIN_AMOUNT_ATOMIC) {
    throw new AdapterValidationError(`${field} must be at least 0.1 XMR`);
  }
  if (amount > MAX_U64) {
    throw new AdapterValidationError(`${field} exceeds the wxmr bridge's u64 range`);
  }
  return value;
}

function assertToken(
  value: TokenRef | undefined,
  expected: TokenRef,
  field: "fromToken" | "toToken",
): void {
  if (!value || value.address !== expected.address) {
    throw new AdapterValidationError(`${field}.address must be ${expected.address}`);
  }
  if (value.symbol !== undefined && value.symbol.toUpperCase() !== "XMR") {
    throw new AdapterValidationError(`${field}.symbol must be XMR when provided`);
  }
  if (value.decimals !== undefined && value.decimals !== 12) {
    throw new AdapterValidationError(`${field}.decimals must be 12 when provided`);
  }
}

function assertSolanaAddress(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) {
    throw new AdapterValidationError(`${field} must be a Solana address`);
  }
  try {
    if (bs58.decode(value).length !== 32) throw new Error("wrong length");
  } catch {
    throw new AdapterValidationError(`${field} must be a Solana address`);
  }
  return value;
}

// Monero addresses use block-wise base58 rather than Bitcoin/Solana's stream
// encoding. Decode enough of the canonical format to verify the mainnet prefix,
// payload length, checksum, and embedded Ed25519 public keys.
const MONERO_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MONERO_ENCODED_BLOCK_SIZES = [0, 2, 3, 5, 6, 7, 9, 10, 11] as const;

function decodeMoneroBase58Block(block: string, byteLength: number): Uint8Array {
  let number = 0n;
  for (const character of block) {
    const digit = MONERO_BASE58_ALPHABET.indexOf(character);
    if (digit < 0) throw new Error("invalid base58 character");
    number = number * 58n + BigInt(digit);
  }
  const decoded = new Uint8Array(byteLength);
  for (let index = byteLength - 1; index >= 0; index--) {
    decoded[index] = Number(number % 256n);
    number /= 256n;
  }
  if (number > 0n) throw new Error("base58 block overflow");
  return decoded;
}

function decodeMoneroBase58(address: string): Uint8Array {
  const fullBlocks = Math.floor(address.length / 11);
  const trailingCharacters = address.length % 11;
  const trailingBytes = MONERO_ENCODED_BLOCK_SIZES.indexOf(
    trailingCharacters as (typeof MONERO_ENCODED_BLOCK_SIZES)[number],
  );
  if (trailingBytes < 0) throw new Error("invalid base58 length");
  const decoded = new Uint8Array(fullBlocks * 8 + trailingBytes);
  for (let index = 0; index < fullBlocks; index++) {
    decoded.set(decodeMoneroBase58Block(address.slice(index * 11, (index + 1) * 11), 8), index * 8);
  }
  if (trailingBytes > 0) {
    decoded.set(
      decodeMoneroBase58Block(address.slice(fullBlocks * 11), trailingBytes),
      fullBlocks * 8,
    );
  }
  return decoded;
}

function assertMoneroMainnetAddress(value: unknown, field: string): string {
  try {
    if (typeof value !== "string" || (value.length !== 95 && value.length !== 106)) {
      throw new Error("invalid length");
    }
    const payload = decodeMoneroBase58(value);
    if (payload.length !== 69 && payload.length !== 77) throw new Error("invalid payload length");
    const body = payload.subarray(0, payload.length - 4);
    const checksum = payload.subarray(payload.length - 4);
    if (!equalBytes(checksum, keccak_256(body).subarray(0, 4))) {
      throw new Error("checksum mismatch");
    }
    const prefix = payload[0];
    if (prefix !== 18 && prefix !== 19 && prefix !== 42) throw new Error("not mainnet");
    if ((prefix === 19 ? 77 : 69) !== payload.length) throw new Error("kind mismatch");
    ed25519.ExtendedPoint.fromHex(payload.subarray(1, 33));
    ed25519.ExtendedPoint.fromHex(payload.subarray(33, 65));
  } catch {
    throw new AdapterValidationError(`${field} must be a Monero mainnet address`);
  }
  return value as string;
}

function assertRecipient(direction: WxmrBridgeDirection, value: unknown): string {
  return direction === "monero-to-solana"
    ? assertSolanaAddress(value, "recipient")
    : assertMoneroMainnetAddress(value, "recipient");
}

function assertOwner(direction: WxmrBridgeDirection, value: unknown, recipient: string): string {
  const owner = assertSolanaAddress(value, "owner");
  if (direction === "monero-to-solana" && owner !== recipient) {
    throw new AdapterValidationError(
      "owner must match the recipient Solana wallet that will connect to wxmr.io",
    );
  }
  return owner;
}

function decodeBase64(value: string): Uint8Array {
  try {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new AdapterProviderError(
      "bridge",
      WXMR_PROVIDER,
      "The wxmr bridge config RPC response was not valid base64.",
    );
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function feeFor(amount: bigint, feeBps: number): bigint {
  return (amount * BigInt(feeBps)) / FEE_DENOMINATOR;
}

function quoteTokens(direction: WxmrBridgeDirection): { fromToken: TokenRef; toToken: TokenRef } {
  return direction === "monero-to-solana"
    ? { fromToken: NATIVE_XMR, toToken: SOLANA_XMR }
    : { fromToken: SOLANA_XMR, toToken: NATIVE_XMR };
}

/**
 * wxmr.io bridge adapter.
 *
 * The provider's public app currently requires an interactive wallet and does
 * not expose a safe transaction-building API. Accordingly, buildBridge returns
 * an explicit non-signable BridgeHandoff, never fabricated calldata or a false
 * settlement result.
 */
export class WxmrBridgeAdapter implements BridgeAdapter {
  readonly category = "bridge" as const;
  readonly provider = WXMR_PROVIDER;
  readonly enabled = true;

  private readonly rpcUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly randomId: () => string;
  private readonly rpcTimeoutMs: number;
  private readonly getTrustedXmrUsdPrice: () => Promise<number | null>;
  private readonly sessions = new Map<string, { session: BridgeSession; expiresAt: number }>();

  constructor(options: WxmrBridgeAdapterOptions = {}) {
    this.rpcUrl = assertRpcUrl(options.rpcUrl?.trim() || DEFAULT_SOLANA_RPC_URL);
    this.fetchFn = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = options.now ?? (() => Date.now());
    this.randomId = options.randomId ?? (() => crypto.randomUUID());
    this.rpcTimeoutMs = options.rpcTimeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
    this.getTrustedXmrUsdPrice =
      options.getTrustedXmrUsdPrice ?? (() => this.fetchTrustedXmrUsdPrice());
    if (!Number.isSafeInteger(this.rpcTimeoutMs) || this.rpcTimeoutMs <= 0) {
      throw new Error("rpcTimeoutMs must be a positive integer");
    }
  }

  private async fetchPriceJson(url: string, source: string): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.rpcTimeoutMs);
    let response: Response;
    try {
      response = await this.fetchFn(url, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
    } catch {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        `${source} XMR/USD pricing was unavailable; bridge authorization failed closed.`,
      );
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        `${source} XMR/USD pricing returned HTTP ${response.status}; bridge authorization failed closed.`,
      );
    }
    try {
      return await response.json();
    } catch {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        `${source} XMR/USD pricing returned invalid JSON; bridge authorization failed closed.`,
      );
    }
  }

  private async fetchTrustedXmrUsdPrice(): Promise<number> {
    const [krakenPayload, coinGeckoPayload] = await Promise.all([
      this.fetchPriceJson(KRAKEN_XMR_USD_URL, "Kraken"),
      this.fetchPriceJson(COINGECKO_XMR_USD_URL, "CoinGecko"),
    ]);

    if (!isRecord(krakenPayload) || !Array.isArray(krakenPayload.error)) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "Kraken XMR/USD pricing had an invalid response shape; bridge authorization failed closed.",
      );
    }
    const krakenResult = krakenPayload.result;
    const krakenEntries = isRecord(krakenResult) ? Object.values(krakenResult) : [];
    const krakenTicker = krakenEntries.length === 1 ? krakenEntries[0] : undefined;
    const ask = isRecord(krakenTicker) ? krakenTicker.a : undefined;
    const krakenPrice = Array.isArray(ask) ? Number(ask[0]) : Number.NaN;
    if (krakenPayload.error.length !== 0 || !Number.isFinite(krakenPrice) || krakenPrice <= 0) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "Kraken XMR/USD pricing could not be verified; bridge authorization failed closed.",
      );
    }

    const coinGeckoMonero = isRecord(coinGeckoPayload) ? coinGeckoPayload.monero : undefined;
    const coinGeckoPrice = isRecord(coinGeckoMonero) ? coinGeckoMonero.usd : undefined;
    const coinGeckoUpdatedAt = isRecord(coinGeckoMonero)
      ? coinGeckoMonero.last_updated_at
      : undefined;
    const coinGeckoAge =
      typeof coinGeckoUpdatedAt === "number"
        ? this.now() - coinGeckoUpdatedAt * 1_000
        : Number.POSITIVE_INFINITY;
    if (
      typeof coinGeckoPrice !== "number" ||
      !Number.isFinite(coinGeckoPrice) ||
      coinGeckoPrice <= 0 ||
      !Number.isSafeInteger(coinGeckoUpdatedAt) ||
      coinGeckoAge < -PRICE_FUTURE_TOLERANCE_MS ||
      coinGeckoAge > PRICE_MAX_AGE_MS
    ) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "CoinGecko XMR/USD pricing was invalid or stale; bridge authorization failed closed.",
      );
    }

    const higherPrice = Math.max(krakenPrice, coinGeckoPrice);
    const lowerPrice = Math.min(krakenPrice, coinGeckoPrice);
    if ((higherPrice - lowerPrice) / higherPrice > PRICE_MAX_DIVERGENCE_RATIO) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "Independent XMR/USD price sources disagreed; bridge authorization failed closed.",
      );
    }
    // Taking the higher independent observation is intentionally conservative:
    // one low feed cannot reduce the policy notional and bypass a spend cap.
    return higherPrice;
  }

  private async fetchSolanaRpc(method: string, params: unknown[]): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.rpcTimeoutMs);
    let response: Response;
    try {
      response = await this.fetchFn(this.rpcUrl, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "steward-wxmr-fee",
          method,
          params,
        }),
        signal: controller.signal,
      });
    } catch {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge fee could not be verified from Solana RPC; try again later.",
      );
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        `The wxmr bridge fee RPC returned HTTP ${response.status}; try again later.`,
      );
    }

    try {
      return await response.json();
    } catch {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge fee RPC returned invalid JSON.",
      );
    }
  }

  private observationSlot(value: unknown): number {
    if (!Number.isSafeInteger(value) || (value as number) < 0) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge fee RPC returned an invalid observation slot.",
      );
    }
    return value as number;
  }

  private accountBytes(account: RpcAccountValue, label: string): Uint8Array {
    if (
      !Array.isArray(account.data) ||
      account.data.length !== 2 ||
      typeof account.data[0] !== "string" ||
      account.data[1] !== "base64"
    ) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        `The wxmr bridge ${label} account did not contain canonical base64 data.`,
      );
    }
    return decodeBase64(account.data[0]);
  }

  private parseGlobalFee(
    account: RpcAccountValue | null | undefined,
    slot: number,
    observedAt: number,
  ): FeeObservation {
    if (!account || account.owner !== WXMR_BRIDGE_PROGRAM_ID) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge config account could not be verified.",
      );
    }
    const bytes = this.accountBytes(account, "config");
    if (
      bytes.length < BRIDGE_CONFIG_LEGACY_LENGTH ||
      !equalBytes(bytes.slice(0, 8), BRIDGE_CONFIG_DISCRIMINATOR) ||
      !equalBytes(
        bytes.slice(BRIDGE_CONFIG_MINT_OFFSET, BRIDGE_CONFIG_MINT_OFFSET + 32),
        bs58.decode(MONERO_ON_SOLANA.address),
      )
    ) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge config account layout or mint did not match the audited integration.",
      );
    }
    if (bytes.length < BRIDGE_CONFIG_FEE_OFFSET + 2) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge config fee field was truncated.",
      );
    }
    const feeBps = bytes[BRIDGE_CONFIG_FEE_OFFSET] | (bytes[BRIDGE_CONFIG_FEE_OFFSET + 1] << 8);
    if (feeBps < 0 || feeBps > 10_000) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge config contained an invalid fee.",
      );
    }
    return { feeBps, slot, observedAt };
  }

  private parseOwnerFeeOverride(
    account: RpcAccountValue | null | undefined,
    owner: PublicKey,
    expectedBump: number,
    fallback: FeeObservation,
  ): FeeObservation {
    if (account === null) return fallback;
    if (!account || account.owner !== WXMR_BRIDGE_PROGRAM_ID) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr wallet fee override account could not be verified.",
      );
    }
    const bytes = this.accountBytes(account, "wallet fee override");
    if (
      bytes.length < FEE_OVERRIDE_LENGTH ||
      !equalBytes(bytes.slice(0, 8), FEE_OVERRIDE_DISCRIMINATOR) ||
      !equalBytes(
        bytes.slice(FEE_OVERRIDE_USER_OFFSET, FEE_OVERRIDE_FEE_OFFSET),
        owner.toBytes(),
      ) ||
      bytes[FEE_OVERRIDE_BUMP_OFFSET] !== expectedBump
    ) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr wallet fee override layout did not match the audited integration.",
      );
    }
    const feeBps = bytes[FEE_OVERRIDE_FEE_OFFSET] | (bytes[FEE_OVERRIDE_FEE_OFFSET + 1] << 8);
    if (feeBps < 0 || feeBps > 10_000) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr wallet fee override contained an invalid fee.",
      );
    }
    return { ...fallback, feeBps };
  }

  private async globalWithdrawalFee(): Promise<FeeObservation> {
    const payload = (await this.fetchSolanaRpc("getAccountInfo", [
      WXMR_BRIDGE_CONFIG_ACCOUNT,
      { encoding: "base64", commitment: "confirmed" },
    ])) as RpcAccountInfoResponse;
    if (payload.error) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge config account could not be verified.",
      );
    }
    const slot = this.observationSlot(payload.result?.context?.slot);
    return this.parseGlobalFee(payload.result?.value, slot, this.now());
  }

  private async ownerWithdrawalFee(ownerAddress: string): Promise<{
    global: FeeObservation;
    owner: FeeObservation;
  }> {
    const owner = new PublicKey(ownerAddress);
    const [overridePda, bump] = PublicKey.findProgramAddressSync(
      [new TextEncoder().encode(FEE_OVERRIDE_SEED), owner.toBytes()],
      new PublicKey(WXMR_BRIDGE_PROGRAM_ID),
    );
    const payload = (await this.fetchSolanaRpc("getMultipleAccounts", [
      [WXMR_BRIDGE_CONFIG_ACCOUNT, overridePda.toBase58()],
      { encoding: "base64", commitment: "confirmed" },
    ])) as RpcMultipleAccountsResponse;
    const accounts = payload.result?.value;
    if (payload.error || !Array.isArray(accounts) || accounts.length !== 2) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge and wallet fee accounts could not be verified together.",
      );
    }
    const slot = this.observationSlot(payload.result?.context?.slot);
    const observedAt = this.now();
    const global = this.parseGlobalFee(accounts[0], slot, observedAt);
    const ownerFee = this.parseOwnerFeeOverride(accounts[1], owner, bump, global);
    return { global, owner: ownerFee };
  }

  private async feeObservation(direction: WxmrBridgeDirection): Promise<FeeObservation> {
    return direction === "monero-to-solana"
      ? { feeBps: 0, observedAt: this.now() }
      : this.globalWithdrawalFee();
  }

  async getQuote(request: BridgeQuoteRequest): Promise<WxmrBridgeQuote> {
    const direction = directionFor(request.fromChainId, request.toChainId);
    const expectedTokens = quoteTokens(direction);
    assertToken(request.fromToken, expectedTokens.fromToken, "fromToken");
    assertToken(request.toToken, expectedTokens.toToken, "toToken");
    if (request.slippageBps !== undefined && request.slippageBps !== 0) {
      throw new AdapterValidationError("slippageBps must be 0 for the fixed-rate wxmr bridge");
    }

    const amountIn = assertBaseUnitAmount(request.amount);
    const recipient = assertRecipient(direction, request.recipient);
    const fee = await this.feeObservation(direction);
    const feeAmount = feeFor(BigInt(amountIn), fee.feeBps);
    const amountOut = BigInt(amountIn) - feeAmount;
    const expiresAt = this.now() + QUOTE_TTL_MS;

    return {
      provider: WXMR_PROVIDER,
      quoteId: `wxmr_${this.randomId()}`,
      fromChainId: request.fromChainId,
      toChainId: request.toChainId,
      ...expectedTokens,
      amountIn,
      amountOut: amountOut.toString(),
      // A per-wallet withdrawal override can be anywhere from 0% to 100% and
      // the quote request has no owner yet. Zero is the only honest generic
      // minimum; buildBridge checks the connected owner's effective fee.
      minAmountOut: direction === "solana-to-monero" ? "0" : amountOut.toString(),
      feeAmount: feeAmount.toString(),
      recipient,
      route: [
        {
          bridge: "wxmr.io",
          fromChainId: request.fromChainId,
          toChainId: request.toChainId,
        },
      ],
      slippageBps: 0,
      expiresAt,
      direction,
      executionMode: "external-handoff",
      handoffUrl: WXMR_BRIDGE_URL,
      feeBps: fee.feeBps,
      feeScope: direction === "monero-to-solana" ? "not-applicable" : "global-estimate",
      ...(fee.slot === undefined ? {} : { feeObservedSlot: fee.slot }),
      feeObservedAt: fee.observedAt,
      notices: HANDOFF_NOTICES,
    };
  }

  private async validateQuote(
    input: BridgeQuote,
    suppliedFee?: FeeObservation,
  ): Promise<WxmrBridgeQuote> {
    if (!input || typeof input !== "object") {
      throw new AdapterValidationError("a valid wxmr bridge quote is required");
    }
    if (input.provider !== WXMR_PROVIDER || !input.quoteId?.startsWith("wxmr_")) {
      throw new AdapterValidationError("quote was not created by the wxmr bridge provider");
    }
    assertId(input.quoteId, "quoteId", 256);
    const direction = directionFor(input.fromChainId, input.toChainId);
    if (input.direction !== direction)
      throw new AdapterValidationError("quote direction is invalid");
    const expectedTokens = quoteTokens(direction);
    assertToken(input.fromToken, expectedTokens.fromToken, "fromToken");
    assertToken(input.toToken, expectedTokens.toToken, "toToken");
    if (
      input.fromToken.symbol !== expectedTokens.fromToken.symbol ||
      input.fromToken.decimals !== expectedTokens.fromToken.decimals ||
      input.toToken.symbol !== expectedTokens.toToken.symbol ||
      input.toToken.decimals !== expectedTokens.toToken.decimals
    ) {
      throw new AdapterValidationError("quote token metadata is not canonical");
    }
    const amountIn = assertBaseUnitAmount(input.amountIn, "quote.amountIn");
    assertRecipient(direction, input.recipient);

    const now = this.now();
    if (
      typeof input.expiresAt !== "number" ||
      !Number.isSafeInteger(input.expiresAt) ||
      input.expiresAt <= now ||
      input.expiresAt > now + QUOTE_TTL_MS
    ) {
      throw new AdapterValidationError(
        "quote has expired or has an invalid expiry; request a fresh quote",
      );
    }
    if (
      input.executionMode !== "external-handoff" ||
      input.handoffUrl !== WXMR_BRIDGE_URL ||
      input.slippageBps !== 0
    ) {
      throw new AdapterValidationError("quote execution metadata is invalid");
    }

    const currentFee = suppliedFee ?? (await this.feeObservation(direction));
    if (input.feeBps !== currentFee.feeBps) {
      throw new AdapterValidationError("wxmr bridge fee changed; request a fresh quote");
    }
    const expectedScope = direction === "monero-to-solana" ? "not-applicable" : "global-estimate";
    if (
      input.feeScope !== expectedScope ||
      typeof input.feeObservedAt !== "number" ||
      !Number.isSafeInteger(input.feeObservedAt) ||
      input.feeObservedAt < input.expiresAt - QUOTE_TTL_MS - 1_000 ||
      input.feeObservedAt > input.expiresAt
    ) {
      throw new AdapterValidationError("quote fee observation metadata is invalid");
    }
    const observedSlotIsValid =
      typeof input.feeObservedSlot === "number" &&
      Number.isSafeInteger(input.feeObservedSlot) &&
      input.feeObservedSlot >= 0;
    if (
      (direction === "solana-to-monero" && !observedSlotIsValid) ||
      (direction === "monero-to-solana" && input.feeObservedSlot !== undefined)
    ) {
      throw new AdapterValidationError("quote fee observation slot is invalid");
    }
    if (
      input.notices?.length !== HANDOFF_NOTICES.length ||
      !HANDOFF_NOTICES.every((notice, index) => input.notices?.[index] === notice) ||
      input.route?.length !== 1 ||
      input.route[0]?.bridge !== "wxmr.io" ||
      input.route[0]?.fromChainId !== input.fromChainId ||
      input.route[0]?.toChainId !== input.toChainId
    ) {
      throw new AdapterValidationError("quote route metadata is invalid");
    }
    const expectedFee = feeFor(BigInt(amountIn), currentFee.feeBps);
    const expectedOut = BigInt(amountIn) - expectedFee;
    const expectedMinimum = direction === "solana-to-monero" ? 0n : expectedOut;
    if (
      input.feeAmount !== expectedFee.toString() ||
      input.amountOut !== expectedOut.toString() ||
      input.minAmountOut !== expectedMinimum.toString()
    ) {
      throw new AdapterValidationError("quote amounts do not match the current wxmr bridge fee");
    }
    return input as WxmrBridgeQuote;
  }

  async buildBridge(request: BridgeBuildRequest): Promise<BridgeHandoff> {
    const direction = directionFor(request.quote.fromChainId, request.quote.toChainId);
    const recipient = assertRecipient(direction, request.quote.recipient);
    const owner = assertOwner(direction, request.owner, recipient);
    const now = this.now();
    if (
      !Number.isSafeInteger(request.quote.expiresAt) ||
      request.quote.expiresAt <= now ||
      request.quote.expiresAt > now + QUOTE_TTL_MS
    ) {
      throw new AdapterValidationError(
        "quote has expired or has an invalid expiry; request a fresh quote",
      );
    }
    const ownerFees =
      direction === "solana-to-monero" ? await this.ownerWithdrawalFee(owner) : undefined;
    const quote = await this.validateQuote(request.quote, ownerFees?.global);
    const effectiveFee = ownerFees?.owner ?? {
      feeBps: quote.feeBps,
      ...(quote.feeObservedSlot === undefined ? {} : { slot: quote.feeObservedSlot }),
      observedAt: quote.feeObservedAt,
    };
    const xmrUsdPrice = await this.getTrustedXmrUsdPrice();
    if (xmrUsdPrice === null || !Number.isFinite(xmrUsdPrice) || xmrUsdPrice <= 0) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "A trusted XMR/USD price was unavailable, so bridge policy authorization failed closed.",
      );
    }
    const rawEstimatedUsd = (Number(BigInt(quote.amountIn)) / XMR_ATOMIC_UNITS) * xmrUsdPrice;
    if (!Number.isFinite(rawEstimatedUsd) || rawEstimatedUsd <= 0) {
      throw new AdapterProviderError(
        "bridge",
        WXMR_PROVIDER,
        "The wxmr bridge notional could not be valued safely.",
      );
    }
    // Policy values are represented as JS numbers throughout Steward. Round up
    // to the next cent so atomic-unit conversion cannot shave value from the
    // trusted notional near a configured policy boundary.
    const estimatedUsd = Math.ceil(rawEstimatedUsd * 100) / 100;
    return {
      kind: "external-handoff",
      category: "bridge",
      provider: WXMR_PROVIDER,
      quoteId: quote.quoteId,
      direction: quote.direction,
      url: WXMR_BRIDGE_URL,
      fromChainId: quote.fromChainId,
      toChainId: quote.toChainId,
      amountIn: quote.amountIn,
      estimatedUsd,
      recipient: quote.recipient,
      recipientSensitive: quote.direction === "solana-to-monero",
      expiresAt: quote.expiresAt,
      feeBps: effectiveFee.feeBps,
      feeScope: quote.direction === "solana-to-monero" ? "owner-observed" : "not-applicable",
      ...(effectiveFee.slot === undefined ? {} : { feeObservedSlot: effectiveFee.slot }),
      feeObservedAt: effectiveFee.observedAt,
      notices: quote.notices,
    };
  }

  async createSession(
    input: BridgeQuote,
    owner: { tenantId: string; userId: string },
  ): Promise<BridgeSession> {
    const quote = await this.validateQuote(input);
    const tenantId = assertId(owner?.tenantId, "tenantId", 128);
    const userId = assertId(owner?.userId, "userId", 128);
    const session: BridgeSession = {
      id: `wxmr_bridge_${this.randomId()}`,
      provider: WXMR_PROVIDER,
      tenantId,
      userId,
      quoteId: quote.quoteId,
      status: "created",
      fromChainId: quote.fromChainId,
      toChainId: quote.toChainId,
      recipient: quote.recipient,
      createdAt: this.now(),
      direction: quote.direction,
      executionMode: "external-handoff",
      recipientSensitive: quote.direction === "solana-to-monero",
      notices: quote.notices,
      expiresAt: quote.expiresAt,
    };
    this.pruneSessions();
    if (this.sessions.size >= MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value;
      if (oldest !== undefined) this.sessions.delete(oldest);
    }
    this.sessions.set(session.id, { session, expiresAt: quote.expiresAt });
    return session;
  }

  async getSession(id: string): Promise<BridgeSession | null> {
    this.pruneSessions();
    return this.sessions.get(assertId(id, "sessionId", 256))?.session ?? null;
  }

  private pruneSessions(): void {
    const now = this.now();
    for (const [id, entry] of this.sessions) {
      if (entry.expiresAt <= now) this.sessions.delete(id);
    }
  }
}
