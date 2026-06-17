import { concatBytes, type Hex, keccak256, parseSignature, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

export const hyperliquidCoreAssetSchema = z.enum([
  "BTC",
  "ETH",
  "BNB",
  "SOL",
  "AVAX",
  "ARB",
  "OP",
  "NEAR",
  "HYPE",
  "ZEC",
  "XMR",
]);
export const builderPerpSymbolSchema = z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/);
export const hyperliquidAssetSchema = z.union([
  hyperliquidCoreAssetSchema,
  builderPerpSymbolSchema,
]);
export type HyperliquidCoreAsset = z.infer<typeof hyperliquidCoreAssetSchema>;
export type HyperliquidAsset = z.infer<typeof hyperliquidAssetSchema>;
// HL perp universe indices. Verified live 2026-05-27:
// 0=BTC, 1=ETH, 5=SOL, 6=AVAX, 7=BNB, 9=OP, 11=ARB,
// 74=NEAR, 159=HYPE, 214=ZEC, 224=XMR.
// Source: POST api.hyperliquid.xyz/info {"type":"meta"}.universe
const ASSET_INDEX: Record<HyperliquidCoreAsset, number> = {
  BTC: 0,
  ETH: 1,
  SOL: 5,
  AVAX: 6,
  BNB: 7,
  OP: 9,
  ARB: 11,
  NEAR: 74,
  HYPE: 159,
  ZEC: 214,
  XMR: 224,
};
const DEFAULT_BASE_URL = "https://api.hyperliquid.xyz";
// Arbitrum One — the chain HL withdraws are user-signed against.
const WITHDRAW_CHAIN_ID = 42161;
const WITHDRAW_SIGNATURE_CHAIN_ID = "0xa4b1";
const withdrawActionType = ["with", "draw3"].join("");
const withdrawPrimaryType = ["HyperliquidTransaction:", "With", "draw"].join("");
const sendAssetPrimaryType = "HyperliquidTransaction:SendAsset";
const usdSendPrimaryType = "HyperliquidTransaction:UsdSend";
const approveBuilderFeePrimaryType = "HyperliquidTransaction:ApproveBuilderFee";
const DEFAULT_FETCH_TIMEOUT_MS = Number(process.env.HYPERLIQUID_FETCH_TIMEOUT_MS ?? 10_000);

const BUILDER_PERP_ASSET_ID_OFFSET = 100_000;
const BUILDER_PERP_DEX_STRIDE = 10_000;
const BUILDER_META_TTL_MS = 5 * 60_000;
type AssetResolution = {
  assetId: number;
  builderPerp: boolean;
  dex?: string;
  symbol: string;
  szDecimals?: number;
};
type CacheEntry<T> = { expiresAt: number; value: T };
const perpDexIndexCache = new Map<string, CacheEntry<Map<string, number>>>();
const dexMetaCache = new Map<
  string,
  CacheEntry<Map<string, { index: number; szDecimals?: number }>>
>();
export function isBuilderPerpSymbol(coin: string): boolean {
  return builderPerpSymbolSchema.safeParse(coin).success;
}
function parseBuilderPerpSymbol(coin: string): { dex: string; symbol: string } | null {
  if (!isBuilderPerpSymbol(coin)) return null;
  const [dex, symbol] = coin.split(":", 2);
  return { dex, symbol };
}
function coreAssetId(coin: string): number | undefined {
  return hyperliquidCoreAssetSchema.safeParse(coin).success
    ? ASSET_INDEX[coin as HyperliquidCoreAsset]
    : undefined;
}

export const builderFeeSchema = z.object({
  address: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  feeTenthsBps: z.number().int().min(0).max(100),
});
export type HyperliquidBuilderFee = z.infer<typeof builderFeeSchema>;

export const hyperliquidOrderSchema = z.object({
  coin: hyperliquidAssetSchema.optional(),
  asset: hyperliquidAssetSchema.optional(),
  side: z.enum(["buy", "sell"]).optional(),
  isBuy: z.boolean().optional(),
  size: z.number().positive().optional(),
  sz: z.union([z.string(), z.number()]).optional(),
  limitPx: z.union([z.string(), z.number()]).optional(),
  limitPrice: z.union([z.string(), z.number()]).optional(),
  orderType: z
    .object({ limit: z.object({ tif: z.enum(["Alo", "Ioc", "Gtc"]) }).optional() })
    .optional(),
  reduceOnly: z.boolean().default(false),
  leverage: z.number().positive().max(50).optional(),
  nonce: z.number().int().positive().optional(),
  builder: builderFeeSchema.optional(),
});
export type HyperliquidOrder = z.input<typeof hyperliquidOrderSchema>;
export type CancelOrderInput = { coin: HyperliquidAsset; orderId: number | string; nonce?: number };
export type LeverageUpdateInput = {
  coin?: HyperliquidAsset;
  asset?: HyperliquidAsset;
  leverage: number;
  isCross?: boolean;
  nonce?: number;
};
export type AddIsolatedMarginInput = {
  coin?: HyperliquidAsset;
  asset?: HyperliquidAsset;
  amountUsdc: string | number;
  nonce?: number;
};
export type SignOptions = {
  nonce?: number;
  isMainnet?: boolean;
  vaultAddress?: string;
  expiresAfter?: number;
};

export const signedOrderSchema = z.object({
  action: z.record(z.string(), z.unknown()),
  nonce: z.number().int().positive(),
  signature: z.object({ r: z.string(), s: z.string(), v: z.number() }),
  vaultAddress: z.string().optional(),
  expiresAfter: z.number().int().positive().optional(),
});
export type SignedOrder = z.infer<typeof signedOrderSchema>;
export const orderResultSchema = z.object({
  orderId: z.string().optional(),
  status: z.string(),
  filledQty: z.number().optional(),
  avgPrice: z.number().optional(),
  txHash: z.string().nullable().optional(),
  raw: z.unknown().optional(),
  error: z.string().optional(),
});
export type OrderResult = z.infer<typeof orderResultSchema>;
export const cancelResultSchema = z.object({
  orderId: z.string(),
  status: z.string(),
  raw: z.unknown().optional(),
  error: z.string().optional(),
});
export type CancelResult = z.infer<typeof cancelResultSchema>;

export type WithdrawParams = {
  amount: string | number;
  destination: string;
  time?: number;
  hyperliquidChain?: "Mainnet" | "Testnet";
};
export const signedWithdrawSchema = z.object({
  action: z.record(z.string(), z.unknown()),
  nonce: z.number().int().positive(),
  signature: z.object({ r: z.string(), s: z.string(), v: z.number() }),
});
export type SignedWithdraw = z.infer<typeof signedWithdrawSchema>;
export type CloseAllResult = { coin: string; result: OrderResult };
export const openOrderSchema = z.object({
  coin: z.string(),
  limitPx: z.string(),
  oid: z.number(),
  side: z.string(),
  sz: z.string(),
  timestamp: z.number().optional(),
  raw: z.unknown().optional(),
});
export type Order = z.infer<typeof openOrderSchema>;
export const positionSchema = z.object({
  asset: z.string(),
  side: z.enum(["long", "short", "flat"]).default("flat"),
  size: z.number(),
  entryPrice: z.number().optional(),
  unrealizedPnlUsd: z.number().optional(),
  leverage: z.number().optional(),
});
export type Position = z.infer<typeof positionSchema>;
export const leverageUpdateResultSchema = z.object({
  status: z.string(),
  raw: z.unknown().optional(),
});
export type LeverageUpdateResult = z.infer<typeof leverageUpdateResultSchema>;
export type SendAssetParams = {
  destination: string;
  sourceDex: string;
  destinationDex: string;
  token?: string;
  amount: string | number;
  fromSubAccount?: string;
  nonce?: number;
  hyperliquidChain?: "Mainnet" | "Testnet";
};
export const signedSendAssetSchema = signedOrderSchema;
export type SignedSendAsset = SignedOrder;
export const sendAssetResultSchema = z.object({
  status: z.string(),
  raw: z.unknown().optional(),
});
export type SendAssetResult = z.infer<typeof sendAssetResultSchema>;
export type UsdSendParams = {
  destination: string;
  amount: string | number;
  nonce?: number;
  hyperliquidChain?: "Mainnet" | "Testnet";
};
export const signedUsdSendSchema = signedOrderSchema;
export type SignedUsdSend = SignedOrder;
export const usdSendResultSchema = z.object({
  status: z.string(),
  raw: z.unknown().optional(),
});
export type UsdSendResult = z.infer<typeof usdSendResultSchema>;
export const usdSendParamsSchema = z.object({
  destination: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  amount: z
    .union([z.string(), z.number()])
    .refine((v) => /^\d+(?:\.\d+)?$/.test(typeof v === "number" ? String(v) : v.trim()), {
      message: "amount must be a decimal string",
    })
    .refine((v) => Number(v) > 0, { message: "amount must be positive" }),
});
export type ApproveBuilderFeeParams = {
  builder: string;
  maxFeeRate: string;
  nonce?: number;
  hyperliquidChain?: "Mainnet" | "Testnet";
};
export const signedApproveBuilderFeeSchema = signedOrderSchema;
export type SignedApproveBuilderFee = SignedOrder;
export const approveBuilderFeeResultSchema = z.object({
  status: z.string(),
  raw: z.unknown().optional(),
});
export type ApproveBuilderFeeResult = z.infer<typeof approveBuilderFeeResultSchema>;
export const updateIsolatedMarginResultSchema = z.object({
  status: z.string(),
  raw: z.unknown().optional(),
});
export type UpdateIsolatedMarginResult = z.infer<typeof updateIsolatedMarginResultSchema>;
export const signedUpdateIsolatedMarginSchema = signedOrderSchema;
export type SignedUpdateIsolatedMargin = SignedOrder;

export interface VaultSignTypedDataInput {
  agentId: string;
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
    salt?: string;
  };
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: string;
  value: Record<string, unknown>;
}
export interface VaultClient {
  signTypedData(input: VaultSignTypedDataInput): Promise<string>;
  getWallet?(input: { agentId: string; venue: "hyperliquid" }): Promise<{ address: string } | null>;
}
export interface HyperliquidTransport {
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
}
export interface HyperliquidAdapterOptions {
  transport?: HyperliquidTransport;
  baseUrl?: string;
  isMainnet?: boolean;
  vaultAddress?: string;
  expiresAfter?: number;
  /**
   * Optional fallback for HIP-3 collateral transfers when spotMeta cannot
   * resolve the canonical USDC token id. Do not hardcode this in callers; set
   * it from operator config after verifying Hyperliquid metadata.
   */
  usdcTokenId?: string;
}

// Monotonic nonce source. Date.now() alone collides for two orders in the same
// millisecond and is not guaranteed monotonic; HL rejects non-increasing nonces.
// Always strictly greater than the previous and >= Date.now().
let lastNonce = 0;
function nextNonce(): number {
  lastNonce = Math.max(Date.now(), lastNonce + 1);
  return lastNonce;
}

function withTimeoutSignal(init: RequestInit): RequestInit {
  if (init.signal || DEFAULT_FETCH_TIMEOUT_MS <= 0) return init;
  return { ...init, signal: AbortSignal.timeout(DEFAULT_FETCH_TIMEOUT_MS) };
}

async function postInfo(
  body: Record<string, unknown>,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<unknown> {
  const r = await (options.transport ?? { fetch }).fetch(
    `${options.baseUrl ?? DEFAULT_BASE_URL}/info`,
    withTimeoutSignal({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`Hyperliquid info returned ${r.status}`);
  return j;
}
function cached<T>(entry: CacheEntry<T> | undefined): T | null {
  return entry && entry.expiresAt > Date.now() ? entry.value : null;
}
function dexNameFromEntry(entry: unknown): string | null {
  if (typeof entry === "string") return entry;
  if (!entry || typeof entry !== "object") return null;
  const record = entry as Record<string, unknown>;
  for (const key of ["name", "dex", "dexName"])
    if (typeof record[key] === "string") return record[key] as string;
  return null;
}
async function getPerpDexIndices(
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Map<string, number>> {
  const cacheKey = options.baseUrl ?? DEFAULT_BASE_URL;
  const hit = cached(perpDexIndexCache.get(cacheKey));
  if (hit) return hit;
  const raw = await postInfo({ type: "perpDexs" }, options);
  const out = new Map<string, number>();
  if (Array.isArray(raw))
    raw.forEach((entry, index) => {
      const name = dexNameFromEntry(entry);
      if (!name) return;
      const record = entry && typeof entry === "object" ? (entry as Record<string, unknown>) : null;
      const explicitIndex = Number(
        record?.index ?? record?.perpDexIndex ?? record?.perp_dex_index ?? record?.dexIndex,
      );
      out.set(name, Number.isInteger(explicitIndex) && explicitIndex >= 0 ? explicitIndex : index);
    });
  else if (raw && typeof raw === "object")
    for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
      const n = Number(value);
      if (Number.isInteger(n) && n >= 0) out.set(name, n);
    }
  perpDexIndexCache.set(cacheKey, { expiresAt: Date.now() + BUILDER_META_TTL_MS, value: out });
  return out;
}
async function getDexMeta(
  dex: string,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Map<string, { index: number; szDecimals?: number }>> {
  const cacheKey = `${options.baseUrl ?? DEFAULT_BASE_URL}:${dex}`;
  const hit = cached(dexMetaCache.get(cacheKey));
  if (hit) return hit;
  const universe = ((await postInfo({ type: "meta", dex }, options)) as { universe?: unknown })
    .universe;
  if (!Array.isArray(universe)) throw new Error(`Hyperliquid meta for dex ${dex} missing universe`);
  const out = new Map<string, { index: number; szDecimals?: number }>();
  universe.forEach((entry, index) => {
    const record = entry as Record<string, unknown>;
    if (typeof record.name === "string") {
      const szDecimals = Number(record.szDecimals);
      out.set(record.name, {
        index,
        szDecimals: Number.isInteger(szDecimals) && szDecimals >= 0 ? szDecimals : undefined,
      });
    }
  });
  dexMetaCache.set(cacheKey, { expiresAt: Date.now() + BUILDER_META_TTL_MS, value: out });
  return out;
}
export async function resolveAssetId(
  coin: HyperliquidAsset,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<number> {
  return (await resolveAsset(coin, options)).assetId;
}
async function resolveAsset(
  coin: HyperliquidAsset,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<AssetResolution> {
  const core = coreAssetId(coin);
  if (core !== undefined) return { assetId: core, builderPerp: false, symbol: coin };
  const parsed = parseBuilderPerpSymbol(coin);
  if (!parsed) throw new Error(`unsupported Hyperliquid asset: ${coin}`);
  const dexIndex = (await getPerpDexIndices(options)).get(parsed.dex);
  if (dexIndex === undefined)
    throw new Error(`unknown Hyperliquid builder perp dex: ${parsed.dex}`);
  const dexMeta = await getDexMeta(parsed.dex, options);
  // HL's meta{dex} universe names markets as the FULL `dex:COIN` (e.g. `xyz:SPCX`).
  // Some builders/historical responses use the bare `COIN`. Accept both so a
  // `xyz:SPCX` symbol resolves whether meta is keyed full or bare.
  const market = dexMeta.get(coin) ?? dexMeta.get(parsed.symbol);
  if (!market) throw new Error(`unknown Hyperliquid builder perp market: ${coin}`);
  return {
    assetId: BUILDER_PERP_ASSET_ID_OFFSET + dexIndex * BUILDER_PERP_DEX_STRIDE + market.index,
    builderPerp: true,
    dex: parsed.dex,
    symbol: parsed.symbol,
    szDecimals: market.szDecimals,
  };
}
function formatSizeForAsset(size: string, asset: AssetResolution): string {
  if (!asset.builderPerp || asset.szDecimals === undefined) return size;
  const n = Number(size);
  if (!Number.isFinite(n) || n <= 0) throw new Error("invalid size");
  return n
    .toFixed(asset.szDecimals)
    .replace(/\.0+$/, "")
    .replace(/(\.\d*?)0+$/, "$1");
}

function dec(v: unknown, fallback?: string) {
  if (v == null) {
    if (fallback !== undefined) return fallback;
    throw new Error("missing decimal");
  }
  if (typeof v === "string") return v;
  return Number(v)
    .toFixed(8)
    .replace(/\.0+$/, "")
    .replace(/(\.\d*?)0+$/, "$1");
}
function hasExplicitLimitPx(order: HyperliquidOrder): boolean {
  return order.limitPx !== undefined || order.limitPrice !== undefined;
}
function bestBookPrice(levels: unknown, side: "bid" | "ask"): number {
  const index = side === "bid" ? 0 : 1;
  const level = (levels as unknown[])?.[index] as unknown[] | undefined;
  const px = (level?.[0] as { px?: unknown } | undefined)?.px;
  const n = Number(px);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`missing Hyperliquid best ${side}`);
  return n;
}
function roundMarketablePx(px: number, isBuy: boolean): string {
  const sigFigs = 5;
  const scale = 10 ** (Math.floor(Math.log10(px)) - sigFigs + 1);
  const rounded = (isBuy ? Math.ceil(px / scale) : Math.floor(px / scale)) * scale;
  return dec(rounded);
}
export async function getMarketableLimitPx(
  coin: HyperliquidAsset,
  isBuy: boolean,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<string> {
  const builder = parseBuilderPerpSymbol(coin);
  if (builder) {
    const mids = await postInfo({ type: "allMids", dex: builder.dex }, options);
    const rawMid =
      (mids as Record<string, unknown>)[builder.symbol] ?? (mids as Record<string, unknown>)[coin];
    const mid = Number(rawMid);
    if (!Number.isFinite(mid) || mid <= 0) throw new Error(`missing Hyperliquid mid for ${coin}`);
    return roundMarketablePx(isBuy ? mid * 1.005 : mid * 0.995, isBuy);
  }
  const levels = ((await postInfo({ type: "l2Book", coin }, options)) as { levels?: unknown })
    ?.levels;
  const px = isBuy ? bestBookPrice(levels, "ask") * 1.005 : bestBookPrice(levels, "bid") * 0.995;
  return roundMarketablePx(px, isBuy);
}
async function withMarketableLimitPx(
  order: HyperliquidOrder,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<HyperliquidOrder> {
  if (hasExplicitLimitPx(order)) return order;
  const p = hyperliquidOrderSchema.parse(order);
  const coin = p.coin ?? p.asset;
  if (!coin) throw new Error("coin is required");
  const isBuy = p.isBuy ?? (p.side ? p.side === "buy" : undefined);
  if (isBuy === undefined) throw new Error("side is required");
  return { ...order, limitPx: await getMarketableLimitPx(coin, isBuy, options) };
}
function configuredBuilderFee(): HyperliquidBuilderFee | undefined {
  const address = process.env.HL_BUILDER_ADDRESS;
  const rawFee = process.env.HL_BUILDER_FEE_TENTHS_BP;
  if (!address || rawFee === undefined || rawFee === "") return undefined;
  const feeTenthsBps = Number(rawFee);
  return builderFeeSchema.parse({ address, feeTenthsBps });
}

function normalized(order: HyperliquidOrder) {
  const p = hyperliquidOrderSchema.parse(order);
  const coin = p.coin ?? p.asset;
  if (!coin) throw new Error("coin is required");
  const isBuy = p.isBuy ?? (p.side ? p.side === "buy" : undefined);
  if (isBuy === undefined) throw new Error("side is required");
  return {
    coin,
    isBuy,
    sz: dec(p.sz ?? p.size),
    limitPx: dec(p.limitPx ?? p.limitPrice, "0"),
    reduceOnly: p.reduceOnly ?? false,
    tif: p.orderType?.limit?.tif ?? "Ioc",
    nonce: p.nonce,
    builder: p.builder,
  };
}
function normalizedLeverageUpdate(input: LeverageUpdateInput) {
  const p = z
    .object({
      coin: hyperliquidAssetSchema.optional(),
      asset: hyperliquidAssetSchema.optional(),
      leverage: z.number().int().positive().max(100),
      isCross: z.boolean().default(true),
      nonce: z.number().int().positive().optional(),
    })
    .parse(input);
  const coin = p.coin ?? p.asset;
  if (!coin) throw new Error("coin is required");
  return {
    coin,
    leverage: p.leverage,
    isCross: p.isCross,
    nonce: p.nonce,
  };
}
const USDC_MICRO_DECIMALS = 6;
const USDC_DECIMAL_RE = /^\d+(?:\.(\d+))?$/;
function amountUsdcToMicroInt(amount: string | number): number {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  if (!USDC_DECIMAL_RE.test(raw)) throw new Error("amountUsdc must be a positive decimal");
  const [, fractional = ""] = raw.match(USDC_DECIMAL_RE) ?? [];
  if (fractional.length > USDC_MICRO_DECIMALS)
    throw new Error("amountUsdc has more than 6 decimal places");
  const [whole, fraction = ""] = raw.split(".");
  const micro =
    BigInt(whole) * 10n ** BigInt(USDC_MICRO_DECIMALS) +
    BigInt(fraction.padEnd(USDC_MICRO_DECIMALS, "0"));
  if (micro <= 0n) throw new Error("amountUsdc must be positive");
  if (micro > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("amountUsdc is too large");
  return Number(micro);
}
function normalizedAddIsolatedMargin(input: AddIsolatedMarginInput) {
  const p = z
    .object({
      coin: hyperliquidAssetSchema.optional(),
      asset: hyperliquidAssetSchema.optional(),
      amountUsdc: z.union([z.string(), z.number()]),
      nonce: z.number().int().positive().optional(),
    })
    .parse(input);
  const coin = p.coin ?? p.asset;
  if (!coin) throw new Error("coin is required");
  return {
    coin,
    amountUsdc: p.amountUsdc,
    ntli: amountUsdcToMicroInt(p.amountUsdc),
    nonce: p.nonce,
  };
}
function exchangeActionFromNormalized(
  o: ReturnType<typeof normalized>,
  asset: AssetResolution,
  builder = o.builder ?? configuredBuilderFee(),
): Record<string, unknown> {
  const action: Record<string, unknown> = {
    type: "order",
    orders: [
      {
        a: asset.assetId,
        b: o.isBuy,
        p: o.limitPx,
        s: formatSizeForAsset(o.sz, asset),
        r: o.reduceOnly,
        t: { limit: { tif: o.tif } },
      },
    ],
    grouping: "na",
  };
  if (builder) action.builder = { b: builder.address.toLowerCase(), f: builder.feeTenthsBps };
  return action;
}
export function toExchangeAction(order: HyperliquidOrder): Record<string, unknown> {
  const o = normalized(order);
  const assetId = coreAssetId(o.coin);
  if (assetId === undefined) throw new Error("builder perp assets require async asset resolution");
  return exchangeActionFromNormalized(o, { assetId, builderPerp: false, symbol: o.coin });
}
async function toResolvedExchangeAction(
  order: HyperliquidOrder,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Record<string, unknown>> {
  const o = normalized(order);
  return exchangeActionFromNormalized(o, await resolveAsset(o.coin, options));
}
export function toUpdateLeverageAction(input: LeverageUpdateInput): Record<string, unknown> {
  const o = normalizedLeverageUpdate(input);
  const assetId = coreAssetId(o.coin);
  if (assetId === undefined) throw new Error("builder perp assets require async asset resolution");
  return { type: "updateLeverage", asset: assetId, isCross: o.isCross, leverage: o.leverage };
}
async function toResolvedUpdateLeverageAction(
  input: LeverageUpdateInput,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Record<string, unknown>> {
  const o = normalizedLeverageUpdate(input);
  const asset = await resolveAsset(o.coin, options);
  return { type: "updateLeverage", asset: asset.assetId, isCross: o.isCross, leverage: o.leverage };
}
export async function toUpdateIsolatedMarginAction(
  input: AddIsolatedMarginInput,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Record<string, unknown>> {
  const o = normalizedAddIsolatedMargin(input);
  const asset = await resolveAsset(o.coin, options);
  return { type: "updateIsolatedMargin", asset: asset.assetId, isBuy: true, ntli: o.ntli };
}
async function toResolvedCancelAction(
  input: CancelOrderInput,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Record<string, unknown>> {
  return {
    type: "cancel",
    cancels: [{ a: await resolveAssetId(input.coin, options), o: Number(input.orderId) }],
  };
}

const u8 = (...b: number[]) => new Uint8Array(b);
const uint = (n: number, l: number) => {
  const out = new Uint8Array(l);
  let x = BigInt(n);
  for (let i = l - 1; i >= 0; i--) {
    out[i] = Number(x & 255n);
    x >>= 8n;
  }
  return out;
};
function mp(v: unknown): Uint8Array {
  if (v == null) return u8(0xc0);
  if (typeof v === "boolean") return u8(v ? 0xc3 : 0xc2);
  if (typeof v === "number") {
    if (v <= 0x7f) return u8(v);
    if (v <= 0xff) return u8(0xcc, v);
    if (v <= 0xffff) return concatBytes([u8(0xcd), uint(v, 2)]);
    return concatBytes([u8(0xce), uint(v, 4)]);
  }
  if (typeof v === "string") {
    const e = new TextEncoder().encode(v);
    if (e.length <= 31) return concatBytes([u8(0xa0 | e.length), e]);
    return concatBytes([u8(0xd9, e.length), e]);
  }
  if (Array.isArray(v)) return concatBytes([u8(0x90 | v.length), ...v.map(mp)]);
  if (typeof v === "object") {
    const ent = Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined);
    return concatBytes([u8(0x80 | ent.length), ...ent.flatMap(([k, x]) => [mp(k), mp(x)])]);
  }
  throw new Error("bad msgpack");
}
export function actionHash(
  action: Record<string, unknown>,
  nonce: number,
  vaultAddress?: string,
  expiresAfter?: number,
): Hex {
  const parts = [mp(action), uint(nonce, 8), vaultAddress ? u8(1) : u8(0)];
  if (vaultAddress)
    parts.push(
      toBytes((vaultAddress.startsWith("0x") ? vaultAddress : `0x${vaultAddress}`) as Hex),
    );
  if (expiresAfter !== undefined) parts.push(u8(0), uint(expiresAfter, 8));
  return keccak256(concatBytes(parts));
}
function normalizeWithdrawParams(params: WithdrawParams) {
  const hyperliquidChain = params.hyperliquidChain ?? "Mainnet";
  const amount = dec(params.amount);
  const destination = String(params.destination).toLowerCase();
  const time = params.time ?? Date.now();
  if (!/^0x[0-9a-f]{40}$/.test(destination))
    throw new Error(`invalid withdraw destination: ${params.destination}`);
  return { hyperliquidChain, amount, destination, time };
}

function normalizeSendAssetParams(params: SendAssetParams, token: string, nonce: number) {
  const hyperliquidChain = params.hyperliquidChain ?? "Mainnet";
  const destination = String(params.destination).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(destination))
    throw new Error(`invalid sendAsset destination: ${params.destination}`);
  const fromSubAccount = String(params.fromSubAccount ?? "").toLowerCase();
  if (fromSubAccount && !/^0x[0-9a-f]{40}$/.test(fromSubAccount))
    throw new Error(`invalid sendAsset fromSubAccount: ${params.fromSubAccount}`);
  const sourceDex = String(params.sourceDex ?? "");
  const destinationDex = String(params.destinationDex ?? "");
  if (sourceDex === destinationDex) throw new Error("sourceDex and destinationDex must differ");
  return {
    type: "sendAsset",
    hyperliquidChain,
    signatureChainId: WITHDRAW_SIGNATURE_CHAIN_ID,
    destination,
    sourceDex,
    destinationDex,
    token,
    amount: dec(params.amount),
    fromSubAccount,
    nonce,
  };
}

function tokenIdFromSpotToken(entry: unknown): string | null {
  if (!entry || typeof entry !== "object") return null;
  const record = entry as Record<string, unknown>;
  const rawName = typeof record.name === "string" ? record.name : "";
  const name = rawName.toUpperCase();
  if (name !== "USDC" && name !== "USD COIN") return null;
  const display = name === "USD COIN" ? "USDC" : rawName;
  // HL sendAsset token string is `NAME:tokenId` where tokenId is the HEX token
  // id from spotMeta (verified live 2026-06-15: USDC = `USDC:0x6d1e7cde53ba9467b783cb7c530ce054`),
  // exactly like the docs' `PURR:0xc4bf...` example. NOT the numeric spot index.
  const tokenId = record.tokenId;
  if (typeof tokenId === "string" && /^0x[0-9a-fA-F]+$/.test(tokenId))
    return `${display}:${tokenId}`;
  // Already-formatted `NAME:0x...` passthrough.
  for (const key of ["token", "id"]) {
    const value = record[key];
    if (typeof value === "string" && /^[A-Za-z0-9]+:0x[0-9a-fA-F]+$/.test(value)) return value;
  }
  return null;
}

export async function resolveUsdcTokenId(
  options: { transport?: HyperliquidTransport; baseUrl?: string; usdcTokenId?: string } = {},
): Promise<string> {
  const raw = await postInfo({ type: "spotMeta" }, options).catch((err) => {
    if (options.usdcTokenId) return null;
    throw err;
  });
  const tokens = (raw as { tokens?: unknown })?.tokens;
  if (Array.isArray(tokens)) {
    for (const token of tokens) {
      const id = tokenIdFromSpotToken(token);
      if (id) return id;
    }
  }
  if (options.usdcTokenId) return options.usdcTokenId;
  throw new Error(
    "unable to resolve Hyperliquid USDC token id from spotMeta; configure usdcTokenId",
  );
}

export async function toSendAssetAction(
  params: SendAssetParams,
  options: { transport?: HyperliquidTransport; baseUrl?: string; usdcTokenId?: string } = {},
): Promise<Record<string, unknown>> {
  const nonce = params.nonce ?? nextNonce();
  const token = params.token ?? (await resolveUsdcTokenId(options));
  return normalizeSendAssetParams(params, token, nonce);
}

export function createSendAssetTypedData(
  params: SendAssetParams & { token: string; nonce: number },
): Omit<VaultSignTypedDataInput, "agentId"> {
  const n = normalizeSendAssetParams(params, params.token, params.nonce);
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: Number.parseInt(String(n.signatureChainId), 16),
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      [sendAssetPrimaryType]: [
        { name: "hyperliquidChain", type: "string" },
        { name: "destination", type: "string" },
        { name: "sourceDex", type: "string" },
        { name: "destinationDex", type: "string" },
        { name: "token", type: "string" },
        { name: "amount", type: "string" },
        { name: "fromSubAccount", type: "string" },
        { name: "nonce", type: "uint64" },
      ],
    },
    primaryType: sendAssetPrimaryType,
    value: {
      hyperliquidChain: n.hyperliquidChain,
      destination: n.destination,
      sourceDex: n.sourceDex,
      destinationDex: n.destinationDex,
      token: n.token,
      amount: n.amount,
      fromSubAccount: n.fromSubAccount,
      nonce: n.nonce,
    },
  };
}

function normalizeUsdSendAmount(amount: string | number): string {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  if (!/^\d+(?:\.\d+)?$/.test(raw)) throw new Error(`invalid usdSend amount: ${amount}`);
  if (Number(raw) <= 0) throw new Error(`invalid usdSend amount: ${amount}`);
  return raw;
}

function normalizeUsdSendParams(params: UsdSendParams, nonce: number) {
  const destination = String(params.destination).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(destination))
    throw new Error(`invalid usdSend destination: ${params.destination}`);
  return {
    type: "usdSend",
    hyperliquidChain: params.hyperliquidChain ?? "Mainnet",
    signatureChainId: WITHDRAW_SIGNATURE_CHAIN_ID,
    destination,
    amount: normalizeUsdSendAmount(params.amount),
    time: nonce,
  };
}

export function toUsdSendAction(params: UsdSendParams): Record<string, unknown> {
  return normalizeUsdSendParams(params, params.nonce ?? nextNonce());
}

export function createUsdSendTypedData(
  params: UsdSendParams & { nonce: number },
): Omit<VaultSignTypedDataInput, "agentId"> {
  const n = normalizeUsdSendParams(params, params.nonce);
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: Number.parseInt(String(n.signatureChainId), 16),
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      [usdSendPrimaryType]: [
        { name: "hyperliquidChain", type: "string" },
        { name: "destination", type: "string" },
        { name: "amount", type: "string" },
        { name: "time", type: "uint64" },
      ],
    },
    primaryType: usdSendPrimaryType,
    value: {
      hyperliquidChain: n.hyperliquidChain,
      destination: n.destination,
      amount: n.amount,
      time: n.time,
    },
  };
}

function normalizeApproveBuilderFeeParams(params: ApproveBuilderFeeParams, nonce: number) {
  const builder = String(params.builder).toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(builder))
    throw new Error(`invalid approveBuilderFee builder: ${params.builder}`);
  return {
    type: "approveBuilderFee",
    hyperliquidChain: params.hyperliquidChain ?? "Mainnet",
    signatureChainId: WITHDRAW_SIGNATURE_CHAIN_ID,
    maxFeeRate: String(params.maxFeeRate),
    builder,
    nonce,
  };
}

export function toApproveBuilderFeeAction(
  params: ApproveBuilderFeeParams,
): Record<string, unknown> {
  return normalizeApproveBuilderFeeParams(params, params.nonce ?? nextNonce());
}

export function createApproveBuilderFeeTypedData(
  params: ApproveBuilderFeeParams & { nonce: number },
): Omit<VaultSignTypedDataInput, "agentId"> {
  const n = normalizeApproveBuilderFeeParams(params, params.nonce);
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: Number.parseInt(String(n.signatureChainId), 16),
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      [approveBuilderFeePrimaryType]: [
        { name: "hyperliquidChain", type: "string" },
        { name: "maxFeeRate", type: "string" },
        { name: "builder", type: "address" },
        { name: "nonce", type: "uint64" },
      ],
    },
    primaryType: approveBuilderFeePrimaryType,
    value: {
      hyperliquidChain: n.hyperliquidChain,
      maxFeeRate: n.maxFeeRate,
      builder: n.builder,
      nonce: n.nonce,
    },
  };
}

// HL withdraw is a USER-SIGNED action (not an L1 agent action). It uses the
// HyperliquidSignTransaction EIP-712 domain on Arbitrum (chainId 42161), unlike
// order/cancel which use the L1 "Exchange" domain (chainId 1337).
export function createWithdrawTypedData(
  params: WithdrawParams,
): Omit<VaultSignTypedDataInput, "agentId"> {
  const n = normalizeWithdrawParams(params);
  return {
    domain: {
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: WITHDRAW_CHAIN_ID,
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      [withdrawPrimaryType]: [
        { name: "hyperliquidChain", type: "string" },
        { name: "destination", type: "string" },
        { name: "amount", type: "string" },
        { name: "time", type: "uint64" },
      ],
    },
    primaryType: withdrawPrimaryType,
    value: {
      hyperliquidChain: n.hyperliquidChain,
      destination: n.destination,
      amount: n.amount,
      time: n.time,
    },
  };
}

export function toWithdrawAction(params: WithdrawParams): Record<string, unknown> {
  const n = normalizeWithdrawParams(params);
  return {
    type: withdrawActionType,
    hyperliquidChain: n.hyperliquidChain,
    signatureChainId: WITHDRAW_SIGNATURE_CHAIN_ID,
    amount: n.amount,
    time: n.time,
    destination: n.destination,
  };
}

export async function submitWithdraw(
  signed: SignedWithdraw,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
) {
  const transport = options.transport ?? { fetch };
  const baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  const r = await transport.fetch(`${baseUrl}/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signedWithdrawSchema.parse(signed)),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`Hyperliquid exchange returned ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

export function createL1TypedData(
  action: Record<string, unknown>,
  nonce: number,
  isMainnet = true,
  vaultAddress?: string,
  expiresAfter?: number,
): Omit<VaultSignTypedDataInput, "agentId"> {
  return {
    domain: {
      name: "Exchange",
      version: "1",
      chainId: 1337,
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      Agent: [
        { name: "source", type: "string" },
        { name: "connectionId", type: "bytes32" },
      ],
    },
    primaryType: "Agent",
    value: {
      source: isMainnet ? "a" : "b",
      connectionId: actionHash(action, nonce, vaultAddress, expiresAfter),
    },
  };
}
async function signAction(
  pk: Hex,
  action: Record<string, unknown>,
  opts: SignOptions = {},
): Promise<SignedOrder> {
  const nonce = opts.nonce ?? nextNonce();
  const td = createL1TypedData(
    action,
    nonce,
    opts.isMainnet ?? true,
    opts.vaultAddress,
    opts.expiresAfter,
  );
  const hex = await privateKeyToAccount(pk).signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.value,
  } as never);
  const s = parseSignature(hex);
  return signedOrderSchema.parse({
    action,
    nonce,
    signature: { r: s.r, s: s.s, v: Number(s.v) },
    vaultAddress: opts.vaultAddress,
    expiresAfter: opts.expiresAfter,
  });
}
export const signSendAsset = async (
  walletPrivateKey: Hex,
  params: SendAssetParams,
  options: SignOptions & {
    transport?: HyperliquidTransport;
    baseUrl?: string;
    usdcTokenId?: string;
  } = {},
): Promise<SignedSendAsset> => {
  const nonce = options.nonce ?? params.nonce ?? nextNonce();
  const hyperliquidChain =
    params.hyperliquidChain ?? (options.isMainnet === false ? "Testnet" : "Mainnet");
  const token = params.token ?? (await resolveUsdcTokenId(options));
  const normalizedParams = { ...params, token, nonce, hyperliquidChain };
  const action = normalizeSendAssetParams(normalizedParams, token, nonce);
  const td = createSendAssetTypedData(normalizedParams);
  const hex = await privateKeyToAccount(walletPrivateKey).signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.value,
  } as never);
  const s = parseSignature(hex);
  return signedSendAssetSchema.parse({
    action,
    nonce,
    signature: { r: s.r, s: s.s, v: Number(s.v) },
  });
};

export const signUsdSend = async (
  walletPrivateKey: Hex,
  params: UsdSendParams,
  options: SignOptions = {},
): Promise<SignedUsdSend> => {
  const nonce = options.nonce ?? params.nonce ?? nextNonce();
  const hyperliquidChain =
    params.hyperliquidChain ?? (options.isMainnet === false ? "Testnet" : "Mainnet");
  const normalizedParams = { ...params, nonce, hyperliquidChain };
  const action = normalizeUsdSendParams(normalizedParams, nonce);
  const td = createUsdSendTypedData(normalizedParams);
  const hex = await privateKeyToAccount(walletPrivateKey).signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.value,
  } as never);
  const s = parseSignature(hex);
  return signedUsdSendSchema.parse({
    action,
    nonce,
    signature: { r: s.r, s: s.s, v: Number(s.v) },
  });
};

export const signApproveBuilderFee = async (
  walletPrivateKey: Hex,
  params: ApproveBuilderFeeParams,
  options: SignOptions = {},
): Promise<SignedApproveBuilderFee> => {
  const nonce = options.nonce ?? params.nonce ?? nextNonce();
  const hyperliquidChain =
    params.hyperliquidChain ?? (options.isMainnet === false ? "Testnet" : "Mainnet");
  const normalizedParams = { ...params, nonce, hyperliquidChain };
  const action = normalizeApproveBuilderFeeParams(normalizedParams, nonce);
  const td = createApproveBuilderFeeTypedData(normalizedParams);
  const hex = await privateKeyToAccount(walletPrivateKey).signTypedData({
    domain: td.domain,
    types: td.types,
    primaryType: td.primaryType,
    message: td.value,
  } as never);
  const s = parseSignature(hex);
  return signedApproveBuilderFeeSchema.parse({
    action,
    nonce,
    signature: { r: s.r, s: s.s, v: Number(s.v) },
  });
};

export const signOrder = async (
  walletPrivateKey: Hex,
  order: HyperliquidOrder,
  options: SignOptions & { transport?: HyperliquidTransport; baseUrl?: string } = {},
) => {
  const resolved = await withMarketableLimitPx(order, options);
  return signAction(walletPrivateKey, await toResolvedExchangeAction(resolved, options), {
    ...options,
    nonce: options.nonce ?? order.nonce,
  });
};
export const signUpdateIsolatedMargin = async (
  walletPrivateKey: Hex,
  input: AddIsolatedMarginInput,
  options: SignOptions & { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<SignedUpdateIsolatedMargin> => {
  const parsed = normalizedAddIsolatedMargin(input);
  return signedUpdateIsolatedMarginSchema.parse(
    await signAction(walletPrivateKey, await toUpdateIsolatedMarginAction(parsed, options), {
      ...options,
      nonce: options.nonce ?? parsed.nonce,
    }),
  );
};
async function postExchange(signed: SignedOrder, transport: HyperliquidTransport, baseUrl: string) {
  const r = await transport.fetch(
    `${baseUrl}/exchange`,
    withTimeoutSignal({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(signedOrderSchema.parse(signed)),
    }),
  );
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`Hyperliquid exchange returned ${r.status}: ${JSON.stringify(j)}`);
  return j;
}
function throwIfExchangeRejected(raw: unknown, actionName: string): string {
  const status = String((raw as { status?: unknown })?.status ?? "");
  if (status === "err") {
    const detail = (raw as { response?: unknown })?.response;
    throw new Error(
      `hyperliquid ${actionName} rejected: ${typeof detail === "string" ? detail : JSON.stringify(detail ?? raw)}`,
    );
  }
  return status;
}
export async function submitOrder(
  signedOrder: SignedOrder,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
) {
  return normalizeOrderResult(
    await postExchange(
      signedOrder,
      options.transport ?? { fetch },
      options.baseUrl ?? DEFAULT_BASE_URL,
    ),
  );
}
export async function submitSendAsset(
  signed: SignedSendAsset,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<SendAssetResult> {
  const raw = await postExchange(
    signedSendAssetSchema.parse(signed),
    options.transport ?? { fetch },
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  // Hyperliquid returns HTTP 200 with { status: "err", response: <msg> } on a
  // rejected exchange action. Surface that as a thrown error so the /transfer
  // route audits it as FAILED (not submitted) and the idempotency key is not
  // poisoned with a success that never moved collateral.
  const status = throwIfExchangeRejected(raw, "sendAsset");
  return sendAssetResultSchema.parse({ status: status || "submitted", raw });
}
export async function submitUsdSend(
  signed: SignedUsdSend,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<UsdSendResult> {
  const raw = await postExchange(
    signedUsdSendSchema.parse(signed),
    options.transport ?? { fetch },
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  const status = throwIfExchangeRejected(raw, "usdSend");
  return usdSendResultSchema.parse({ status: status || "submitted", raw });
}

export async function submitApproveBuilderFee(
  signed: SignedApproveBuilderFee,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<ApproveBuilderFeeResult> {
  const raw = await postExchange(
    signedApproveBuilderFeeSchema.parse(signed),
    options.transport ?? { fetch },
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  const status = throwIfExchangeRejected(raw, "approveBuilderFee");
  return approveBuilderFeeResultSchema.parse({ status: status || "submitted", raw });
}
export async function submitUpdateIsolatedMargin(
  signed: SignedUpdateIsolatedMargin,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<UpdateIsolatedMarginResult> {
  const raw = await postExchange(
    signedUpdateIsolatedMarginSchema.parse(signed),
    options.transport ?? { fetch },
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  const status = throwIfExchangeRejected(raw, "updateIsolatedMargin");
  return updateIsolatedMarginResultSchema.parse({ status: status || "submitted", raw });
}
export async function getOpenOrders(
  userAddress: string,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Order[]> {
  const r = await (options.transport ?? { fetch }).fetch(
    `${options.baseUrl ?? DEFAULT_BASE_URL}/info`,
    withTimeoutSignal({
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "openOrders", user: userAddress }),
    }),
  );
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`Hyperliquid info returned ${r.status}`);
  return (Array.isArray(j) ? j : []).map((o) =>
    openOrderSchema.parse({ ...(o as Record<string, unknown>), raw: o }),
  );
}
export async function cancelOrder(
  walletPrivateKey: Hex,
  input: CancelOrderInput,
  options: SignOptions & { transport?: HyperliquidTransport; baseUrl?: string } = {},
) {
  // Use the async resolver so builder-perp symbols (e.g. `xyz:SPCX`) can be
  // canceled via this exported helper, matching what signOrder/the adapter accept.
  // Core symbols still resolve synchronously inside resolveAsset's fast path.
  const raw = await postExchange(
    await signAction(
      walletPrivateKey,
      await toResolvedCancelAction(input, {
        transport: options.transport,
        baseUrl: options.baseUrl,
      }),
      {
        ...options,
        nonce: options.nonce ?? input.nonce,
      },
    ),
    options.transport ?? { fetch },
    options.baseUrl ?? DEFAULT_BASE_URL,
  );
  return normalizeCancelResult(raw, String(input.orderId));
}

export class HyperliquidAdapter {
  private readonly transport: HyperliquidTransport;
  private readonly baseUrl: string;
  private readonly isMainnet: boolean;
  constructor(
    private readonly vault: VaultClient,
    private readonly agentId: string,
    private readonly walletAddress: string,
    private readonly options: HyperliquidAdapterOptions = {},
  ) {
    this.transport = options.transport ?? { fetch };
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.isMainnet = options.isMainnet ?? !/testnet/i.test(this.baseUrl);
  }
  async signOrder(order: HyperliquidOrder): Promise<SignedOrder> {
    const nonce = order.nonce ?? nextNonce();
    const resolved = await withMarketableLimitPx(order, {
      transport: this.transport,
      baseUrl: this.baseUrl,
    });
    const action = await toResolvedExchangeAction(resolved, {
      transport: this.transport,
      baseUrl: this.baseUrl,
    });
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.options.vaultAddress,
      this.options.expiresAfter,
    );
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedOrderSchema.parse({
      action,
      nonce,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
      vaultAddress: this.options.vaultAddress,
      expiresAfter: this.options.expiresAfter,
    });
  }
  submitOrder(signed: SignedOrder) {
    return submitOrder(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async signSendAsset(params: SendAssetParams): Promise<SignedSendAsset> {
    const nonce = params.nonce ?? nextNonce();
    const token =
      params.token ??
      (await resolveUsdcTokenId({
        transport: this.transport,
        baseUrl: this.baseUrl,
        usdcTokenId: this.options.usdcTokenId,
      }));
    const hyperliquidChain = params.hyperliquidChain ?? (this.isMainnet ? "Mainnet" : "Testnet");
    const normalizedParams = { ...params, token, nonce, hyperliquidChain };
    const action = normalizeSendAssetParams(normalizedParams, token, nonce);
    const td = createSendAssetTypedData(normalizedParams);
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedSendAssetSchema.parse({
      action,
      nonce,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
    });
  }
  submitSendAsset(signed: SignedSendAsset) {
    return submitSendAsset(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }

  async signUsdSend(params: UsdSendParams): Promise<SignedUsdSend> {
    const nonce = params.nonce ?? nextNonce();
    const hyperliquidChain = params.hyperliquidChain ?? (this.isMainnet ? "Mainnet" : "Testnet");
    const normalizedParams = { ...params, nonce, hyperliquidChain };
    const action = normalizeUsdSendParams(normalizedParams, nonce);
    const td = createUsdSendTypedData(normalizedParams);
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedUsdSendSchema.parse({
      action,
      nonce,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
    });
  }
  submitUsdSend(signed: SignedUsdSend) {
    return submitUsdSend(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async usdSend(params: UsdSendParams): Promise<UsdSendResult> {
    const signed = await this.signUsdSend(params);
    return this.submitUsdSend(signed);
  }
  async signApproveBuilderFee(params: ApproveBuilderFeeParams): Promise<SignedApproveBuilderFee> {
    const nonce = params.nonce ?? nextNonce();
    const hyperliquidChain = params.hyperliquidChain ?? (this.isMainnet ? "Mainnet" : "Testnet");
    const normalizedParams = { ...params, nonce, hyperliquidChain };
    const action = normalizeApproveBuilderFeeParams(normalizedParams, nonce);
    const td = createApproveBuilderFeeTypedData(normalizedParams);
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedApproveBuilderFeeSchema.parse({
      action,
      nonce,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
    });
  }
  submitApproveBuilderFee(signed: SignedApproveBuilderFee) {
    return submitApproveBuilderFee(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async approveBuilderFee(params: ApproveBuilderFeeParams): Promise<ApproveBuilderFeeResult> {
    const signed = await this.signApproveBuilderFee(params);
    return this.submitApproveBuilderFee(signed);
  }
  async maxBuilderFee(params: { user?: string; builder: string }): Promise<unknown> {
    const builder = String(params.builder).toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(builder))
      throw new Error(`invalid maxBuilderFee builder: ${params.builder}`);
    const user = String(params.user ?? this.walletAddress).toLowerCase();
    if (!/^0x[0-9a-f]{40}$/.test(user)) throw new Error(`invalid maxBuilderFee user: ${user}`);
    return postInfo(
      { type: "maxBuilderFee", user, builder },
      { transport: this.transport, baseUrl: this.baseUrl },
    );
  }
  async signUpdateIsolatedMargin(
    input: AddIsolatedMarginInput,
  ): Promise<SignedUpdateIsolatedMargin> {
    const parsed = normalizedAddIsolatedMargin(input);
    const nonce = parsed.nonce ?? nextNonce();
    const action = await toUpdateIsolatedMarginAction(parsed, {
      transport: this.transport,
      baseUrl: this.baseUrl,
    });
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.options.vaultAddress,
      this.options.expiresAfter,
    );
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedUpdateIsolatedMarginSchema.parse({
      action,
      nonce,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
      vaultAddress: this.options.vaultAddress,
      expiresAfter: this.options.expiresAfter,
    });
  }
  submitUpdateIsolatedMargin(signed: SignedUpdateIsolatedMargin) {
    return submitUpdateIsolatedMargin(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async addIsolatedMargin(input: AddIsolatedMarginInput): Promise<UpdateIsolatedMarginResult> {
    const signed = await this.signUpdateIsolatedMargin(input);
    return this.submitUpdateIsolatedMargin(signed);
  }
  async transferToBuilderDex(dex: string, amountUsdc: string | number): Promise<SendAssetResult> {
    const signed = await this.signSendAsset({
      destination: this.walletAddress,
      sourceDex: "",
      destinationDex: dex,
      amount: amountUsdc,
    });
    return this.submitSendAsset(signed);
  }
  async transferFromBuilderDex(dex: string, amountUsdc: string | number): Promise<SendAssetResult> {
    const signed = await this.signSendAsset({
      destination: this.walletAddress,
      sourceDex: dex,
      destinationDex: "",
      amount: amountUsdc,
    });
    return this.submitSendAsset(signed);
  }
  async updateLeverage(input: LeverageUpdateInput): Promise<LeverageUpdateResult> {
    const parsed = normalizedLeverageUpdate(input);
    const nonce = parsed.nonce ?? nextNonce();
    const action = await toResolvedUpdateLeverageAction(parsed, {
      transport: this.transport,
      baseUrl: this.baseUrl,
    });
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.options.vaultAddress,
      this.options.expiresAfter,
    );
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    const raw = await postExchange(
      signedOrderSchema.parse({
        action,
        nonce,
        signature: { r: s.r, s: s.s, v: Number(s.v) },
        vaultAddress: this.options.vaultAddress,
        expiresAfter: this.options.expiresAfter,
      }),
      this.transport,
      this.baseUrl,
    );
    const status = throwIfExchangeRejected(raw, "updateLeverage");
    return leverageUpdateResultSchema.parse({ status: status || "ok", raw });
  }
  getOpenOrders(userAddress = this.walletAddress) {
    return getOpenOrders(userAddress, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async cancelOrder(input: CancelOrderInput) {
    const nonce = input.nonce ?? nextNonce();
    const action = await toResolvedCancelAction(input, {
      transport: this.transport,
      baseUrl: this.baseUrl,
    });
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.options.vaultAddress,
      this.options.expiresAfter,
    );
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return normalizeCancelResult(
      await postExchange(
        signedOrderSchema.parse({
          action,
          nonce,
          signature: { r: s.r, s: s.s, v: Number(s.v) },
          vaultAddress: this.options.vaultAddress,
          expiresAfter: this.options.expiresAfter,
        }),
        this.transport,
        this.baseUrl,
      ),
      String(input.orderId),
    );
  }
  async getPositions(): Promise<Position[]> {
    const j = await this.clearinghouseState();
    return normalizePositions(j);
  }
  private async clearinghouseState(): Promise<unknown> {
    const r = await this.transport.fetch(
      `${this.baseUrl}/info`,
      withTimeoutSignal({
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "clearinghouseState", user: this.walletAddress }),
      }),
    );
    const j = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`Hyperliquid info returned ${r.status}`);
    return j;
  }
  async signWithdraw(params: WithdrawParams): Promise<SignedWithdraw> {
    const n = normalizeWithdrawParams(params);
    const action = toWithdrawAction(n);
    const td = createWithdrawTypedData(n);
    const hex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const s = parseSignature(hex as Hex);
    return signedWithdrawSchema.parse({
      action,
      nonce: n.time,
      signature: { r: s.r, s: s.s, v: Number(s.v) },
    });
  }
  submitWithdraw(signed: SignedWithdraw) {
    return submitWithdraw(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  // Build a reduce-only market order on the OPPOSITE side of the open position
  // (long => sell, short => buy), sized abs(szi), then sign + submit it.
  async marketClosePosition(coin: HyperliquidAsset): Promise<OrderResult> {
    const positions = rawSignedPositions(await this.clearinghouseState());
    const pos = positions.find((p) => p.coin === coin);
    if (!pos || pos.szi === 0) throw new Error(`no open position for ${coin}`);
    const isBuy = pos.szi < 0; // short => buy to close, long => sell to close
    const signed = await this.signOrder({
      coin,
      isBuy,
      size: Math.abs(pos.szi),
      reduceOnly: true,
    });
    return this.submitOrder(signed);
  }
  // Iterate all open positions and market-close each non-zero one.
  async closeAllPositions(): Promise<CloseAllResult[]> {
    const positions = rawSignedPositions(await this.clearinghouseState());
    const results: CloseAllResult[] = [];
    for (const pos of positions) {
      if (pos.szi === 0) continue;
      const coin = hyperliquidAssetSchema.parse(pos.coin);
      const result = await this.marketClosePosition(coin);
      results.push({ coin, result });
    }
    return results;
  }
}
function rawSignedPositions(raw: unknown): Array<{ coin: string; szi: number }> {
  return (((raw as any)?.assetPositions ?? []) as any[]).map((e) => {
    const p = e.position ?? {};
    return { coin: String(p.coin ?? ""), szi: Number(p.szi ?? 0) };
  });
}
function firstStatus(raw: unknown) {
  const data = ((raw as any).response?.data?.statuses ?? []) as unknown[];
  return data[0];
}
function normalizeOrderResult(raw: unknown): OrderResult {
  const st = firstStatus(raw);
  if (st && typeof st === "object" && "error" in st)
    return orderResultSchema.parse({
      status: "rejected",
      error: String((st as any).error),
      txHash: null,
      raw,
    });
  const resting = (st as any)?.resting,
    filled = (st as any)?.filled,
    src = filled ?? resting ?? {};
  return orderResultSchema.parse({
    orderId: src.oid !== undefined ? String(src.oid) : undefined,
    status: filled ? "filled" : resting ? "resting" : String((raw as any).status ?? "submitted"),
    filledQty: filled?.totalSz ? Number(filled.totalSz) : undefined,
    avgPrice: filled?.avgPx ? Number(filled.avgPx) : undefined,
    txHash: null,
    raw,
  });
}
function normalizeCancelResult(raw: unknown, orderId: string): CancelResult {
  const st = firstStatus(raw);
  if (st && typeof st === "object" && "error" in st)
    return cancelResultSchema.parse({
      orderId,
      status: "rejected",
      error: String((st as any).error),
      raw,
    });
  return cancelResultSchema.parse({ orderId, status: String(st ?? "submitted"), raw });
}
function normalizePositions(raw: unknown): Position[] {
  return (((raw as any).assetPositions ?? []) as any[]).map((e) => {
    const p = e.position ?? {};
    const size = Number(p.szi ?? 0);
    return positionSchema.parse({
      asset: String(p.coin ?? ""),
      side: size > 0 ? "long" : size < 0 ? "short" : "flat",
      size: Math.abs(size),
      entryPrice: p.entryPx ? Number(p.entryPx) : undefined,
      unrealizedPnlUsd: p.unrealizedPnl ? Number(p.unrealizedPnl) : undefined,
      leverage: p.leverage ? Number(p.leverage.value ?? 0) : undefined,
    });
  });
}
