import { concatBytes, type Hex, keccak256, parseSignature, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

export const hyperliquidAssetSchema = z.enum(["BTC", "ETH"]);
export type HyperliquidAsset = z.infer<typeof hyperliquidAssetSchema>;
export const hyperliquidTifSchema = z.enum(["Alo", "Ioc", "Gtc"]);
export type HyperliquidTif = z.infer<typeof hyperliquidTifSchema>;

export const hyperliquidOrderSchema = z.object({
  coin: hyperliquidAssetSchema.optional(),
  asset: hyperliquidAssetSchema.optional(),
  side: z.enum(["buy", "sell"]).optional(),
  isBuy: z.boolean().optional(),
  size: z.number().positive().optional(),
  sz: z.union([z.string(), z.number()]).optional(),
  limitPx: z.union([z.string(), z.number()]).optional(),
  limitPrice: z.union([z.string(), z.number()]).optional(),
  orderType: z.object({ limit: z.object({ tif: hyperliquidTifSchema }).optional() }).optional(),
  reduceOnly: z.boolean().default(false),
  leverage: z.number().positive().max(2).optional(),
  nonce: z.number().int().positive().optional(),
});
export type HyperliquidOrder = z.input<typeof hyperliquidOrderSchema>;

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
export const openOrderSchema = z.object({
  coin: z.string(),
  limitPx: z.string(),
  oid: z.number(),
  side: z.string(),
  sz: z.string(),
  timestamp: z.number().optional(),
  reduceOnly: z.boolean().optional(),
  orderType: z.string().optional(),
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
}
export interface SignOptions {
  nonce?: number;
  isMainnet?: boolean;
  vaultAddress?: string;
  expiresAfter?: number;
}
export interface CancelOrderInput {
  coin: HyperliquidAsset;
  orderId: number | string;
  nonce?: number;
}

const ASSET_INDEX: Record<HyperliquidAsset, number> = { BTC: 0, ETH: 1 };
const DEFAULT_BASE_URL = "https://api.hyperliquid.xyz";
const TESTNET_HOST_RE = /hyperliquid-testnet/i;
const L1_DOMAIN = {
  name: "Exchange",
  version: "1",
  chainId: 1337,
  verifyingContract: "0x0000000000000000000000000000000000000000",
} as const;
const L1_TYPES: Record<string, Array<{ name: string; type: string }>> = {
  Agent: [
    { name: "source", type: "string" },
    { name: "connectionId", type: "bytes32" },
  ],
};

function normalizeDecimal(value: string | number | undefined, fallback?: string): string {
  if (value === undefined) {
    if (fallback !== undefined) return fallback;
    throw new Error("Missing decimal value");
  }
  if (typeof value === "string") return value;
  if (!Number.isFinite(value)) throw new Error("Invalid decimal value");
  const rounded = value.toFixed(8);
  if (Math.abs(Number(rounded) - value) >= 1e-12)
    throw new Error(`Hyperliquid decimal would round: ${value}`);
  return rounded.replace(/\.0+$/, "").replace(/(\.\d*?)0+$/, "$1");
}

function normalizeOrder(order: HyperliquidOrder): {
  coin: HyperliquidAsset;
  isBuy: boolean;
  sz: string;
  limitPx: string;
  reduceOnly: boolean;
  tif: HyperliquidTif;
  nonce?: number;
} {
  const parsed = hyperliquidOrderSchema.parse(order);
  const coin = parsed.coin ?? parsed.asset;
  if (!coin) throw new Error("Hyperliquid order requires coin");
  const isBuy = parsed.isBuy ?? (parsed.side ? parsed.side === "buy" : undefined);
  if (isBuy === undefined) throw new Error("Hyperliquid order requires side/isBuy");
  return {
    coin,
    isBuy,
    sz: normalizeDecimal(parsed.sz ?? parsed.size),
    limitPx: normalizeDecimal(parsed.limitPx ?? parsed.limitPrice, "0"),
    reduceOnly: parsed.reduceOnly ?? false,
    tif: parsed.orderType?.limit?.tif ?? "Ioc",
    nonce: parsed.nonce,
  };
}

export function toExchangeAction(order: HyperliquidOrder): Record<string, unknown> {
  const n = normalizeOrder(order);
  return {
    type: "order",
    orders: [
      {
        a: ASSET_INDEX[n.coin],
        b: n.isBuy,
        p: n.limitPx,
        s: n.sz,
        r: n.reduceOnly,
        t: { limit: { tif: n.tif } },
      },
    ],
    grouping: "na",
  };
}
function toCancelAction(input: CancelOrderInput): Record<string, unknown> {
  const coin = hyperliquidAssetSchema.parse(input.coin);
  const oid = Number(input.orderId);
  if (!Number.isSafeInteger(oid) || oid <= 0) throw new Error("Invalid Hyperliquid order id");
  return { type: "cancel", cancels: [{ a: ASSET_INDEX[coin], o: oid }] };
}
function u8(...bytes: number[]) {
  return new Uint8Array(bytes);
}
function utf8(value: string) {
  return new TextEncoder().encode(value);
}
function uintBytes(value: number, byteLength: number) {
  const bytes = new Uint8Array(byteLength);
  let r = BigInt(value);
  for (let i = byteLength - 1; i >= 0; i -= 1) {
    bytes[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  return bytes;
}
function encodeMsgpack(value: unknown): Uint8Array {
  if (value == null) return u8(0xc0);
  if (typeof value === "boolean") return u8(value ? 0xc3 : 0xc2);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0)
      throw new Error(`Unsupported msgpack number: ${value}`);
    if (value <= 0x7f) return u8(value);
    if (value <= 0xff) return u8(0xcc, value);
    if (value <= 0xffff) return concatBytes([u8(0xcd), uintBytes(value, 2)]);
    if (value <= 0xffffffff) return concatBytes([u8(0xce), uintBytes(value, 4)]);
    return concatBytes([u8(0xcf), uintBytes(value, 8)]);
  }
  if (typeof value === "string") {
    const e = utf8(value);
    const len = e.length;
    if (len <= 31) return concatBytes([u8(0xa0 | len), e]);
    if (len <= 0xff) return concatBytes([u8(0xd9, len), e]);
    if (len <= 0xffff) return concatBytes([u8(0xda), uintBytes(len, 2), e]);
    return concatBytes([u8(0xdb), uintBytes(len, 4), e]);
  }
  if (Array.isArray(value)) {
    const items = value.map(encodeMsgpack);
    const len = items.length;
    const prefix =
      len <= 15
        ? u8(0x90 | len)
        : len <= 0xffff
          ? concatBytes([u8(0xdc), uintBytes(len, 2)])
          : concatBytes([u8(0xdd), uintBytes(len, 4)]);
    return concatBytes([prefix, ...items]);
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined,
    );
    const len = entries.length;
    const prefix =
      len <= 15
        ? u8(0x80 | len)
        : len <= 0xffff
          ? concatBytes([u8(0xde), uintBytes(len, 2)])
          : concatBytes([u8(0xdf), uintBytes(len, 4)]);
    return concatBytes([
      prefix,
      ...entries.flatMap(([k, v]) => [encodeMsgpack(k), encodeMsgpack(v)]),
    ]);
  }
  throw new Error(`Unsupported msgpack value: ${typeof value}`);
}
function addressToBytes(address: string) {
  return toBytes((address.startsWith("0x") ? address : `0x${address}`) as Hex);
}
export function actionHash(
  action: Record<string, unknown>,
  nonce: number,
  vaultAddress?: string,
  expiresAfter?: number,
): Hex {
  const parts = [encodeMsgpack(action), uintBytes(nonce, 8)];
  if (vaultAddress) parts.push(u8(0x01), addressToBytes(vaultAddress));
  else parts.push(u8(0x00));
  if (expiresAfter !== undefined) parts.push(u8(0x00), uintBytes(expiresAfter, 8));
  return keccak256(concatBytes(parts));
}
export function createL1TypedData(
  action: Record<string, unknown>,
  nonce: number,
  isMainnet = true,
  vaultAddress?: string,
  expiresAfter?: number,
): Omit<VaultSignTypedDataInput, "agentId"> {
  return {
    domain: L1_DOMAIN,
    types: L1_TYPES,
    primaryType: "Agent",
    value: {
      source: isMainnet ? "a" : "b",
      connectionId: actionHash(action, nonce, vaultAddress, expiresAfter),
    },
  };
}

async function signActionWithPrivateKey(
  walletPrivateKey: Hex,
  action: Record<string, unknown>,
  options: SignOptions = {},
): Promise<SignedOrder> {
  const nonce = options.nonce ?? Date.now();
  const typedData = createL1TypedData(
    action,
    nonce,
    options.isMainnet ?? true,
    options.vaultAddress,
    options.expiresAfter,
  );
  const account = privateKeyToAccount(walletPrivateKey);
  const sigHex = await (account.signTypedData as (args: unknown) => Promise<Hex>)({
    domain: typedData.domain,
    types: typedData.types,
    primaryType: typedData.primaryType,
    message: typedData.value,
  });
  const sig = parseSignature(sigHex);
  if (sig.v === undefined) throw new Error("EIP-712 signature missing recovery id");
  return signedOrderSchema.parse({
    action,
    nonce,
    signature: { r: sig.r, s: sig.s, v: Number(sig.v) },
    vaultAddress: options.vaultAddress,
    expiresAfter: options.expiresAfter,
  });
}
export async function signOrder(
  walletPrivateKey: Hex,
  order: HyperliquidOrder,
  options: SignOptions = {},
) {
  return signActionWithPrivateKey(walletPrivateKey, toExchangeAction(order), {
    ...options,
    nonce: options.nonce ?? order.nonce,
  });
}

async function postExchange(signed: SignedOrder, transport: HyperliquidTransport, baseUrl: string) {
  const body = signedOrderSchema.parse(signed);
  const res = await transport.fetch(`${baseUrl}/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok)
    throw new Error(`Hyperliquid exchange returned ${res.status}: ${JSON.stringify(json)}`);
  return json as unknown;
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
export async function getOpenOrders(
  userAddress: string,
  options: { transport?: HyperliquidTransport; baseUrl?: string } = {},
): Promise<Order[]> {
  const transport = options.transport ?? { fetch };
  const res = await transport.fetch(`${options.baseUrl ?? DEFAULT_BASE_URL}/info`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "openOrders", user: userAddress }),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`Hyperliquid info returned ${res.status}: ${JSON.stringify(json)}`);
  return (Array.isArray(json) ? json : []).map((o) =>
    openOrderSchema.parse({ ...(o as Record<string, unknown>), raw: o }),
  );
}
export async function cancelOrder(
  walletPrivateKey: Hex,
  input: CancelOrderInput,
  options: SignOptions & { transport?: HyperliquidTransport; baseUrl?: string } = {},
) {
  const signed = await signActionWithPrivateKey(walletPrivateKey, toCancelAction(input), {
    nonce: options.nonce ?? input.nonce,
    isMainnet: options.isMainnet,
    vaultAddress: options.vaultAddress,
    expiresAfter: options.expiresAfter,
  });
  return normalizeCancelResult(
    await postExchange(signed, options.transport ?? { fetch }, options.baseUrl ?? DEFAULT_BASE_URL),
    String(input.orderId),
  );
}

export class HyperliquidAdapter {
  private readonly transport: HyperliquidTransport;
  private readonly baseUrl: string;
  private readonly isMainnet: boolean;
  private readonly vaultAddress?: string;
  private readonly expiresAfter?: number;
  constructor(
    private readonly vault: VaultClient,
    private readonly agentId: string,
    private readonly walletAddress: string,
    options: HyperliquidAdapterOptions = {},
  ) {
    this.transport = options.transport ?? { fetch };
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
    this.isMainnet = options.isMainnet ?? !TESTNET_HOST_RE.test(this.baseUrl);
    this.vaultAddress = options.vaultAddress;
    this.expiresAfter = options.expiresAfter;
  }
  async signOrder(order: HyperliquidOrder): Promise<SignedOrder> {
    const parsed = hyperliquidOrderSchema.parse(order);
    const nonce = parsed.nonce ?? Date.now();
    const action = toExchangeAction(parsed);
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.vaultAddress,
      this.expiresAfter,
    );
    const sigHex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const sig = parseSignature(sigHex as Hex);
    if (sig.v === undefined)
      throw new Error("Vault returned an EIP-712 signature without a recovery id");
    return signedOrderSchema.parse({
      action,
      nonce,
      signature: { r: sig.r, s: sig.s, v: Number(sig.v) },
      vaultAddress: this.vaultAddress,
      expiresAfter: this.expiresAfter,
    });
  }
  async submitOrder(signed: SignedOrder) {
    return submitOrder(signed, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async getOpenOrders(userAddress = this.walletAddress) {
    return getOpenOrders(userAddress, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async cancelOrder(input: CancelOrderInput) {
    const action = toCancelAction(input);
    const nonce = input.nonce ?? Date.now();
    const td = createL1TypedData(
      action,
      nonce,
      this.isMainnet,
      this.vaultAddress,
      this.expiresAfter,
    );
    const sigHex = await this.vault.signTypedData({ ...td, agentId: this.agentId });
    const sig = parseSignature(sigHex as Hex);
    if (sig.v === undefined)
      throw new Error("Vault returned an EIP-712 signature without a recovery id");
    const signed = signedOrderSchema.parse({
      action,
      nonce,
      signature: { r: sig.r, s: sig.s, v: Number(sig.v) },
      vaultAddress: this.vaultAddress,
      expiresAfter: this.expiresAfter,
    });
    return normalizeCancelResult(
      await postExchange(signed, this.transport, this.baseUrl),
      String(input.orderId),
    );
  }
  async getPositions(): Promise<Position[]> {
    const res = await this.transport.fetch(`${this.baseUrl}/info`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "clearinghouseState", user: this.walletAddress }),
    });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw new Error(`Hyperliquid info returned ${res.status}`);
    return normalizePositions(json);
  }
}
function firstStatus(raw: unknown) {
  const payload = raw as Record<string, unknown>;
  const response = payload.response as Record<string, unknown> | undefined;
  const data = response?.data as Record<string, unknown> | undefined;
  const statuses = Array.isArray(data?.statuses) ? data.statuses : [];
  return statuses[0];
}
function normalizeOrderResult(raw: unknown): OrderResult {
  const status = firstStatus(raw);
  if (typeof status === "object" && status && "error" in status)
    return orderResultSchema.parse({
      status: "rejected",
      txHash: null,
      raw,
      error: String((status as Record<string, unknown>).error),
    });
  const resting = (status as Record<string, unknown> | undefined)?.resting as
    | Record<string, unknown>
    | undefined;
  const filled = (status as Record<string, unknown> | undefined)?.filled as
    | Record<string, unknown>
    | undefined;
  const src = filled ?? resting ?? (status as Record<string, unknown> | undefined) ?? {};
  return orderResultSchema.parse({
    orderId: src.oid !== undefined ? String(src.oid) : undefined,
    status: filled
      ? "filled"
      : resting
        ? "resting"
        : String((raw as Record<string, unknown>).status ?? "submitted"),
    filledQty: filled?.totalSz !== undefined ? Number(filled.totalSz) : undefined,
    avgPrice: filled?.avgPx !== undefined ? Number(filled.avgPx) : undefined,
    txHash: null,
    raw,
  });
}
function normalizeCancelResult(raw: unknown, orderId: string): CancelResult {
  const status = firstStatus(raw);
  if (typeof status === "object" && status && "error" in status)
    return cancelResultSchema.parse({
      orderId,
      status: "rejected",
      raw,
      error: String((status as Record<string, unknown>).error),
    });
  return cancelResultSchema.parse({ orderId, status: String(status ?? "submitted"), raw });
}
function normalizePositions(raw: unknown): Position[] {
  const payload = raw as { assetPositions?: Array<{ position?: Record<string, unknown> }> };
  return (payload.assetPositions ?? []).map((entry) => {
    const p = entry.position ?? {};
    const size = Number(p.szi ?? 0);
    return positionSchema.parse({
      asset: String(p.coin ?? ""),
      side: size > 0 ? "long" : size < 0 ? "short" : "flat",
      size: Math.abs(size),
      entryPrice: p.entryPx ? Number(p.entryPx) : undefined,
      unrealizedPnlUsd: p.unrealizedPnl ? Number(p.unrealizedPnl) : undefined,
      leverage:
        typeof p.leverage === "object" && p.leverage
          ? Number((p.leverage as Record<string, unknown>).value ?? 0)
          : undefined,
    });
  });
}
