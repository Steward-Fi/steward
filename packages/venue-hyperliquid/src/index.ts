import { concatBytes, type Hex, keccak256, parseSignature, toBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

export const hyperliquidAssetSchema = z.enum(["BTC", "ETH"]);
export type HyperliquidAsset = z.infer<typeof hyperliquidAssetSchema>;
const ASSET_INDEX: Record<HyperliquidAsset, number> = { BTC: 0, ETH: 1 };
const DEFAULT_BASE_URL = "https://api.hyperliquid.xyz";

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
  leverage: z.number().positive().max(2).optional(),
  nonce: z.number().int().positive().optional(),
});
export type HyperliquidOrder = z.input<typeof hyperliquidOrderSchema>;
export type CancelOrderInput = { coin: HyperliquidAsset; orderId: number | string; nonce?: number };
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
  };
}
export function toExchangeAction(order: HyperliquidOrder): Record<string, unknown> {
  const o = normalized(order);
  return {
    type: "order",
    orders: [
      {
        a: ASSET_INDEX[o.coin],
        b: o.isBuy,
        p: o.limitPx,
        s: o.sz,
        r: o.reduceOnly,
        t: { limit: { tif: o.tif } },
      },
    ],
    grouping: "na",
  };
}
function toCancelAction(input: CancelOrderInput): Record<string, unknown> {
  return { type: "cancel", cancels: [{ a: ASSET_INDEX[input.coin], o: Number(input.orderId) }] };
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
  const nonce = opts.nonce ?? Date.now();
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
export const signOrder = (
  walletPrivateKey: Hex,
  order: HyperliquidOrder,
  options: SignOptions = {},
) =>
  signAction(walletPrivateKey, toExchangeAction(order), {
    ...options,
    nonce: options.nonce ?? order.nonce,
  });
async function postExchange(signed: SignedOrder, transport: HyperliquidTransport, baseUrl: string) {
  const r = await transport.fetch(`${baseUrl}/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signedOrderSchema.parse(signed)),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`Hyperliquid exchange returned ${r.status}: ${JSON.stringify(j)}`);
  return j;
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
  const r = await (options.transport ?? { fetch }).fetch(
    `${options.baseUrl ?? DEFAULT_BASE_URL}/info`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "openOrders", user: userAddress }),
    },
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
  const raw = await postExchange(
    await signAction(walletPrivateKey, toCancelAction(input), {
      ...options,
      nonce: options.nonce ?? input.nonce,
    }),
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
    const nonce = order.nonce ?? Date.now();
    const action = toExchangeAction(order);
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
  getOpenOrders(userAddress = this.walletAddress) {
    return getOpenOrders(userAddress, { transport: this.transport, baseUrl: this.baseUrl });
  }
  async cancelOrder(input: CancelOrderInput) {
    const nonce = input.nonce ?? Date.now();
    const action = toCancelAction(input);
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
    const r = await this.transport.fetch(`${this.baseUrl}/info`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "clearinghouseState", user: this.walletAddress }),
    });
    const j = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`Hyperliquid info returned ${r.status}`);
    return normalizePositions(j);
  }
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
