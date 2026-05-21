import { type Hex, parseSignature } from "viem";
import { z } from "zod";

export const hyperliquidAssetSchema = z.enum(["BTC", "ETH"]);
export type HyperliquidAsset = z.infer<typeof hyperliquidAssetSchema>;

export const hyperliquidOrderSchema = z.object({
  asset: hyperliquidAssetSchema,
  side: z.enum(["buy", "sell"]),
  size: z.number().positive(),
  leverage: z.number().positive().max(2),
  reduceOnly: z.boolean().default(false),
  limitPrice: z.string().optional(),
  nonce: z.number().int().positive().optional(),
});
export type HyperliquidOrder = z.infer<typeof hyperliquidOrderSchema>;

export const signedOrderSchema = z.object({
  action: z.record(z.string(), z.unknown()),
  nonce: z.number().int().positive(),
  signature: z.object({
    r: z.string(),
    s: z.string(),
    v: z.number(),
  }),
});
export type SignedOrder = z.infer<typeof signedOrderSchema>;

export const orderResultSchema = z.object({
  orderId: z.string().optional(),
  status: z.string(),
  filledQty: z.number().optional(),
  avgPrice: z.number().optional(),
  txHash: z.string().nullable().optional(),
  raw: z.unknown().optional(),
});
export type OrderResult = z.infer<typeof orderResultSchema>;

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
}

const ASSET_INDEX: Record<HyperliquidAsset, number> = {
  BTC: 0,
  ETH: 1,
};

const DEFAULT_BASE_URL = "https://api.hyperliquid.xyz";

function toExchangeAction(order: HyperliquidOrder): Record<string, unknown> {
  const parsed = hyperliquidOrderSchema.parse(order);
  return {
    type: "order",
    orders: [
      {
        a: ASSET_INDEX[parsed.asset],
        b: parsed.side === "buy",
        p: parsed.limitPrice ?? "0",
        s: String(parsed.size),
        r: parsed.reduceOnly,
        t: {
          limit: {
            tif: "Ioc",
          },
        },
      },
    ],
    grouping: "na",
  };
}

function createTypedData(
  order: HyperliquidOrder,
  action: Record<string, unknown>,
  walletAddress: string,
  nonce: number,
): VaultSignTypedDataInput {
  return {
    agentId: "",
    domain: {
      name: "Exchange",
      version: "1",
      chainId: 1337,
      verifyingContract: "0x0000000000000000000000000000000000000000",
    },
    types: {
      HyperliquidOrder: [
        { name: "wallet", type: "address" },
        { name: "asset", type: "string" },
        { name: "side", type: "string" },
        { name: "size", type: "string" },
        { name: "leverage", type: "uint256" },
        { name: "reduceOnly", type: "bool" },
        { name: "nonce", type: "uint64" },
        { name: "action", type: "string" },
      ],
    },
    primaryType: "HyperliquidOrder",
    value: {
      wallet: walletAddress,
      asset: order.asset,
      side: order.side,
      size: String(order.size),
      leverage: order.leverage,
      reduceOnly: order.reduceOnly ?? false,
      nonce,
      action: JSON.stringify(action),
    },
  };
}

export class HyperliquidAdapter {
  private readonly transport: HyperliquidTransport;
  private readonly baseUrl: string;

  constructor(
    private readonly vault: VaultClient,
    private readonly agentId: string,
    private readonly walletAddress: string,
    options: HyperliquidAdapterOptions = {},
  ) {
    this.transport = options.transport ?? { fetch };
    this.baseUrl = options.baseUrl ?? DEFAULT_BASE_URL;
  }

  async signOrder(order: HyperliquidOrder): Promise<SignedOrder> {
    const parsed = hyperliquidOrderSchema.parse(order);
    const nonce = parsed.nonce ?? Date.now();
    const action = toExchangeAction(parsed);
    const typedData = createTypedData(parsed, action, this.walletAddress, nonce);
    const signatureHex = await this.vault.signTypedData({
      ...typedData,
      agentId: this.agentId,
    });
    const signature = parseSignature(signatureHex as Hex);
    if (signature.v === undefined) {
      throw new Error("Vault returned an EIP-712 signature without a recovery id");
    }

    return signedOrderSchema.parse({
      action,
      nonce,
      signature: {
        r: signature.r,
        s: signature.s,
        v: Number(signature.v),
      },
    });
  }

  async submitOrder(signed: SignedOrder): Promise<OrderResult> {
    const body = signedOrderSchema.parse(signed);
    const response = await this.transport.fetch(`${this.baseUrl}/exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const json = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      throw new Error(`Hyperliquid exchange returned ${response.status}`);
    }
    return normalizeOrderResult(json);
  }

  async getPositions(): Promise<Position[]> {
    const response = await this.transport.fetch(`${this.baseUrl}/info`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "clearinghouseState", user: this.walletAddress }),
    });
    const json = (await response.json().catch(() => null)) as unknown;
    if (!response.ok) {
      throw new Error(`Hyperliquid info returned ${response.status}`);
    }
    return normalizePositions(json);
  }
}

function normalizeOrderResult(raw: unknown): OrderResult {
  const payload = raw as Record<string, unknown>;
  const statuses = Array.isArray((payload.response as Record<string, unknown> | undefined)?.data)
    ? ((payload.response as Record<string, unknown>).data as unknown[])
    : [];
  const first = statuses[0] as Record<string, unknown> | undefined;
  return orderResultSchema.parse({
    orderId: String(first?.oid ?? first?.orderId ?? crypto.randomUUID()),
    status: String(payload.status ?? "submitted"),
    filledQty: typeof first?.totalSz === "number" ? first.totalSz : undefined,
    avgPrice: typeof first?.avgPx === "number" ? first.avgPx : undefined,
    txHash: null,
    raw,
  });
}

function normalizePositions(raw: unknown): Position[] {
  const payload = raw as { assetPositions?: Array<{ position?: Record<string, unknown> }> };
  return (payload.assetPositions ?? []).map((entry) => {
    const position = entry.position ?? {};
    const size = Number(position.szi ?? 0);
    return positionSchema.parse({
      asset: String(position.coin ?? ""),
      side: size > 0 ? "long" : size < 0 ? "short" : "flat",
      size: Math.abs(size),
      entryPrice: position.entryPx ? Number(position.entryPx) : undefined,
      unrealizedPnlUsd: position.unrealizedPnl ? Number(position.unrealizedPnl) : undefined,
      leverage:
        typeof position.leverage === "object" && position.leverage
          ? Number((position.leverage as Record<string, unknown>).value ?? 0)
          : undefined,
    });
  });
}
