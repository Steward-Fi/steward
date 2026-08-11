import { z } from "zod";

// ---------------------------------------------------------------------------
// Core primitives
// ---------------------------------------------------------------------------

// tickSize: minimum price increment per market. Resolve per-market, don't assume.
export const tickSizeSchema = z.enum(["0.1", "0.01", "0.001", "0.0001"]);
export type PolymarketTickSize = z.infer<typeof tickSizeSchema>;

export const sideSchema = z.enum(["buy", "sell"]);
export type OrderSide = z.infer<typeof sideSchema>;

// "market" is emulated as a marketable limit (FOK). We never use createMarketOrder.
export const orderTypeSchema = z.enum(["limit", "market", "FOK", "GTC"]);
export type OrderType = z.infer<typeof orderTypeSchema>;

// token_id is the unit of everything on the order side (NOT the slug). Big numeric string.
export const tokenIdSchema = z.string().regex(/^[0-9]+$/, "token_id must be a numeric string");

// ---------------------------------------------------------------------------
// createOrder options (tickSize + negRisk) — MUST be passed to createOrder
// ---------------------------------------------------------------------------

export const createOrderOptionsSchema = z.object({
  tickSize: tickSizeSchema,
  negRisk: z.boolean(),
});
export type PolymarketCreateOrderOptions = z.infer<typeof createOrderOptionsSchema>;

// ---------------------------------------------------------------------------
// Order request (the neutral shape the adapter accepts)
// ---------------------------------------------------------------------------

export const orderRequestSchema = z.object({
  tokenId: tokenIdSchema,
  side: sideSchema,
  // For BUY: amount is USD notional to spend. For SELL: amount is shares.
  amount: z.union([z.string(), z.number()]),
  // Limit price in (0,1). For "market" emulation, pass best ask (buy) / best bid (sell).
  price: z.union([z.string(), z.number()]),
  orderType: orderTypeSchema.default("limit"),
  // tickSize/negRisk hints. If omitted, resolved from the CLOB book.
  tickSize: tickSizeSchema.optional(),
  negRisk: z.boolean().optional(),
  // Fee rate. Leave UNDEFINED to let the clob-client resolve the market fee
  // (passing 0 on a non-zero-fee market makes the SDK reject the order). Only
  // set this when you know it matches the market's base_fee.
  feeRateBps: z.number().int().min(0).optional(),
  nonce: z.number().int().min(0).default(0),
});
export type PolymarketOrderRequest = z.input<typeof orderRequestSchema>;

// ---------------------------------------------------------------------------
// Signed order (opaque from the clob-client). We validate the shape we read.
// ---------------------------------------------------------------------------

export const signedOrderSchema = z
  .object({
    signer: z.string().optional(),
    maker: z.string().optional(),
    makerAmount: z.string().optional(),
    takerAmount: z.string().optional(),
    tokenId: z.string().optional(),
    side: z.union([z.string(), z.number()]).optional(),
    signature: z.string().optional(),
  })
  .passthrough();
export type PolymarketSignedOrder = z.infer<typeof signedOrderSchema>;

export const postOrderResultSchema = z.object({
  venue: z.literal("polymarket"),
  orderId: z.string().optional(),
  status: z.string().optional(),
  success: z.boolean().optional(),
  errorMsg: z.string().optional(),
  makingAmount: z.string().optional(),
  takingAmount: z.string().optional(),
  actualAmount: z.number().optional(),
  actualPrice: z.number().optional(),
  raw: z.unknown().optional(),
});
export type PolymarketPostOrderResult = z.infer<typeof postOrderResultSchema>;

export const cancelResultSchema = z.object({
  venue: z.literal("polymarket"),
  orderId: z.string().optional(),
  raw: z.unknown().optional(),
});
export type PolymarketCancelResult = z.infer<typeof cancelResultSchema>;

export const openOrderSchema = z
  .object({
    id: z.string(),
    market: z.string().optional(),
    asset_id: z.string().optional(),
    side: z.string().optional(),
    outcome: z.string().optional(),
    price: z.string().optional(),
    original_size: z.string().optional(),
    size_matched: z.string().optional(),
    order_type: z.string().optional(),
    status: z.string().optional(),
    created_at: z.union([z.string(), z.number()]).optional(),
    expiration: z.union([z.string(), z.number()]).optional(),
  })
  .passthrough();
export type PolymarketOpenOrder = z.infer<typeof openOrderSchema>;

// ---------------------------------------------------------------------------
// Market / discovery
// ---------------------------------------------------------------------------

export const marketSchema = z.object({
  id: z.string(),
  question: z.string().optional(),
  slug: z.string().optional(),
  conditionId: z.string().nullish(),
  // Gamma encodes these as JSON-string; we parse inside the adapter and expose arrays.
  clobTokenIds: z.array(z.string()),
  outcomes: z.array(z.string()),
  outcomePrices: z.array(z.string()),
  negRisk: z.boolean().optional(),
  active: z.boolean().optional(),
  closed: z.boolean().optional(),
  volume: z.number().optional(),
  liquidity: z.number().optional(),
  endDate: z.string().optional(),
});
export type PolymarketMarket = z.infer<typeof marketSchema>;

export const eventSchema = z.object({
  id: z.string(),
  title: z.string().optional(),
  slug: z.string().optional(),
  active: z.boolean().optional(),
  closed: z.boolean().optional(),
  archived: z.boolean().optional(),
  markets: z.array(marketSchema).default([]),
});
export type PolymarketEvent = z.infer<typeof eventSchema>;

// ---------------------------------------------------------------------------
// Positions (Data API)
// ---------------------------------------------------------------------------

export const positionSchema = z.object({
  tokenId: z.string(),
  conditionId: z.string().optional(),
  marketQuestion: z.string().optional(),
  outcome: z.string().optional(),
  balance: z.number(),
  avgPrice: z.number().optional(),
  currentPrice: z.number().optional(),
  currentValue: z.number().optional(),
  realizedPnl: z.number().optional(),
  unrealizedPnl: z.number().optional(),
  totalPnl: z.number().optional(),
  negRisk: z.boolean().optional(),
  raw: z.unknown().optional(),
});
export type PolymarketPosition = z.infer<typeof positionSchema>;

// ---------------------------------------------------------------------------
// Marketdata
// ---------------------------------------------------------------------------

export interface VenueOrderbookLevel {
  price: string;
  size: string;
}
export interface PolymarketOrderbook {
  tokenId: string;
  bids: VenueOrderbookLevel[];
  asks: VenueOrderbookLevel[];
  tickSize?: PolymarketTickSize;
  negRisk?: boolean;
  timestamp: string;
}
export interface PolymarketPricePoint {
  t: number;
  p: number;
}
export interface PolymarketBestPrice {
  tokenId: string;
  side: OrderSide;
  price: string;
}
