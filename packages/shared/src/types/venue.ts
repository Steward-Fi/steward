export type VenueId = "hyperliquid";

export type TradeAsset = "BTC" | "ETH";

export interface TradePolicyContext {
  venue: VenueId;
  asset: TradeAsset;
  leverage: number;
  size: number;
  sizeUsd?: number;
}
