// Polymarket runs on Polygon (chain id 137), settled in USDC (6 decimals).
// Three hosts, three jobs: Gamma=discover, CLOB=quote+trade, Data=positions.
// See POLYMARKET-KNOWLEDGE-DUMP.md §2.

export const POLYMARKET_GAMMA_API_BASE = "https://gamma-api.polymarket.com";
export const POLYMARKET_CLOB_API_BASE = "https://clob.polymarket.com";
export const POLYMARKET_DATA_API_BASE = "https://data-api.polymarket.com";

export const POLYGON_CHAIN_ID = 137;
export const USDC_DECIMALS = 6;

// signatureType: 0=EOA, 1=POLY_PROXY, 2=POLY_GNOSIS_SAFE.
// The Safe-funder model (type 2) is the right shape for agent custody: agent
// funds live in a Gnosis Safe, a delegate key signs. signer !== funder.
export const POLY_GNOSIS_SAFE_SIGNATURE_TYPE = 2;
export const POLY_PROXY_SIGNATURE_TYPE = 1;
export const POLY_EOA_SIGNATURE_TYPE = 0;

// CLOB batch-prices-history caps the markets array at 20 asset ids per call.
export const POLYMARKET_BATCH_PRICE_HISTORY_LIMIT = 20;

// Default polygon RPC. Override via PolymarketAdapterOptions.rpcUrl — do NOT
// hardcode operator config in callers.
export const DEFAULT_POLYGON_RPC_URL = "https://polygon-rpc.com";

export const DEFAULT_FETCH_TIMEOUT_MS = Number(process.env.POLYMARKET_FETCH_TIMEOUT_MS ?? 15_000);
