import {
  DEFAULT_FETCH_TIMEOUT_MS,
  POLYMARKET_BATCH_PRICE_HISTORY_LIMIT,
  POLYMARKET_CLOB_API_BASE,
} from "./constants";
import type { PolymarketFetchOptions } from "./discovery";
import { isPricePoint } from "./parsing";
import {
  type OrderSide,
  type PolymarketBestPrice,
  type PolymarketOrderbook,
  type PolymarketPricePoint,
  type PolymarketTickSize,
  tickSizeSchema,
} from "./types";

// ---------------------------------------------------------------------------
// Marketdata — CLOB. Batch books/prices/history. Public reads (no creds).
// POST /books, POST /prices, POST /batch-prices-history (cap 20 ids/call).
// ---------------------------------------------------------------------------

function timeoutSignal(opts?: PolymarketFetchOptions): AbortSignal | undefined {
  if (opts?.signal) return opts.signal;
  if (DEFAULT_FETCH_TIMEOUT_MS <= 0) return undefined;
  return AbortSignal.timeout(DEFAULT_FETCH_TIMEOUT_MS);
}

interface RawOrderbook {
  market?: string;
  asset_id?: string;
  timestamp?: string;
  bids?: { price: string; size: string }[];
  asks?: { price: string; size: string }[];
  tick_size?: string;
  neg_risk?: boolean;
}

function toTickSize(value: unknown): PolymarketTickSize | undefined {
  const parsed = tickSizeSchema.safeParse(value);
  return parsed.success ? parsed.data : undefined;
}

function toOrderbook(tokenId: string, raw: RawOrderbook): PolymarketOrderbook {
  return {
    tokenId: raw.asset_id || tokenId,
    bids: raw.bids ?? [],
    asks: raw.asks ?? [],
    tickSize: toTickSize(raw.tick_size),
    negRisk: typeof raw.neg_risk === "boolean" ? raw.neg_risk : undefined,
    timestamp: raw.timestamp || Date.now().toString(),
  };
}

function emptyOrderbook(tokenId: string): PolymarketOrderbook {
  return { tokenId, bids: [], asks: [], timestamp: Date.now().toString() };
}

/** Single orderbook (also the cheapest way to resolve tickSize + negRisk). */
export async function getOrderbook(
  tokenId: string,
  opts?: PolymarketFetchOptions,
): Promise<PolymarketOrderbook> {
  const doFetch = opts?.fetch ?? fetch;
  const url = new URL("/book", POLYMARKET_CLOB_API_BASE);
  url.searchParams.set("token_id", tokenId);
  const response = await doFetch(url.toString(), {
    headers: { Accept: "application/json" },
    signal: timeoutSignal(opts),
  });
  if (response.status === 404) return emptyOrderbook(tokenId);
  if (!response.ok) throw new Error(`Polymarket CLOB book error: ${response.status}`);
  return toOrderbook(tokenId, (await response.json()) as RawOrderbook);
}

/** Batch orderbooks via POST /books. Each book carries tick_size + neg_risk. */
export async function getOrderbooks(
  tokenIds: string[],
  opts?: PolymarketFetchOptions,
): Promise<Map<string, PolymarketOrderbook>> {
  const out = new Map<string, PolymarketOrderbook>(tokenIds.map((id) => [id, emptyOrderbook(id)]));
  if (tokenIds.length === 0) return out;

  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(`${POLYMARKET_CLOB_API_BASE}/books`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(tokenIds.map((token_id) => ({ token_id }))),
    signal: timeoutSignal(opts),
  });
  if (response.status === 404) return out;
  if (!response.ok) throw new Error(`Polymarket CLOB books error: ${response.status}`);

  const data = (await response.json()) as RawOrderbook[];
  for (const raw of data) {
    const id = raw.asset_id;
    if (id && out.has(id)) out.set(id, toOrderbook(id, raw));
  }
  return out;
}

export interface ResolveOrderOptionsOpts extends PolymarketFetchOptions {
  /**
   * When true (default), the book MUST yield a real tickSize + negRisk or this
   * throws. Signing with guessed contract params would get the order rejected
   * or signed for the wrong exchange, so the trading path requires strict mode.
   * Set false for non-signing reads that can tolerate the 0.01/false fallback.
   */
  strict?: boolean;
  /** negRisk hint used only when strict === false. */
  fallbackNegRisk?: boolean;
}

/**
 * Resolve { tickSize, negRisk } from the CLOB book — REQUIRED for createOrder.
 *
 * STRICT by default: if the /book lookup fails or omits tickSize, this THROWS
 * rather than guessing — a wrong tickSize/negRisk produces a broken order hash
 * (rejected or wrong-exchange). Callers that already know both should pass them
 * to the adapter and skip this. Non-signing reads can opt into the lenient
 * 0.01/false fallback via { strict: false }.
 */
export async function resolveCreateOrderOptions(
  tokenId: string,
  opts: ResolveOrderOptionsOpts = {},
): Promise<{ tickSize: PolymarketTickSize; negRisk: boolean }> {
  const strict = opts.strict ?? true;
  const fallback = {
    tickSize: "0.01" as PolymarketTickSize,
    negRisk: typeof opts.fallbackNegRisk === "boolean" ? opts.fallbackNegRisk : false,
  };

  let book: Awaited<ReturnType<typeof getOrderbook>>;
  try {
    book = await getOrderbook(tokenId, opts);
  } catch (err) {
    if (strict) {
      throw new Error(
        `failed to resolve tickSize/negRisk for token ${tokenId} from CLOB book; refusing to guess: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
    return fallback;
  }

  if (book.tickSize === undefined || typeof book.negRisk !== "boolean") {
    if (strict) {
      throw new Error(
        `CLOB book for token ${tokenId} did not return tickSize/negRisk; refusing to guess order options`,
      );
    }
    return {
      tickSize: book.tickSize ?? fallback.tickSize,
      negRisk: typeof book.negRisk === "boolean" ? book.negRisk : fallback.negRisk,
    };
  }

  return { tickSize: book.tickSize, negRisk: book.negRisk };
}

interface RawPrice {
  token_id?: string;
  asset_id?: string;
  side?: string;
  price?: string;
}

// The real CLOB POST /prices returns a MAPPED object keyed by token id, each
// value keyed by side: { "<token_id>": { "BUY": "0.6", "SELL": "0.61" } }.
// (Some responses/proxies return an array of rows instead — handle both.)
type RawPricesResponse = Record<string, Record<string, string>> | RawPrice[];

function priceFromMapped(
  data: Record<string, Record<string, string>>,
  tokenId: string,
  side: OrderSide,
): string | undefined {
  const bySide = data[tokenId];
  if (!bySide || typeof bySide !== "object") return undefined;
  // Side keys are upper-cased ("BUY"/"SELL") in the live response; be lenient.
  const upper = side.toUpperCase();
  return bySide[upper] ?? bySide[side] ?? bySide[side.toLowerCase()];
}

/**
 * Batch best bid/ask via POST /prices. Body [{ token_id, side }].
 * Returns one entry per REQUEST (so the requested side is always preserved),
 * resolving prices from the mapped-object response (primary) or array (fallback).
 */
export async function getPrices(
  requests: { tokenId: string; side: OrderSide }[],
  opts?: PolymarketFetchOptions,
): Promise<PolymarketBestPrice[]> {
  if (requests.length === 0) return [];
  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(`${POLYMARKET_CLOB_API_BASE}/prices`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(
      requests.map((r) => ({ token_id: r.tokenId, side: r.side.toUpperCase() })),
    ),
    signal: timeoutSignal(opts),
  });
  if (!response.ok) throw new Error(`Polymarket CLOB prices error: ${response.status}`);
  const data = (await response.json()) as RawPricesResponse;

  if (Array.isArray(data)) {
    // Array fallback shape: [{ token_id, side, price }].
    return data.map((p, i) => {
      const echoed = p.side?.toLowerCase();
      const side: OrderSide =
        echoed === "sell" ? "sell" : echoed === "buy" ? "buy" : (requests[i]?.side ?? "buy");
      return {
        tokenId: p.token_id || p.asset_id || requests[i]?.tokenId || "",
        side,
        price: p.price ?? "0",
      };
    });
  }

  // Mapped-object shape (the live response). One result per request so the
  // requested side is always honored.
  return requests.map((r) => ({
    tokenId: r.tokenId,
    side: r.side,
    price: priceFromMapped(data, r.tokenId, r.side) ?? "0",
  }));
}

export interface PriceHistoryParams {
  interval?: "1h" | "6h" | "1d" | "1w" | "1m" | "max";
  fidelity?: number;
  startTs?: number;
  endTs?: number;
}

interface RawPriceHistoryResponse {
  history?: unknown[];
  error?: string;
}
interface RawBatchPriceHistoryResponse {
  history?: Record<string, unknown[]>;
  error?: string;
}

/** Single-token price history. */
export async function getPriceHistory(
  tokenId: string,
  params: PriceHistoryParams = {},
  opts?: PolymarketFetchOptions,
): Promise<PolymarketPricePoint[]> {
  const doFetch = opts?.fetch ?? fetch;
  const url = new URL("/prices-history", POLYMARKET_CLOB_API_BASE);
  url.searchParams.set("market", tokenId);
  url.searchParams.set("interval", params.interval ?? "1d");
  url.searchParams.set("fidelity", String(params.fidelity ?? 1));
  // Honor bounded windows (mirrors the batch path). When omitted, the interval
  // governs the range.
  if (params.startTs !== undefined) url.searchParams.set("startTs", String(params.startTs));
  if (params.endTs !== undefined) url.searchParams.set("endTs", String(params.endTs));
  const response = await doFetch(url.toString(), { signal: timeoutSignal(opts) });
  if (response.status === 404 || response.status === 429 || !response.ok) return [];
  const data = (await response.json()) as RawPriceHistoryResponse;
  if (data.error) return [];
  return (data.history ?? []).filter(isPricePoint);
}

/**
 * Batch price history via POST /batch-prices-history. markets capped at 20/call.
 * THE efficiency win — moved price keepers to this in 20-token chunks.
 */
export async function getBatchPriceHistory(
  tokenIds: string[],
  params: PriceHistoryParams = {},
  opts?: PolymarketFetchOptions,
): Promise<Map<string, PolymarketPricePoint[]>> {
  if (tokenIds.length > POLYMARKET_BATCH_PRICE_HISTORY_LIMIT) {
    throw new Error(
      `Polymarket batch price history accepts at most ${POLYMARKET_BATCH_PRICE_HISTORY_LIMIT} token ids`,
    );
  }
  const out = new Map<string, PolymarketPricePoint[]>(tokenIds.map((id) => [id, []]));
  if (tokenIds.length === 0) return out;

  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(`${POLYMARKET_CLOB_API_BASE}/batch-prices-history`, {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify({
      markets: tokenIds,
      interval: params.interval ?? "1d",
      fidelity: params.fidelity ?? 1,
      start_ts: params.startTs,
      end_ts: params.endTs,
    }),
    signal: timeoutSignal(opts),
  });
  if (response.status === 404 || response.status === 429 || !response.ok) return out;
  const data = (await response.json()) as RawBatchPriceHistoryResponse;
  if (data.error || !data.history) return out;
  for (const tokenId of tokenIds) {
    out.set(tokenId, (data.history[tokenId] ?? []).filter(isPricePoint));
  }
  return out;
}
