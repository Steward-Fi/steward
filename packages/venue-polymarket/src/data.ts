import { defaultFetchTimeoutMs, POLYMARKET_DATA_API_BASE } from "./constants";
import type { PolymarketFetchOptions } from "./discovery";
import { type PolymarketPosition } from "./types";

// ---------------------------------------------------------------------------
// Data API — positions / trades / activity (public reads).
//
// Positions are read from the public /positions endpoint keyed by the funder
// Safe address. This adapter does not join tenant-owned market metadata.
// ---------------------------------------------------------------------------

function timeoutSignal(opts?: PolymarketFetchOptions): AbortSignal | undefined {
  if (opts?.signal) return opts.signal;
  const timeoutMs = defaultFetchTimeoutMs();
  if (timeoutMs <= 0) return undefined;
  return AbortSignal.timeout(timeoutMs);
}

interface RawDataApiPosition {
  asset?: string; // token_id
  tokenId?: string;
  conditionId?: string;
  title?: string;
  outcome?: string;
  size?: number | string;
  avgPrice?: number | string;
  curPrice?: number | string;
  currentValue?: number | string;
  cashPnl?: number | string;
  realizedPnl?: number | string;
  percentPnl?: number | string;
  negativeRisk?: boolean;
  negRisk?: boolean;
}

function num(v: unknown): number | undefined {
  if (v === undefined || v === null || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

function normalizePosition(raw: RawDataApiPosition): PolymarketPosition {
  const tokenId = String(raw.asset ?? raw.tokenId ?? "");
  const balance = num(raw.size) ?? 0;
  const avgPrice = num(raw.avgPrice);
  const currentPrice = num(raw.curPrice);
  const currentValue =
    num(raw.currentValue) ?? (currentPrice !== undefined ? balance * currentPrice : undefined);
  const realizedPnl = num(raw.realizedPnl);
  const unrealizedPnl =
    num(raw.cashPnl) ??
    (currentValue !== undefined && avgPrice !== undefined
      ? currentValue - balance * avgPrice
      : undefined);
  const totalPnl =
    realizedPnl !== undefined || unrealizedPnl !== undefined
      ? (realizedPnl ?? 0) + (unrealizedPnl ?? 0)
      : undefined;

  return {
    tokenId,
    conditionId: raw.conditionId,
    marketQuestion: raw.title,
    outcome: raw.outcome,
    balance,
    avgPrice,
    currentPrice,
    currentValue,
    realizedPnl,
    unrealizedPnl,
    totalPnl,
    negRisk: raw.negativeRisk ?? raw.negRisk,
    raw,
  };
}

export interface ListPositionsParams {
  /** The funder Safe address (the wallet that holds tokens). */
  user: string;
  limit?: number;
  /** Filter dust below this balance. Defaults 0 (keep all non-negative). */
  minBalance?: number;
}

/** Open positions by wallet via Data API /positions. */
export async function listPositions(
  params: ListPositionsParams,
  opts?: PolymarketFetchOptions,
): Promise<PolymarketPosition[]> {
  const doFetch = opts?.fetch ?? fetch;
  const url = new URL("/positions", POLYMARKET_DATA_API_BASE);
  url.searchParams.set("user", params.user);
  if (params.limit !== undefined) url.searchParams.set("limit", String(params.limit));

  const response = await doFetch(url.toString(), {
    headers: { Accept: "application/json" },
    signal: timeoutSignal(opts),
  });
  if (!response.ok) throw new Error(`Polymarket Data API positions error: ${response.status}`);

  const data = (await response.json()) as RawDataApiPosition[];
  const minBalance = params.minBalance ?? 0;
  return (Array.isArray(data) ? data : [])
    .map(normalizePosition)
    .filter((p) => p.balance > minBalance);
}
