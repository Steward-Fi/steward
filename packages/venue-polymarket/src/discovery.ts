import { DEFAULT_FETCH_TIMEOUT_MS, POLYMARKET_GAMMA_API_BASE } from "./constants";
import { getClobTokenIds, getOutcomePrices, getOutcomes } from "./parsing";
import { type PolymarketEvent, type PolymarketMarket } from "./types";

// ---------------------------------------------------------------------------
// Discovery — Gamma. Keyset/cursor pagination is the stable path for backfills.
// `offset` is REJECTED on keyset endpoints; keyset events expose `closed` but
// NOT `active` (filter active client-side). See KNOWLEDGE-DUMP §3.
// ---------------------------------------------------------------------------

export interface PolymarketFetchOptions {
  fetch?: typeof fetch;
  signal?: AbortSignal;
}

function gammaUrl(
  path: string,
  params: Record<string, string | number | boolean | undefined>,
): string {
  const url = new URL(path, POLYMARKET_GAMMA_API_BASE);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function timeoutSignal(opts?: PolymarketFetchOptions): AbortSignal | undefined {
  if (opts?.signal) return opts.signal;
  if (DEFAULT_FETCH_TIMEOUT_MS <= 0) return undefined;
  return AbortSignal.timeout(DEFAULT_FETCH_TIMEOUT_MS);
}

// Raw Gamma market shape (JSON-string fields parsed inside the adapter).
interface RawGammaMarket {
  id: string;
  question?: string;
  slug?: string;
  conditionId?: string | null;
  clobTokenIds?: string | string[] | null;
  outcomes?: string | string[] | null;
  outcomePrices?: string | string[] | null;
  negRisk?: boolean;
  active?: boolean;
  closed?: boolean;
  volume?: number;
  liquidity?: number;
  endDate?: string;
}

interface RawGammaEvent {
  id: string;
  title?: string;
  slug?: string;
  active?: boolean;
  closed?: boolean;
  archived?: boolean;
  markets?: RawGammaMarket[];
}

interface GammaEventsKeysetResponse {
  events?: RawGammaEvent[];
  next_cursor?: string;
}

/** Normalize a raw Gamma market: parse the JSON-string array fields here. */
export function normalizeGammaMarket(raw: RawGammaMarket): PolymarketMarket {
  return {
    id: raw.id,
    question: raw.question,
    slug: raw.slug,
    conditionId: raw.conditionId ?? undefined,
    clobTokenIds: getClobTokenIds(raw.clobTokenIds),
    outcomes: getOutcomes(raw.outcomes),
    outcomePrices: getOutcomePrices(raw.outcomePrices),
    negRisk: raw.negRisk,
    active: raw.active,
    closed: raw.closed,
    volume: raw.volume,
    liquidity: raw.liquidity,
    endDate: raw.endDate,
  };
}

function normalizeGammaEvent(raw: RawGammaEvent): PolymarketEvent {
  return {
    id: raw.id,
    title: raw.title,
    slug: raw.slug,
    active: raw.active,
    closed: raw.closed,
    archived: raw.archived,
    markets: (raw.markets ?? []).map(normalizeGammaMarket),
  };
}

export interface ListEventsParams {
  active?: boolean;
  closed?: boolean;
  archived?: boolean;
  tag?: string;
  order?: string;
  ascending?: boolean;
  limit?: number;
  offset?: number;
}

/** Standard (offset) Gamma /events. Use for shallow fetches. */
export async function listEvents(
  params: ListEventsParams = {},
  opts?: PolymarketFetchOptions,
): Promise<PolymarketEvent[]> {
  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(gammaUrl("/events", { ...params }), {
    signal: timeoutSignal(opts),
  });
  if (!response.ok) throw new Error(`Polymarket Gamma events error: ${response.status}`);
  const data = (await response.json()) as RawGammaEvent[];
  return (Array.isArray(data) ? data : []).map(normalizeGammaEvent);
}

/** Standard (offset) Gamma /markets. */
export async function listMarkets(
  params: ListEventsParams = {},
  opts?: PolymarketFetchOptions,
): Promise<PolymarketMarket[]> {
  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(gammaUrl("/markets", { ...params }), {
    signal: timeoutSignal(opts),
  });
  if (!response.ok) throw new Error(`Polymarket Gamma markets error: ${response.status}`);
  const data = (await response.json()) as RawGammaMarket[];
  return (Array.isArray(data) ? data : []).map(normalizeGammaMarket);
}

export interface ListEventsKeysetParams {
  // NB: keyset events expose `closed` but NOT `active`. Filter active client-side.
  closed?: boolean;
  limit?: number;
  order?: string;
  ascending?: boolean;
  afterCursor?: string;
}

export interface EventsKeysetPage {
  events: PolymarketEvent[];
  nextCursor?: string;
}

/**
 * Keyset/cursor pagination — the stable path for deep backfills/status sync.
 * `offset` is intentionally NOT accepted here (Gamma rejects it on keyset).
 */
export async function listEventsKeyset(
  params: ListEventsKeysetParams = {},
  opts?: PolymarketFetchOptions,
): Promise<EventsKeysetPage> {
  const doFetch = opts?.fetch ?? fetch;
  const response = await doFetch(
    gammaUrl("/events/keyset", {
      closed: params.closed,
      limit: params.limit,
      order: params.order,
      ascending: params.ascending,
      after_cursor: params.afterCursor,
    }),
    { signal: timeoutSignal(opts) },
  );
  if (!response.ok) throw new Error(`Polymarket Gamma keyset events error: ${response.status}`);
  const data = (await response.json()) as GammaEventsKeysetResponse;
  return {
    events: (data.events ?? []).map(normalizeGammaEvent),
    nextCursor: data.next_cursor,
  };
}

/**
 * Convenience: page through ALL active events via keyset, filtering `active`
 * client-side (keyset doesn't expose it). Yields pages so callers control depth.
 */
export async function* iterateActiveEventsKeyset(
  params: Omit<ListEventsKeysetParams, "afterCursor"> = {},
  opts?: PolymarketFetchOptions,
): AsyncGenerator<PolymarketEvent[], void, unknown> {
  let cursor: string | undefined;
  do {
    const page = await listEventsKeyset({ ...params, afterCursor: cursor }, opts);
    // keyset can't filter `active`; drop closed/inactive client-side.
    const active = page.events.filter((e) => e.active !== false && e.closed !== true);
    if (active.length > 0) yield active;
    cursor = page.nextCursor;
  } while (cursor);
}
