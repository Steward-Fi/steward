import type { PolymarketPricePoint } from "./types";

// ---------------------------------------------------------------------------
// Gamma JSON-string parsing — kept INSIDE the adapter (don't leak Polymarket-isms).
// Each Gamma market carries clobTokenIds / outcomes / outcomePrices as
// JSON-ENCODED STRINGS. Parse them here, once.
// ---------------------------------------------------------------------------

export function parseMaybeJsonArray(value: string[] | string | null | undefined): string[] {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
  } catch {
    return [];
  }
}

/**
 * Extract clobTokenIds, filtering to plausible numeric asset ids (token_id is a
 * big numeric string). Mirrors the matchr pipeline filter.
 */
export function getClobTokenIds(value: string[] | string | null | undefined): string[] {
  return parseMaybeJsonArray(value).filter(
    (tokenId) => typeof tokenId === "string" && tokenId.length > 30 && /^[0-9]+$/.test(tokenId),
  );
}

export function getOutcomes(value: string[] | string | null | undefined): string[] {
  return parseMaybeJsonArray(value);
}

export function getOutcomePrices(value: string[] | string | null | undefined): string[] {
  return parseMaybeJsonArray(value);
}

export function isPricePoint(point: unknown): point is PolymarketPricePoint {
  return (
    typeof point === "object" &&
    point !== null &&
    typeof (point as PolymarketPricePoint).t === "number" &&
    typeof (point as PolymarketPricePoint).p === "number" &&
    (point as PolymarketPricePoint).p >= 0 &&
    (point as PolymarketPricePoint).p <= 1
  );
}
