// @stwd/venue-polymarket
//
// Polymarket venue adapter for Steward. Pure adapter logic + types — NO routes,
// NO DB, NO tenant wiring (that's Phase B/C). Mirrors @stwd/venue-hyperliquid's
// shape: injected signer/credentials, zod schemas, config-driven builder fee.
//
// Layout (per POLYMARKET-KNOWLEDGE-DUMP §6):
//   constants    — hosts, chain id, sig types, limits
//   types        — zod schemas (order, signed order, market, position)
//   parsing      — Gamma JSON-string parsing (clobTokenIds/outcomes/outcomePrices)
//   credentials  — injection model + signer abstraction (no DB reads)
//   builder      — builder attribution (config, OFF/0 by default — the revenue rail)
//   discovery    — Gamma keyset pagination
//   marketdata   — CLOB batch books/prices/history
//   data         — positions via Data API
//   execution    — sigType-2 order build, precision rounding, post/cancel/list

export * from "./builder";
export * from "./constants";
export * from "./credentials";
export * from "./data";
export * from "./discovery";
export * from "./execution";
export * from "./marketdata";
export * from "./parsing";
export * from "./types";
