import {
  type AttestationProvider,
  createDstackTdxProvider,
  createNoopDevProvider,
} from "@stwd/attestation";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

export const quoteRoutes = new Hono<{ Variables: AppVariables }>();

// SEC-085: /quote is mounted unauthenticated, and every request drives two
// blocking unix-socket round trips into the dstack guest agent (TDX quote
// generation is non-trivial). Bound anonymous callers with a per-client-IP
// fixed-window limiter so the guest agent cannot be exhausted.
const QUOTE_RATE_LIMIT_WINDOW_MS = 60_000;
const QUOTE_RATE_LIMIT_MAX = 30;
const QUOTE_RATE_BUCKET_CAP = 10_000;
const quoteRateBuckets = new Map<string, { windowStart: number; count: number }>();

function quoteRateLimitExceeded(clientKey: string, nowMs: number): boolean {
  const bucket = quoteRateBuckets.get(clientKey);
  if (!bucket || nowMs - bucket.windowStart >= QUOTE_RATE_LIMIT_WINDOW_MS) {
    quoteRateBuckets.set(clientKey, { windowStart: nowMs, count: 1 });
    if (quoteRateBuckets.size > QUOTE_RATE_BUCKET_CAP) {
      // Bound the limiter map itself against spoofed-IP growth.
      for (const [key, value] of quoteRateBuckets) {
        if (nowMs - value.windowStart >= QUOTE_RATE_LIMIT_WINDOW_MS) quoteRateBuckets.delete(key);
      }
    }
    return false;
  }
  bucket.count += 1;
  return bucket.count > QUOTE_RATE_LIMIT_MAX;
}

/**
 * SEC-085: raw dstack evidence embeds `vm_config`, which contains the full
 * compose definition and can leak internal config/env to anonymous clients.
 * Strip it recursively from the HTTP response; verification consumers only
 * need the quote/event_log/report_data fields.
 */
export function redactQuoteEvidence(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactQuoteEvidence);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== "vm_config")
        .map(([key, entry]) => [key, redactQuoteEvidence(entry)]),
    );
  }
  return value;
}

quoteRoutes.get("/", async (c) => {
  const clientKey = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (quoteRateLimitExceeded(clientKey, Date.now())) {
    return c.json({ error: "rate limit exceeded" }, 429);
  }

  const nonce = c.req.query("nonce") ?? crypto.randomUUID();
  // normalizeReportData caps report_data at 64 bytes; reject oversized
  // nonces as a client error instead of an unhandled 500.
  // TextEncoder instead of Buffer.byteLength: this package also builds for
  // Cloudflare Workers, where the Buffer global is not available.
  const nonceByteLength =
    nonce.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(nonce)
      ? nonce.length / 2
      : new TextEncoder().encode(nonce).length;
  if (nonceByteLength > 64) {
    return c.json({ error: "nonce must be <= 64 bytes" }, 400);
  }

  try {
    const provider = createConfiguredAttestationProvider();
    const quote = await provider.generateQuote({ nonce });
    const body = { ...quote, raw: redactQuoteEvidence(quote.raw) };
    return c.json(body, quote.verified ? 200 : 503);
  } catch (error) {
    // SEC-085: provider failures (guest agent unreachable, misconfigured
    // provider) must not leak internals to anonymous callers.
    console.error("attestation quote generation failed:", error);
    return c.json({ error: "attestation unavailable" }, 503);
  }
});

export function createConfiguredAttestationProvider(): AttestationProvider {
  const provider = process.env.STEWARD_ATTESTATION_PROVIDER ?? "noop-dev";
  switch (provider) {
    case "dstack-tdx":
      return createDstackTdxProvider();
    case "noop-dev":
      return createNoopDevProvider();
    default:
      throw new Error(`Unsupported STEWARD_ATTESTATION_PROVIDER: ${provider}`);
  }
}
