/**
 * Webhook signature verification — for consumers receiving HMAC-signed events.
 *
 * Server side (packages/webhooks/dispatcher.ts) signs the JSON body with
 * HMAC-SHA-256 over the raw request bytes and ships the hex digest in the
 * `X-Steward-Signature` header. Consumers verify by re-computing the HMAC
 * with their shared secret and comparing in constant time.
 *
 * Optionally, an `X-Steward-Timestamp` header records the dispatch time as
 * seconds-since-epoch. Callers can reject messages whose timestamp drifts
 * past a tolerance window (default 5 minutes) to limit replay value.
 *
 * Both sign and verify paths use only the Web Crypto / Subtle Crypto APIs
 * so the helper works in browsers, Workers, and Node 20+ without any
 * runtime-specific code paths.
 */

const encoder = new TextEncoder();

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.toLowerCase().replace(/^0x/, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0) return new Uint8Array(0);
  if (!/^[0-9a-f]+$/.test(normalized)) return new Uint8Array(0);
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = parseInt(normalized.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(buf: ArrayBuffer): string {
  const view = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < view.length; i++) {
    out += view[i].toString(16).padStart(2, "0");
  }
  return out;
}

/** Constant-time byte-array equality. Always reads both arrays to the end. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const secretBytes = encoder.encode(secret);
  return crypto.subtle.importKey(
    "raw",
    secretBytes.buffer.slice(
      secretBytes.byteOffset,
      secretBytes.byteOffset + secretBytes.byteLength,
    ) as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Compute the canonical hex signature for `body` with `secret`. Exposed so
 * tests and self-checks can produce expected values without re-implementing
 * the HMAC details.
 */
export async function signWebhookPayload(body: string, secret: string): Promise<string> {
  const key = await importHmacKey(secret);
  const bytes = encoder.encode(body);
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
  );
  return bytesToHex(sig);
}

export interface VerifyWebhookOptions {
  /** Maximum age in seconds. Default 300 (5 minutes). Set Infinity to skip. */
  toleranceSec?: number;
  /** Defaults to Date.now()/1000 — injectable for deterministic testing. */
  nowSec?: number;
}

export interface VerifyWebhookResult {
  valid: boolean;
  /** Set when `valid` is false. Coarse enum so callers can log without leaking detail. */
  reason?: "missing-signature" | "bad-signature" | "stale-timestamp" | "bad-timestamp";
}

/**
 * Verify an inbound webhook against the shared secret. The `signature` arg
 * is the raw value of `X-Steward-Signature`; `timestamp` is the optional
 * `X-Steward-Timestamp` header. `body` MUST be the raw request body as the
 * server saw it — re-serialized JSON will not match because key ordering
 * and whitespace differ.
 */
export async function verifyWebhookSignature(
  body: string,
  signature: string | null | undefined,
  secret: string,
  timestamp?: string | number | null,
  options: VerifyWebhookOptions = {},
): Promise<VerifyWebhookResult> {
  if (!signature || typeof signature !== "string") {
    return { valid: false, reason: "missing-signature" };
  }

  if (timestamp !== undefined && timestamp !== null) {
    const tsNum = typeof timestamp === "number" ? timestamp : Number(timestamp);
    if (!Number.isFinite(tsNum)) {
      return { valid: false, reason: "bad-timestamp" };
    }
    const tolerance = options.toleranceSec ?? 300;
    if (Number.isFinite(tolerance)) {
      const now = options.nowSec ?? Math.floor(Date.now() / 1000);
      if (Math.abs(now - tsNum) > tolerance) {
        return { valid: false, reason: "stale-timestamp" };
      }
    }
  }

  // When a timestamp is present, the canonical signed string is
  // `<timestamp>.<body>` — matching Stripe's convention and what newer
  // releases of the server dispatcher emit. The verifier accepts EITHER
  // shape so older dispatchers (signing the body alone) continue to work
  // until the rollout completes.
  const candidates: string[] = [];
  if (timestamp !== undefined && timestamp !== null) {
    candidates.push(`${timestamp}.${body}`);
  }
  candidates.push(body);

  const provided = hexToBytes(signature);
  if (provided.length === 0) return { valid: false, reason: "bad-signature" };

  for (const candidate of candidates) {
    const expectedHex = await signWebhookPayload(candidate, secret);
    const expected = hexToBytes(expectedHex);
    if (constantTimeEqual(provided, expected)) {
      return { valid: true };
    }
  }
  return { valid: false, reason: "bad-signature" };
}
