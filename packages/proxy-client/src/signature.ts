/**
 * Request signing for the Steward proxy.
 *
 * Replicates the proxy's canonical form and HMAC exactly. The proxy verifier
 * lives in `@stwd/proxy` (middleware/auth.ts, `createProxyAuthorizationSignature`
 * + the server-side `canonicalProxyRequest`). This module is a dependency-light
 * mirror so agent containers do not have to import the whole proxy server.
 *
 * The two are pinned together by golden-vector tests
 * (`src/__tests__/signature.test.ts`) that verify this signer against the
 * proxy's own signer for identical inputs. If the proxy canonical form ever
 * changes, those tests fail and force this file to be updated in lockstep.
 */

const SIGNATURE_PREFIX = "v1=";

/** Canonical-form domain separator. Must match the proxy verifier. */
const CANONICAL_VERSION = "steward-proxy-request-signature-v1";

/** Placeholder base used only to parse a relative request path/search. */
const RELATIVE_URL_BASE = "https://steward-proxy.local";

export interface ProxySignatureInput {
  method: string;
  /** Request path (absolute URL or path+search). Only pathname+search are signed. */
  url: string;
  tenantId: string;
  agentId: string;
  /** Unix seconds. At least one of timestamp/expiresAt must be present at send time. */
  timestamp?: string;
  /** Unix seconds. */
  expiresAt?: string;
  idempotencyKey?: string;
  body?: string | ArrayBuffer | Uint8Array;
}

function copyToArrayBuffer(view: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(view.byteLength);
  new Uint8Array(out).set(view);
  return out;
}

function toArrayBuffer(body: string | ArrayBuffer | Uint8Array | undefined): ArrayBuffer {
  if (body === undefined) return new ArrayBuffer(0);
  if (typeof body === "string") {
    return copyToArrayBuffer(new TextEncoder().encode(body));
  }
  if (body instanceof Uint8Array) {
    return copyToArrayBuffer(body);
  }
  return body;
}

async function sha256Hex(input: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Build the canonical string that gets HMAC'd.
 *
 * MUST byte-match the proxy's `canonicalProxyRequest` /
 * `createProxyAuthorizationSignature` in @stwd/proxy. Field order:
 *   version, METHOD, path+search, tenantId, agentId, timestamp, expiresAt,
 *   idempotencyKey, sha256(body). Missing optional fields serialize as "".
 */
export async function buildCanonicalRequest(input: ProxySignatureInput): Promise<string> {
  const url = new URL(input.url, RELATIVE_URL_BASE);
  const bodyHash = await sha256Hex(toArrayBuffer(input.body));
  return [
    CANONICAL_VERSION,
    input.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    input.tenantId,
    input.agentId,
    input.timestamp ?? "",
    input.expiresAt ?? "",
    input.idempotencyKey ?? "",
    bodyHash,
  ].join("\n");
}

/**
 * Produce the `X-Steward-Signature` header value: `v1=<hex hmac>`.
 */
export async function signProxyRequest(
  input: ProxySignatureInput,
  secret: string,
): Promise<string> {
  const canonical = await buildCanonicalRequest(input);
  return `${SIGNATURE_PREFIX}${await hmacSha256Hex(secret, canonical)}`;
}

export { SIGNATURE_PREFIX };
