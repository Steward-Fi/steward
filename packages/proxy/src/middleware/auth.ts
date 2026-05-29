/**
 * JWT authentication middleware for the proxy.
 *
 * Validates the agent's Bearer token, extracts agentId/tenantId,
 * and sets them on the Hono context for downstream handlers.
 */

import { assertTokenNotRevoked, verifyToken } from "@stwd/auth";
import { agents, and, eq, getDb } from "@stwd/db";
import type { Context, Next } from "hono";
import { PROXY_SCOPE } from "../config";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AgentClaims {
  agentId: string;
  tenantId: string;
  /** Legacy singular scope. Kept for backward compatibility. */
  scope: string;
  /** New explicit permissions list. Proxy access requires api:proxy. */
  scopes?: string[];
}

const SIGNATURE_PREFIX = "v1=";
const MAX_SIGNATURE_AGE_MS = 5 * 60_000;
const MAX_SIGNED_PROXY_BODY_BYTES = Number(
  process.env.STEWARD_PROXY_SIGNED_BODY_BYTES ?? 2 * 1024 * 1024,
);

function proxyRequestSignatureRequired(): boolean {
  return (
    process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE === "true" ||
    process.env.NODE_ENV === "production"
  );
}

function configuredProxySigningSecrets(): string[] {
  return [
    process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS,
    process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET,
    process.env.STEWARD_REQUEST_SIGNING_SECRETS,
    process.env.STEWARD_REQUEST_SIGNING_SECRET,
  ]
    .filter(Boolean)
    .join(",")
    .split(",")
    .map((secret) => secret.trim())
    .filter(Boolean);
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b)) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function sha256Hex(input: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", input);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function boundedRequestBodyBuffer(
  request: Request,
): Promise<{ ok: true; body: ArrayBuffer } | { ok: false; status: number; error: string }> {
  const rawLength = request.headers.get("content-length");
  if (rawLength) {
    const contentLength = Number(rawLength);
    if (!Number.isFinite(contentLength) || contentLength < 0) {
      return { ok: false, status: 400, error: "Invalid Content-Length header" };
    }
    if (contentLength > MAX_SIGNED_PROXY_BODY_BYTES) {
      return { ok: false, status: 413, error: "Signed proxy request body is too large" };
    }
  }

  const clone = request.clone();
  if (!clone.body) return { ok: true, body: new ArrayBuffer(0) };

  const reader = clone.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_SIGNED_PROXY_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, status: 413, error: "Signed proxy request body is too large" };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, body: body.buffer };
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

function extractSignature(header: string | undefined): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed.startsWith(SIGNATURE_PREFIX)) return null;
  const signature = trimmed.slice(SIGNATURE_PREFIX.length).trim();
  return /^[0-9a-f]{64}$/i.test(signature) ? signature.toLowerCase() : null;
}

function hasFreshSignatureWindow(request: Request): boolean {
  const now = Date.now();
  const timestamp = request.headers.get("x-steward-request-timestamp");
  if (timestamp) {
    const timestampMs = Number(timestamp) * 1000;
    if (Number.isFinite(timestampMs) && Math.abs(now - timestampMs) <= MAX_SIGNATURE_AGE_MS) {
      return true;
    }
  }

  const expiresAt = request.headers.get("x-steward-request-expires-at");
  if (!expiresAt) return false;
  const expiresAtMs = Number(expiresAt) * 1000;
  return (
    Number.isFinite(expiresAtMs) && expiresAtMs >= now && expiresAtMs - now <= MAX_SIGNATURE_AGE_MS
  );
}

async function canonicalProxyRequest(
  request: Request,
  tenantId: string,
  agentId: string,
): Promise<{ ok: true; canonical: string } | { ok: false; status: number; error: string }> {
  const url = new URL(request.url);
  const body = await boundedRequestBodyBuffer(request);
  if (!body.ok) return body;
  const bodyHash = await sha256Hex(body.body);
  return {
    ok: true,
    canonical: [
      "steward-proxy-request-signature-v1",
      request.method.toUpperCase(),
      `${url.pathname}${url.search}`,
      tenantId,
      agentId,
      request.headers.get("x-steward-request-timestamp") ?? "",
      request.headers.get("x-steward-request-expires-at") ?? "",
      request.headers.get("idempotency-key") ?? "",
      bodyHash,
    ].join("\n"),
  };
}

async function verifyProxyRequestSignature(
  request: Request,
  tenantId: string,
  agentId: string,
): Promise<{ ok: true } | { ok: false; status: number; error: string }> {
  if (!proxyRequestSignatureRequired()) return { ok: true };

  const signature = extractSignature(request.headers.get("x-steward-signature") ?? undefined);
  if (!signature) {
    return { ok: false, status: 401, error: "X-Steward-Signature header required" };
  }
  if (!hasFreshSignatureWindow(request)) {
    return {
      ok: false,
      status: 400,
      error: "Signed proxy requests require a fresh timestamp or expiry header",
    };
  }

  const secrets = configuredProxySigningSecrets();
  if (secrets.length === 0) {
    return { ok: false, status: 500, error: "Proxy request signing is not configured" };
  }

  const canonical = await canonicalProxyRequest(request, tenantId, agentId);
  if (!canonical.ok) return canonical;
  const expected = await Promise.all(
    secrets.map((secret) => hmacSha256Hex(secret, canonical.canonical)),
  );
  return expected.some((value) => timingSafeEqualHex(value, signature))
    ? { ok: true }
    : { ok: false, status: 401, error: "Invalid proxy request signature" };
}

export async function createProxyAuthorizationSignature(
  input: {
    method: string;
    url: string;
    tenantId: string;
    agentId: string;
    timestamp?: string;
    expiresAt?: string;
    idempotencyKey?: string;
    body?: string | ArrayBuffer;
  },
  secret: string,
): Promise<string> {
  let body: ArrayBuffer;
  if (typeof input.body === "string") {
    const bytes = new TextEncoder().encode(input.body);
    body = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  } else {
    body = input.body ?? new ArrayBuffer(0);
  }
  const bodyHash = await sha256Hex(body);
  const url = new URL(input.url, "https://steward-proxy.local");
  const canonical = [
    "steward-proxy-request-signature-v1",
    input.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    input.tenantId,
    input.agentId,
    input.timestamp ?? "",
    input.expiresAt ?? "",
    input.idempotencyKey ?? "",
    bodyHash,
  ].join("\n");
  return `${SIGNATURE_PREFIX}${await hmacSha256Hex(secret, canonical)}`;
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * Authenticate incoming requests via Bearer JWT.
 *
 * Sets `agentId` and `tenantId` on the Hono context variables.
 * Rejects with 401 if token is missing/invalid, 403 if scope is wrong.
 */
export async function authMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ ok: false, error: "Missing or invalid Authorization header" }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifyToken(token);

    const agentId = payload.agentId as string | undefined;
    const tenantId = payload.tenantId as string | undefined;
    const scopes = payload.scopes;

    if (!agentId || !tenantId) {
      return c.json({ ok: false, error: "Token missing agentId or tenantId claims" }, 401);
    }

    if (!Array.isArray(scopes) || !scopes.includes(PROXY_SCOPE)) {
      return c.json({ ok: false, error: `Token missing required ${PROXY_SCOPE} scope` }, 403);
    }

    const [agent] = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    if (!agent) {
      return c.json({ ok: false, error: "Agent not found" }, 403);
    }

    const signature = await verifyProxyRequestSignature(c.req.raw, tenantId, agentId);
    if (!signature.ok) {
      return c.json({ ok: false, error: signature.error }, signature.status as 400 | 401 | 500);
    }

    await assertTokenNotRevoked(payload);

    // Set on context for downstream handlers
    c.set("agentId", agentId);
    c.set("tenantId", tenantId);

    await next();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Token verification failed";
    return c.json({ ok: false, error: `Authentication failed: ${message}` }, 401);
  }
}
