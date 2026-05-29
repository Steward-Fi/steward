import { createMiddleware } from "hono/factory";
import type { ApiResponse, AppVariables } from "../services/context";

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SIGNATURE_PREFIX = "v1=";
// ±5min skew / TTL, matching request-expiry.ts and the webhook tolerance convention.
const DEFAULT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_TIMESTAMP_TTL_MS = 5 * 60 * 1000;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

// Accept Unix seconds (SDK client.ts emits seconds) or ms, or an HTTP/ISO date string.
function parseHttpTime(value: string | undefined): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (/^\d+$/.test(trimmed)) {
    const numeric = Number(trimmed);
    if (!Number.isSafeInteger(numeric)) return null;
    return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
  }
  const parsed = Date.parse(trimmed);
  return Number.isFinite(parsed) ? parsed : null;
}

export type AuthorizationSignatureOptions = {
  required?: boolean;
  secrets?: string[];
};

function configuredSecrets(): string[] {
  const combined = [
    process.env.STEWARD_REQUEST_SIGNING_SECRETS,
    process.env.STEWARD_REQUEST_SIGNING_SECRET,
  ]
    .filter(Boolean)
    .join(",");
  return combined
    .split(",")
    .map((secret) => secret.trim())
    .filter(Boolean);
}

function isSensitivePath(path: string): boolean {
  return (
    path.startsWith("/vault") ||
    path.startsWith("/agents") ||
    path.startsWith("/policies") ||
    path.startsWith("/secrets") ||
    path.startsWith("/trade") ||
    path.startsWith("/v1/trade") ||
    path.startsWith("/approvals") ||
    path.startsWith("/intents") ||
    path.startsWith("/audit") ||
    path.startsWith("/auth") ||
    path.startsWith("/user") ||
    path.startsWith("/webhooks") ||
    path.startsWith("/tenants") ||
    path.startsWith("/platform") ||
    path.startsWith("/condition-sets") ||
    path.startsWith("/condition_sets") ||
    path.startsWith("/v1/condition_sets")
  );
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

async function sha256TextHex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  return sha256Hex(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
}

async function canonicalRequest(request: Request): Promise<string> {
  const url = new URL(request.url);
  const bodyHash = await sha256Hex(await request.clone().arrayBuffer());
  const authHash = await sha256TextHex(request.headers.get("authorization") ?? "");
  const apiKeyHash = await sha256TextHex(request.headers.get("x-steward-key") ?? "");
  const platformKeyHash = await sha256TextHex(request.headers.get("x-steward-platform-key") ?? "");
  const signerIdHash = await sha256TextHex(request.headers.get("x-steward-signer-id") ?? "");
  const signerSecretHash = await sha256TextHex(
    request.headers.get("x-steward-signer-secret") ?? "",
  );
  const quorumIdHash = await sha256TextHex(request.headers.get("x-steward-key-quorum-id") ?? "");
  const quorumCredentialsHash = await sha256TextHex(
    request.headers.get("x-steward-key-quorum-credentials") ?? "",
  );
  return [
    "steward-request-signature-v1",
    request.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    request.headers.get("x-steward-tenant") ?? "",
    authHash,
    apiKeyHash,
    platformKeyHash,
    signerIdHash,
    signerSecretHash,
    quorumIdHash,
    quorumCredentialsHash,
    request.headers.get("x-steward-request-timestamp") ?? "",
    request.headers.get("x-steward-request-expires-at") ?? "",
    request.headers.get("idempotency-key") ?? "",
    bodyHash,
  ].join("\n");
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

export async function createAuthorizationSignature(
  input: {
    method: string;
    url: string;
    tenantId?: string;
    authorization?: string;
    apiKey?: string;
    platformKey?: string;
    signerId?: string;
    signerSecret?: string;
    quorumId?: string;
    quorumCredentials?: string;
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
  const authHash = await sha256TextHex(input.authorization ?? "");
  const apiKeyHash = await sha256TextHex(input.apiKey ?? "");
  const platformKeyHash = await sha256TextHex(input.platformKey ?? "");
  const signerIdHash = await sha256TextHex(input.signerId ?? "");
  const signerSecretHash = await sha256TextHex(input.signerSecret ?? "");
  const quorumIdHash = await sha256TextHex(input.quorumId ?? "");
  const quorumCredentialsHash = await sha256TextHex(input.quorumCredentials ?? "");
  const url = new URL(input.url, "https://steward.local");
  const canonical = [
    "steward-request-signature-v1",
    input.method.toUpperCase(),
    `${url.pathname}${url.search}`,
    input.tenantId ?? "",
    authHash,
    apiKeyHash,
    platformKeyHash,
    signerIdHash,
    signerSecretHash,
    quorumIdHash,
    quorumCredentialsHash,
    input.timestamp ?? "",
    input.expiresAt ?? "",
    input.idempotencyKey ?? "",
    bodyHash,
  ].join("\n");
  return `${SIGNATURE_PREFIX}${await hmacSha256Hex(secret, canonical)}`;
}

export function authorizationSignature(options?: AuthorizationSignatureOptions) {
  const required =
    options?.required ??
    (process.env.STEWARD_REQUIRE_AUTH_SIGNATURE === "true" ||
      process.env.NODE_ENV === "production");
  const secrets = options?.secrets ?? configuredSecrets();
  const maxClockSkewMs = parsePositiveInt(
    process.env.STEWARD_REQUEST_EXPIRY_MAX_SKEW_MS,
    DEFAULT_MAX_CLOCK_SKEW_MS,
  );
  const timestampTtlMs = parsePositiveInt(
    process.env.STEWARD_REQUEST_TIMESTAMP_TTL_MS,
    DEFAULT_TIMESTAMP_TTL_MS,
  );

  return createMiddleware<{ Variables: AppVariables }>(async (c, next) => {
    if (!MUTATING_METHODS.has(c.req.method.toUpperCase()) || !isSensitivePath(c.req.path)) {
      return next();
    }

    const rawSignature = c.req.header("X-Steward-Signature");
    if (!rawSignature) {
      if (!required) return next();
      return c.json<ApiResponse>({ ok: false, error: "X-Steward-Signature header required" }, 401);
    }

    const signature = extractSignature(rawSignature);
    if (!signature) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid X-Steward-Signature header" }, 400);
    }
    const timestampHeader = c.req.header("X-Steward-Request-Timestamp");
    const expiresAtHeader = c.req.header("X-Steward-Request-Expires-At");
    if (!timestampHeader && !expiresAtHeader) {
      return c.json<ApiResponse>(
        { ok: false, error: "Signed requests require a timestamp or expiry header" },
        400,
      );
    }
    // Enforce freshness here so a captured signed request cannot be replayed
    // indefinitely on paths that lack idempotency-store enforcement.
    const currentTime = Date.now();
    const expiresAt = parseHttpTime(expiresAtHeader);
    if (expiresAtHeader && expiresAt === null) {
      return c.json<ApiResponse>(
        { ok: false, error: "Invalid X-Steward-Request-Expires-At header" },
        400,
      );
    }
    if (expiresAt !== null) {
      if (expiresAt + maxClockSkewMs <= currentTime) {
        return c.json<ApiResponse>({ ok: false, error: "Signed request has expired" }, 401);
      }
      if (expiresAt - currentTime > timestampTtlMs + maxClockSkewMs) {
        return c.json<ApiResponse>(
          { ok: false, error: "Signed request expiry is too far in the future" },
          400,
        );
      }
    }
    const timestamp = parseHttpTime(timestampHeader);
    if (timestampHeader && timestamp === null) {
      return c.json<ApiResponse>(
        { ok: false, error: "Invalid X-Steward-Request-Timestamp header" },
        400,
      );
    }
    if (timestamp !== null) {
      if (timestamp - currentTime > maxClockSkewMs) {
        return c.json<ApiResponse>(
          { ok: false, error: "Signed request timestamp is too far in the future" },
          400,
        );
      }
      if (currentTime - timestamp > timestampTtlMs + maxClockSkewMs) {
        return c.json<ApiResponse>({ ok: false, error: "Signed request timestamp is stale" }, 401);
      }
    }
    if (!c.req.header("Idempotency-Key")) {
      return c.json<ApiResponse>(
        { ok: false, error: "Signed requests require an Idempotency-Key header" },
        400,
      );
    }
    if (secrets.length === 0) {
      return c.json<ApiResponse>({ ok: false, error: "Request signing is not configured" }, 500);
    }

    const canonical = await canonicalRequest(c.req.raw);
    const expectedSignatures = await Promise.all(
      secrets.map((secret) => hmacSha256Hex(secret, canonical)),
    );
    const valid = expectedSignatures.some((expected) => timingSafeEqualHex(expected, signature));
    if (!valid) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid request signature" }, 401);
    }

    c.set("requestSignatureVerified", true);
    return next();
  });
}

export const requireAuthorizationSignature = authorizationSignature({ required: true });
