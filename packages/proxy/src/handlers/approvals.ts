import type { PendingProxyRequest, SecretRoute } from "@stwd/db";
import { and, eq, getDb, pendingProxyRequests } from "@stwd/db";
import { type EncryptedKey, KeyStore } from "@stwd/vault";
import { positiveIntegerEnv } from "../config";

const MAX_HELD_PROXY_BODY_BYTES = positiveIntegerEnv(
  "STEWARD_PROXY_APPROVAL_MAX_BODY_BYTES",
  2 * 1024 * 1024,
);
const DEFAULT_APPROVAL_TTL_MS = positiveIntegerEnv("STEWARD_PROXY_APPROVAL_TTL_MS", 15 * 60 * 1000);

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "cookie",
  "proxy-authorization",
  "x-api-key",
  "x-auth-token",
  "x-steward-key",
  "x-steward-platform-key",
  "x-steward-signature",
  "x-steward-signer-secret",
]);

const SAFE_HEADER_NAMES = new Set([
  "accept",
  "accept-language",
  "content-type",
  "idempotency-key",
  "anthropic-version",
  "anthropic-beta",
  "openai-beta",
  "openai-organization",
  "openai-project",
  "user-agent",
  "x-request-id",
  "x-correlation-id",
  "x-steward-request-timestamp",
  "x-steward-request-expires-at",
]);

function approvalKeyStore(): KeyStore {
  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) throw new Error("STEWARD_MASTER_PASSWORD is required for proxy approvals");
  return new KeyStore(masterPassword, undefined, "secret-vault");
}

function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

async function sha256Hex(input: string | ArrayBuffer | Uint8Array): Promise<string> {
  const data =
    typeof input === "string"
      ? new TextEncoder().encode(input)
      : input instanceof Uint8Array
        ? input
        : input;
  const digest = await crypto.subtle.digest("SHA-256", new Uint8Array(data));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function safeProxyApprovalHeaders(headers: Headers): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const [name, value] of headers.entries()) {
    const lower = name.toLowerCase();
    if (SENSITIVE_HEADER_NAMES.has(lower)) continue;
    if (!SAFE_HEADER_NAMES.has(lower)) continue;
    if (/[\r\n]/.test(value)) continue;
    safe[lower] = value;
  }
  return safe;
}

async function readBoundedRequestBody(request: Request): Promise<Uint8Array> {
  const rawLength = request.headers.get("content-length");
  if (rawLength) {
    const contentLength = Number(rawLength);
    if (!Number.isFinite(contentLength) || contentLength < 0) {
      throw new Error("Invalid Content-Length header");
    }
    if (contentLength > MAX_HELD_PROXY_BODY_BYTES) {
      throw new Error("Proxy request body is too large to hold for approval");
    }
  }
  const clone = request.clone();
  if (!clone.body) return new Uint8Array();
  const reader = clone.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_HELD_PROXY_BODY_BYTES) {
        await reader.cancel();
        throw new Error("Proxy request body is too large to hold for approval");
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
  return body;
}

/**
 * Derive a structural schema from a parsed JSON value. This deliberately never
 * copies scalar VALUES into the output — only field names and value TYPES — so
 * secrets embedded anywhere in the body (under innocuous keys, in arrays, or as
 * bare strings) can never leak through the persisted preview. Operators and
 * agents see the request SHAPE, not its contents.
 */
function schemaOfJson(value: unknown, depth = 0): unknown {
  if (depth > 6) return "unknown";
  if (value === null) return "null";
  if (Array.isArray(value)) {
    // Report element types without preserving element order/values. We sample a
    // bounded prefix to derive the union of element types.
    const elementTypes = new Set<string>();
    for (const item of value.slice(0, 50)) {
      elementTypes.add(JSON.stringify(schemaOfJson(item, depth + 1)));
    }
    const types = [...elementTypes].map((t) => JSON.parse(t) as unknown);
    return { type: "array", length: value.length, elementTypes: types };
  }
  const t = typeof value;
  if (t !== "object") return t; // "string" | "number" | "boolean"
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>).slice(0, 100)) {
    // Keep field NAMES (structural), never their values.
    out[key] = schemaOfJson(item, depth + 1);
  }
  return out;
}

/**
 * Build a preview that contains ONLY structural metadata about the request body:
 * content type, byte length, canonical digest, and (for JSON) a value-free
 * schema. No body values are ever persisted here — this row is later shown to
 * agents and operators, so it must never carry credentials regardless of what
 * key they were nested under.
 */
export function bodyPreview(headers: Headers, body: Uint8Array): Record<string, unknown> {
  const contentType = headers.get("content-type") ?? "";
  const preview: Record<string, unknown> = {
    contentType: contentType || null,
    bodyBytes: body.byteLength,
    bodySha256: "",
  };
  if (body.byteLength === 0) return preview;
  if (contentType.includes("application/json")) {
    try {
      preview.schema = schemaOfJson(JSON.parse(bytesToString(body)));
      return preview;
    } catch {
      preview.parseError = "invalid-json";
    }
  }
  // Non-JSON (or unparseable) bodies expose nothing beyond their type + size.
  return preview;
}

function approvalTtlMs(route: SecretRoute): number {
  const raw = (route.approvalConfig as { ttlSeconds?: unknown } | null)?.ttlSeconds;
  if (typeof raw !== "number" || !Number.isFinite(raw)) return DEFAULT_APPROVAL_TTL_MS;
  return Math.max(30, Math.min(3600, Math.floor(raw))) * 1000;
}

export async function canonicalProxyApprovalDigest(input: {
  tenantId: string;
  agentId: string;
  routeId: string;
  method: string;
  targetHost: string;
  targetPath: string;
  safeHeaders: Record<string, string>;
  body: Uint8Array;
}): Promise<string> {
  const normalizedHeaders = Object.keys(input.safeHeaders)
    .sort()
    .map((key) => `${key}:${input.safeHeaders[key]}`)
    .join("\n");
  return sha256Hex(
    [
      "steward-proxy-approval-v1",
      input.tenantId,
      input.agentId,
      input.routeId,
      input.method.toUpperCase(),
      input.targetHost.toLowerCase(),
      input.targetPath,
      normalizedHeaders,
      await sha256Hex(input.body),
    ].join("\n"),
  );
}

export async function holdProxyApprovalRequest(input: {
  tenantId: string;
  agentId: string;
  route: SecretRoute;
  method: string;
  targetHost: string;
  targetPath: string;
  request: Request;
}): Promise<PendingProxyRequest> {
  const body = await readBoundedRequestBody(input.request);
  const safeHeaders = safeProxyApprovalHeaders(input.request.headers);
  const preview = bodyPreview(input.request.headers, body);
  preview.bodySha256 = await sha256Hex(body);
  const idempotencyKey = safeHeaders["idempotency-key"] ?? null;
  const digest = await canonicalProxyApprovalDigest({
    tenantId: input.tenantId,
    agentId: input.agentId,
    routeId: input.route.id,
    method: input.method,
    targetHost: input.targetHost,
    targetPath: input.targetPath,
    safeHeaders,
    body,
  });
  if (idempotencyKey) {
    const [existing] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(
        and(
          eq(pendingProxyRequests.tenantId, input.tenantId),
          eq(pendingProxyRequests.agentId, input.agentId),
          eq(pendingProxyRequests.idempotencyKey, idempotencyKey),
        ),
      )
      .limit(1);
    if (existing) {
      if (existing.requestDigest !== digest)
        throw new Error("Idempotency-Key was already used for a different proxy request");
      return existing;
    }
  }
  const encrypted = approvalKeyStore().encrypt(bytesToBase64(body), {
    tenantId: input.tenantId,
    agentId: input.agentId,
    name: `pending-proxy:${digest}`,
  });
  const [row] = await getDb()
    .insert(pendingProxyRequests)
    .values({
      tenantId: input.tenantId,
      agentId: input.agentId,
      routeId: input.route.id,
      method: input.method.toUpperCase(),
      targetHost: input.targetHost,
      targetPath: input.targetPath,
      requestDigest: digest,
      idempotencyKey,
      preview,
      safeHeaders,
      bodyCiphertext: encrypted.ciphertext,
      bodyIv: encrypted.iv,
      bodyAuthTag: encrypted.tag,
      bodySalt: encrypted.salt,
      status: "pending",
      expiresAt: new Date(Date.now() + approvalTtlMs(input.route)),
    })
    .onConflictDoNothing()
    .returning();
  if (row) return row;
  if (idempotencyKey) {
    const [existing] = await getDb()
      .select()
      .from(pendingProxyRequests)
      .where(
        and(
          eq(pendingProxyRequests.tenantId, input.tenantId),
          eq(pendingProxyRequests.agentId, input.agentId),
          eq(pendingProxyRequests.idempotencyKey, idempotencyKey),
        ),
      )
      .limit(1);
    if (existing?.requestDigest === digest) return existing;
  }
  throw new Error("Failed to persist pending proxy request");
}

export function decryptPendingProxyBody(row: PendingProxyRequest): Uint8Array {
  const encrypted: EncryptedKey = {
    ciphertext: row.bodyCiphertext,
    iv: row.bodyIv,
    tag: row.bodyAuthTag,
    salt: row.bodySalt,
  };
  const plaintext = approvalKeyStore().decrypt(encrypted, {
    tenantId: row.tenantId,
    agentId: row.agentId,
    name: `pending-proxy:${row.requestDigest}`,
  });
  return base64ToBytes(plaintext);
}
