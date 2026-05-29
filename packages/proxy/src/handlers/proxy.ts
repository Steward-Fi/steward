/**
 * Core proxy handler.
 *
 * Implements the full credential injection flow:
 *   1. Parse target from request path (alias or direct)
 *   2. Find matching secret route for (tenantId, host, path, method)
 *   3. Decrypt credential from secret vault
 *   4. Build outbound request with injected credential
 *   5. Forward request, stream response back
 *   6. Log audit entry
 *   7. Zero credential from memory
 */

import type { LookupAddress } from "node:dns";
import { lookup as dnsLookup } from "node:dns/promises";
import type { ClientRequest, RequestOptions } from "node:http";
import { isIP, type LookupFunction } from "node:net";
import type { SecretRoute } from "@stwd/db";
import { and, desc, eq, getDb, gt, isNull, or, secretRoutes, secrets } from "@stwd/db";
import { getRedis, type SpendReservation, settleReservedSpend } from "@stwd/redis";
import { SecretVault } from "@stwd/vault";
import type { Context } from "hono";
import { recordAudit, recordRequiredAudit } from "../middleware/audit";
import {
  checkProxyRateLimit,
  checkProxySpendLimit,
  estimateProxyLlmReservationUsd,
  isProxyRedisAvailable,
  type ProxySpendLimitResult,
  reserveProxySpendLimit,
  trackProxySpend,
} from "../middleware/redis-enforcement";
import { resolveTarget } from "./alias";
import { compareRouteMatchSpecificity, matchHost, matchPath } from "./matching";

// ─── Secret Vault singleton ──────────────────────────────────────────────────

let _secretVault: SecretVault | null = null;
let checkProxyRateLimitForHandler = checkProxyRateLimit;

function getSecretVault(): SecretVault {
  if (!_secretVault) {
    const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
    if (!masterPassword) {
      throw new Error("STEWARD_MASTER_PASSWORD is required for secret decryption");
    }
    _secretVault = new SecretVault(masterPassword);
  }
  return _secretVault;
}

// ─── Route matching ──────────────────────────────────────────────────────────

/**
 * Find the best matching secret route for a request.
 *
 * Routes are matched by:
 *   - tenant_id (exact)
 *   - host_pattern (exact match or wildcard)
 *   - path_pattern (prefix match with wildcard)
 *   - method (* or exact match)
 *   - enabled = true
 *
 * Returns the highest-priority matching route, or null.
 */
async function findMatchingRoute(
  tenantId: string,
  agentId: string,
  host: string,
  path: string,
  method: string,
): Promise<SecretRoute | null> {
  const db = getDb();
  const now = new Date();

  // Fetch all enabled routes whose backing secret is currently active.
  const routes = await db
    .select({ route: secretRoutes })
    .from(secretRoutes)
    .innerJoin(
      secrets,
      and(
        eq(secrets.id, secretRoutes.secretId),
        eq(secrets.tenantId, tenantId),
        isNull(secrets.deletedAt),
        or(isNull(secrets.expiresAt), gt(secrets.expiresAt, now)),
      ),
    )
    .where(
      and(
        eq(secretRoutes.tenantId, tenantId),
        eq(secretRoutes.agentId, agentId),
        eq(secretRoutes.enabled, true),
      ),
    )
    .orderBy(desc(secretRoutes.priority));

  const matches: SecretRoute[] = [];
  for (const { route } of routes) {
    if (!matchHost(route.hostPattern, host)) continue;
    if (!matchPath(route.pathPattern ?? "/*", path)) continue;
    if (route.method !== "*" && route.method?.toUpperCase() !== method.toUpperCase()) continue;
    matches.push(route);
  }

  matches.sort(compareRouteMatchSpecificity);
  return matches[0] ?? null;
}

// matchHost and matchPath imported from ./matching

// ─── Secret decryption ───────────────────────────────────────────────────────

/**
 * Decrypt a secret by its ID using the shared SecretVault lifecycle checks.
 * Returns the plaintext credential value.
 */
async function decryptSecret(tenantId: string, secretId: string): Promise<string> {
  return getSecretVault().decryptSecret(tenantId, secretId);
}

// ─── Credential injection ────────────────────────────────────────────────────

/**
 * Inject a credential into the outbound request based on the route config.
 */
function injectCredential(
  headers: Headers,
  url: URL,
  body: ReadableStream<Uint8Array> | null,
  route: SecretRoute,
  credential: string,
): { headers: Headers; url: URL; body: ReadableStream<Uint8Array> | null } {
  const formattedValue = (route.injectFormat ?? "{value}").replace("{value}", credential);

  switch (route.injectAs) {
    case "header":
      if (/[\r\n]/.test(formattedValue)) {
        throw new Error("Invalid credential header value");
      }
      headers.set(route.injectKey, formattedValue);
      break;

    case "query":
      throw new Error("Query credential injection is not supported");

    case "body":
      throw new Error("Body credential injection is not supported");

    default:
      console.warn(`[proxy] Unknown inject_as: ${route.injectAs}`);
  }

  return { headers, url, body };
}

function stripHopByHopHeaders(headers: Headers): Set<string> {
  const blocked = new Set([
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "forwarded",
    "host",
    "idempotency-key",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-forwarded-protocol",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
    "x-original-url",
    "x-real-ip",
    "x-rewrite-url",
    "x-steward-key",
    "x-steward-platform-key",
    "x-steward-signature",
  ]);
  const connection = headers.get("connection");
  if (connection) {
    for (const token of connection.split(",")) {
      const name = token.trim().toLowerCase();
      if (name) blocked.add(name);
    }
  }
  return blocked;
}

async function parseJsonRequestBody(c: Context): Promise<Record<string, unknown> | null> {
  const contentType = requestHeader(c, "content-type") ?? "";
  if (!contentType.includes("application/json")) return null;
  const contentLength = Number(requestHeader(c, "content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_LLM_SPEND_TRACKING_BODY_BYTES) {
    return null;
  }

  try {
    const clone = c.req.raw.clone();
    if (!clone.body) return null;

    const reader = clone.body.getReader();
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_LLM_SPEND_TRACKING_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }

    const buffer = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      buffer.set(chunk, offset);
      offset += chunk.byteLength;
    }
    const body = JSON.parse(new TextDecoder().decode(buffer)) as unknown;
    return body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

async function releaseProxySpendReservation(
  agentId: string,
  tenantId: string,
  host: string,
  reservation: SpendReservation | null,
): Promise<void> {
  if (!reservation || reservation.reservedUsd <= 0) return;
  await settleReservedSpend(
    agentId,
    tenantId,
    reservation.reservedUsd,
    0,
    host,
    reservation.periods,
    reservation.buckets,
  );
}

let checkProxySpendLimitForHandler = checkProxySpendLimit;
let resolveProxyHostForHandler = dnsLookup;
const MAX_LLM_SPEND_TRACKING_BODY_BYTES = Number(
  process.env.STEWARD_PROXY_MAX_SPEND_BODY_BYTES ?? 1024 * 1024,
);
const PROXY_IDEMPOTENCY_TTL_MS = Number(
  process.env.STEWARD_PROXY_IDEMPOTENCY_TTL_MS ?? 24 * 60 * 60 * 1000,
);
const MAX_PROXY_IDEMPOTENCY_BODY_BYTES = Number(
  process.env.STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES ?? 2 * 1024 * 1024,
);
const PROXY_UPSTREAM_TIMEOUT_MS = Number(process.env.STEWARD_PROXY_UPSTREAM_TIMEOUT_MS ?? 30_000);
const MAX_PROXY_RESPONSE_BYTES = Number(
  process.env.STEWARD_PROXY_RESPONSE_BYTES ?? 25 * 1024 * 1024,
);
const MAX_PROXY_STREAM_DURATION_MS = Number(
  process.env.STEWARD_PROXY_STREAM_DURATION_MS ?? 5 * 60_000,
);
const MAX_PROXY_IN_FLIGHT_PER_AGENT = Number(
  process.env.STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT ?? 50,
);
const MAX_PROXY_IN_FLIGHT_PER_TENANT = Number(
  process.env.STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT ?? 250,
);
const IDEMPOTENCY_KEY_RE = /^[\x21-\x7e]{8,255}$/;
const SAFE_PROXY_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const inFlightByAgent = new Map<string, number>();
const inFlightByTenant = new Map<string, number>();

type ProxyReplayClaim = {
  fingerprint: string;
  status: "processing" | "completed";
  expiresAt: number;
};

type ProxyReplayClaimResult =
  | { ok: true; storageKey: string; storage: "memory" | "redis" }
  | { ok: false; status: number; error: string };

const proxyReplayClaims = new Map<string, ProxyReplayClaim>();

function incrementCounter(counter: Map<string, number>, key: string): void {
  counter.set(key, (counter.get(key) ?? 0) + 1);
}

function decrementCounter(counter: Map<string, number>, key: string): void {
  const next = (counter.get(key) ?? 0) - 1;
  if (next > 0) counter.set(key, next);
  else counter.delete(key);
}

function acquireProxySlot(
  agentId: string,
  tenantId: string,
):
  | {
      ok: true;
      release: () => void;
    }
  | {
      ok: false;
      status: 429;
      error: string;
    } {
  const agentCount = inFlightByAgent.get(agentId) ?? 0;
  if (MAX_PROXY_IN_FLIGHT_PER_AGENT > 0 && agentCount >= MAX_PROXY_IN_FLIGHT_PER_AGENT) {
    return { ok: false, status: 429, error: "Too many in-flight proxy requests for agent" };
  }
  const tenantCount = inFlightByTenant.get(tenantId) ?? 0;
  if (MAX_PROXY_IN_FLIGHT_PER_TENANT > 0 && tenantCount >= MAX_PROXY_IN_FLIGHT_PER_TENANT) {
    return { ok: false, status: 429, error: "Too many in-flight proxy requests for tenant" };
  }
  incrementCounter(inFlightByAgent, agentId);
  incrementCounter(inFlightByTenant, tenantId);
  let released = false;
  return {
    ok: true,
    release: () => {
      if (released) return;
      released = true;
      decrementCounter(inFlightByAgent, agentId);
      decrementCounter(inFlightByTenant, tenantId);
    },
  };
}

function releaseWhenBodyCloses(
  body: ReadableStream<Uint8Array> | null,
  release: () => void,
): ReadableStream<Uint8Array> | null {
  if (!body) {
    release();
    return null;
  }
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          release();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (error) {
        release();
        controller.error(error);
      }
    },
    async cancel(reason) {
      try {
        await reader.cancel(reason);
      } finally {
        release();
      }
    },
  });
}

function requireSharedProxyReplayStore(): boolean {
  return (
    process.env.REDIS_REQUIRED === "true" ||
    (process.env.NODE_ENV === "production" &&
      process.env.STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL !== "true")
  );
}

/** Test hook for overriding spend-limit enforcement without module mocks. */
export function __setCheckProxySpendLimitForTests(checker: typeof checkProxySpendLimit): void {
  checkProxySpendLimitForHandler = checker;
}

/** Test hook for overriding rate-limit enforcement without module mocks. */
export function __setCheckProxyRateLimitForTests(checker: typeof checkProxyRateLimit): void {
  checkProxyRateLimitForHandler = checker;
}

/** Test hook for overriding proxy DNS resolution without making real network lookups. */
export function __setResolveProxyHostForTests(resolver: typeof dnsLookup): void {
  resolveProxyHostForHandler = resolver;
}

function responseMayExposeInjectedQueryCredential(response: Response): boolean {
  return response.status >= 300 && response.status < 400 && response.headers.has("location");
}

const URL_BEARING_RESPONSE_HEADERS = new Set(["location", "content-location", "link", "refresh"]);

function shouldStripResponseHeaderForRoute(route: SecretRoute, headerName: string): boolean {
  if (route.injectAs !== "query") return false;
  return URL_BEARING_RESPONSE_HEADERS.has(headerName.toLowerCase());
}

function responseHeaderReflectsCredential(headers: Headers, credentialValue: string): boolean {
  for (const value of headers.values()) {
    if (value.includes(credentialValue)) return true;
  }
  return false;
}

function responseBodyCanReflectCredential(headers: Headers): boolean {
  return !responseLooksStreaming(headers);
}

async function sha256Hex(input: string | ArrayBuffer): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requestHeader(c: Context, name: string): string | undefined {
  return c.req.header?.(name) ?? c.req.raw.headers.get(name) ?? undefined;
}

async function boundedRequestBodyHash(c: Context): Promise<string | null> {
  const contentLength = Number(requestHeader(c, "content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > MAX_PROXY_IDEMPOTENCY_BODY_BYTES) {
    return null;
  }
  const clone = c.req.raw.clone();
  if (!clone.body) return sha256Hex("");

  const reader = clone.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_PROXY_IDEMPOTENCY_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const buffer = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return sha256Hex(buffer.buffer);
}

function collectExpiredProxyReplayClaims(): void {
  const now = Date.now();
  for (const [key, claim] of proxyReplayClaims.entries()) {
    if (claim.expiresAt <= now) proxyReplayClaims.delete(key);
  }
}

async function claimUnsafeProxyRequest(
  c: Context,
  tenantId: string,
  agentId: string,
  target: { host: string; path: string },
  method: string,
): Promise<ProxyReplayClaimResult> {
  const signedRequest = Boolean(requestHeader(c, "x-steward-signature"));
  if (SAFE_PROXY_METHODS.has(method.toUpperCase()) && !signedRequest) {
    return { ok: true, storageKey: "", storage: "memory" };
  }

  const key = requestHeader(c, "idempotency-key")?.trim();
  if (!key || !IDEMPOTENCY_KEY_RE.test(key)) {
    const requestType = signedRequest ? "signed proxy requests" : "mutating proxy requests";
    return {
      ok: false,
      status: 400,
      error: `Idempotency-Key header is required for ${requestType}`,
    };
  }

  const bodyHash = await boundedRequestBodyHash(c);
  if (!bodyHash) {
    return {
      ok: false,
      status: 413,
      error: "Proxy request body is too large for replay protection",
    };
  }

  const fingerprint = await sha256Hex(
    [tenantId, agentId, method.toUpperCase(), target.host, target.path, bodyHash].join("\n"),
  );
  const storageKey = `proxy:idempotency:${await sha256Hex([tenantId, agentId, key].join("\n"))}`;
  const claim: ProxyReplayClaim = {
    fingerprint,
    status: "processing",
    expiresAt: Date.now() + PROXY_IDEMPOTENCY_TTL_MS,
  };
  if (isProxyRedisAvailable()) {
    const redis = getRedis();
    const claimed = await redis.set(
      storageKey,
      JSON.stringify(claim),
      "PX",
      PROXY_IDEMPOTENCY_TTL_MS,
      "NX",
    );
    if (claimed) return { ok: true, storageKey, storage: "redis" };

    const rawExisting = await redis.get(storageKey);
    const existing = rawExisting ? safeJsonParseString<ProxyReplayClaim>(rawExisting) : null;
    if (!existing || existing.expiresAt <= Date.now()) {
      await redis.del(storageKey);
      return claimUnsafeProxyRequest(c, tenantId, agentId, target, method);
    }
    if (existing.fingerprint !== fingerprint) {
      return {
        ok: false,
        status: 409,
        error: "Idempotency-Key was already used for a different proxy request",
      };
    }
    return {
      ok: false,
      status: 409,
      error:
        existing.status === "processing"
          ? "Proxy request with this Idempotency-Key is already processing"
          : "Proxy request with this Idempotency-Key was already forwarded",
    };
  }

  if (requireSharedProxyReplayStore()) {
    return {
      ok: false,
      status: 503,
      error: "Shared proxy idempotency store unavailable",
    };
  }

  collectExpiredProxyReplayClaims();
  const existing = proxyReplayClaims.get(storageKey);
  if (existing) {
    if (existing.fingerprint !== fingerprint) {
      return {
        ok: false,
        status: 409,
        error: "Idempotency-Key was already used for a different proxy request",
      };
    }
    return {
      ok: false,
      status: 409,
      error:
        existing.status === "processing"
          ? "Proxy request with this Idempotency-Key is already processing"
          : "Proxy request with this Idempotency-Key was already forwarded",
    };
  }

  proxyReplayClaims.set(storageKey, claim);
  return { ok: true, storageKey, storage: "memory" };
}

function safeJsonParseString<T>(value: string): T | null {
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

async function completeUnsafeProxyRequest(claimResult: ProxyReplayClaimResult): Promise<void> {
  if (!claimResult.ok || !claimResult.storageKey) return;
  const { storageKey } = claimResult;
  if (!storageKey) return;
  if (claimResult.storage === "redis") {
    const rawClaim = await getRedis().get(storageKey);
    const claim = rawClaim ? safeJsonParseString<ProxyReplayClaim>(rawClaim) : null;
    if (claim) {
      await getRedis().set(
        storageKey,
        JSON.stringify({ ...claim, status: "completed" }),
        "PX",
        Math.max(1, claim.expiresAt - Date.now()),
      );
    }
    return;
  }
  const claim = proxyReplayClaims.get(storageKey);
  if (claim) proxyReplayClaims.set(storageKey, { ...claim, status: "completed" });
}

async function releaseUnsafeProxyRequest(claimResult: ProxyReplayClaimResult): Promise<void> {
  if (!claimResult.ok || !claimResult.storageKey) return;
  if (claimResult.storage === "redis") {
    await getRedis().del(claimResult.storageKey);
    return;
  }
  proxyReplayClaims.delete(claimResult.storageKey);
}

export function __clearProxyReplayClaimsForTests(): void {
  proxyReplayClaims.clear();
}

type ProxyDnsCheckResult =
  | { ok: true; records: LookupAddress[] }
  | { ok: false; status: 403 | 502; reason: string; error: string };

function isUnsafeIPv4Address(address: string): boolean {
  const parts = address.split(".").map((part) => Number(part));
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return true;
  }

  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0) ||
    a >= 224
  );
}

function ipv4FromMappedIPv6(address: string): string | null {
  const normalized = address.toLowerCase().split("%", 1)[0];
  const dotted = normalized.match(/(?:::ffff:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (dotted) return dotted[1];

  const halves = normalized.split("::");
  if (halves.length > 2) return null;

  const parseWords = (part: string): number[] | null => {
    if (!part) return [];
    const words = part.split(":");
    const parsed = words.map((word) => {
      if (!/^[0-9a-f]{1,4}$/.test(word)) return Number.NaN;
      return Number.parseInt(word, 16);
    });
    return parsed.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)
      ? null
      : parsed;
  };

  const left = parseWords(halves[0]);
  const right = parseWords(halves[1] ?? "");
  if (!left || !right) return null;

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  const words = [...left, ...Array.from({ length: missing }, () => 0), ...right];
  if (
    words.length !== 8 ||
    words[0] !== 0 ||
    words[1] !== 0 ||
    words[2] !== 0 ||
    words[3] !== 0 ||
    words[4] !== 0 ||
    words[5] !== 0xffff
  ) {
    return null;
  }

  return [words[6] >> 8, words[6] & 0xff, words[7] >> 8, words[7] & 0xff].join(".");
}

function expandIPv6Words(address: string): number[] | null {
  const normalized = address.toLowerCase().split("%", 1)[0];
  const halves = normalized.split("::");
  if (halves.length > 2) return null;

  const parseWords = (part: string): number[] | null => {
    if (!part) return [];
    const words = part.split(":");
    const parsed = words.map((word) => {
      if (!/^[0-9a-f]{1,4}$/.test(word)) return Number.NaN;
      return Number.parseInt(word, 16);
    });
    return parsed.some((word) => !Number.isInteger(word) || word < 0 || word > 0xffff)
      ? null
      : parsed;
  };

  const left = parseWords(halves[0]);
  const right = parseWords(halves[1] ?? "");
  if (!left || !right) return null;

  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;

  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function ipv4FromEmbeddedIPv6(address: string): string | null {
  const words = expandIPv6Words(address);
  if (!words || words.length !== 8) return null;

  const fromWords = (high: number, low: number) =>
    [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");

  const isNat64WellKnown =
    words[0] === 0x64 &&
    words[1] === 0xff9b &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0;
  if (isNat64WellKnown) return fromWords(words[6], words[7]);

  const isNat64LocalUse =
    words[0] === 0x64 && words[1] === 0xff9b && words[2] === 1 && words[3] === 0;
  if (isNat64LocalUse) return fromWords(words[6], words[7]);

  if (words[0] === 0x2002) return fromWords(words[1], words[2]);

  return null;
}

function isUnsafeIPv6Address(address: string): boolean {
  const normalized = address.toLowerCase();
  const mappedV4 = ipv4FromMappedIPv6(normalized);
  if (mappedV4) return isUnsafeIPv4Address(mappedV4);
  const embeddedV4 = ipv4FromEmbeddedIPv6(normalized);
  if (embeddedV4) return isUnsafeIPv4Address(embeddedV4);
  const words = expandIPv6Words(normalized);
  if (!words || words.length !== 8) return true;
  if (words?.[0] === 0x2001 && (words[1] === 0 || words[1] === 0xdb8)) return true;
  const first = words[0];

  return (
    words.every((word) => word === 0) ||
    (words.slice(0, 7).every((word) => word === 0) && words[7] === 1) ||
    (first & 0xfe00) === 0xfc00 ||
    (first & 0xffc0) === 0xfe80 ||
    (first & 0xffc0) === 0xfec0 ||
    (first & 0xff00) === 0xff00
  );
}

function isUnsafeResolvedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isUnsafeIPv4Address(address);
  if (family === 6) return isUnsafeIPv6Address(address);
  return true;
}

async function verifyProxyHostResolvesPublicly(host: string): Promise<ProxyDnsCheckResult> {
  try {
    const records = await resolveProxyHostForHandler(host, { all: true, verbatim: true });
    if (records.length === 0) {
      return {
        ok: false,
        status: 502,
        reason: "target-dns-resolution-empty",
        error: "Unable to resolve proxy target host",
      };
    }

    const unsafe = records.find((record) => isUnsafeResolvedAddress(record.address));
    if (unsafe) {
      return {
        ok: false,
        status: 403,
        reason: "target-resolves-private",
        error: `Proxy target host resolves to a private or reserved address (${unsafe.address})`,
      };
    }
    return { ok: true, records };
  } catch {
    return {
      ok: false,
      status: 502,
      reason: "target-dns-resolution-failed",
      error: "Unable to resolve proxy target host",
    };
  }
}

function lookupFromVettedRecords(records: LookupAddress[]): LookupFunction {
  return (_hostname, _options, callback) => {
    const selected = records[0];
    if (!selected) {
      callback(
        new Error("No vetted proxy target address") as NodeJS.ErrnoException,
        "" as never,
        0 as never,
      );
      return;
    }
    callback(null, selected.address, selected.family);
  };
}

function headersToNode(headers: Headers): Record<string, string> {
  const nodeHeaders: Record<string, string> = {};
  for (const [key, value] of headers.entries()) {
    nodeHeaders[key] = value;
  }
  return nodeHeaders;
}

async function writeWebBodyToNodeRequest(
  request: ClientRequest,
  body: ReadableStream<Uint8Array> | null,
): Promise<void> {
  if (!body) {
    request.end();
    return;
  }

  const reader = body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!request.write(value)) {
        await new Promise<void>((resolve, reject) => {
          request.once("drain", resolve);
          request.once("error", reject);
        });
      }
    }
    request.end();
  } catch (error) {
    request.destroy(
      error instanceof Error ? error : new Error("Failed to stream proxy request body"),
    );
  } finally {
    reader.releaseLock();
  }
}

function proxyResponseBody(
  response: NodeJS.ReadableStream,
  maxBytes: number,
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(controller) {
      let bytes = 0;
      const streamDeadline =
        maxBytes === 0 && MAX_PROXY_STREAM_DURATION_MS > 0
          ? setTimeout(() => {
              const error = new Error("Proxy streaming response exceeded duration limit");
              (response as { destroy?: (error?: Error) => void }).destroy?.(error);
              controller.error(error);
            }, MAX_PROXY_STREAM_DURATION_MS)
          : null;
      const clearDeadline = () => {
        if (streamDeadline) clearTimeout(streamDeadline);
      };
      response.on("data", (chunk: Buffer | string) => {
        bytes += typeof chunk === "string" ? Buffer.byteLength(chunk) : chunk.byteLength;
        if (maxBytes > 0 && bytes > maxBytes) {
          (response as { destroy?: (error?: Error) => void }).destroy?.(
            new Error("Proxy upstream response exceeded size limit"),
          );
          controller.error(new Error("Proxy upstream response exceeded size limit"));
          return;
        }
        controller.enqueue(
          typeof chunk === "string" ? new TextEncoder().encode(chunk) : new Uint8Array(chunk),
        );
      });
      response.on("end", () => {
        clearDeadline();
        controller.close();
      });
      response.on("error", (error) => {
        clearDeadline();
        controller.error(error);
      });
    },
    cancel() {
      (response as { destroy?: () => void }).destroy?.();
    },
  });
}

function responseLooksStreaming(headers: Headers): boolean {
  const contentType = headers.get("content-type")?.toLowerCase() ?? "";
  return contentType.includes("text/event-stream");
}

async function forwardWithVettedDns(
  url: URL,
  method: string,
  headers: Headers,
  body: ReadableStream<Uint8Array> | null,
  records: LookupAddress[],
): Promise<Response> {
  const transport =
    url.protocol === "https:" ? await import("node:https") : await import("node:http");
  const options: RequestOptions & { servername?: string } = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port ? Number(url.port) : undefined,
    path: `${url.pathname}${url.search}`,
    method,
    headers: headersToNode(headers),
    lookup: lookupFromVettedRecords(records),
  };
  if (url.protocol === "https:") {
    options.servername = url.hostname;
  }

  return new Promise<Response>((resolve, reject) => {
    const request = transport.request(options, (upstream) => {
      const responseHeaders = new Headers();
      for (const [key, value] of Object.entries(upstream.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) responseHeaders.append(key, item);
        } else if (value !== undefined) {
          responseHeaders.set(key, value);
        }
      }
      const rawLength = responseHeaders.get("content-length");
      const contentLength = rawLength ? Number(rawLength) : 0;
      if (
        MAX_PROXY_RESPONSE_BYTES > 0 &&
        Number.isFinite(contentLength) &&
        contentLength > MAX_PROXY_RESPONSE_BYTES &&
        !responseLooksStreaming(responseHeaders)
      ) {
        upstream.destroy();
        reject(new Error("Proxy upstream response exceeded size limit"));
        return;
      }
      resolve(
        new Response(
          proxyResponseBody(
            upstream,
            responseLooksStreaming(responseHeaders) ? 0 : MAX_PROXY_RESPONSE_BYTES,
          ),
          {
            status: upstream.statusCode ?? 502,
            statusText: upstream.statusMessage,
            headers: responseHeaders,
          },
        ),
      );
    });
    request.setTimeout(PROXY_UPSTREAM_TIMEOUT_MS, () => {
      request.destroy(new Error("Proxy upstream request timed out"));
    });
    request.on("error", reject);
    void writeWebBodyToNodeRequest(request, body);
  });
}

type ProxyForwarder = typeof forwardWithVettedDns;
let forwardProxyRequestForHandler: ProxyForwarder = forwardWithVettedDns;

export function __setForwardProxyRequestForTests(forwarder: ProxyForwarder): void {
  forwardProxyRequestForHandler = forwarder;
}

// ─── Main proxy handler ──────────────────────────────────────────────────────

/**
 * Handle a proxied request.
 *
 * This is the catch-all handler mounted on the Hono app.
 * Auth middleware has already run, so agentId and tenantId are available.
 */
export async function handleProxy(c: Context): Promise<Response> {
  const startTime = Date.now();
  const agentId = c.get("agentId") as string;
  const tenantId = c.get("tenantId") as string;
  const method = c.req.method;

  // 1. Resolve target URL from request path
  const target = resolveTarget(c.req.path);
  if (!target) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: "unresolved",
      targetPath: c.req.path,
      method,
      statusCode: 400,
      latencyMs: Date.now() - startTime,
      reason: "target-resolution-failed",
    });
    return c.json(
      {
        ok: false,
        error:
          "Could not resolve target from request path. Use a named alias (e.g. /openai/...) or /proxy/hostname/path",
      },
      400,
    );
  }

  // 2. Find matching secret route
  const route = await findMatchingRoute(tenantId, agentId, target.host, target.path, method);
  if (!route) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 403,
      latencyMs: Date.now() - startTime,
      reason: "credential-route-miss",
    });
    return c.json(
      {
        ok: false,
        error: `No credential route configured for ${target.host}${target.path}`,
      },
      403,
    );
  }
  if (route.injectAs === "query") {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 403,
      latencyMs: Date.now() - startTime,
      reason: "query-credential-injection-disabled",
    });
    return c.json(
      {
        ok: false,
        error: "Query credential injection is disabled because upstream responses can reflect credentials",
      },
      403,
    );
  }

  // 2.5. Redis rate-limit check (per agent + host)
  const rlResult = await checkProxyRateLimitForHandler(agentId, target.host);
  if (!rlResult.allowed) {
    c.header("Retry-After", String(Math.ceil(rlResult.resetMs / 1000)));
    c.header("X-RateLimit-Remaining", "0");
    c.header("X-RateLimit-Reset", String(Math.ceil(rlResult.resetMs / 1000)));
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 429,
      latencyMs: Date.now() - startTime,
      reason: "proxy-rate-limit-exceeded",
    });
    return c.json(
      {
        ok: false,
        error: `Rate limit exceeded for ${target.host}. Retry after ${Math.ceil(rlResult.resetMs / 1000)}s`,
      },
      429,
    );
  }

  const requestBodyParsed = await parseJsonRequestBody(c);

  // 2.6. Redis spend-limit check (per agent, configured by spending-limit policy)
  const spendResult: ProxySpendLimitResult = await checkProxySpendLimitForHandler(
    agentId,
    tenantId,
    target.host,
  );
  if (!spendResult.allowed) {
    const latencyMs = Date.now() - startTime;
    const limit = spendResult.limit ?? 0;
    const period = spendResult.period ?? "day";
    const reason =
      spendResult.reason ??
      `${period === "day" ? "Daily" : "Monthly"} proxy spend limit exceeded for ${target.host}`;

    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 402,
      latencyMs,
      reason,
    });

    return c.json(
      {
        ok: false,
        error: reason,
        limit: {
          type: "spend",
          period,
          limitUsd: limit,
          spentUsd: spendResult.spent,
          remainingUsd: spendResult.remaining,
        },
      },
      402,
    );
  }
  let spendReservation: SpendReservation | null = null;
  if (
    spendResult.configured &&
    (target.host === "api.openai.com" || target.host === "api.anthropic.com") &&
    requestBodyParsed?.stream === true
  ) {
    const reason = "Streaming proxy requests are disabled when spend limits are configured";
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 402,
      latencyMs: Date.now() - startTime,
      reason,
    });
    return c.json({ ok: false, error: reason }, 402);
  }
  if (
    spendResult.configured &&
    target.host !== "api.openai.com" &&
    target.host !== "api.anthropic.com"
  ) {
    const reason = `Spend-limited proxy requests to ${target.host} are blocked because this host has no metering strategy`;
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 402,
      latencyMs: Date.now() - startTime,
      reason,
    });
    return c.json({ ok: false, error: reason }, 402);
  }
  if (
    spendResult.configured &&
    (target.host === "api.openai.com" || target.host === "api.anthropic.com")
  ) {
    const reserveUsd = requestBodyParsed
      ? estimateProxyLlmReservationUsd(target.host, requestBodyParsed)
      : null;
    if (reserveUsd === null) {
      const reason =
        "Spend-limited LLM proxy requests must be text-only and include a known model and max token cap";
      await recordAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 402,
        latencyMs: Date.now() - startTime,
        reason,
      });
      return c.json({ ok: false, error: reason }, 402);
    }

    const reservationResult = await reserveProxySpendLimit(
      agentId,
      tenantId,
      target.host,
      reserveUsd,
    );
    if (!reservationResult.allowed) {
      const reason =
        reservationResult.reason ??
        `Proxy spend reservation exceeded for ${target.host}: requested $${reserveUsd.toFixed(4)}`;
      await recordAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 402,
        latencyMs: Date.now() - startTime,
        reason,
      });
      return c.json({ ok: false, error: reason }, 402);
    }
    spendReservation = reservationResult.reservation ?? null;
  }

  const dnsCheck = await verifyProxyHostResolvesPublicly(target.host);
  if (!dnsCheck.ok) {
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: dnsCheck.status,
      latencyMs: Date.now() - startTime,
      reason: dnsCheck.reason,
    });
    return c.json({ ok: false, error: dnsCheck.error }, dnsCheck.status);
  }

  const replayClaim = await claimUnsafeProxyRequest(c, tenantId, agentId, target, method);
  if (!replayClaim.ok) {
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: replayClaim.status,
      latencyMs: Date.now() - startTime,
      reason: replayClaim.error,
    });
    return c.json(
      { ok: false, error: replayClaim.error },
      replayClaim.status as 400 | 409 | 413 | 503,
    );
  }
  const proxySlot = acquireProxySlot(agentId, tenantId);
  if (!proxySlot.ok) {
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: proxySlot.status,
      latencyMs: Date.now() - startTime,
      reason: proxySlot.error,
    });
    return c.json({ ok: false, error: proxySlot.error }, proxySlot.status);
  }

  try {
    await recordRequiredAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 102,
      latencyMs: Date.now() - startTime,
      reason: "credential-proxy-authorized",
    });
  } catch (err) {
    console.error("[proxy] Required audit write failed before credential forwarding:", err);
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Proxy audit logging unavailable" }, 503);
  }

  // 3. Decrypt credential
  let credential: string;
  try {
    credential = await decryptSecret(tenantId, route.secretId);
  } catch (err) {
    console.error(`[proxy] Failed to decrypt secret ${route.secretId}:`, err);
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 500,
      latencyMs: Date.now() - startTime,
      reason: "credential-decrypt-failed",
    });
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Failed to decrypt credential" }, 500);
  }

  // 4. Build outbound request
  const outboundUrl = new URL(target.url);
  const outboundHeaders = new Headers();

  const skipHeaders = stripHopByHopHeaders(c.req.raw.headers);

  for (const [key, value] of c.req.raw.headers.entries()) {
    if (!skipHeaders.has(key.toLowerCase())) {
      outboundHeaders.set(key, value);
    }
  }

  // Set the correct host header for the target
  outboundHeaders.set("host", outboundUrl.host);

  // Inject credential
  let injectedCredentialValue: string | null =
    route.injectAs === "header"
      ? (route.injectFormat ?? "{value}").replace("{value}", credential)
      : null;
  try {
    injectCredential(outboundHeaders, outboundUrl, null, route, credential);
  } catch {
    credential = "";
    injectedCredentialValue = null;
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 400,
      latencyMs: Date.now() - startTime,
      reason: "credential-injection-failed",
    });
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Invalid credential injection configuration" }, 400);
  }

  // 5. Forward request to real API (streaming passthrough)
  let response: Response;
  try {
    response = await forwardProxyRequestForHandler(
      outboundUrl,
      method,
      outboundHeaders,
      method !== "GET" && method !== "HEAD" ? c.req.raw.body : null,
      dnsCheck.records,
    );
  } catch (err) {
    const latencyMs = Date.now() - startTime;
    console.error(`[proxy] Upstream request failed:`, err);

    // Audit the failure
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs,
    });

    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await completeUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Upstream request failed" }, 502);
  } finally {
    // 6. Zero credential from memory
    // In JS we can't truly zero strings, but we can dereference immediately.
    // The credential variable goes out of scope here.
    credential = "";
  }
  await completeUnsafeProxyRequest(replayClaim);

  const latencyMs = Date.now() - startTime;

  // 7. Audit log
  await recordAudit({
    agentId,
    tenantId,
    targetHost: target.host,
    targetPath: target.path,
    method,
    statusCode: response.status,
    latencyMs,
  });

  // 7.5. Spend tracking for LLM API responses
  //
  // For known LLM hosts, we need to read the response body to extract token
  // usage for cost estimation. We buffer the response body, parse it, track
  // the cost, and still return the body to the client.
  //
  // For non-LLM hosts or streaming responses, we pass through without buffering.
  let responseBody: ReadableStream<Uint8Array> | ArrayBuffer | null = response.body;
  const contentType = response.headers.get("content-type") || "";
  const isJsonResponse = contentType.includes("application/json");
  const isLLMHost =
    isProxyRedisAvailable() &&
    (target.host === "api.openai.com" || target.host === "api.anthropic.com");

  if (isLLMHost && isJsonResponse && response.body) {
    try {
      const contentLength = Number(response.headers.get("content-length") ?? "0");
      if (Number.isFinite(contentLength) && contentLength > MAX_LLM_SPEND_TRACKING_BODY_BYTES) {
        throw new Error("LLM response too large for spend parsing");
      }
      const bodyBuffer = await response.arrayBuffer();
      if (bodyBuffer.byteLength > MAX_LLM_SPEND_TRACKING_BODY_BYTES) {
        responseBody = bodyBuffer;
        throw new Error("LLM response too large for spend parsing");
      }
      const bodyText = new TextDecoder().decode(bodyBuffer);
      const parsedResponse = JSON.parse(bodyText);

      // Try to get the request body for model detection
      // We clone what we can from the original request
      if (response.status >= 200 && response.status < 300) {
        await trackProxySpend(
          agentId,
          tenantId,
          target.host,
          requestBodyParsed ?? { model: parsedResponse?.model },
          parsedResponse,
          spendReservation ?? undefined,
        );
      } else if (parsedResponse?.usage) {
        await trackProxySpend(
          agentId,
          tenantId,
          target.host,
          requestBodyParsed ?? { model: parsedResponse?.model },
          parsedResponse,
          spendReservation ?? undefined,
        );
      } else {
        await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
      }
      spendReservation = null;

      responseBody = bodyBuffer;
    } catch {
      // If body parsing fails, just pass through the original response body
      // This can happen with streaming responses
      if (spendReservation) {
        if (response.status >= 200 && response.status < 300) {
          await settleReservedSpend(
            agentId,
            tenantId,
            spendReservation.reservedUsd,
            spendReservation.reservedUsd,
            target.host,
            spendReservation.periods,
            spendReservation.buckets,
          );
        } else {
          await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
        }
        spendReservation = null;
      }
    }
  }
  if (spendReservation) {
    if (response.status >= 200 && response.status < 300) {
      await settleReservedSpend(
        agentId,
        tenantId,
        spendReservation.reservedUsd,
        spendReservation.reservedUsd,
        target.host,
        spendReservation.periods,
        spendReservation.buckets,
      );
    } else {
      await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    }
    spendReservation = null;
  }

  // 8. Build response — stream body through without buffering
  if (
    injectedCredentialValue &&
    responseHeaderReflectsCredential(response.headers, injectedCredentialValue)
  ) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: "credential-reflected-in-response-header",
    });
    injectedCredentialValue = null;
    proxySlot.release();
    return c.json({ ok: false, error: "Upstream response reflected injected credential" }, 502);
  }

  if (injectedCredentialValue && responseLooksStreaming(response.headers)) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: "credential-streaming-response-blocked",
    });
    injectedCredentialValue = null;
    proxySlot.release();
    return c.json({ ok: false, error: "Streaming response blocked after credential injection" }, 502);
  }

  if (
    injectedCredentialValue &&
    responseBodyCanReflectCredential(response.headers) &&
    responseBody instanceof ReadableStream
  ) {
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (
      MAX_PROXY_RESPONSE_BYTES <= 0 ||
      !Number.isFinite(contentLength) ||
      contentLength <= MAX_PROXY_RESPONSE_BYTES
    ) {
      const bodyBuffer = await new Response(responseBody).arrayBuffer();
      const bodyText = new TextDecoder().decode(bodyBuffer);
      if (bodyText.includes(injectedCredentialValue)) {
        await recordAudit({
          agentId,
          tenantId,
          targetHost: target.host,
          targetPath: target.path,
          method,
          statusCode: 502,
          latencyMs: Date.now() - startTime,
          reason: "credential-reflected-in-response-body",
        });
        injectedCredentialValue = null;
        proxySlot.release();
        return c.json({ ok: false, error: "Upstream response reflected injected credential" }, 502);
      }
      responseBody = bodyBuffer;
    }
  } else if (
    injectedCredentialValue &&
    responseBody instanceof ArrayBuffer &&
    responseBodyCanReflectCredential(response.headers)
  ) {
    const bodyText = new TextDecoder().decode(responseBody);
    if (bodyText.includes(injectedCredentialValue)) {
      await recordAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 502,
        latencyMs: Date.now() - startTime,
        reason: "credential-reflected-in-response-body",
      });
      injectedCredentialValue = null;
      proxySlot.release();
      return c.json({ ok: false, error: "Upstream response reflected injected credential" }, 502);
    }
  }
  injectedCredentialValue = null;

  const responseHeaders = new Headers();
  const skipResponseHeaders = new Set([
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
  ]);

  for (const [key, value] of response.headers.entries()) {
    const lower = key.toLowerCase();
    if (
      shouldStripResponseHeaderForRoute(route, lower) ||
      (lower === "location" && responseMayExposeInjectedQueryCredential(response))
    ) {
      continue;
    }
    if (!skipResponseHeaders.has(lower)) {
      responseHeaders.set(key, value);
    }
  }

  const releasedResponseBody =
    responseBody instanceof ReadableStream
      ? releaseWhenBodyCloses(responseBody, proxySlot.release)
      : responseBody;
  if (!(responseBody instanceof ReadableStream)) {
    proxySlot.release();
  }

  return new Response(releasedResponseBody, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

// ─── Exports for testing ─────────────────────────────────────────────────────

export { findMatchingRoute };
