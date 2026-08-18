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
import {
  and,
  desc,
  eq,
  getDb,
  gt,
  isNull,
  or,
  providerAccounts,
  providerOperations,
  secretRoutes,
  secrets,
  workspaces,
} from "@stwd/db";
import { getRedis, type SpendReservation, settleReservedSpend } from "@stwd/redis";
import { strictParseJson } from "@stwd/shared";
import { SecretVault } from "@stwd/vault";
import type { Context } from "hono";
import { boundedPositiveIntegerEnv, isProxyDevMode } from "../config";
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
import { injectAwsSigV4AtFinalBoundary } from "../sigv4";
import { resolveTarget } from "./alias";
import { holdProxyApprovalRequest } from "./approvals";
import {
  __setGoogleExecutionTokenForwarderForTests,
  mintGoogleExecutionAccessToken,
} from "./google-execution-credential";
import { compareRouteMatchSpecificity, matchHost, matchPath } from "./matching";
import { applyGovernedQuery, extractRawQuery } from "./query-forwarding";

export { __setGoogleExecutionTokenForwarderForTests };

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

/** Reset the process-local vault cache between isolated test fixtures. */
export function __resetSecretVaultForTests(): void {
  _secretVault = null;
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

/**
 * Slack's governed routes are intentionally bot-token only. Secret routes are
 * otherwise provider-neutral, so enforce the credential kind again at the last
 * possible boundary: after decrypt and before it can enter an outbound header.
 * This prevents a mistakenly stored user token (xoxp-) or arbitrary plaintext
 * secret from inheriting the bot grant's authority.
 */
function isSlackBotTokenCredential(value: string): boolean {
  if (!value.startsWith("xoxb-") || value.length > 512) return false;
  const suffix = value.slice(5);
  return suffix.length >= 10 && !/[^A-Za-z0-9-]/.test(suffix);
}

export function extractProviderCredentialForHost(host: string, credential: string): string {
  const parsed = safeJsonParseString<unknown>(credential);
  const parsedEnvelope =
    typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  const googleHost = host === "gmail.googleapis.com" || host === "www.googleapis.com";
  const xHost = host === "api.x.com";
  const schemaVersion = parsedEnvelope?.schemaVersion;
  if (schemaVersion === "steward.provider-google.credential.v1") {
    // Bind the credential type to its intended provider. Merely transforming the
    // envelope when the destination happens to be Google would let a misbound
    // route forward the whole JSON value, including the server-held refresh token.
    if (!googleHost) throw new Error("Google OAuth credential used for a non-Google host");
  } else if (schemaVersion === "steward.provider-x.credential.v1") {
    // X connect stores access + refresh tokens together. Only the access token
    // may cross the proxy boundary; the refresh token remains server-side.
    if (!xHost) throw new Error("X OAuth credential used for a non-X host");
  } else {
    if (googleHost) throw new Error("invalid Google OAuth credential envelope");
    // A parseable object at the X boundary is an envelope, not a legacy raw
    // token. Unknown/malformed envelopes must never be formatted into a header.
    if (xHost && typeof parsed === "object" && parsed !== null)
      throw new Error("invalid X OAuth credential envelope");
    return credential;
  }
  if (!parsedEnvelope) throw new Error("invalid provider OAuth credential envelope");
  if (
    typeof parsedEnvelope.accessToken !== "string" ||
    parsedEnvelope.accessToken.length < 1 ||
    parsedEnvelope.accessToken.length > 16_384
  )
    throw new Error(
      googleHost
        ? "invalid Google OAuth credential envelope"
        : "invalid X OAuth credential envelope",
    );
  return parsedEnvelope.accessToken;
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
      // SEC-176: fail closed. Forwarding with no credential in a state the
      // operator never configured is worse than rejecting the request.
      throw new Error(`Unknown credential injection mode: ${String(route.injectAs)}`);
  }

  return { headers, url, body };
}

function bytesToBody(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
}

function stripHopByHopHeaders(headers: Headers): Set<string> {
  const blocked = new Set([
    "authorization",
    // SEC-097: alternate client-IP headers trusted by some providers/CDNs for
    // IP attribution or geo-gating. An authenticated agent must not be able to
    // relay spoofed values to the credential-injected upstream.
    "cf-connecting-ip",
    "connection",
    "content-length",
    "cookie",
    "fastly-client-ip",
    "forwarded",
    "host",
    "idempotency-key",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "true-client-ip",
    "upgrade",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-forwarded-protocol",
    "x-http-method",
    "x-http-method-override",
    "x-method-override",
    "x-original-forwarded-for",
    "x-original-url",
    "x-real-ip",
    "x-rewrite-url",
    "x-steward-key",
    "x-steward-platform-key",
    // SEC-099: the proxy's request-signing window metadata is internal; do not
    // disclose it to upstream providers.
    "x-steward-request-expires-at",
    "x-steward-request-timestamp",
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
const MAX_LLM_SPEND_TRACKING_BODY_BYTES = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_MAX_SPEND_BODY_BYTES",
  1024 * 1024,
  100 * 1024 * 1024,
);
const PROXY_IDEMPOTENCY_TTL_MS = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_IDEMPOTENCY_TTL_MS",
  24 * 60 * 60 * 1000,
  30 * 24 * 60 * 60 * 1000,
);
const MAX_PROXY_IDEMPOTENCY_BODY_BYTES = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_IDEMPOTENCY_BODY_BYTES",
  2 * 1024 * 1024,
  100 * 1024 * 1024,
);
const PROXY_UPSTREAM_TIMEOUT_MS = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_UPSTREAM_TIMEOUT_MS",
  30_000,
  5 * 60_000,
);
/**
 * SEC-100: proxy resource limits fail closed — they cannot be disabled. A `0`
 * (or garbage) env value previously meant "unlimited", silently removing the
 * response-size, stream-duration, and concurrency caps on operator
 * misconfiguration. Reject non-positive / non-integer values at startup
 * (module load) instead.
 */
const MAX_PROXY_RESPONSE_BYTES = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_RESPONSE_BYTES",
  25 * 1024 * 1024,
  100 * 1024 * 1024,
);
// Credential-bearing responses are buffered for reflection inspection. Keep
// this security boundary independent from the much larger generic proxy cap.
const MAX_CREDENTIAL_RESPONSE_BODY_BYTES = 2 * 1024 * 1024;
const MAX_PROXY_STREAM_DURATION_MS = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_STREAM_DURATION_MS",
  5 * 60_000,
  30 * 60_000,
);
let MAX_PROXY_IN_FLIGHT_PER_AGENT = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT",
  50,
  10_000,
);
let MAX_PROXY_IN_FLIGHT_PER_TENANT = boundedPositiveIntegerEnv(
  "STEWARD_PROXY_MAX_IN_FLIGHT_PER_TENANT",
  250,
  100_000,
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
  if (process.env.REDIS_REQUIRED === "true") return true;
  if (process.env.STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL === "true") return false;
  // SEC-175: default-deny — the per-process replay store is a dev-only
  // fallback and now needs the explicit dev-mode opt-in; an unset NODE_ENV
  // no longer selects it silently, and a production NODE_ENV overrides a
  // stray dev-mode flag.
  if (process.env.NODE_ENV === "production") return true;
  return !isProxyDevMode();
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

/**
 * Test hook for overriding the in-flight concurrency caps. The production
 * values are read once from env at module load; this lets tests exercise the
 * 429 overflow path deterministically regardless of import order. Pass `null`
 * to leave a cap unchanged.
 */
export function __setProxyInFlightCapsForTests(caps: {
  perAgent?: number | null;
  perTenant?: number | null;
}): void {
  if (typeof caps.perAgent === "number") MAX_PROXY_IN_FLIGHT_PER_AGENT = caps.perAgent;
  if (typeof caps.perTenant === "number") MAX_PROXY_IN_FLIGHT_PER_TENANT = caps.perTenant;
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

function responseHeaderReflectsAnyCredential(
  headers: Headers,
  credentialValues: string[],
): boolean {
  return credentialValues.some((value) => responseHeaderReflectsCredential(headers, value));
}

function responseBodyCanReflectCredential(headers: Headers): boolean {
  return !responseLooksStreaming(headers);
}

function responseHasEncodedBody(headers: Headers): boolean {
  const encoding = headers.get("content-encoding")?.trim().toLowerCase();
  return Boolean(encoding && encoding !== "identity");
}

function responseTextReflectsAnyCredential(bodyText: string, credentialValues: string[]): boolean {
  return credentialValues.some((value) => bodyText.includes(value));
}

function cancelResponseBody(body: ReadableStream<Uint8Array>): void {
  try {
    void body.cancel().catch(() => undefined);
  } catch {
    // Hostile/custom streams may throw synchronously from cancel().
  }
}

async function readResponseBodyBounded(
  body: ReadableStream<Uint8Array>,
  headers: Headers,
  maxBytes: number,
): Promise<ArrayBuffer> {
  const declared = headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxBytes) {
      cancelResponseBody(body);
      throw new Error("Upstream response body inspection failed");
    }
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const cancelReader = () => {
    try {
      void reader.cancel().catch(() => undefined);
    } catch {
      // See cancelResponseBody: contain custom stream diagnostics.
    }
  };
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        cancelReader();
        throw new Error("Upstream response body inspection failed");
      }
      chunks.push(value);
    }
  } catch {
    cancelReader();
    throw new Error("Upstream response body inspection failed");
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A disturbed custom stream may retain its reader; it is never reused.
    }
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes.buffer;
}

function credentialLeakVariants(values: string[]): string[] {
  const variants = new Set<string>();
  for (const value of values) {
    if (!value) continue;
    variants.add(value);
    const encoded = encodeURIComponent(value);
    variants.add(encoded);
    variants.add(encoded.toLowerCase());
    variants.add(encoded.replace(/%20/g, "+"));
    variants.add(encoded.toLowerCase().replace(/%20/g, "+"));
  }
  return [...variants];
}

async function sha256Hex(input: string | ArrayBuffer): Promise<string> {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function requestHeader(c: Context, name: string): string | undefined {
  return c.req.header?.(name) ?? c.req.raw.headers.get(name) ?? undefined;
}

function setProxyNoStoreHeaders(headers: Headers): void {
  headers.set("Cache-Control", "no-store, max-age=0");
  headers.set("Pragma", "no-cache");
  headers.set("Expires", "0");
}

function setProxyContextNoStore(c: Context): void {
  c.header("Cache-Control", "no-store, max-age=0");
  c.header("Pragma", "no-cache");
  c.header("Expires", "0");
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
  rawQuery: string,
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

  // The query is part of the request we forward upstream, so it must be part of
  // the replay/idempotency identity: two requests that differ only by their
  // query (e.g. ?id=1 vs ?id=2) are distinct operations and must not collide on
  // the same Idempotency-Key. `rawQuery` preserves exact bytes + ordering.
  const fingerprint = await sha256Hex(
    [tenantId, agentId, method.toUpperCase(), target.host, target.path, rawQuery, bodyHash].join(
      "\n",
    ),
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
      return claimUnsafeProxyRequest(c, tenantId, agentId, target, method, rawQuery);
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
  const words = expandIPv6Words(normalized);
  // RFC 8215 reserves 64:ff9b:1::/48 for operator-local translation and
  // explicitly does not fix the embedded IPv4 position. Treat the entire
  // prefix as non-public instead of applying the /96 low-word extraction
  // used for the well-known 64:ff9b::/96 prefix.
  if (words?.[0] === 0x0064 && words[1] === 0xff9b && words[2] === 0x0001) return true;
  const mappedV4 = ipv4FromMappedIPv6(normalized);
  if (mappedV4) return isUnsafeIPv4Address(mappedV4);
  const embeddedV4 = ipv4FromEmbeddedIPv6(normalized);
  if (embeddedV4) return isUnsafeIPv4Address(embeddedV4);
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

/** Restore every mutable proxy-handler dependency after an integration fixture. */
export function __resetProxyHandlerTestHooksForTests(): void {
  checkProxySpendLimitForHandler = checkProxySpendLimit;
  checkProxyRateLimitForHandler = checkProxyRateLimit;
  resolveProxyHostForHandler = dnsLookup;
  forwardProxyRequestForHandler = forwardWithVettedDns;
  __setGoogleExecutionTokenForwarderForTests(null);
}

// ─── Main proxy handler ──────────────────────────────────────────────────────

/**
 * Handle a proxied request.
 *
 * This is the catch-all handler mounted on the Hono app.
 * Auth middleware has already run, so agentId and tenantId are available.
 */
export async function handleProxy(c: Context): Promise<Response> {
  setProxyContextNoStore(c);
  const startTime = Date.now();
  const agentId = c.get("agentId") as string;
  const tenantId = c.get("tenantId") as string;
  const method = c.req.method;
  const governedExecutionClaim = c.get("governedExecutionClaim" as never) as unknown;
  const hasGovernedExecutionClaim = Boolean(governedExecutionClaim);

  // 1. Resolve target URL from request path
  const target = resolveTarget(c.req.path, { governed: hasGovernedExecutionClaim });
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

  // Extract the client's raw query string once (encoding + ordered duplicate
  // keys preserved, fragment stripped). Target resolution and route matching
  // above intentionally used the path only, so the query never influences which
  // route/host we select; it is only forwarded onto the pinned upstream below,
  // and mixed into the replay/idempotency fingerprint so that two otherwise
  // identical requests with different queries are treated as distinct.
  const rawQuery = extractRawQuery(c.req.raw.url);

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
  // ── PR4 governed-route authority gate (spec §5.1, X1/X7) ──────────────────
  // The gate is on the SELECTED route row, so a governed route is unreachable
  // via direct /proxy, named aliases, or /proxy/<host>/... regardless of how it
  // was addressed. A governed route is permitted ONLY when the request arrived
  // through dispatchGovernedExecution, which sets a non-forgeable in-process
  // `governedExecutionClaim` context (never from a header — mirror the
  // proxyApprovalRelease rule). Any unknown authority_mode default-denies so a
  // reverted/older proxy that no longer understands governed mode still fails
  // closed (§6.3).
  const authorityMode = (route as { authorityMode?: string }).authorityMode ?? "legacy";
  const governedClaim = c.get("governedExecutionClaim" as never) as
    | {
        authorizationId: string;
        executionId: string;
        routeId: string;
        routeRevision?: number;
        secretId?: string;
        secretVersion?: number;
        workspaceId?: string;
        providerAccountId?: string;
        operationId?: string;
        operationRevision?: number;
        providerAccountRevision?: number;
      }
    | undefined;
  // Set once the governed claim is verified against the selected route; the
  // single-use v2 nonce it represents is the replay guard, so a verified governed
  // dispatch skips the header-based Idempotency-Key claim below (codex P1).
  let isVerifiedGovernedDispatch = false;
  if (authorityMode !== "legacy") {
    // The claim must match the SELECTED route by id AND by the exact revision +
    // secret binding it was minted against (codex P1). A rotated route/secret
    // after the claim (routeId unchanged) would otherwise decrypt with the CURRENT
    // credential; requiring the claimed authorityRevision + secretId here fails
    // closed on any such drift before the decrypt. The secret VERSION is
    // additionally re-checked at decrypt time (the version lives on the secret,
    // not the route row).
    const routeSecretId = (route as { secretId?: string }).secretId;
    const routeRevision = (route as { authorityRevision?: number }).authorityRevision;
    const claimMatches =
      authorityMode === "governed_v2" &&
      governedClaim !== undefined &&
      governedClaim.routeId === route.id &&
      governedClaim.routeRevision !== undefined &&
      governedClaim.routeRevision === routeRevision &&
      governedClaim.secretId !== undefined &&
      governedClaim.secretId === routeSecretId &&
      // secretVersion is REQUIRED for a verified governed claim (codex P2): a
      // partial claim that omits it must NOT be treated as verified, otherwise the
      // decrypt-time version recheck below (guarded on secretVersion !== undefined)
      // would be skipped and a rotated secret could be decrypted. The live
      // account/operation boundary fields are also required for the final
      // decrypt-time recheck below. Missing = unverified.
      governedClaim.secretVersion !== undefined &&
      governedClaim.workspaceId !== undefined &&
      governedClaim.providerAccountId !== undefined &&
      governedClaim.operationId !== undefined &&
      governedClaim.operationRevision !== undefined &&
      governedClaim.providerAccountRevision !== undefined;
    if (!claimMatches) {
      await recordRequiredAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 403,
        latencyMs: Date.now() - startTime,
        reason:
          authorityMode === "governed_v2"
            ? "governed-route-direct-denied"
            : "governed-route-unknown-authority-mode",
      });
      return c.json(
        {
          ok: false,
          error: "GOVERNED_ROUTE_DIRECT_DENIED",
        },
        403,
      );
    }
    isVerifiedGovernedDispatch = true;
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
        error:
          "Query credential injection is disabled because upstream responses can reflect credentials",
      },
      403,
    );
  }

  // Only the in-process release handler can set this context value. Never trust
  // a request header for approval bypass, since agents control all headers.
  const approvalReleaseId = c.get("proxyApprovalRelease" as never) as string | undefined;
  const approvalReleaseRouteId = c.get("proxyApprovalRouteId" as never) as string | undefined;
  if (approvalReleaseId && approvalReleaseRouteId !== route.id) {
    await recordRequiredAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 409,
      latencyMs: Date.now() - startTime,
      reason: "proxy-approval-route-mismatch",
    });
    return c.json({ ok: false, error: "Approved proxy route no longer matches" }, 409);
  }
  if (route.requiresApproval && !approvalReleaseId && !isVerifiedGovernedDispatch) {
    // NOTE: a verified governed dispatch is EXCLUDED here (codex P1). A governed
    // route's approval was already adjudicated by the v2 authority flow (the
    // intent is approved + the binding is execution_ready before the nonce is
    // minted); it must NOT re-enter the legacy proxy-approval hold, which would
    // return a 202 hold that dispatchOnce would misread as a successful upstream
    // dispatch and falsely consume the authorization / mark the action succeeded.
    //
    // Fail closed on approval-gated routes that carry a query. The approval
    // hold/replay path reconstructs the request from the stored path only and
    // cannot yet round-trip the query, so executing it later would forward a
    // semantically different (query-stripped) request than the one the agent
    // submitted and the human approved. Rejecting here is safer than silently
    // changing the approved request. (Direct, non-approval routes preserve the
    // query via applyGovernedQuery below.)
    if (rawQuery !== "") {
      await recordAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 400,
        latencyMs: Date.now() - startTime,
        reason: "proxy-approval-query-unsupported",
      });
      return c.json(
        {
          ok: false,
          error: "Query strings are not supported on approval-gated proxy routes",
        },
        400,
      );
    }
    try {
      const held = await holdProxyApprovalRequest({
        tenantId,
        agentId,
        route,
        method,
        targetHost: target.host,
        targetPath: target.path,
        request: c.req.raw,
      });
      await recordRequiredAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 202,
        latencyMs: Date.now() - startTime,
        reason: "proxy-approval-held",
      });
      return c.json(
        {
          ok: true,
          status: "pending_approval",
          id: held.id,
          approvalId: held.id,
          pollUrl: `/approvals/proxy/${held.id}`,
          expiresAt: held.expiresAt.toISOString(),
        },
        202,
      );
    } catch (err) {
      await recordAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 500,
        latencyMs: Date.now() - startTime,
        reason: "proxy-approval-hold-failed",
      });
      const error = err instanceof Error ? err.message : "Failed to hold proxy request";
      const status = error.includes("too large")
        ? 413
        : error.includes("Idempotency-Key")
          ? 409
          : 500;
      return c.json({ ok: false, error }, status);
    }
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

  // A governed dispatch (verified single-use v2 nonce, already atomically
  // consumed by the claim) and an approval-release both carry their OWN replay
  // protection, so neither goes through the header Idempotency-Key claim. Without
  // this, mutating governed actions (POST/PUT/PATCH/DELETE) would 400 for a
  // missing Idempotency-Key AFTER the nonce was already spent (codex P1) — the
  // provider-action header allowlist does not even permit that header.
  const replayClaim =
    approvalReleaseId || isVerifiedGovernedDispatch
      ? ({ ok: true, storageKey: "", storage: "memory" } as const)
      : await claimUnsafeProxyRequest(c, tenantId, agentId, target, method, rawQuery);
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
  //
  // Governed signing-boundary backstop: account/workspace/operation status and
  // secret version can change after the claim transaction but before this exact
  // decrypt point. Re-read every live boundary fact here, after proxy policy/DNS
  // checks and immediately before touching the vault.
  const denyGovernedAtDecryptBoundary = async (
    error: "EXEC_AUTH_ACCOUNT_DISABLED" | "EXEC_AUTH_STALE_DEPENDENCY" | "EXEC_AUTH_STALE_SECRET",
    reason: string,
  ): Promise<Response> => {
    let auditUnavailable = false;
    try {
      await recordRequiredAudit({
        agentId,
        tenantId,
        targetHost: target.host,
        targetPath: target.path,
        method,
        statusCode: 409,
        latencyMs: Date.now() - startTime,
        reason,
      });
    } catch {
      auditUnavailable = true;
    } finally {
      // Required-audit failure must fail closed without leaking the slot or spend
      // reservation held by this pre-forward path.
      await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
      await releaseUnsafeProxyRequest(replayClaim);
      proxySlot.release();
    }
    return auditUnavailable
      ? c.json({ ok: false, error: "EXEC_AUDIT_UNAVAILABLE" }, 503)
      : c.json({ ok: false, error }, 409);
  };

  let governedLiveAccountRevision: number | null = null;
  if (authorityMode === "governed_v2" && governedClaim) {
    const db = getDb();
    const [liveWorkspace] = await db
      .select({ status: workspaces.status })
      .from(workspaces)
      .where(
        and(
          eq(workspaces.tenantId, tenantId),
          eq(workspaces.id, governedClaim.workspaceId as string),
        ),
      )
      .limit(1);
    const [liveAccount] = await db
      .select({ status: providerAccounts.status, revision: providerAccounts.revision })
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, tenantId),
          eq(providerAccounts.workspaceId, governedClaim.workspaceId as string),
          eq(providerAccounts.id, governedClaim.providerAccountId as string),
        ),
      )
      .limit(1);
    const [liveOperation] = await db
      .select({ status: providerOperations.status, revision: providerOperations.revision })
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, tenantId),
          eq(providerOperations.workspaceId, governedClaim.workspaceId as string),
          eq(providerOperations.providerAccountId, governedClaim.providerAccountId as string),
          eq(providerOperations.id, governedClaim.operationId as string),
        ),
      )
      .limit(1);
    if (
      !liveWorkspace ||
      liveWorkspace.status !== "active" ||
      !liveAccount ||
      liveAccount.status !== "active" ||
      !liveOperation ||
      liveOperation.status !== "active"
    ) {
      return denyGovernedAtDecryptBoundary(
        "EXEC_AUTH_ACCOUNT_DISABLED",
        "governed-account-boundary-disabled",
      );
    }
    if (
      liveAccount.revision !== governedClaim.providerAccountRevision ||
      liveOperation.revision !== governedClaim.operationRevision
    ) {
      return denyGovernedAtDecryptBoundary(
        "EXEC_AUTH_STALE_DEPENDENCY",
        "governed-operation-revision-stale",
      );
    }
    governedLiveAccountRevision = liveAccount.revision;
    const [liveSecret] = await db
      .select({ version: secrets.version })
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, route.secretId)))
      .limit(1);
    if (!liveSecret || liveSecret.version !== governedClaim.secretVersion) {
      return denyGovernedAtDecryptBoundary(
        "EXEC_AUTH_STALE_SECRET",
        "governed-stale-secret-version",
      );
    }
  }

  let credential: string;
  try {
    credential = await decryptSecret(tenantId, route.secretId);
    const googleHost =
      target.host === "gmail.googleapis.com" || target.host === "www.googleapis.com";
    if (googleHost) {
      if (!governedClaim || governedLiveAccountRevision === null) {
        throw new Error("Google OAuth credentials require governed execution");
      }
      const clientId = process.env.GOOGLE_PROVIDER_CLIENT_ID?.trim();
      const clientSecret = process.env.GOOGLE_PROVIDER_CLIENT_SECRET?.trim();
      if (!clientId || !clientSecret) throw new Error("Google provider OAuth is not configured");
      credential = await mintGoogleExecutionAccessToken({
        tenantId,
        workspaceId: governedClaim.workspaceId as string,
        accountId: governedClaim.providerAccountId as string,
        accountRevision: governedLiveAccountRevision,
        credential,
        vault: getSecretVault(),
        clientId,
        clientSecret,
      });
    } else {
      credential = extractProviderCredentialForHost(target.host, credential);
    }
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

  if (target.host === "slack.com" && !isSlackBotTokenCredential(credential)) {
    // Do not include the credential (or any derivative of it) in the response,
    // logs, or audit reason. The agent only learns that the configured grant is
    // not an eligible Slack bot credential.
    credential = "";
    await recordRequiredAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 403,
      latencyMs: Date.now() - startTime,
      reason: "slack-bot-credential-required",
    });
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Slack route requires a bot credential" }, 403);
  }

  // 4. Build outbound request
  //
  // Compose the client's query string onto the pinned upstream target. Target
  // resolution above (and route matching) intentionally used the path only, so
  // the query cannot influence which route/host we selected. Here we forward the
  // client's exact query bytes (encoding + ordered duplicate keys preserved)
  // while re-validating that the query did not alter the pinned
  // scheme/host/port/path or introduce userinfo/fragment.
  const governedQuery = applyGovernedQuery(new URL(target.url), rawQuery);
  if (!governedQuery.ok) {
    credential = "";
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 400,
      latencyMs: Date.now() - startTime,
      reason: `query-forwarding-rejected:${governedQuery.reason}`,
    });
    await releaseProxySpendReservation(agentId, tenantId, target.host, spendReservation);
    await releaseUnsafeProxyRequest(replayClaim);
    proxySlot.release();
    return c.json({ ok: false, error: "Invalid proxy request target" }, 400);
  }
  const outboundUrl = governedQuery.url;
  const outboundHeaders = new Headers();

  const skipHeaders = stripHopByHopHeaders(c.req.raw.headers);

  for (const [key, value] of c.req.raw.headers.entries()) {
    if (!skipHeaders.has(key.toLowerCase())) {
      outboundHeaders.set(key, value);
    }
  }
  outboundHeaders.set("accept-encoding", "identity");

  // Set the correct host header for the target
  outboundHeaders.set("host", outboundUrl.host);

  // Inject credential
  const rawCredentialValue = credential;
  let injectedCredentialValue: string | null =
    route.injectAs === "header"
      ? (route.injectFormat ?? "{value}").replace("{value}", credential)
      : null;
  let sensitiveCredentialValues =
    injectedCredentialValue && rawCredentialValue
      ? credentialLeakVariants([injectedCredentialValue, rawCredentialValue])
      : [];
  let outboundBody: ReadableStream<Uint8Array> | null =
    method !== "GET" && method !== "HEAD" ? c.req.raw.body : null;
  try {
    if (route.injectionStrategy === "sigv4") {
      const config = route.injectionConfig as { service?: unknown; region?: unknown };
      const bodyBytes = new Uint8Array(await c.req.raw.clone().arrayBuffer());
      if (bodyBytes.byteLength > MAX_PROXY_IDEMPOTENCY_BODY_BYTES) {
        throw new Error("SigV4 request body exceeds the signing limit");
      }
      const injected = injectAwsSigV4AtFinalBoundary({
        authorityMode,
        routeHostPattern: route.hostPattern,
        routePathPattern: route.pathPattern,
        method,
        url: outboundUrl,
        headers: outboundHeaders,
        body: bodyBytes,
        service: config.service,
        region: config.region,
        credentialSecret: credential,
      });
      for (const [name, value] of injected.headers) outboundHeaders.set(name, value);
      injectedCredentialValue = injected.headers.get("authorization");
      sensitiveCredentialValues = credentialLeakVariants(injected.sensitiveValues);
      outboundBody = bytesToBody(bodyBytes);
    } else if (route.injectionStrategy === "header") {
      injectCredential(outboundHeaders, outboundUrl, null, route, credential);
    } else {
      throw new Error("Unknown credential injection strategy");
    }
  } catch {
    credential = "";
    injectedCredentialValue = null;
    sensitiveCredentialValues = [];
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
      outboundBody,
      dnsCheck.records,
    );
  } catch (err) {
    const latencyMs = Date.now() - startTime;
    // Fetch errors can embed the full outbound URL. Query-injected credentials
    // must never be copied from that error into application logs.
    console.error("[proxy] Upstream request failed", {
      errorName: err instanceof Error ? err.name : "UnknownError",
    });

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

  // 7. Inspect provider-specific response semantics before recording an outcome.
  //
  // For known LLM hosts, we need to read the response body to extract token
  // usage for cost estimation. We buffer the response body, parse it, track
  // the cost, and still return the body to the client.
  //
  // For non-LLM hosts or streaming responses, we pass through without buffering.
  let responseBody: ReadableStream<Uint8Array> | ArrayBuffer | null = response.body;
  const contentType = response.headers.get("content-type") || "";
  const isJsonResponse = contentType.includes("application/json");
  let slackSemanticFailure: string | null = null;
  let deferSlackSuccessAudit = false;
  let credentialResponseInspectionFailed = false;

  // Every credential-bearing, non-streaming identity-encoded body is consumed
  // exactly once through an independent 2 MiB reader. This bounds allocation
  // even when Content-Length is absent or false, and the resulting bytes are
  // reused by provider semantics, spend parsing, reflection scanning, and the
  // downstream response.
  if (
    sensitiveCredentialValues.length > 0 &&
    responseBody instanceof ReadableStream &&
    responseBodyCanReflectCredential(response.headers) &&
    !responseHasEncodedBody(response.headers)
  ) {
    try {
      responseBody = await readResponseBodyBounded(
        responseBody,
        response.headers,
        MAX_CREDENTIAL_RESPONSE_BODY_BYTES,
      );
    } catch {
      responseBody = new ArrayBuffer(0);
      credentialResponseInspectionFailed = true;
    }
  }

  // Slack Web API encodes operation failures as HTTP 200 + {ok:false}. Treat
  // that envelope as a failed dispatch, while retaining the buffered bytes for
  // credential-reflection scanning below. A malformed/non-JSON 2xx response is
  // also fail-closed: it cannot prove that the requested action succeeded.
  if (target.host === "slack.com" && response.status >= 200 && response.status < 300) {
    try {
      if (credentialResponseInspectionFailed || !(responseBody instanceof ArrayBuffer)) {
        throw new Error("Slack response inspection failed");
      }
      slackSemanticFailure = classifySlackWebApiPayload(new TextDecoder().decode(responseBody));
      deferSlackSuccessAudit = slackSemanticFailure === null;
    } catch {
      // Never hand partial provider bytes to a later scanner or the client.
      responseBody = new ArrayBuffer(0);
      slackSemanticFailure = "invalid_response";
    }
  }

  // Slack can report failure in an HTTP 200 envelope. Do not persist a
  // contradictory successful audit row before the semantic failure row below.
  if (!slackSemanticFailure && !deferSlackSuccessAudit) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: response.status,
      latencyMs,
    });
  }

  // 7.5. Spend tracking for LLM API responses
  const isLLMHost =
    isProxyRedisAvailable() &&
    (target.host === "api.openai.com" || target.host === "api.anthropic.com");

  if (isLLMHost && isJsonResponse && responseBody instanceof ArrayBuffer) {
    try {
      const contentLength = Number(response.headers.get("content-length") ?? "0");
      if (Number.isFinite(contentLength) && contentLength > MAX_LLM_SPEND_TRACKING_BODY_BYTES) {
        throw new Error("LLM response too large for spend parsing");
      }
      const bodyBuffer = responseBody;
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
    sensitiveCredentialValues.length > 0 &&
    responseHeaderReflectsAnyCredential(response.headers, sensitiveCredentialValues)
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
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json({ ok: false, error: "Upstream response reflected injected credential" }, 502);
  }

  if (sensitiveCredentialValues.length > 0 && responseLooksStreaming(response.headers)) {
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
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json(
      { ok: false, error: "Streaming response blocked after credential injection" },
      502,
    );
  }

  if (
    sensitiveCredentialValues.length > 0 &&
    responseHasEncodedBody(response.headers) &&
    responseBodyCanReflectCredential(response.headers)
  ) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: "credential-encoded-response-blocked",
    });
    injectedCredentialValue = null;
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json({ ok: false, error: "Encoded response blocked after credential injection" }, 502);
  }

  if (
    sensitiveCredentialValues.length > 0 &&
    responseBodyCanReflectCredential(response.headers) &&
    responseBody instanceof ReadableStream
  ) {
    // Defensive invariant: every inspectable credential-bearing stream was
    // converted to a bounded ArrayBuffer above.
    cancelResponseBody(responseBody);
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: "credential-response-inspection-failed",
    });
    injectedCredentialValue = null;
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json({ ok: false, error: "Upstream response could not be inspected safely" }, 502);
  } else if (
    sensitiveCredentialValues.length > 0 &&
    responseBody instanceof ArrayBuffer &&
    responseBodyCanReflectCredential(response.headers)
  ) {
    const bodyText = new TextDecoder().decode(responseBody);
    if (responseTextReflectsAnyCredential(bodyText, sensitiveCredentialValues)) {
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
      sensitiveCredentialValues = [];
      proxySlot.release();
      return c.json({ ok: false, error: "Upstream response reflected injected credential" }, 502);
    }
  }
  if (slackSemanticFailure) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: `slack-api-error:${slackSemanticFailure}`,
    });
    injectedCredentialValue = null;
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json(
      {
        ok: false,
        error: "Slack upstream operation failed",
        data: { providerError: slackSemanticFailure },
      },
      502,
    );
  }
  if (sensitiveCredentialValues.length > 0 && credentialResponseInspectionFailed) {
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: 502,
      latencyMs: Date.now() - startTime,
      reason: "credential-response-inspection-failed",
    });
    injectedCredentialValue = null;
    sensitiveCredentialValues = [];
    proxySlot.release();
    return c.json({ ok: false, error: "Upstream response could not be inspected safely" }, 502);
  }
  if (deferSlackSuccessAudit) {
    // A Slack `ok:true` envelope is not a successful Steward dispatch until
    // response headers/body have also passed the credential-reflection gates
    // above. Persist success only at that final boundary so blocked responses
    // cannot leave a contradictory 200 audit row.
    await recordAudit({
      agentId,
      tenantId,
      targetHost: target.host,
      targetPath: target.path,
      method,
      statusCode: response.status,
      latencyMs: Date.now() - startTime,
    });
  }
  injectedCredentialValue = null;
  sensitiveCredentialValues = [];

  const responseHeaders = new Headers();
  const skipResponseHeaders = new Set([
    "connection",
    "keep-alive",
    // SEC-098: never relay upstream session cookies to the agent — a
    // credential-derived session token would let it replay directly against
    // the provider, bypassing proxy policy and audit.
    "set-cookie",
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
  setProxyNoStoreHeaders(responseHeaders);

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

/** Null means Slack explicitly attested success; any string is a safe failure code. */
export function classifySlackWebApiPayload(bodyText: string): string | null {
  try {
    const parsed = strictParseJson(bodyText) as { ok?: unknown; error?: unknown };
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return "invalid_response";
    }
    if (parsed.ok === true) return null;
    return typeof parsed.error === "string" && /^[a-z0-9_]{1,128}$/i.test(parsed.error)
      ? parsed.error
      : "invalid_response";
  } catch {
    return "invalid_response";
  }
}

// ─── Exports for testing ─────────────────────────────────────────────────────

export { findMatchingRoute };
