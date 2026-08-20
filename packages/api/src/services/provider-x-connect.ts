/**
 * Provider-account X (Twitter) OAuth connect and token lifecycle.
 *
 * This is the PROVIDER-CONNECTION plane (agent execution authority), NOT the
 * user sign-in plane. Login-with-X (packages/auth oauth.ts `twitter` provider)
 * authenticates a human; this module connects an X account a workspace's agents
 * can act as, holding the rotating OAuth tokens in the versioned vault so the
 * agent never sees a raw credential.
 *
 * Security posture (mirrors the hardened user-auth OAuth flow):
 *   - PKCE S256, minimal explicit scopes.
 *   - Pending-connect state lives in a short-TTL, single-use store. We persist
 *     ONLY the SHA-256 hash of the state token and the SHA-256 hash of the PKCE
 *     verifier, so a store compromise cannot replay a connect or forge the code
 *     exchange. The raw state travels only in the browser round-trip; the raw
 *     verifier is re-derived from a sealed payload the caller carries back.
 *   - State is consumed exactly once and a durable intent is recorded before
 *     provider I/O. Successful code-exchange responses are encrypted before
 *     semantic validation, identity lookup, or account persistence.
 *   - Tokens land as a NEW versioned vault secret; provider_accounts links the
 *     current {credential_secret_id, credential_version}. Reconnect for the same
 *     X user id updates the version + bumps revision, never duplicates the row.
 *   - Refresh is serialized per account (SELECT ... FOR UPDATE on the account
 *     row inside the tenant-audited transaction) because X refresh tokens are
 *     SINGLE-USE ROTATING: two concurrent refreshes must never both spend the
 *     same refresh token. On upstream `invalid_grant` the account is degraded
 *     and audited, failing closed.
 *   - Every X network call goes through an injectable seam (__-prefixed test
 *     setter) so tests never touch the network.
 *
 * All lifecycle events are written on the tenant audit chain via
 * withTenantAuditedTransaction / appendRequiredAudit.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  and,
  asc,
  auditEvents,
  desc,
  eq,
  getDb,
  inArray,
  providerAccounts,
  providerXCredentialLifecycles,
  type Secret,
  secretRoutes,
  secrets,
  sql,
  withTenantAuditedTransaction,
} from "@stwd/db";
import {
  isValidOAuthBearerToken,
  isValidOAuthOpaqueToken,
  MAX_OAUTH_TOKEN_LENGTH,
} from "@stwd/shared";
import type { SecretVault } from "@stwd/vault";

type DbBase = ReturnType<typeof getDb>;
type DbExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];

// ── X (Twitter) OAuth 2.0 endpoints ──────────────────────────────────────────
// Provider-connect endpoints. Kept SEPARATE from the user-auth `twitter`
// provider config (packages/auth oauth.ts) on purpose: different plane, different
// client credentials (X_CLIENT_ID / X_CLIENT_SECRET vs TWITTER_CLIENT_ID).
export const X_AUTHORIZE_URL = "https://x.com/i/oauth2/authorize";
export const X_TOKEN_URL = "https://api.x.com/2/oauth2/token";
export const X_REVOKE_URL = "https://api.x.com/2/oauth2/revoke";
export const X_USERINFO_URL = "https://api.x.com/2/users/me?user.fields=id,name,username";

export const X_ADAPTER_KEY = "x";

/** Minimal default scopes. `offline.access` is REQUIRED to receive a refresh token. */
export const X_DEFAULT_SCOPES = [
  "tweet.read",
  "tweet.write",
  "users.read",
  "offline.access",
] as const;

/** Access tokens live ~2h; refresh a little early to avoid mid-flight expiry. */
export const X_REFRESH_SKEW_MS = 5 * 60 * 1000;

/** Pending-connect state TTL — long enough for a human to authorize, short
 *  enough to bound replay exposure. */
export const X_CONNECT_STATE_TTL_MS = 10 * 60 * 1000;

// ── Errors ────────────────────────────────────────────────────────────────────
export type XConnectErrorCode =
  | "X_CONFIG_MISSING"
  | "X_STATE_INVALID"
  | "X_STATE_EXPIRED"
  | "X_STATE_REUSED"
  | "X_PKCE_MISMATCH"
  | "X_TOKEN_EXCHANGE_FAILED"
  | "X_IDENTITY_FAILED"
  | "X_ACCOUNT_NOT_FOUND"
  | "X_ACCOUNT_NOT_X"
  | "X_REFRESH_TOKEN_MISSING"
  | "X_REFRESH_REVOKED"
  | "X_CREDENTIAL_NEEDS_ATTENTION"
  | "X_REFRESH_FAILED";

export class XConnectError extends Error {
  constructor(
    readonly code: XConnectErrorCode,
    readonly httpStatus: number,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "XConnectError";
  }
}

// ── Stored token payload (the vault secret value) ─────────────────────────────
export interface XCredentialPayload {
  schemaVersion: "steward.provider-x.credential.v1";
  accessToken: string;
  refreshToken: string | null;
  scopesGranted: string[];
  xUserId: string;
  xUsername: string;
  obtainedAt: string; // ISO
  expiresAt: string | null; // ISO
}

// ── Network seam (injectable for tests) ───────────────────────────────────────
export interface XTokenResponse {
  access_token: string;
  refresh_token?: string;
  scope?: string;
  token_type?: string;
  expires_in?: number;
  // Upstream error envelope (non-2xx bodies)
  error?: string;
  error_description?: string;
}

export interface XUserResponse {
  data?: { id: string; name?: string; username?: string };
}

export interface XForwardRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
}

export interface XForwardResponse {
  status: number;
  ok: boolean;
  json: unknown;
  text: string;
}

export type XForwardFn = (req: XForwardRequest) => Promise<XForwardResponse>;

const X_FORWARD_TIMEOUT_MS = 10_000;
const X_FORWARD_MAX_RESPONSE_BYTES = 1024 * 1024;

async function readBoundedXResponse(res: Response): Promise<string> {
  const declaredLength = res.headers.get("content-length");
  if (declaredLength) {
    const length = Number(declaredLength);
    if (!Number.isFinite(length) || length < 0 || length > X_FORWARD_MAX_RESPONSE_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new Error("X provider response exceeded maximum size");
    }
  }
  if (!res.body) return "";

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > X_FORWARD_MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("X provider response exceeded maximum size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

async function defaultForward(req: XForwardRequest): Promise<XForwardResponse> {
  const res = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
    // OAuth requests carry credentials in both headers and bodies. Never let a
    // provider redirect replay them to a different endpoint or origin.
    redirect: "error",
    signal: AbortSignal.timeout(X_FORWARD_TIMEOUT_MS),
  });
  const text = await readBoundedXResponse(res);
  let json: unknown = null;
  try {
    json = text.length > 0 ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, ok: res.ok, json, text };
}

/** Test-only access to the real bounded transport (never used by runtime callers). */
export function __runDefaultXForwardForTests(req: XForwardRequest): Promise<XForwardResponse> {
  return defaultForward(req);
}

let forwardImpl: XForwardFn = defaultForward;
let afterXRefreshIntentForTests: (() => Promise<void>) | null = null;
let afterXCredentialStageForTests: (() => Promise<void>) | null = null;
let afterXRevocationClaimForTests: (() => Promise<void>) | null = null;
let afterXDisconnectJournalForTests: (() => Promise<void>) | null = null;

/**
 * Test-only seam setter. Mirrors the repo's `__setForwardProxyRequestForTests`
 * naming convention. Never called from production paths. Returns a restore fn.
 */
export function __setXForwardForTests(fn: XForwardFn | null): () => void {
  const previous = forwardImpl;
  forwardImpl = fn ?? defaultForward;
  return () => {
    forwardImpl = previous;
  };
}

/** Test-only crash seam after durable staging and before adoption. */
export function __setAfterXCredentialStageForTests(fn: (() => Promise<void>) | null): () => void {
  const previous = afterXCredentialStageForTests;
  afterXCredentialStageForTests = fn;
  return () => {
    afterXCredentialStageForTests = previous;
  };
}

/** Test-only crash seam after the durable intent and before provider I/O. */
export function __setAfterXRefreshIntentForTests(fn: (() => Promise<void>) | null): () => void {
  const previous = afterXRefreshIntentForTests;
  afterXRefreshIntentForTests = fn;
  return () => {
    afterXRefreshIntentForTests = previous;
  };
}

/** Test-only crash seam after a durable revocation lease is acquired. */
export function __setAfterXRevocationClaimForTests(fn: (() => Promise<void>) | null): () => void {
  const previous = afterXRevocationClaimForTests;
  afterXRevocationClaimForTests = fn;
  return () => {
    afterXRevocationClaimForTests = previous;
  };
}

/** Test-only crash seam after local revocation and durable upstream handoff. */
export function __setAfterXDisconnectJournalForTests(fn: (() => Promise<void>) | null): () => void {
  const previous = afterXDisconnectJournalForTests;
  afterXDisconnectJournalForTests = fn;
  return () => {
    afterXDisconnectJournalForTests = previous;
  };
}

// ── Config ────────────────────────────────────────────────────────────────────
export interface XConnectConfig {
  clientId: string;
  clientSecret: string;
}

/**
 * Resolve provider-connect X credentials from env. These are DISTINCT from the
 * user-auth `TWITTER_CLIENT_ID` / `TWITTER_CLIENT_SECRET` (login plane). See
 * .env.example for the separation rationale.
 */
export function resolveXConnectConfig(env: NodeJS.ProcessEnv = process.env): XConnectConfig {
  const clientId = env.X_CLIENT_ID?.trim();
  const clientSecret = env.X_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) {
    throw new XConnectError(
      "X_CONFIG_MISSING",
      503,
      "X_CLIENT_ID and X_CLIENT_SECRET are required for provider-account X connect",
    );
  }
  return { clientId, clientSecret };
}

// ── Hash + PKCE helpers ───────────────────────────────────────────────────────
function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function base64url(buf: Buffer): string {
  // The bun-types Buffer encoding union is narrower than Node's; encode base64url
  // via btoa over a binary string to stay within the allowed surface (matches
  // packages/auth oauth.ts uint8ArrayToBase64url).
  const binary = Array.from(buf, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64ToUtf8(b64: string): string {
  // Decode a base64url string to utf8 without relying on Buffer's base64url
  // encoding (unavailable in the bun-types union).
  const normalized = b64.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function utf8ToBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary);
}

/** RFC 7636 §4.1: high-entropy verifier (43-128 unreserved chars). */
export function generateCodeVerifier(): string {
  return randomBytes(48).toString("hex");
}

/** RFC 7636 §4.2: BASE64URL(SHA256(ASCII(verifier))). */
export function deriveCodeChallenge(verifier: string): string {
  return base64url(createHash("sha256").update(verifier).digest());
}

export function generateStateToken(): string {
  return randomBytes(32).toString("hex");
}

// ── Pending-connect state store contract ──────────────────────────────────────
// The route layer supplies a store instance (Redis-backed in prod, memory in
// tests) so this service stays free of process-wide singletons. We store the
// SHA-256 hash of the state as the KEY and, in the VALUE, the SHA-256 hash of
// the PKCE verifier plus the non-secret connect context. The raw verifier is
// NEVER persisted; on callback the caller re-supplies it (sealed in the state
// round-trip) and we verify hash(rawVerifier) === storedVerifierHash before
// spending it.
export interface PendingConnectStore {
  /** Store value under a hashed key. Overwrites are not expected (fresh state). */
  set(key: string, value: string, ttlMs: number): Promise<void>;
  /** Read without consuming. */
  get(key: string): Promise<string | null>;
  /** Read + atomically delete (single-use). Returns the stored value or null. */
  consume(key: string): Promise<string | null>;
}

export interface PendingConnectRecord {
  schemaVersion: "steward.provider-x.pending-connect.v1";
  tenantId: string;
  workspaceId: string;
  initiatedByUserId: string;
  verifierHash: string;
  scopes: string[];
  redirectUri: string;
  createdAt: string;
}

function isCanonicalIsoTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 32) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function validatePendingConnectRecord(value: unknown): PendingConnectRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    record.schemaVersion !== "steward.provider-x.pending-connect.v1" ||
    typeof record.tenantId !== "string" ||
    record.tenantId.length === 0 ||
    record.tenantId.length > 64 ||
    typeof record.workspaceId !== "string" ||
    record.workspaceId.length > 64 ||
    typeof record.initiatedByUserId !== "string" ||
    record.initiatedByUserId.length > 128 ||
    typeof record.verifierHash !== "string" ||
    !/^[a-f0-9]{64}$/.test(record.verifierHash) ||
    typeof record.redirectUri !== "string" ||
    record.redirectUri.length === 0 ||
    record.redirectUri.length > 2048 ||
    !isCanonicalIsoTimestamp(record.createdAt) ||
    !Array.isArray(record.scopes) ||
    record.scopes.length === 0 ||
    record.scopes.length > X_DEFAULT_SCOPES.length ||
    record.scopes.some(
      (scope) =>
        typeof scope !== "string" || !(X_DEFAULT_SCOPES as readonly string[]).includes(scope),
    ) ||
    new Set(record.scopes).size !== record.scopes.length
  ) {
    return null;
  }
  return record as unknown as PendingConnectRecord;
}

// ── Initiate ──────────────────────────────────────────────────────────────────
export interface InitiateConnectInput {
  tenantId: string;
  workspaceId: string;
  initiatedByUserId: string;
  redirectUri: string;
  scopes?: string[];
  config: XConnectConfig;
  store: PendingConnectStore;
  requestId?: string | null;
}

export interface InitiateConnectResult {
  authorizeUrl: string;
  state: string;
  /** Sealed verifier the caller must carry back to the callback. Opaque token. */
  connectToken: string;
}

/**
 * Build the X authorize URL, persist hashed pending-connect state, and return
 * the raw state + a `connectToken` that carries the raw PKCE verifier back to
 * the callback. The connectToken is base64url(JSON{state, verifier}); it is only
 * ever handed to the initiating client and echoed back, mirroring how the user-
 * auth flow keeps the verifier server-adjacent. The STORE only ever holds the
 * hash of both values.
 */
export async function initiateXConnect(
  input: InitiateConnectInput,
): Promise<InitiateConnectResult> {
  const scopes = normalizeScopes(input.scopes);
  const verifier = generateCodeVerifier();
  const challenge = deriveCodeChallenge(verifier);
  const state = generateStateToken();

  const record: PendingConnectRecord = {
    schemaVersion: "steward.provider-x.pending-connect.v1",
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    initiatedByUserId: input.initiatedByUserId,
    verifierHash: sha256Hex(verifier),
    scopes,
    redirectUri: input.redirectUri,
    createdAt: new Date().toISOString(),
  };

  await input.store.set(stateStoreKey(state), JSON.stringify(record), X_CONNECT_STATE_TTL_MS);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: input.config.clientId,
    redirect_uri: input.redirectUri,
    scope: scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  const connectToken = base64url(Buffer.from(JSON.stringify({ state, verifier }), "utf8"));

  return {
    authorizeUrl: `${X_AUTHORIZE_URL}?${params.toString()}`,
    state,
    connectToken,
  };
}

function normalizeScopes(scopes?: string[]): string[] {
  const allowed = new Set<string>(X_DEFAULT_SCOPES);
  if (!scopes || scopes.length === 0) return [...X_DEFAULT_SCOPES];
  const filtered = scopes.filter((s) => allowed.has(s));
  // offline.access is required to obtain a refresh token; always include it.
  if (!filtered.includes("offline.access")) filtered.push("offline.access");
  // users.read is required to identify the connected account (external_ref).
  if (!filtered.includes("users.read")) filtered.push("users.read");
  return [...new Set(filtered)];
}

function stateStoreKey(state: string): string {
  return `provider-x-connect:${sha256Hex(state)}`;
}

export interface ParsedConnectToken {
  state: string;
  verifier: string;
}

export function parseConnectToken(token: string): ParsedConnectToken | null {
  try {
    if (token.length === 0 || token.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(token)) return null;
    const json = base64ToUtf8(token);
    if (base64url(Buffer.from(json, "utf8")) !== token) return null;
    const parsed = JSON.parse(json) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const candidate = parsed as Record<string, unknown>;
    if (
      typeof candidate.state !== "string" ||
      !/^[a-f0-9]{64}$/.test(candidate.state) ||
      typeof candidate.verifier !== "string" ||
      !/^[a-f0-9]{96}$/.test(candidate.verifier)
    ) {
      return null;
    }
    return { state: candidate.state, verifier: candidate.verifier };
  } catch {
    return null;
  }
}

// ── Callback (code exchange + token storage) ──────────────────────────────────
export interface CompleteConnectInput {
  tenantId: string;
  workspaceId: string;
  callerUserId: string;
  code: string;
  state: string;
  connectToken: string;
  redirectUri: string;
  config: XConnectConfig;
  store: PendingConnectStore;
  vault: SecretVault;
  requestId?: string | null;
}

export interface CompleteConnectResult {
  providerAccountId: string;
  xUserId: string;
  xUsername: string;
  scopesGranted: string[];
  credentialVersion: number;
  reconnected: boolean;
}

interface XConnectLifecycleSecret {
  schemaVersion: "steward.provider-x.lifecycle.v1";
  token: unknown;
  allowedScopes: string[];
  callerUserId: string;
  requestId: string | null;
}

async function createXConnectIntent(input: CompleteConnectInput): Promise<string> {
  const lifecycleId = randomUUID();
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    await tx.insert(providerXCredentialLifecycles).values({
      id: lifecycleId,
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      kind: "connect_exchange",
      state: "inflight",
      providerAccountId: null,
      expectedAccountRevision: null,
    });
    await append({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.callerUserId,
      action: "provider.x.connect.exchange_intent",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { workspaceId: input.workspaceId, requestId: input.requestId ?? null },
    });
  });
  return lifecycleId;
}

async function stageXConnectResponse(
  input: CompleteConnectInput,
  lifecycleId: string,
  token: unknown,
  allowedScopes: string[],
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const secret = await input.vault.createSecretWithinTx(
      tx,
      input.tenantId,
      `provider-x-lifecycle:${lifecycleId}`,
      JSON.stringify({
        schemaVersion: "steward.provider-x.lifecycle.v1",
        token,
        allowedScopes,
        callerUserId: input.callerUserId,
        requestId: input.requestId ?? null,
      } satisfies XConnectLifecycleSecret),
      { description: "Encrypted transient X OAuth connect response" },
    );
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({ state: "credential_staged", credentialSecretId: secret.id, updatedAt: new Date() })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, lifecycleId),
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "inflight"),
        ),
      )
      .returning({ id: providerXCredentialLifecycles.id });
    if (!updated)
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "X connect lifecycle changed before staging",
      );
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.x.connect.credential_staged",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { workspaceId: input.workspaceId },
    });
  });
}

async function setXConnectLifecycleFailure(
  tenantId: string,
  lifecycleId: string,
  reason: string,
  hasHandle: boolean,
  terminalRevoked = false,
): Promise<void> {
  await withTenantAuditedTransaction(tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const now = new Date();
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({
        state: terminalRevoked ? "revoked" : hasHandle ? "revocation_pending" : "needs_attention",
        lastErrorCode: reason,
        nextRetryAt: hasHandle ? now : null,
        updatedAt: now,
      })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, tenantId),
          eq(providerXCredentialLifecycles.id, lifecycleId),
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          inArray(providerXCredentialLifecycles.state, ["inflight", "credential_staged"]),
        ),
      )
      .returning({ id: providerXCredentialLifecycles.id });
    if (!updated) return;
    await append({
      tenantId,
      actorType: "system",
      actorId: "system",
      action: terminalRevoked
        ? "provider.x.connect.exchange_terminal"
        : "provider.x.connect.recovery_required",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { reason, hasHandle, terminalRevoked },
    });
  });
}

export async function completeXConnect(
  input: CompleteConnectInput,
): Promise<CompleteConnectResult> {
  // 1. Load pending state WITHOUT consuming — a bad provider code must not burn
  //    a live attempt's one-time state.
  const key = stateStoreKey(input.state);
  const raw = await input.store.get(key);
  if (!raw) throw new XConnectError("X_STATE_INVALID", 401, "unknown or expired connect state");

  let parsedRecord: unknown;
  try {
    parsedRecord = JSON.parse(raw);
  } catch {
    throw new XConnectError("X_STATE_INVALID", 400, "malformed connect state");
  }
  const record = validatePendingConnectRecord(parsedRecord);
  if (!record) throw new XConnectError("X_STATE_INVALID", 400, "malformed connect state");
  const recordAgeMs = Date.now() - new Date(record.createdAt).getTime();
  if (recordAgeMs < 0 || recordAgeMs > X_CONNECT_STATE_TTL_MS) {
    throw new XConnectError("X_STATE_EXPIRED", 401, "expired connect state");
  }

  // Bind the state to THIS tenant/workspace/caller — a state minted for another
  // workspace cannot be replayed here.
  if (
    record.tenantId !== input.tenantId ||
    record.workspaceId !== input.workspaceId ||
    record.initiatedByUserId !== input.callerUserId
  ) {
    throw new XConnectError("X_STATE_INVALID", 401, "connect state scope mismatch");
  }
  if (record.redirectUri !== input.redirectUri) {
    throw new XConnectError("X_STATE_INVALID", 400, "redirect_uri mismatch");
  }

  // 2. Verify the PKCE verifier carried in the connectToken matches the hash we
  //    stored at initiate. Prevents a stolen state (without the verifier) from
  //    completing the exchange.
  const parsedToken = parseConnectToken(input.connectToken);
  if (!parsedToken || parsedToken.state !== input.state) {
    throw new XConnectError("X_PKCE_MISMATCH", 400, "connect token mismatch");
  }
  if (sha256Hex(parsedToken.verifier) !== record.verifierHash) {
    throw new XConnectError("X_PKCE_MISMATCH", 400, "PKCE verifier mismatch");
  }

  // 3. Claim the state BEFORE any provider call. Security takes precedence over
  // retrying a bad authorization code: two replicas must never both exchange a
  // one-time code and strand the losing callback's newly issued grant.
  const consumed = await input.store.consume(key);
  if (consumed !== raw) {
    throw new XConnectError("X_STATE_REUSED", 401, "connect state already used");
  }

  const lifecycleId = await createXConnectIntent(input);
  let tokenRes: XTokenResponse;
  try {
    // A successful exchange is a one-way boundary. Persist its exact bounded
    // response before any validation or downstream call that can fail.
    tokenRes = await exchangeAuthorizationCode({
      config: input.config,
      code: input.code,
      redirectUri: input.redirectUri,
      verifier: parsedToken.verifier,
    });
  } catch (error) {
    await setXConnectLifecycleFailure(
      input.tenantId,
      lifecycleId,
      "TOKEN_EXCHANGE_OUTCOME_UNKNOWN",
      false,
    );
    throw error;
  }
  try {
    await stageXConnectResponse(input, lifecycleId, tokenRes, record.scopes);
  } catch (error) {
    const raw = tokenRes as unknown as Record<string, unknown>;
    const accessToken = boundedStagedToken(raw.access_token);
    const refreshToken = boundedStagedToken(raw.refresh_token);
    const revoked =
      accessToken || refreshToken
        ? await revokeUpstreamBestEffort(
            input.config,
            accessToken ?? (refreshToken as string),
            refreshToken,
          ).catch(() => false)
        : false;
    await setXConnectLifecycleFailure(
      input.tenantId,
      lifecycleId,
      revoked ? "STAGING_FAILED_GRANT_REVOKED" : "STAGING_FAILED_OUTCOME_UNKNOWN",
      false,
      revoked,
    );
    throw error;
  }
  await afterXCredentialStageForTests?.();
  return reconcileXConnectLifecycle({
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    lifecycleId,
    vault: input.vault,
    config: input.config,
  });
}

interface XIdentity {
  id: string;
  username: string;
  name: string;
}

async function fetchXIdentity(accessToken: string): Promise<XIdentity> {
  const res = await forwardImpl({
    url: X_USERINFO_URL,
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) {
    throw new XConnectError("X_IDENTITY_FAILED", 502, `X identity fetch failed (${res.status})`);
  }
  const data = (res.json as XUserResponse | null)?.data;
  if (
    !data ||
    typeof data.id !== "string" ||
    !/^\d{1,32}$/.test(data.id) ||
    (data.username !== undefined &&
      (typeof data.username !== "string" || !/^[A-Za-z0-9_]{1,64}$/.test(data.username))) ||
    (data.name !== undefined &&
      (typeof data.name !== "string" ||
        data.name.length > 128 ||
        /[\u0000-\u001f\u007f]/.test(data.name)))
  ) {
    throw new XConnectError("X_IDENTITY_FAILED", 502, "X identity response missing user id");
  }
  return { id: data.id, username: data.username ?? "", name: data.name ?? "" };
}

/** Resume a staged connect response without exchanging the authorization code again. */
export async function reconcileXConnectLifecycle(input: {
  tenantId: string;
  workspaceId: string;
  lifecycleId: string;
  vault: SecretVault;
  config: XConnectConfig;
}): Promise<CompleteConnectResult> {
  try {
    const db = getDb() as DbExecutor;
    const [lifecycle] = await db
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
          eq(providerXCredentialLifecycles.id, input.lifecycleId),
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "credential_staged"),
        ),
      )
      .limit(1);
    if (!lifecycle?.credentialSecretId) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "staged X connect response is missing",
      );
    }
    const [secret] = (await db
      .select()
      .from(secrets)
      .where(
        and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, lifecycle.credentialSecretId)),
      )
      .limit(1)) as Secret[];
    if (!secret)
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "staged X connect response is missing",
      );
    const staged = JSON.parse(
      input.vault.decryptSecretRow(input.tenantId, secret),
    ) as XConnectLifecycleSecret;
    if (
      staged.schemaVersion !== "steward.provider-x.lifecycle.v1" ||
      !Array.isArray(staged.allowedScopes) ||
      staged.allowedScopes.length === 0 ||
      staged.allowedScopes.length > X_DEFAULT_SCOPES.length ||
      !staged.allowedScopes.every(
        (scope) =>
          typeof scope === "string" && (X_DEFAULT_SCOPES as readonly string[]).includes(scope),
      ) ||
      typeof staged.callerUserId !== "string" ||
      staged.callerUserId.length === 0 ||
      staged.callerUserId.length > 128 ||
      (staged.requestId !== null &&
        (typeof staged.requestId !== "string" || staged.requestId.length > 255)) ||
      !staged.token ||
      typeof staged.token !== "object" ||
      Array.isArray(staged.token)
    ) {
      throw new XConnectError(
        "X_TOKEN_EXCHANGE_FAILED",
        502,
        "staged X connect response is invalid",
      );
    }
    const token = staged.token as XTokenResponse;
    validateXTokenEnvelope(token);
    const scopesGranted = parseXGrantedScopes(
      token.scope,
      staged.allowedScopes,
      "X_TOKEN_EXCHANGE_FAILED",
    );
    const identity = await fetchXIdentity(token.access_token);
    const obtainedAt = new Date();
    const expiresAt =
      typeof token.expires_in === "number"
        ? new Date(obtainedAt.getTime() + token.expires_in * 1000)
        : null;
    const payload: XCredentialPayload = {
      schemaVersion: "steward.provider-x.credential.v1",
      accessToken: token.access_token,
      refreshToken: token.refresh_token ?? null,
      scopesGranted,
      xUserId: identity.id,
      xUsername: identity.username,
      obtainedAt: obtainedAt.toISOString(),
      expiresAt: expiresAt?.toISOString() ?? null,
    };
    return await persistConnectedAccount({
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      callerUserId: staged.callerUserId,
      vault: input.vault,
      identity,
      payload,
      scopesGranted,
      requestId: staged.requestId,
      lifecycleId: input.lifecycleId,
    });
  } catch (error) {
    await setXConnectLifecycleFailure(
      input.tenantId,
      input.lifecycleId,
      "CONNECT_COMPLETION_FAILED",
      true,
    );
    await reconcileStagedXCredentialRevocation({
      ...input,
      now: new Date(),
    });
    throw error;
  }
}

interface ExchangeInput {
  config: XConnectConfig;
  code: string;
  redirectUri: string;
  verifier: string;
}

async function exchangeAuthorizationCode(input: ExchangeInput): Promise<XTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.config.clientId,
    code_verifier: input.verifier,
  });
  const res = await forwardImpl({
    url: X_TOKEN_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: basicAuthHeader(input.config),
    },
    body: body.toString(),
  });
  const parsed = res.json as unknown;
  if (!res.ok || !parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new XConnectError(
      "X_TOKEN_EXCHANGE_FAILED",
      502,
      `X token exchange failed (${res.status})`,
    );
  }
  return parsed as XTokenResponse;
}

function validateXTokenEnvelope(parsed: XTokenResponse): void {
  if (
    !isValidOAuthBearerToken(parsed.access_token) ||
    (parsed.refresh_token !== undefined && !isValidOAuthOpaqueToken(parsed.refresh_token)) ||
    (parsed.token_type !== undefined &&
      (typeof parsed.token_type !== "string" || parsed.token_type.toLowerCase() !== "bearer")) ||
    (parsed.expires_in !== undefined &&
      (typeof parsed.expires_in !== "number" ||
        !Number.isSafeInteger(parsed.expires_in) ||
        parsed.expires_in <= 0 ||
        parsed.expires_in > 86_400)) ||
    (parsed.scope !== undefined &&
      (typeof parsed.scope !== "string" || parsed.scope.length === 0 || parsed.scope.length > 4096))
  ) {
    throw new XConnectError("X_TOKEN_EXCHANGE_FAILED", 502, "X token exchange response is invalid");
  }
}

function parseXGrantedScopes(
  raw: unknown,
  allowedScopes: string[],
  errorCode: "X_TOKEN_EXCHANGE_FAILED" | "X_REFRESH_FAILED",
): string[] {
  if (raw === undefined) return [...new Set(allowedScopes)].sort();
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 4096) {
    throw new XConnectError(errorCode, 502, "X OAuth scope is invalid");
  }
  const scopes = raw.split(/\s+/).filter(Boolean);
  if (
    scopes.length === 0 ||
    scopes.length > 64 ||
    scopes.some((scope) => !/^[A-Za-z0-9._:-]{1,128}$/.test(scope)) ||
    scopes.some((scope) => !allowedScopes.includes(scope))
  ) {
    throw new XConnectError(errorCode, 502, "X OAuth scope is invalid");
  }
  return [...new Set(scopes)].sort();
}

/** X token endpoint accepts confidential-client creds via HTTP Basic. */
function basicAuthHeader(config: XConnectConfig): string {
  const raw = `${config.clientId}:${config.clientSecret}`;
  return `Basic ${utf8ToBase64(raw)}`;
}

// ── Persist / reconnect ───────────────────────────────────────────────────────
interface PersistInput {
  tenantId: string;
  workspaceId: string;
  callerUserId: string;
  vault: SecretVault;
  identity: XIdentity;
  payload: XCredentialPayload;
  scopesGranted: string[];
  requestId: string | null;
  lifecycleId: string;
}

/** Deterministic per-account secret name so reconnect targets the same lineage. */
export function xCredentialSecretName(workspaceId: string, xUserId: string): string {
  return `provider-x/${workspaceId}/${xUserId}`;
}

async function persistConnectedAccount(input: PersistInput): Promise<CompleteConnectResult> {
  // Serialize reconnect against the account/lifecycle rows, then write the
  // credential and account link in the same transaction. Do not rotate the
  // active secret until every unresolved refresh is safe to supersede: a staged
  // response is a live provider handle, not garbage.
  const secretName = xCredentialSecretName(input.workspaceId, input.identity.id);
  const serialized = JSON.stringify(input.payload);

  return withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    let routesDisabledByDisconnect: Array<{ id: string; authorityRevision: number }> = [];

    const [connectLifecycle] = await tx
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, input.lifecycleId),
          eq(providerXCredentialLifecycles.kind, "connect_exchange"),
          eq(providerXCredentialLifecycles.state, "credential_staged"),
        ),
      )
      .limit(1)
      .for("update");
    if (!connectLifecycle?.credentialSecretId) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "staged X connect credential is missing",
      );
    }

    const [account] = await tx
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.adapterKey, X_ADAPTER_KEY),
          eq(providerAccounts.externalRef, input.identity.id),
        ),
      )
      .limit(1)
      .for("update");

    // Timestamps are not a total order: replica clock skew, a database clock
    // correction, or equal timestamp precision can all make a later reconnect
    // appear older. The tenant audit sequence is serialized and monotonic, and
    // both the exchange intent and successful adoption are required writes in
    // the same transactions as their lifecycle changes.
    const [connectIntentAudit] = account
      ? await tx
          .select({ seq: auditEvents.seq })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, input.tenantId),
              eq(auditEvents.action, "provider.x.connect.exchange_intent"),
              eq(auditEvents.resourceType, "provider_x_credential_lifecycle"),
              eq(auditEvents.resourceId, connectLifecycle.id),
            ),
          )
          .orderBy(desc(auditEvents.seq))
          .limit(1)
      : [];
    if (account && !connectIntentAudit) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "staged X connect lineage cannot be established",
      );
    }
    const [latestConnectAdoption] =
      account && connectIntentAudit
        ? await tx
            .select({ id: auditEvents.id })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, input.tenantId),
                eq(auditEvents.resourceType, "provider_account"),
                eq(auditEvents.resourceId, account.id),
                inArray(auditEvents.action, [
                  "provider.x.connect.completed",
                  "provider.x.connect.reconnected",
                ]),
              ),
            )
            .orderBy(desc(auditEvents.seq))
            .limit(1)
        : [];
    const [latestCredentialAdoption] =
      account && connectIntentAudit
        ? await tx
            .select({
              action: auditEvents.action,
              metadata: auditEvents.metadata,
              seq: auditEvents.seq,
            })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, input.tenantId),
                eq(auditEvents.resourceType, "provider_account"),
                eq(auditEvents.resourceId, account.id),
                inArray(auditEvents.action, [
                  "provider.x.connect.completed",
                  "provider.x.connect.reconnected",
                  "provider.x.refresh.completed",
                ]),
              ),
            )
            .orderBy(desc(auditEvents.seq))
            .limit(1)
        : [];
    const [latestAccountMutation] =
      account && connectIntentAudit
        ? await tx
            .select({
              action: auditEvents.action,
              metadata: auditEvents.metadata,
              seq: auditEvents.seq,
            })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, input.tenantId),
                eq(auditEvents.resourceType, "provider_account"),
                eq(auditEvents.resourceId, account.id),
                inArray(auditEvents.action, [
                  "provider.x.connect.completed",
                  "provider.x.connect.reconnected",
                  "provider.x.refresh.completed",
                  "provider.x.refresh.needs_attention",
                  "provider.x.refresh.revoked",
                  "provider.x.disconnect.completed",
                  "provider.account.disable",
                  "provider.account.disable.completed",
                ]),
                sql`(
                  ${auditEvents.action} <> 'provider.account.disable'
                  OR (
                    ${account.status === "disabled"}
                    AND ${auditEvents.metadata}->>'expectedRevision' = ${String(account.revision - 1)}
                  )
                )`,
              ),
            )
            .orderBy(desc(auditEvents.seq))
            .limit(1)
        : [];
    // Before provider.account.disable.completed existed, a successful generic
    // disable left only its authorization event. Treat that legacy event as
    // authoritative only when the currently locked row proves the exact CAS
    // landed. A newer orphan intent from an update failure/CAS loss is skipped
    // so it cannot manufacture durable recovery lineage.
    // An existing account is only safe to rotate when its current credential
    // has an authoritative X-connect adoption before this intent. A generic
    // provider-account insert (or a selectively missing adoption record) gives
    // us no total-order proof that the staged response is newer, so fail closed
    // and let the outer reconciler revoke the staged grant.
    if (account && !latestConnectAdoption) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "current X account adoption lineage cannot be established",
      );
    }
    // A refresh, disconnect, disable, or second connect can all replace the
    // credential/status lineage without leaving an unresolved lifecycle. The
    // staged grant is safe only when no such account mutation follows its
    // exchange intent on the serialized tenant audit chain.
    if (
      latestAccountMutation &&
      connectIntentAudit &&
      latestAccountMutation.seq >= connectIntentAudit.seq
    ) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "a newer X account mutation already superseded this staged connect response",
      );
    }

    if (account && latestAccountMutation && latestCredentialAdoption) {
      const adoptionVersion = latestCredentialAdoption.metadata.credentialVersion;
      const accountHasCredential =
        typeof account.credentialSecretId === "string" &&
        account.credentialSecretId.length > 0 &&
        Number.isSafeInteger(account.credentialVersion) &&
        (account.credentialVersion as number) > 0;
      const disconnected = latestAccountMutation.action === "provider.x.disconnect.completed";
      if (disconnected) {
        if (
          account.status !== "revoked" ||
          account.credentialSecretId !== null ||
          account.credentialVersion !== null
        ) {
          throw new XConnectError(
            "X_CREDENTIAL_NEEDS_ATTENTION",
            409,
            "current X account state does not match its disconnect lineage",
          );
        }
      } else {
        const expectedStatus =
          latestAccountMutation.action === "provider.x.refresh.revoked"
            ? "revoked"
            : latestAccountMutation.action === "provider.account.disable" ||
                latestAccountMutation.action === "provider.account.disable.completed" ||
                (latestAccountMutation.action === "provider.x.refresh.needs_attention" &&
                  latestAccountMutation.metadata.accountDisabled === true)
              ? "disabled"
              : "active";
        const [currentCredential] = accountHasCredential
          ? await tx
              .select({
                id: secrets.id,
                name: secrets.name,
                version: secrets.version,
              })
              .from(secrets)
              .where(
                and(
                  eq(secrets.tenantId, input.tenantId),
                  eq(secrets.id, account.credentialSecretId as string),
                  eq(secrets.version, account.credentialVersion as number),
                  sql`${secrets.deletedAt} IS NULL`,
                ),
              )
              .limit(1)
              .for("update")
          : [];
        if (
          account.status !== expectedStatus ||
          !currentCredential ||
          currentCredential.name !== secretName ||
          typeof adoptionVersion !== "number" ||
          !Number.isSafeInteger(adoptionVersion) ||
          adoptionVersion !== account.credentialVersion ||
          ((latestCredentialAdoption.action === "provider.x.connect.completed" ||
            latestCredentialAdoption.action === "provider.x.connect.reconnected") &&
            latestCredentialAdoption.metadata.credentialSecretId !== account.credentialSecretId)
        ) {
          throw new XConnectError(
            "X_CREDENTIAL_NEEDS_ATTENTION",
            409,
            "current X account credential lineage cannot be established",
          );
        }
        if (
          latestAccountMutation.action === "provider.account.disable" ||
          latestAccountMutation.action === "provider.account.disable.completed"
        ) {
          const disabledRevision = latestAccountMutation.metadata.expectedRevision;
          if (
            typeof disabledRevision !== "number" ||
            !Number.isSafeInteger(disabledRevision) ||
            account.revision < disabledRevision + 1
          ) {
            throw new XConnectError(
              "X_CREDENTIAL_NEEDS_ATTENTION",
              409,
              "current X account disable lineage cannot be established",
            );
          }
        }
      }
    }

    const unresolvedLifecycles = account
      ? await tx
          .select({
            id: providerXCredentialLifecycles.id,
            kind: providerXCredentialLifecycles.kind,
            state: providerXCredentialLifecycles.state,
            credentialSecretId: providerXCredentialLifecycles.credentialSecretId,
            expectedAccountRevision: providerXCredentialLifecycles.expectedAccountRevision,
            lastErrorCode: providerXCredentialLifecycles.lastErrorCode,
            disabledRoutes: providerXCredentialLifecycles.disabledRoutes,
          })
          .from(providerXCredentialLifecycles)
          .where(
            and(
              eq(providerXCredentialLifecycles.tenantId, input.tenantId),
              eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
              eq(providerXCredentialLifecycles.providerAccountId, account.id),
              inArray(providerXCredentialLifecycles.state, [
                "inflight",
                "credential_staged",
                "revocation_pending",
                "needs_attention",
              ]),
            ),
          )
          .orderBy(asc(providerXCredentialLifecycles.createdAt))
          .for("update")
      : [];

    const supersedableLifecycles = account
      ? unresolvedLifecycles.filter(
          (row) =>
            row.state === "needs_attention" &&
            row.credentialSecretId === null &&
            row.expectedAccountRevision !== null &&
            row.expectedAccountRevision <= account.revision &&
            ((row.kind === "refresh_rotation" && row.lastErrorCode === "REFRESH_OUTCOME_UNKNOWN") ||
              (row.kind === "disconnect_revoke" &&
                row.lastErrorCode === "DISCONNECT_REVOCATION_HANDLE_UNAVAILABLE")),
        )
      : [];
    if (supersedableLifecycles.length !== unresolvedLifecycles.length) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "previous X credential lifecycle must be reconciled before reconnect",
      );
    }

    const supersedableDisconnect = supersedableLifecycles.find(
      (row) => row.kind === "disconnect_revoke",
    );
    if (supersedableDisconnect) {
      routesDisabledByDisconnect = supersedableDisconnect.disabledRoutes;
    } else if (account) {
      const [completedDisconnect] = await tx
        .select({ disabledRoutes: providerXCredentialLifecycles.disabledRoutes })
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
            eq(providerXCredentialLifecycles.providerAccountId, account.id),
            eq(providerXCredentialLifecycles.kind, "disconnect_revoke"),
            eq(providerXCredentialLifecycles.state, "revoked"),
          ),
        )
        .orderBy(desc(providerXCredentialLifecycles.updatedAt))
        .limit(1)
        .for("update");
      routesDisabledByDisconnect = completedDisconnect?.disabledRoutes ?? [];
    }

    const [existingSecret] = await tx
      .select({ id: secrets.id, deletedAt: secrets.deletedAt })
      .from(secrets)
      .where(and(eq(secrets.tenantId, input.tenantId), eq(secrets.name, secretName)))
      .orderBy(desc(secrets.version))
      .limit(1)
      .for("update");
    const meta = existingSecret
      ? await input.vault.rotateSecretWithinTx(tx, input.tenantId, secretName, serialized, {
          allowDeletedCurrent: existingSecret.deletedAt !== null,
        })
      : await input.vault.createSecretWithinTx(tx, input.tenantId, secretName, serialized, {
          description: "X (Twitter) provider-account OAuth credential",
        });

    const displayName = input.identity.username ? `@${input.identity.username}` : input.identity.id;

    let providerAccountId: string;
    let reconnected: boolean;

    if (account) {
      reconnected = true;
      providerAccountId = account.id;
      const [updated] = await tx
        .update(providerAccounts)
        .set({
          displayName,
          status: "active",
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
          revision: account.revision + 1,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.id, account.id),
            eq(providerAccounts.revision, account.revision),
          ),
        )
        .returning();
      if (!updated) {
        throw new XConnectError("X_REFRESH_FAILED", 409, "account revision conflict on reconnect");
      }
      for (const route of routesDisabledByDisconnect) {
        if (
          !route ||
          typeof route.id !== "string" ||
          !Number.isSafeInteger(route.authorityRevision) ||
          route.authorityRevision < 1
        ) {
          continue;
        }
        await tx
          .update(secretRoutes)
          .set({ enabled: true })
          .where(
            and(
              eq(secretRoutes.tenantId, input.tenantId),
              eq(secretRoutes.id, route.id),
              eq(secretRoutes.secretId, meta.id),
              eq(secretRoutes.enabled, false),
              // Disconnect and credential rotation each advance the route
              // revision. Only untouched routes are restored automatically.
              eq(secretRoutes.authorityRevision, route.authorityRevision + 2),
            ),
          );
      }
    } else {
      reconnected = false;
      const [created] = await tx
        .insert(providerAccounts)
        .values({
          tenantId: input.tenantId,
          workspaceId: input.workspaceId,
          adapterKey: X_ADAPTER_KEY,
          externalRef: input.identity.id,
          displayName,
          status: "active",
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
        })
        .returning();
      providerAccountId = created.id;
    }

    await append({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.callerUserId,
      action: reconnected ? "provider.x.connect.reconnected" : "provider.x.connect.completed",
      resourceType: "provider_account",
      resourceId: providerAccountId,
      metadata: {
        workspaceId: input.workspaceId,
        adapterKey: X_ADAPTER_KEY,
        xUserId: input.identity.id,
        xUsername: input.identity.username,
        scopesGranted: input.scopesGranted,
        credentialSecretId: meta.id,
        credentialVersion: meta.version,
        requestId: input.requestId,
      },
    });

    const [adopted] = await tx
      .update(providerXCredentialLifecycles)
      .set({
        providerAccountId,
        expectedAccountRevision: account ? account.revision + 1 : 1,
        state: "adopted",
        credentialSecretId: null,
        nextRetryAt: null,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, input.lifecycleId),
          eq(providerXCredentialLifecycles.state, "credential_staged"),
          eq(providerXCredentialLifecycles.credentialSecretId, connectLifecycle.credentialSecretId),
        ),
      )
      .returning({ id: providerXCredentialLifecycles.id });
    if (!adopted)
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "X connect lifecycle changed during adoption",
      );
    await tx
      .delete(secrets)
      .where(
        and(
          eq(secrets.tenantId, input.tenantId),
          eq(secrets.id, connectLifecycle.credentialSecretId),
        ),
      );

    if (supersedableLifecycles.length > 0) {
      const lifecycleIds = supersedableLifecycles.map((row) => row.id).sort();
      const superseded = await tx
        .update(providerXCredentialLifecycles)
        .set({
          state: "superseded",
          lastErrorCode: "SUPERSEDED_BY_RECONNECT",
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
            eq(providerXCredentialLifecycles.providerAccountId, providerAccountId),
            inArray(providerXCredentialLifecycles.id, lifecycleIds),
            eq(providerXCredentialLifecycles.state, "needs_attention"),
            sql`${providerXCredentialLifecycles.credentialSecretId} IS NULL`,
          ),
        )
        .returning({ id: providerXCredentialLifecycles.id });
      if (superseded.length !== supersedableLifecycles.length) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "X credential lifecycle changed during reconnect",
        );
      }
      await append({
        tenantId: input.tenantId,
        actorType: "user",
        actorId: input.callerUserId,
        action: "provider.x.lifecycle.superseded_by_reconnect",
        resourceType: "provider_account",
        resourceId: providerAccountId,
        metadata: {
          workspaceId: input.workspaceId,
          lifecycleIds,
          priorKinds: supersedableLifecycles.map((row) => row.kind).sort(),
          newAccountRevision: account ? account.revision + 1 : 1,
          requestId: input.requestId,
        },
      });
    }

    return {
      providerAccountId,
      xUserId: input.identity.id,
      xUsername: input.identity.username,
      scopesGranted: input.scopesGranted,
      credentialVersion: meta.version,
      reconnected,
    };
  });
}

// ── Refresh (single-flight, rotating token) ───────────────────────────────────
export interface RefreshInput {
  tenantId: string;
  /**
   * The workspace the CALLER was authorized for. The account MUST belong to it,
   * or refresh fails closed with X_ACCOUNT_NOT_FOUND. Prevents a cross-workspace
   * IDOR where a user authorized for workspace A passes an account id from
   * workspace B.
   */
  workspaceId: string;
  accountId: string;
  vault: SecretVault;
  config: XConnectConfig;
  actorId?: string;
  requestId?: string | null;
  /** Force refresh even if the current access token is not near expiry. */
  force?: boolean;
}

export interface RefreshResult {
  refreshed: boolean;
  credentialVersion: number;
  expiresAt: string | null;
}

/**
 * Refresh a connected X account's access token. SINGLE-FLIGHT per account: the
 * A durable lifecycle intent serializes concurrent callers before provider I/O,
 * so the rotating refresh token is spent exactly once. A loser observes the
 * staged/adopted lifecycle and never makes a second token call.
 *
 * On upstream `invalid_grant` (revoked) the account is degraded + audited and we
 * throw X_REFRESH_REVOKED (fail closed). Every successful one-time response is
 * encrypted before semantic validation; crashes adopt the staged response, and
 * ambiguous outcomes disable the exact account revision until reconnect.
 */
export async function refreshXProviderCredential(input: RefreshInput): Promise<RefreshResult> {
  type Prepared =
    | { kind: "fresh"; result: RefreshResult }
    | { kind: "wait"; lifecycleId: string }
    | {
        kind: "call";
        lifecycleId: string;
        refreshToken: string;
        allowedScopes: string[];
      };
  const prepared = await withTenantAuditedTransaction<Prepared>(
    input.tenantId,
    async (txRaw, append) => {
      const tx = txRaw as DbExecutor;

      // Acquire the per-account row lock first. Everything below runs under it.
      const [account] = await tx
        .select()
        .from(providerAccounts)
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.id, input.accountId),
          ),
        )
        .limit(1)
        .for("update");

      assertXRefreshAccount(account, input.workspaceId);
      if (!account.credentialSecretId || account.credentialVersion == null) {
        throw new XConnectError("X_REFRESH_TOKEN_MISSING", 409, "account has no credential");
      }

      // Load the CURRENT credential under the lock.
      const current = await loadCredential(
        input.vault,
        input.tenantId,
        account.credentialSecretId,
        tx,
      );
      if (current.payload.xUserId !== account.externalRef) {
        throw new XConnectError("X_REFRESH_FAILED", 409, "credential account binding mismatch");
      }

      // Single-flight fast path: a concurrent winner already rotated us to a fresh
      // token while we waited for the lock. If not forced and the token is still
      // valid, skip the network call entirely.
      if (!input.force && !isNearExpiry(current.expiresAt)) {
        return {
          kind: "fresh",
          result: {
            refreshed: false,
            credentialVersion: account.credentialVersion,
            expiresAt: current.expiresAt,
          },
        };
      }

      if (!current.refreshToken) {
        throw new XConnectError("X_REFRESH_TOKEN_MISSING", 409, "no refresh token on record");
      }
      const [activeLifecycle] = await tx
        .select({
          id: providerXCredentialLifecycles.id,
          state: providerXCredentialLifecycles.state,
        })
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.providerAccountId, account.id),
            inArray(providerXCredentialLifecycles.state, [
              "inflight",
              "credential_staged",
              "revocation_pending",
              "needs_attention",
            ]),
          ),
        )
        .limit(1);
      if (activeLifecycle) {
        if (
          activeLifecycle.state === "needs_attention" ||
          activeLifecycle.state === "revocation_pending"
        ) {
          throw new XConnectError(
            "X_CREDENTIAL_NEEDS_ATTENTION",
            409,
            "X refresh outcome must be recovered by reconnect",
          );
        }
        return { kind: "wait", lifecycleId: activeLifecycle.id };
      }
      const lifecycleId = randomUUID();
      await tx.insert(providerXCredentialLifecycles).values({
        id: lifecycleId,
        tenantId: input.tenantId,
        workspaceId: account.workspaceId,
        providerAccountId: account.id,
        kind: "refresh_rotation",
        state: "inflight",
        expectedAccountRevision: account.revision,
      });
      await append({
        tenantId: input.tenantId,
        actorType: input.actorId ? "user" : "system",
        actorId: input.actorId ?? "system",
        action: "provider.x.refresh.intent_staged",
        resourceType: "provider_x_credential_lifecycle",
        resourceId: lifecycleId,
        metadata: {
          workspaceId: account.workspaceId,
          providerAccountId: account.id,
          expectedAccountRevision: account.revision,
          requestId: input.requestId ?? null,
        },
      });
      return {
        kind: "call",
        lifecycleId,
        refreshToken: current.refreshToken,
        allowedScopes: current.payload.scopesGranted,
      };
    },
  );
  if (prepared.kind === "fresh") return prepared.result;
  if (prepared.kind === "wait") {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const [row] = await (getDb() as DbExecutor)
        .select({ state: providerXCredentialLifecycles.state })
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.id, prepared.lifecycleId),
          ),
        )
        .limit(1);
      if (row?.state === "credential_staged") {
        return reconcileXRefreshLifecycle({ ...input, lifecycleId: prepared.lifecycleId });
      }
      if (row?.state === "adopted") {
        const [account] = await (getDb() as DbExecutor)
          .select()
          .from(providerAccounts)
          .where(
            and(
              eq(providerAccounts.tenantId, input.tenantId),
              eq(providerAccounts.id, input.accountId),
            ),
          )
          .limit(1);
        if (account?.credentialSecretId && account.credentialVersion != null) {
          const credential = await loadCredential(
            input.vault,
            input.tenantId,
            account.credentialSecretId,
          );
          return {
            refreshed: false,
            credentialVersion: account.credentialVersion,
            expiresAt: credential.expiresAt,
          };
        }
      }
      if (
        row?.state === "needs_attention" ||
        row?.state === "revocation_pending" ||
        row?.state === "revoked"
      ) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "concurrent X refresh did not complete",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new XConnectError(
      "X_REFRESH_FAILED",
      409,
      "X refresh is already in progress; retry shortly",
    );
  }

  await afterXRefreshIntentForTests?.();
  let tokenRes: RefreshUpstreamResult;
  try {
    tokenRes = await refreshUpstream(input.config, prepared.refreshToken);
  } catch (error) {
    await disableXAccountForLifecycle(input, prepared.lifecycleId, "REFRESH_OUTCOME_UNKNOWN");
    throw error;
  }
  if (tokenRes.revoked) {
    await revokeXAccountForLifecycle(input, prepared.lifecycleId);
    throw new XConnectError("X_REFRESH_REVOKED", 409, "X refresh token revoked");
  }
  try {
    await stageXRefreshResponse(input, prepared.lifecycleId, tokenRes.raw);
  } catch (error) {
    // The provider may already have rotated the one-time refresh token. Use the
    // response still held in memory to revoke that exact new grant before it can
    // become an orphan, then fail closed locally. Reconnect remains the recovery
    // boundary whether revocation succeeds or the outcome is unknowable.
    const candidate =
      tokenRes.raw && typeof tokenRes.raw === "object" && !Array.isArray(tokenRes.raw)
        ? (tokenRes.raw as Record<string, unknown>)
        : null;
    // Revocation uses the exact bounded strings returned by X. A credential may
    // fail Steward's adoption grammar while still being live at the provider.
    const accessToken = candidate ? boundedStagedToken(candidate.access_token) : null;
    const refreshToken = candidate ? boundedStagedToken(candidate.refresh_token) : null;
    const revokedAtUpstream =
      accessToken || refreshToken
        ? await revokeUpstreamBestEffort(
            input.config,
            accessToken ?? (refreshToken as string),
            refreshToken,
          ).catch(() => false)
        : false;
    if (revokedAtUpstream) {
      await revokeXAccountForLifecycle(
        input,
        prepared.lifecycleId,
        "ROTATED_GRANT_REVOKED_AFTER_STAGING_FAILURE",
      );
    } else {
      // There is no durable handle because staging itself failed. Keep this
      // lifecycle non-supersedable: reconnect must not proceed while the new
      // rotated grant may still be live upstream.
      await disableXAccountForLifecycle(
        input,
        prepared.lifecycleId,
        "REFRESH_RESPONSE_STAGING_FAILED",
      );
    }
    throw error;
  }
  await afterXCredentialStageForTests?.();
  return reconcileXRefreshLifecycle({
    ...input,
    lifecycleId: prepared.lifecycleId,
    allowedScopes: prepared.allowedScopes,
  });
}

interface XRefreshLifecycleSecret {
  schemaVersion: "steward.provider-x.lifecycle.v1";
  token: unknown;
}

function assertXRefreshAccount(
  account: typeof providerAccounts.$inferSelect | undefined,
  workspaceId: string,
): asserts account is typeof providerAccounts.$inferSelect {
  if (!account || account.workspaceId !== workspaceId) {
    throw new XConnectError("X_ACCOUNT_NOT_FOUND", 404, "provider account not found");
  }
  if (account.adapterKey !== X_ADAPTER_KEY) {
    throw new XConnectError("X_ACCOUNT_NOT_X", 400, "provider account is not an X account");
  }
  if (account.status !== "active") {
    throw new XConnectError(
      "X_REFRESH_REVOKED",
      409,
      "provider account is not active; reconnect required",
    );
  }
}

async function stageXRefreshResponse(
  input: RefreshInput,
  lifecycleId: string,
  raw: unknown,
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const secret = await input.vault.createSecretWithinTx(
      tx,
      input.tenantId,
      `provider-x-lifecycle:${lifecycleId}`,
      JSON.stringify({
        schemaVersion: "steward.provider-x.lifecycle.v1",
        token: raw,
      } satisfies XRefreshLifecycleSecret),
      { description: "Encrypted transient X OAuth rotation response" },
    );
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({ state: "credential_staged", credentialSecretId: secret.id, updatedAt: new Date() })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, lifecycleId),
          eq(providerXCredentialLifecycles.state, "inflight"),
        ),
      )
      .returning();
    if (!updated) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "X refresh lifecycle changed before staging",
      );
    }
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.x.refresh.credential_staged",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { providerAccountId: input.accountId, workspaceId: input.workspaceId },
    });
  });
}

async function disableXAccountForLifecycle(
  input: RefreshInput,
  lifecycleId: string,
  reason: string,
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [lifecycle] = await tx
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, lifecycleId),
          eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
          eq(providerXCredentialLifecycles.providerAccountId, input.accountId),
        ),
      )
      .limit(1)
      .for("update");
    let accountDisabled = false;
    if (lifecycle?.expectedAccountRevision != null) {
      const [disabled] = await tx
        .update(providerAccounts)
        .set({
          status: "disabled",
          revision: sql`${providerAccounts.revision} + 1`,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.workspaceId, input.workspaceId),
            eq(providerAccounts.id, input.accountId),
            eq(providerAccounts.revision, lifecycle.expectedAccountRevision),
          ),
        )
        .returning({ id: providerAccounts.id });
      accountDisabled = Boolean(disabled);
      await tx
        .update(providerXCredentialLifecycles)
        .set({
          state: lifecycle.credentialSecretId ? "revocation_pending" : "needs_attention",
          lastErrorCode: reason,
          nextRetryAt: lifecycle.credentialSecretId ? new Date() : null,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.id, lifecycleId),
            inArray(providerXCredentialLifecycles.state, [
              "inflight",
              "credential_staged",
              "revocation_pending",
              "needs_attention",
            ]),
          ),
        );
    }
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.x.refresh.needs_attention",
      resourceType: "provider_account",
      resourceId: input.accountId,
      metadata: { lifecycleId, reason, workspaceId: input.workspaceId, accountDisabled },
    });
  });
}

async function revokeXAccountForLifecycle(
  input: RefreshInput,
  lifecycleId: string,
  reason = "INVALID_GRANT",
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [lifecycle] = await tx
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, lifecycleId),
          eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
          eq(providerXCredentialLifecycles.providerAccountId, input.accountId),
        ),
      )
      .limit(1)
      .for("update");
    let accountRevoked = false;
    if (lifecycle?.expectedAccountRevision != null) {
      const [revoked] = await tx
        .update(providerAccounts)
        .set({
          status: "revoked",
          revision: sql`${providerAccounts.revision} + 1`,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.workspaceId, input.workspaceId),
            eq(providerAccounts.id, input.accountId),
            eq(providerAccounts.revision, lifecycle.expectedAccountRevision),
          ),
        )
        .returning({ id: providerAccounts.id });
      accountRevoked = Boolean(revoked);
      await tx
        .update(providerXCredentialLifecycles)
        .set({ state: "revoked", lastErrorCode: reason, updatedAt: new Date() })
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.id, lifecycleId),
          ),
        );
    }
    await append({
      tenantId: input.tenantId,
      actorType: input.actorId ? "user" : "system",
      actorId: input.actorId ?? "system",
      action: "provider.x.refresh.revoked",
      resourceType: "provider_account",
      resourceId: input.accountId,
      metadata: { lifecycleId, workspaceId: input.workspaceId, accountRevoked, reason },
    });
  });
}

interface ValidatedXRefreshResponse {
  accessToken: string;
  refreshToken: string;
  scopes: string[];
  expiresIn?: number;
}

function validateXRefreshResponse(
  raw: unknown,
  allowedScopes: string[],
): ValidatedXRefreshResponse {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new XConnectError("X_REFRESH_FAILED", 502, "X refresh response is invalid");
  }
  const token = raw as Record<string, unknown>;
  if (
    !isValidOAuthBearerToken(token.access_token) ||
    !isValidOAuthOpaqueToken(token.refresh_token)
  ) {
    throw new XConnectError("X_REFRESH_FAILED", 502, "X refresh response is invalid");
  }
  if (
    token.token_type !== undefined &&
    (typeof token.token_type !== "string" || token.token_type.toLowerCase() !== "bearer")
  ) {
    throw new XConnectError("X_REFRESH_FAILED", 502, "X refresh token_type is invalid");
  }
  if (
    token.expires_in !== undefined &&
    (typeof token.expires_in !== "number" ||
      !Number.isSafeInteger(token.expires_in) ||
      token.expires_in <= 0 ||
      token.expires_in > 86_400)
  ) {
    throw new XConnectError("X_REFRESH_FAILED", 502, "X refresh expires_in is invalid");
  }
  const scopes = parseXGrantedScopes(token.scope, allowedScopes, "X_REFRESH_FAILED");
  return {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    scopes,
    expiresIn: token.expires_in as number | undefined,
  };
}

/** Adopt an encrypted single-use X refresh response without another provider call. */
export async function reconcileXRefreshLifecycle(
  input: RefreshInput & { lifecycleId: string; allowedScopes?: string[] },
): Promise<RefreshResult> {
  try {
    return await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
      const [lifecycle] = await tx
        .select()
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.id, input.lifecycleId),
            eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
            eq(providerXCredentialLifecycles.providerAccountId, input.accountId),
          ),
        )
        .limit(1)
        .for("update");
      if (!lifecycle || lifecycle.state !== "credential_staged" || !lifecycle.credentialSecretId) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "no staged X refresh credential",
        );
      }
      const [account] = await tx
        .select()
        .from(providerAccounts)
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.id, input.accountId),
          ),
        )
        .limit(1)
        .for("update");
      assertXRefreshAccount(account, input.workspaceId);
      if (
        account.revision !== lifecycle.expectedAccountRevision ||
        !account.credentialSecretId ||
        account.credentialVersion == null
      ) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "X refresh account revision changed",
        );
      }
      const current = await loadCredential(
        input.vault,
        input.tenantId,
        account.credentialSecretId,
        tx,
      );
      if (current.payload.xUserId !== account.externalRef) {
        throw new XConnectError("X_REFRESH_FAILED", 409, "credential account binding mismatch");
      }
      const [stagedSecret] = (await tx
        .select()
        .from(secrets)
        .where(
          and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, lifecycle.credentialSecretId)),
        )
        .limit(1)) as Secret[];
      if (!stagedSecret) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "staged X refresh credential is missing",
        );
      }
      const staged = JSON.parse(
        input.vault.decryptSecretRow(input.tenantId, stagedSecret),
      ) as XRefreshLifecycleSecret;
      if (staged.schemaVersion !== "steward.provider-x.lifecycle.v1") {
        throw new XConnectError("X_REFRESH_FAILED", 502, "staged X refresh response is invalid");
      }
      const token = validateXRefreshResponse(
        staged.token,
        input.allowedScopes ?? current.payload.scopesGranted,
      );
      const obtainedAt = new Date();
      const expiresAt =
        token.expiresIn === undefined
          ? null
          : new Date(obtainedAt.getTime() + token.expiresIn * 1000);
      const payload: XCredentialPayload = {
        ...current.payload,
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
        scopesGranted: token.scopes,
        obtainedAt: obtainedAt.toISOString(),
        expiresAt: expiresAt?.toISOString() ?? null,
      };
      const meta = await input.vault.rotateSecretWithinTx(
        tx,
        input.tenantId,
        current.secretName,
        JSON.stringify(payload),
      );
      await tx
        .update(secretRoutes)
        .set({ secretId: meta.id })
        .where(
          and(
            eq(secretRoutes.tenantId, input.tenantId),
            eq(secretRoutes.secretId, account.credentialSecretId),
          ),
        );
      const [updated] = await tx
        .update(providerAccounts)
        .set({
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
          status: "active",
          revision: account.revision + 1,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerAccounts.tenantId, input.tenantId),
            eq(providerAccounts.id, account.id),
            eq(providerAccounts.revision, account.revision),
          ),
        )
        .returning({ id: providerAccounts.id });
      if (!updated) {
        throw new XConnectError(
          "X_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "X refresh account changed before adoption",
        );
      }
      await tx
        .update(providerXCredentialLifecycles)
        .set({ state: "adopted", credentialSecretId: null, updatedAt: new Date() })
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, input.tenantId),
            eq(providerXCredentialLifecycles.id, lifecycle.id),
          ),
        );
      await tx
        .delete(secrets)
        .where(
          and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, lifecycle.credentialSecretId)),
        );
      await append({
        tenantId: input.tenantId,
        actorType: input.actorId ? "user" : "system",
        actorId: input.actorId ?? "system",
        action: "provider.x.refresh.completed",
        resourceType: "provider_account",
        resourceId: account.id,
        metadata: {
          lifecycleId: lifecycle.id,
          workspaceId: input.workspaceId,
          credentialVersion: meta.version,
          requestId: input.requestId ?? null,
        },
      });
      return { refreshed: true, credentialVersion: meta.version, expiresAt: payload.expiresAt };
    });
  } catch (error) {
    const adopted = await readAdoptedXRefreshResult(input);
    if (adopted) return adopted;
    await disableXAccountForLifecycle(input, input.lifecycleId, "STAGED_ADOPTION_FAILED");
    throw error;
  }
}

async function readAdoptedXRefreshResult(
  input: RefreshInput & { lifecycleId: string },
): Promise<RefreshResult | null> {
  const db = getDb() as DbExecutor;
  const [lifecycle] = await db
    .select({ state: providerXCredentialLifecycles.state })
    .from(providerXCredentialLifecycles)
    .where(
      and(
        eq(providerXCredentialLifecycles.tenantId, input.tenantId),
        eq(providerXCredentialLifecycles.id, input.lifecycleId),
        eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
        eq(providerXCredentialLifecycles.providerAccountId, input.accountId),
      ),
    )
    .limit(1);
  if (lifecycle?.state !== "adopted") return null;
  const [account] = await db
    .select()
    .from(providerAccounts)
    .where(
      and(
        eq(providerAccounts.tenantId, input.tenantId),
        eq(providerAccounts.workspaceId, input.workspaceId),
        eq(providerAccounts.id, input.accountId),
      ),
    )
    .limit(1);
  if (!account?.credentialSecretId || account.credentialVersion == null) return null;
  const credential = await loadCredential(input.vault, input.tenantId, account.credentialSecretId);
  return {
    refreshed: false,
    credentialVersion: account.credentialVersion,
    expiresAt: credential.expiresAt,
  };
}

export interface XCredentialLifecycleSweepResult {
  processed: number;
  adopted: number;
  revoked: number;
  attention: number;
  remaining: boolean;
}

const X_LIFECYCLE_SWEEP_BATCH_SIZE = 25;
const X_LIFECYCLE_STALE_AFTER_MS = 60_000;
export const X_LIFECYCLE_MAX_REVOCATION_ATTEMPTS = 5;
const X_LIFECYCLE_REVOCATION_BASE_BACKOFF_MS = 60_000;
const X_LIFECYCLE_REVOCATION_MAX_BACKOFF_MS = 15 * 60_000;

function xRevocationBackoffMs(attempts: number): number {
  return Math.min(
    X_LIFECYCLE_REVOCATION_MAX_BACKOFF_MS,
    X_LIFECYCLE_REVOCATION_BASE_BACKOFF_MS * 2 ** Math.max(0, attempts - 1),
  );
}

/** Bounded all-tenant recovery for abandoned X OAuth lifecycle work. */
export async function runXCredentialLifecycleSweep(input: {
  vault: SecretVault;
  config: XConnectConfig;
  limit?: number;
  now?: Date;
}): Promise<XCredentialLifecycleSweepResult> {
  const limit = Math.min(
    X_LIFECYCLE_SWEEP_BATCH_SIZE,
    Math.max(1, Math.floor(input.limit ?? X_LIFECYCLE_SWEEP_BATCH_SIZE)),
  );
  const now = input.now ?? new Date();
  const staleBefore = new Date(now.getTime() - X_LIFECYCLE_STALE_AFTER_MS);
  const rows = await (getDb() as DbExecutor)
    .select()
    .from(providerXCredentialLifecycles)
    .where(
      and(
        sql`(
          (${providerXCredentialLifecycles.state} IN ('inflight', 'credential_staged') AND ${providerXCredentialLifecycles.updatedAt} <= ${staleBefore})
          OR
          (${providerXCredentialLifecycles.state} = 'revocation_pending'
            AND ${providerXCredentialLifecycles.credentialSecretId} IS NOT NULL
            AND ${providerXCredentialLifecycles.nextRetryAt} IS NOT NULL
            AND ${providerXCredentialLifecycles.nextRetryAt} <= ${now})
        )`,
      ),
    )
    .orderBy(asc(providerXCredentialLifecycles.updatedAt))
    .limit(limit);
  const result: XCredentialLifecycleSweepResult = {
    processed: 0,
    adopted: 0,
    revoked: 0,
    attention: 0,
    remaining: false,
  };
  for (const row of rows) {
    result.processed += 1;
    const recoveryInput: RefreshInput & { lifecycleId: string } = {
      tenantId: row.tenantId,
      workspaceId: row.workspaceId,
      accountId: row.providerAccountId ?? "",
      lifecycleId: row.id,
      vault: input.vault,
      config: { clientId: "recovery", clientSecret: "recovery" },
      force: true,
    };
    try {
      if (row.state === "revocation_pending") {
        if (row.attempts >= X_LIFECYCLE_MAX_REVOCATION_ATTEMPTS) {
          await terminalizeExhaustedXRevocation(row, now);
          result.attention += 1;
          continue;
        }
        const revoked = await reconcileStagedXCredentialRevocation({
          tenantId: row.tenantId,
          workspaceId: row.workspaceId,
          accountId: row.providerAccountId,
          lifecycleId: row.id,
          vault: input.vault,
          config: input.config,
          now,
        });
        if (revoked) result.revoked += 1;
        else result.attention += 1;
      } else if (row.kind === "connect_exchange" && row.state === "credential_staged") {
        await reconcileXConnectLifecycle({
          tenantId: row.tenantId,
          workspaceId: row.workspaceId,
          lifecycleId: row.id,
          vault: input.vault,
          config: input.config,
        });
        result.adopted += 1;
      } else if (row.kind === "connect_exchange") {
        await setXConnectLifecycleFailure(row.tenantId, row.id, "CONNECT_OUTCOME_UNKNOWN", false);
        result.attention += 1;
      } else if (row.state === "credential_staged") {
        await reconcileXRefreshLifecycle(recoveryInput);
        result.adopted += 1;
      } else {
        await disableXAccountForLifecycle(recoveryInput, row.id, "REFRESH_OUTCOME_UNKNOWN");
        result.attention += 1;
      }
    } catch {
      // Connect reconciliation deliberately rethrows its adoption error after
      // compensating a stale staged grant. Classify the durable terminal state
      // instead of reporting a successfully revoked grant as unresolved.
      const [reconciled] = await (getDb() as DbExecutor)
        .select({ state: providerXCredentialLifecycles.state })
        .from(providerXCredentialLifecycles)
        .where(
          and(
            eq(providerXCredentialLifecycles.tenantId, row.tenantId),
            eq(providerXCredentialLifecycles.id, row.id),
          ),
        )
        .limit(1);
      if (row.kind === "connect_exchange" && reconciled?.state === "revoked") {
        result.revoked += 1;
      } else {
        result.attention += 1;
      }
    }
  }
  result.remaining = rows.length === limit && result.attention === 0;
  return result;
}

async function terminalizeExhaustedXRevocation(
  row: typeof providerXCredentialLifecycles.$inferSelect,
  now: Date,
): Promise<void> {
  await withTenantAuditedTransaction(row.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({ state: "needs_attention", nextRetryAt: null, updatedAt: now })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, row.tenantId),
          eq(providerXCredentialLifecycles.id, row.id),
          eq(providerXCredentialLifecycles.state, "revocation_pending"),
          eq(providerXCredentialLifecycles.attempts, row.attempts),
          eq(providerXCredentialLifecycles.nextRetryAt, row.nextRetryAt as Date),
          sql`${providerXCredentialLifecycles.attempts} >= ${X_LIFECYCLE_MAX_REVOCATION_ATTEMPTS}`,
        ),
      )
      .returning({ id: providerXCredentialLifecycles.id });
    if (!updated) return;
    await append({
      tenantId: row.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.x.lifecycle.revocation_exhausted",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: row.id,
      metadata: {
        providerAccountId: row.providerAccountId,
        workspaceId: row.workspaceId,
        attempts: row.attempts,
      },
    });
  });
}

export async function reconcileStagedXCredentialRevocation(input: {
  tenantId: string;
  workspaceId: string;
  accountId?: string | null;
  lifecycleId: string;
  vault: SecretVault;
  config: XConnectConfig;
  now?: Date;
}): Promise<boolean> {
  const claimed = await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [lifecycle] = await tx
      .select()
      .from(providerXCredentialLifecycles)
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, input.lifecycleId),
          eq(providerXCredentialLifecycles.workspaceId, input.workspaceId),
          eq(providerXCredentialLifecycles.state, "revocation_pending"),
          sql`${providerXCredentialLifecycles.attempts} < ${X_LIFECYCLE_MAX_REVOCATION_ATTEMPTS}`,
          sql`${providerXCredentialLifecycles.nextRetryAt} IS NOT NULL AND ${providerXCredentialLifecycles.nextRetryAt} <= ${input.now ?? new Date()}`,
          sql`${providerXCredentialLifecycles.credentialSecretId} IS NOT NULL`,
        ),
      )
      .limit(1)
      .for("update");
    if (!lifecycle?.credentialSecretId) return null;
    const claimedAt = input.now ?? new Date();
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({
        attempts: lifecycle.attempts + 1,
        nextRetryAt: new Date(claimedAt.getTime() + X_LIFECYCLE_STALE_AFTER_MS),
        updatedAt: claimedAt,
      })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, lifecycle.id),
          eq(providerXCredentialLifecycles.attempts, lifecycle.attempts),
          eq(providerXCredentialLifecycles.state, "revocation_pending"),
        ),
      )
      .returning({
        credentialSecretId: providerXCredentialLifecycles.credentialSecretId,
        attempts: providerXCredentialLifecycles.attempts,
      });
    if (!updated?.credentialSecretId) return null;
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.x.lifecycle.revocation_claimed",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: lifecycle.id,
      metadata: {
        providerAccountId: input.accountId ?? null,
        workspaceId: input.workspaceId,
        attempts: updated.attempts,
      },
    });
    return {
      credentialSecretId: updated.credentialSecretId,
      claimedAt,
      attempts: updated.attempts,
    };
  });
  if (!claimed) return false;
  await afterXRevocationClaimForTests?.();

  let accessToken: string | null = null;
  let refreshToken: string | null = null;
  try {
    const [secret] = (await (getDb() as DbExecutor)
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, claimed.credentialSecretId)))
      .limit(1)) as Secret[];
    if (!secret) throw new Error("staged secret missing");
    const staged = JSON.parse(
      input.vault.decryptSecretRow(input.tenantId, secret),
    ) as XRefreshLifecycleSecret;
    const token = staged?.token;
    if (!token || typeof token !== "object" || Array.isArray(token)) {
      throw new Error("staged token invalid");
    }
    const raw = token as Record<string, unknown>;
    // Adoption applies the strict token grammar. Revocation instead uses the
    // exact bounded string X returned: a rotated refresh credential that fails
    // Steward's grammar may still be live upstream and must not be discarded.
    accessToken = boundedStagedToken(raw.access_token);
    refreshToken = boundedStagedToken(raw.refresh_token);
    if (!accessToken && !refreshToken) throw new Error("no revocable staged token");
  } catch {
    await finishStagedXCredentialRevocation(
      input,
      claimed,
      false,
      "STAGED_REVOCATION_HANDLE_INVALID",
      true,
    );
    return false;
  }

  let revoked = false;
  try {
    revoked = await revokeUpstreamBestEffort(
      input.config,
      accessToken ?? (refreshToken as string),
      refreshToken,
    );
  } catch {
    revoked = false;
  }
  await finishStagedXCredentialRevocation(
    input,
    claimed,
    revoked,
    revoked ? "STAGED_CREDENTIAL_REVOKED" : "STAGED_REVOCATION_FAILED",
  );
  return revoked;
}

function boundedStagedToken(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_OAUTH_TOKEN_LENGTH
    ? value
    : null;
}

async function finishStagedXCredentialRevocation(
  input: {
    tenantId: string;
    workspaceId: string;
    accountId?: string | null;
    lifecycleId: string;
    now?: Date;
  },
  claimed: { credentialSecretId: string; claimedAt: Date; attempts: number },
  revoked: boolean,
  reason: string,
  terminal = false,
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const exhausted = terminal || claimed.attempts >= X_LIFECYCLE_MAX_REVOCATION_ATTEMPTS;
    const finishedAt = input.now ?? new Date();
    const [updated] = await tx
      .update(providerXCredentialLifecycles)
      .set({
        state: revoked ? "revoked" : exhausted ? "needs_attention" : "revocation_pending",
        credentialSecretId: revoked ? null : claimed.credentialSecretId,
        lastErrorCode: reason,
        nextRetryAt:
          revoked || exhausted
            ? null
            : new Date(finishedAt.getTime() + xRevocationBackoffMs(claimed.attempts)),
        updatedAt: finishedAt,
      })
      .where(
        and(
          eq(providerXCredentialLifecycles.tenantId, input.tenantId),
          eq(providerXCredentialLifecycles.id, input.lifecycleId),
          eq(providerXCredentialLifecycles.state, "revocation_pending"),
          eq(providerXCredentialLifecycles.credentialSecretId, claimed.credentialSecretId),
          eq(providerXCredentialLifecycles.updatedAt, claimed.claimedAt),
        ),
      )
      .returning({ id: providerXCredentialLifecycles.id });
    if (!updated) return;
    if (revoked) {
      await tx
        .delete(secrets)
        .where(
          and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, claimed.credentialSecretId)),
        );
    }
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: revoked
        ? "provider.x.lifecycle.staged_credential_revoked"
        : "provider.x.lifecycle.staged_revocation_failed",
      resourceType: "provider_x_credential_lifecycle",
      resourceId: input.lifecycleId,
      metadata: {
        providerAccountId: input.accountId ?? null,
        workspaceId: input.workspaceId,
        reason,
        attempts: claimed.attempts,
        terminal: !revoked && exhausted,
      },
    });
  });
}

interface LoadedCredential {
  secretName: string;
  payload: XCredentialPayload;
  refreshToken: string | null;
  expiresAt: string | null;
}

async function loadCredential(
  vault: SecretVault,
  tenantId: string,
  secretId: string,
  executor?: DbExecutor,
): Promise<LoadedCredential> {
  const db = (executor ?? getDb()) as DbExecutor;
  const [row] = (await db
    .select()
    .from(secrets)
    .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, secretId)))
    .limit(1)) as Secret[];
  if (!row) throw new XConnectError("X_REFRESH_TOKEN_MISSING", 409, "credential secret missing");
  // Decrypt from the ALREADY-READ row so we do not issue a second getDb() read
  // that would block behind an outer transaction on single-connection PGLite.
  const decrypted = vault.decryptSecretRow(tenantId, row);
  let parsed: unknown;
  try {
    parsed = JSON.parse(decrypted);
  } catch {
    throw new XConnectError("X_REFRESH_FAILED", 409, "credential payload invalid");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new XConnectError("X_REFRESH_FAILED", 409, "credential payload invalid");
  }
  const candidate = parsed as Record<string, unknown>;
  if (
    candidate.schemaVersion !== "steward.provider-x.credential.v1" ||
    !isValidOAuthBearerToken(candidate.accessToken) ||
    !(candidate.refreshToken === null || isValidOAuthOpaqueToken(candidate.refreshToken)) ||
    !Array.isArray(candidate.scopesGranted) ||
    candidate.scopesGranted.length === 0 ||
    candidate.scopesGranted.length > X_DEFAULT_SCOPES.length ||
    candidate.scopesGranted.some(
      (scope) =>
        typeof scope !== "string" || !(X_DEFAULT_SCOPES as readonly string[]).includes(scope),
    ) ||
    new Set(candidate.scopesGranted).size !== candidate.scopesGranted.length ||
    typeof candidate.xUserId !== "string" ||
    !/^\d{1,32}$/.test(candidate.xUserId) ||
    typeof candidate.xUsername !== "string" ||
    (candidate.xUsername !== "" && !/^[A-Za-z0-9_]{1,64}$/.test(candidate.xUsername)) ||
    !isCanonicalIsoTimestamp(candidate.obtainedAt) ||
    !(candidate.expiresAt === null || isCanonicalIsoTimestamp(candidate.expiresAt))
  ) {
    throw new XConnectError("X_REFRESH_FAILED", 409, "credential payload invalid");
  }
  const payload = candidate as unknown as XCredentialPayload;
  return {
    secretName: row.name,
    payload,
    refreshToken: payload.refreshToken,
    expiresAt: payload.expiresAt,
  };
}

function isNearExpiry(expiresAtIso: string | null): boolean {
  if (!expiresAtIso) return true;
  const expiresAt = new Date(expiresAtIso).getTime();
  return Number.isNaN(expiresAt) || expiresAt - Date.now() <= X_REFRESH_SKEW_MS;
}

interface RefreshUpstreamResult {
  revoked: boolean;
  raw: unknown;
}

async function refreshUpstream(
  config: XConnectConfig,
  refreshToken: string,
): Promise<RefreshUpstreamResult> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: config.clientId,
  });
  const res = await forwardImpl({
    url: X_TOKEN_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: basicAuthHeader(config),
    },
    body: body.toString(),
  });
  const parsed = res.json as XTokenResponse | null;
  if (!res.ok) {
    // invalid_grant => the refresh token was revoked or already rotated away.
    if (parsed?.error === "invalid_grant") {
      return { revoked: true, raw: parsed };
    }
    throw new XConnectError("X_REFRESH_FAILED", 502, `X refresh failed (${res.status})`);
  }
  // Successful rotating responses are intentionally returned unparsed. The
  // caller encrypts the exact response before token/scope/time validation so a
  // malformed one-time response can never strand the account on a spent token.
  return { revoked: false, raw: res.json };
}

// ── Disconnect ────────────────────────────────────────────────────────────────
export interface DisconnectInput {
  tenantId: string;
  workspaceId: string;
  accountId: string;
  callerUserId: string;
  vault: SecretVault;
  config: XConnectConfig;
  requestId?: string | null;
}

export interface DisconnectResult {
  providerAccountId: string;
  revoked: boolean;
}

/**
 * Disconnect a connected X account. Local credential authority and an encrypted
 * upstream-revocation handle are committed in one transaction. Provider cleanup
 * then uses the common leased retry path, so a crash cannot restore local access
 * or discard either the stored grant or a separately staged rotated grant.
 */
export async function disconnectXProviderCredential(
  input: DisconnectInput,
): Promise<DisconnectResult> {
  const prepared = await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [account] = await tx
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.id, input.accountId),
        ),
      )
      .limit(1)
      .for("update");
    if (!account) throw new XConnectError("X_ACCOUNT_NOT_FOUND", 404, "provider account not found");
    if (account.adapterKey !== X_ADAPTER_KEY) {
      throw new XConnectError("X_ACCOUNT_NOT_X", 400, "provider account is not an X account");
    }

    const now = new Date();
    const expectedSecretName = xCredentialSecretName(input.workspaceId, account.externalRef);
    // The account pointer is mutable bookkeeping, not proof of credential
    // ownership. Resolve disconnect authority from the deterministic X account
    // lineage so a corrupt pointer can neither sacrifice an unrelated secret
    // nor hide the actual X grant from local revocation.
    const lineageSecrets = (await tx
      .select()
      .from(secrets)
      .where(
        and(
          eq(secrets.tenantId, input.tenantId),
          eq(secrets.name, expectedSecretName),
          sql`${secrets.deletedAt} IS NULL`,
        ),
      )
      .orderBy(desc(secrets.version))
      .for("update")) as Secret[];
    const classifiedLineage = lineageSecrets.map((secret) =>
      classifyXDisconnectLineageSecret(input.vault, input.tenantId, secret, account.externalRef),
    );
    const ambiguousLineage = classifiedLineage.filter((entry) => !entry.owned);
    if (ambiguousLineage.length > 0) {
      throw new XConnectError(
        "X_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "X credential lineage ownership is ambiguous",
      );
    }
    const ownedLineage = classifiedLineage.filter(
      (entry): entry is XOwnedDisconnectLineageSecret => entry.owned,
    );
    const ownedLineageIds = ownedLineage.map((entry) => entry.secret.id);

    if (account.status === "revoked" && !account.credentialSecretId && ownedLineage.length === 0) {
      return { lifecycles: [], allHandlesAvailable: false };
    }

    const pointerIssue = !account.credentialSecretId
      ? "CREDENTIAL_POINTER_MISSING"
      : !ownedLineageIds.includes(account.credentialSecretId)
        ? "CREDENTIAL_POINTER_MISMATCH"
        : null;
    const routesToDisable =
      ownedLineageIds.length > 0
        ? await tx
            .select({ id: secretRoutes.id, authorityRevision: secretRoutes.authorityRevision })
            .from(secretRoutes)
            .where(
              and(
                eq(secretRoutes.tenantId, input.tenantId),
                inArray(secretRoutes.secretId, ownedLineageIds),
                eq(secretRoutes.enabled, true),
              ),
            )
            .for("update")
        : [];

    const lifecycleMaterials =
      ownedLineage.length > 0
        ? ownedLineage
        : [
            {
              secret: null,
              accessToken: null,
              refreshToken: null,
              issue: "CREDENTIAL_LINEAGE_MISSING",
            },
          ];
    const lifecycles: Array<{ lifecycleId: string; retryAt: Date | null }> = [];
    for (const material of lifecycleMaterials) {
      const lifecycleId = randomUUID();
      const hasRevocationHandle = Boolean(material.accessToken || material.refreshToken);
      let lifecycleSecretId: string | null = null;
      if (hasRevocationHandle) {
        const secret = await input.vault.createSecretWithinTx(
          tx,
          input.tenantId,
          `provider-x-lifecycle:${lifecycleId}:disconnect`,
          JSON.stringify({
            schemaVersion: "steward.provider-x.lifecycle.v1",
            token: {
              access_token: material.accessToken ?? undefined,
              refresh_token: material.refreshToken ?? undefined,
            },
          } satisfies XRefreshLifecycleSecret),
          { description: "Encrypted transient X OAuth revocation material" },
        );
        lifecycleSecretId = secret.id;
      }
      await tx.insert(providerXCredentialLifecycles).values({
        id: lifecycleId,
        tenantId: input.tenantId,
        workspaceId: input.workspaceId,
        providerAccountId: account.id,
        kind: "disconnect_revoke",
        state: lifecycleSecretId ? "revocation_pending" : "needs_attention",
        credentialSecretId: lifecycleSecretId,
        expectedAccountRevision: account.revision + 1,
        attempts: 0,
        nextRetryAt: lifecycleSecretId ? now : null,
        lastErrorCode: lifecycleSecretId
          ? "DISCONNECT_REVOCATION_PENDING"
          : "DISCONNECT_REVOCATION_HANDLE_UNAVAILABLE",
        disabledRoutes: routesToDisable,
      });
      await append({
        tenantId: input.tenantId,
        actorType: "user",
        actorId: input.callerUserId,
        action: "provider.x.disconnect.intent_staged",
        resourceType: "provider_x_credential_lifecycle",
        resourceId: lifecycleId,
        metadata: {
          workspaceId: input.workspaceId,
          providerAccountId: account.id,
          revocationHandleAvailable: hasRevocationHandle,
          credentialIssue:
            pointerIssue ??
            material.issue ??
            (ownedLineage.length > 1 ? "CREDENTIAL_LINEAGE_MULTIPLE" : null),
        },
      });
      lifecycles.push({ lifecycleId, retryAt: lifecycleSecretId ? now : null });
    }

    if (ownedLineageIds.length > 0) {
      await tx
        .update(secretRoutes)
        .set({ enabled: false })
        .where(
          and(
            eq(secretRoutes.tenantId, input.tenantId),
            inArray(secretRoutes.secretId, ownedLineageIds),
            eq(secretRoutes.enabled, true),
          ),
        );
    }

    const [degraded] = await tx
      .update(providerAccounts)
      .set({
        status: "revoked",
        credentialSecretId: null,
        credentialVersion: null,
        revision: account.revision + 1,
        updatedAt: now,
      })
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.id, account.id),
          eq(providerAccounts.revision, account.revision),
        ),
      )
      .returning();
    if (!degraded) {
      throw new XConnectError("X_REFRESH_FAILED", 409, "account revision conflict on disconnect");
    }

    if (ownedLineageIds.length > 0) {
      await tx
        .update(secrets)
        .set({ deletedAt: now, updatedAt: now })
        .where(
          and(
            eq(secrets.tenantId, input.tenantId),
            inArray(secrets.id, ownedLineageIds),
            sql`${secrets.deletedAt} IS NULL`,
          ),
        );
    }

    await append({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.callerUserId,
      action: "provider.x.disconnect.completed",
      resourceType: "provider_account",
      resourceId: account.id,
      metadata: {
        workspaceId: input.workspaceId,
        xUserId: account.externalRef,
        revokedAtUpstream: false,
        upstreamRevocationPending: lifecycles.some((entry) => entry.retryAt !== null),
        revocationHandleAvailable:
          ownedLineage.length > 0 &&
          ownedLineage.every((entry) => Boolean(entry.accessToken || entry.refreshToken)),
        credentialLineageCount: ownedLineage.length,
        disabledRouteCount: routesToDisable.length,
        previousRevision: account.revision,
        newRevision: degraded.revision,
        requestId: input.requestId ?? null,
      },
    });

    return {
      lifecycles,
      allHandlesAvailable:
        ownedLineage.length > 0 &&
        ownedLineage.every((entry) => Boolean(entry.accessToken || entry.refreshToken)),
    };
  });

  const pendingLifecycles = prepared.lifecycles.filter(
    (entry): entry is { lifecycleId: string; retryAt: Date } => entry.retryAt !== null,
  );
  if (pendingLifecycles.length === 0) {
    return { providerAccountId: input.accountId, revoked: false };
  }
  await afterXDisconnectJournalForTests?.();
  const revocationResults: boolean[] = [];
  for (const lifecycle of pendingLifecycles) {
    revocationResults.push(
      await reconcileStagedXCredentialRevocation({
        ...input,
        lifecycleId: lifecycle.lifecycleId,
        now: lifecycle.retryAt,
      }),
    );
  }
  return {
    providerAccountId: input.accountId,
    revoked: prepared.allHandlesAvailable && revocationResults.every(Boolean),
  };
}

interface XOwnedDisconnectLineageSecret {
  owned: true;
  secret: Secret;
  accessToken: string | null;
  refreshToken: string | null;
  issue: string | null;
}

interface XAmbiguousDisconnectLineageSecret {
  owned: false;
  secret: Secret;
  issue: "CREDENTIAL_BINDING_MISMATCH" | "CREDENTIAL_PAYLOAD_INVALID" | "CREDENTIAL_DECRYPT_FAILED";
}

function classifyXDisconnectLineageSecret(
  vault: SecretVault,
  tenantId: string,
  secret: Secret,
  expectedXUserId: string,
): XOwnedDisconnectLineageSecret | XAmbiguousDisconnectLineageSecret {
  try {
    const parsed = JSON.parse(vault.decryptSecretRow(tenantId, secret)) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { owned: false, secret, issue: "CREDENTIAL_PAYLOAD_INVALID" };
    }
    const candidate = parsed as Record<string, unknown>;
    if (candidate.schemaVersion !== "steward.provider-x.credential.v1") {
      return { owned: false, secret, issue: "CREDENTIAL_PAYLOAD_INVALID" };
    }
    if (candidate.xUserId !== expectedXUserId) {
      return { owned: false, secret, issue: "CREDENTIAL_BINDING_MISMATCH" };
    }
    const accessToken = boundedStagedToken(candidate.accessToken);
    const refreshToken = boundedStagedToken(candidate.refreshToken);
    return {
      owned: true,
      secret,
      accessToken,
      refreshToken,
      issue: accessToken || refreshToken ? null : "CREDENTIAL_REVOCATION_HANDLE_INVALID",
    };
  } catch {
    return { owned: false, secret, issue: "CREDENTIAL_DECRYPT_FAILED" };
  }
}

async function revokeUpstreamBestEffort(
  config: XConnectConfig,
  accessToken: string,
  refreshToken: string | null,
): Promise<boolean> {
  // Revoke the refresh token when present (invalidates the whole grant); else
  // revoke the access token.
  const token = refreshToken ?? accessToken;
  const tokenTypeHint = refreshToken ? "refresh_token" : "access_token";
  const body = new URLSearchParams({
    token,
    token_type_hint: tokenTypeHint,
    client_id: config.clientId,
  });
  const res = await forwardImpl({
    url: X_REVOKE_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: basicAuthHeader(config),
    },
    body: body.toString(),
  });
  // RFC 7009 specifies HTTP 200 for a processed revocation request, including
  // an already-invalid token. Do not treat an arbitrary 2xx (especially an
  // asynchronous 202) as proof strong enough to destroy our only staged handle.
  return res.status === 200;
}

// re-export sql for callers/tests that need raw predicates
export { sql };
