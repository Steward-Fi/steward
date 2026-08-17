/**
 * Google Workspace provider-account OAuth connect + token lifecycle (#203).
 *
 * This is the PROVIDER-CONNECTION plane (agent execution authority), NOT the
 * user sign-in plane. A user-login OAuth provider authenticates a human; this
 * module connects a Google account a workspace's agents can act as, holding
 * OAuth credentials in the versioned vault so the
 * agent never sees a raw credential.
 *
 * Security posture (mirrors the hardened user-auth OAuth flow):
 *   - PKCE S256, minimal explicit scopes.
 *   - Pending-connect state lives in a short-TTL, single-use store. We persist
 *     ONLY the SHA-256 hash of the state token and the SHA-256 hash of the PKCE
 *     verifier, so a store compromise cannot replay a connect or forge the code
 *     exchange. The raw state travels only in the browser round-trip; the raw
 *     verifier is re-derived from a sealed payload the caller carries back.
 *   - State is consumed exactly once, only after the upstream token exchange and
 *     identity fetch succeed, so a bad provider code cannot burn a live attempt.
 *   - Tokens land as a NEW versioned vault secret; provider_accounts links the
 *     current {credential_secret_id, credential_version}. Reconnect for the same
 *     Google subject updates the version + bumps revision, never duplicates the row.
 *   - Refresh is serialized per account (SELECT ... FOR UPDATE on the account
 *     row inside the tenant-audited transaction), so two concurrent callers
 *     never both spend the same refresh token. On upstream `invalid_grant` the account is revoked
 *     and audited, failing closed.
 *   - Every Google network call goes through an injectable seam (__-prefixed test
 *     setter) so tests never touch the network.
 *
 * All lifecycle events are written on the tenant audit chain via
 * withTenantAuditedTransaction / appendRequiredAudit.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  and,
  eq,
  getDb,
  inArray,
  providerAccounts,
  providerGoogleCredentialLifecycles,
  type Secret,
  secrets,
  sql,
  withTenantAuditedTransaction,
} from "@stwd/db";
import type { SecretVault } from "@stwd/vault";

type DbBase = ReturnType<typeof getDb>;
type DbExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];

// ── Google OAuth 2.0 endpoints ──────────────────────────────────────────
// Provider-connect endpoints. Kept separate from user-auth provider config on
// purpose: this is an agent-execution credential plane.
export const GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_REVOKE_URL = "https://oauth2.googleapis.com/revoke";
export const GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";

export const GOOGLE_ADAPTER_KEY = "google";

/** Minimal default scopes. Google offline consent is required to receive a refresh token. */
export const GOOGLE_DEFAULT_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/calendar.events",
] as const;

/** Refresh a little early to avoid mid-flight expiry. */
export const GOOGLE_REFRESH_SKEW_MS = 5 * 60 * 1000;

/** Pending-connect state TTL — long enough for a human to authorize, short
 *  enough to bound replay exposure. */
export const GOOGLE_CONNECT_STATE_TTL_MS = 10 * 60 * 1000;

export function assertGoogleConnectStoreIsSafe(
  source: "redis" | "postgres" | "memory",
  env: NodeJS.ProcessEnv = process.env,
): void {
  const requiresDurableStore = env.NODE_ENV === "production" || env.STEWARD_RUNTIME === "workers";
  if (
    requiresDurableStore &&
    source === "memory" &&
    env.STEWARD_ALLOW_MEMORY_AUTH_STORES !== "true"
  ) {
    throw new Error("Durable storage is required for Google provider-connect state");
  }
}

// ── Errors ────────────────────────────────────────────────────────────────────
export type GoogleConnectErrorCode =
  | "GOOGLE_CONFIG_MISSING"
  | "GOOGLE_STATE_INVALID"
  | "GOOGLE_STATE_EXPIRED"
  | "GOOGLE_STATE_REUSED"
  | "GOOGLE_PKCE_MISMATCH"
  | "GOOGLE_TOKEN_EXCHANGE_FAILED"
  | "GOOGLE_IDENTITY_FAILED"
  | "GOOGLE_ACCOUNT_NOT_FOUND"
  | "GOOGLE_ACCOUNT_NOT_GOOGLE"
  | "GOOGLE_REFRESH_TOKEN_MISSING"
  | "GOOGLE_REFRESH_REVOKED"
  | "GOOGLE_SCOPE_WIDENED"
  | "GOOGLE_CREDENTIAL_NEEDS_ATTENTION"
  | "GOOGLE_REFRESH_FAILED";

export class GoogleConnectError extends Error {
  constructor(
    readonly code: GoogleConnectErrorCode,
    readonly httpStatus: number,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "GoogleConnectError";
  }
}

// ── Stored token payload (the vault secret value) ─────────────────────────────
export interface GoogleCredentialPayload {
  schemaVersion: "steward.provider-google.credential.v1";
  accessToken: string;
  refreshToken: string | null;
  scopesGranted: string[];
  googleUserId: string;
  googleEmail: string;
  obtainedAt: string; // ISO
  expiresAt: string | null; // ISO
}

// ── Network seam (injectable for tests) ───────────────────────────────────────
export interface GoogleTokenResponse {
  access_token: string;
  refresh_token?: string;
  scope?: string;
  token_type?: string;
  expires_in?: number;
  // Upstream error envelope (non-2xx bodies)
  error?: string;
  error_description?: string;
}

export interface GoogleUserResponse {
  sub?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
}

export interface GoogleForwardRequest {
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
}

export interface GoogleForwardResponse {
  status: number;
  ok: boolean;
  json: unknown;
  text: string;
}

export type GoogleForwardFn = (req: GoogleForwardRequest) => Promise<GoogleForwardResponse>;

const GOOGLE_FORWARD_TIMEOUT_MS = 10_000;
const GOOGLE_FORWARD_MAX_RESPONSE_BYTES = 1024 * 1024;

async function readBoundedGoogleResponse(res: Response): Promise<string> {
  const declaredLength = res.headers.get("content-length");
  if (declaredLength) {
    const length = Number(declaredLength);
    if (!Number.isFinite(length) || length < 0 || length > GOOGLE_FORWARD_MAX_RESPONSE_BYTES) {
      await res.body?.cancel().catch(() => {});
      throw new Error("Google provider response exceeded maximum size");
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
      if (total > GOOGLE_FORWARD_MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("Google provider response exceeded maximum size");
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

async function defaultForward(req: GoogleForwardRequest): Promise<GoogleForwardResponse> {
  const allowed = new Map<string, "GET" | "POST">([
    [GOOGLE_TOKEN_URL, "POST"],
    [GOOGLE_REVOKE_URL, "POST"],
    [GOOGLE_USERINFO_URL, "GET"],
  ]);
  if (allowed.get(req.url) !== req.method) {
    throw new Error("Google provider request endpoint is not allowlisted");
  }
  const res = await fetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
    redirect: "error",
    signal: AbortSignal.timeout(GOOGLE_FORWARD_TIMEOUT_MS),
  });
  const text = await readBoundedGoogleResponse(res);
  let json: unknown = null;
  try {
    json = text.length > 0 ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, ok: res.ok, json, text };
}

/** Test-only access to the real bounded transport (never used by runtime callers). */
export function __runDefaultGoogleForwardForTests(
  req: GoogleForwardRequest,
): Promise<GoogleForwardResponse> {
  return defaultForward(req);
}

let forwardImpl: GoogleForwardFn = defaultForward;

/**
 * Test-only seam setter. Mirrors the repo's `__setForwardProxyRequestForTests`
 * naming convention. Never called from production paths. Returns a restore fn.
 */
export function __setGoogleForwardForTests(fn: GoogleForwardFn | null): () => void {
  const previous = forwardImpl;
  forwardImpl = fn ?? defaultForward;
  return () => {
    forwardImpl = previous;
  };
}

let beforeConnectCommitForTests: (() => void | Promise<void>) | null = null;
let afterGoogleCredentialStageForTests: (() => void | Promise<void>) | null = null;
let afterGoogleRefreshIntentForTests: (() => void | Promise<void>) | null = null;

/** Inject a failure immediately before the connect audit append. Test-only. */
export function __setGoogleConnectCommitHookForTests(
  hook: (() => void | Promise<void>) | null,
): () => void {
  const previous = beforeConnectCommitForTests;
  beforeConnectCommitForTests = hook;
  return () => {
    beforeConnectCommitForTests = previous;
  };
}

/** Inject a crash after a one-time upstream response is durably encrypted. */
export function __setGoogleCredentialStageHookForTests(
  hook: (() => void | Promise<void>) | null,
): () => void {
  const previous = afterGoogleCredentialStageForTests;
  afterGoogleCredentialStageForTests = hook;
  return () => {
    afterGoogleCredentialStageForTests = previous;
  };
}

/** Inject a crash after the refresh intent commits but before provider I/O. */
export function __setGoogleRefreshIntentHookForTests(
  hook: (() => void | Promise<void>) | null,
): () => void {
  const previous = afterGoogleRefreshIntentForTests;
  afterGoogleRefreshIntentForTests = hook;
  return () => {
    afterGoogleRefreshIntentForTests = previous;
  };
}

// ── Config ────────────────────────────────────────────────────────────────────
export interface GoogleConnectConfig {
  clientId: string;
  clientSecret: string;
}

/**
 * Resolve provider-connect Google credentials from env. These are DISTINCT from
 * the user-auth `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (login plane). See
 * .env.example for the separation rationale.
 */
export function resolveGoogleConnectConfig(
  env: NodeJS.ProcessEnv = process.env,
): GoogleConnectConfig {
  const clientId = env.GOOGLE_PROVIDER_CLIENT_ID?.trim();
  const clientSecret = env.GOOGLE_PROVIDER_CLIENT_SECRET?.trim();
  if (!clientId || !clientSecret) {
    throw new GoogleConnectError(
      "GOOGLE_CONFIG_MISSING",
      503,
      "GOOGLE_PROVIDER_CLIENT_ID and GOOGLE_PROVIDER_CLIENT_SECRET are required for provider-account Google connect",
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
  schemaVersion: "steward.provider-google.pending-connect.v1";
  tenantId: string;
  workspaceId: string;
  initiatedByUserId: string;
  verifierHash: string;
  scopes: string[];
  redirectUri: string;
  createdAt: string;
}

// ── Initiate ──────────────────────────────────────────────────────────────────
export interface InitiateConnectInput {
  tenantId: string;
  workspaceId: string;
  initiatedByUserId: string;
  redirectUri: string;
  scopes?: string[];
  config: GoogleConnectConfig;
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
 * Build the Google authorize URL, persist hashed pending-connect state, and return
 * the raw state + a `connectToken` that carries the raw PKCE verifier back to
 * the callback. The connectToken is base64url(JSON{state, verifier}); it is only
 * ever handed to the initiating client and echoed back, mirroring how the user-
 * auth flow keeps the verifier server-adjacent. The STORE only ever holds the
 * hash of both values.
 */
export async function initiateGoogleConnect(
  input: InitiateConnectInput,
): Promise<InitiateConnectResult> {
  const scopes = normalizeScopes(input.scopes);
  const verifier = generateCodeVerifier();
  const challenge = deriveCodeChallenge(verifier);
  const state = generateStateToken();

  const record: PendingConnectRecord = {
    schemaVersion: "steward.provider-google.pending-connect.v1",
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    initiatedByUserId: input.initiatedByUserId,
    verifierHash: sha256Hex(verifier),
    scopes,
    redirectUri: input.redirectUri,
    createdAt: new Date().toISOString(),
  };

  await input.store.set(stateStoreKey(state), JSON.stringify(record), GOOGLE_CONNECT_STATE_TTL_MS);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: input.config.clientId,
    redirect_uri: input.redirectUri,
    scope: scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    access_type: "offline",
    prompt: "consent",
  });

  const connectToken = base64url(Buffer.from(JSON.stringify({ state, verifier }), "utf8"));

  return {
    authorizeUrl: `${GOOGLE_AUTHORIZE_URL}?${params.toString()}`,
    state,
    connectToken,
  };
}

function normalizeScopes(scopes?: string[]): string[] {
  const allowed = new Set<string>(GOOGLE_DEFAULT_SCOPES);
  if (!scopes || scopes.length === 0) return [...GOOGLE_DEFAULT_SCOPES];
  const filtered = scopes.filter((s) => allowed.has(s));
  if (!filtered.includes("openid")) filtered.push("openid");
  if (!filtered.includes("email")) filtered.push("email");
  return [...new Set(filtered)];
}

function boundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function isReasonableEmail(value: string): boolean {
  return value.length <= 512 && !/[\r\n\0]/.test(value) && /^[^@\s]+@[^@\s]+$/.test(value);
}

function parseGrantedScopes(
  scope: unknown,
  fallback: string[],
  code: "GOOGLE_TOKEN_EXCHANGE_FAILED" | "GOOGLE_REFRESH_FAILED",
): string[] {
  if (scope === undefined) return fallback;
  if (typeof scope !== "string" || scope.length > 32_768) {
    throw new GoogleConnectError(code, 502, "Google token scope invalid");
  }
  const scopes = [...new Set(scope.split(/\s+/).filter(Boolean))];
  if (
    scopes.length === 0 ||
    scopes.length > 64 ||
    scopes.some((value) => value.length > 512 || !/^[\x21-\x7e]+$/.test(value))
  ) {
    throw new GoogleConnectError(code, 502, "Google token scope invalid");
  }
  return scopes;
}

function stateStoreKey(state: string): string {
  return `provider-google-connect:${sha256Hex(state)}`;
}

export interface ParsedConnectToken {
  state: string;
  verifier: string;
}

export function parseConnectToken(token: string): ParsedConnectToken | null {
  try {
    if (typeof token !== "string" || token.length < 1 || token.length > 1024) return null;
    const json = base64ToUtf8(token);
    const parsed = JSON.parse(json) as Record<string, unknown>;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      Array.isArray(parsed) ||
      Object.keys(parsed).sort().join(",") !== "state,verifier" ||
      typeof parsed.state !== "string" ||
      !/^[a-f0-9]{64}$/.test(parsed.state) ||
      typeof parsed.verifier !== "string" ||
      !/^[a-f0-9]{96}$/.test(parsed.verifier)
    ) {
      return null;
    }
    return { state: parsed.state, verifier: parsed.verifier };
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
  config: GoogleConnectConfig;
  store: PendingConnectStore;
  vault: SecretVault;
  requestId?: string | null;
}

export interface CompleteConnectResult {
  providerAccountId: string;
  googleUserId: string;
  googleEmail: string;
  scopesGranted: string[];
  credentialVersion: number;
  reconnected: boolean;
}

interface GoogleLifecycleSecret {
  schemaVersion: "steward.provider-google.lifecycle.v1";
  token: GoogleTokenResponse;
}

async function stageGoogleCredentialResponse(input: {
  tenantId: string;
  workspaceId: string;
  vault: SecretVault;
  kind: "connect_exchange" | "refresh_rotation";
  token: GoogleTokenResponse;
  providerAccountId?: string;
  expectedAccountRevision?: number;
}): Promise<string> {
  const lifecycleId = randomUUID();
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const secret = await input.vault.createSecretWithinTx(
      tx,
      input.tenantId,
      `provider-google-lifecycle:${lifecycleId}`,
      JSON.stringify({
        schemaVersion: "steward.provider-google.lifecycle.v1",
        token: input.token,
      } satisfies GoogleLifecycleSecret),
      { description: "Encrypted transient Google OAuth recovery material" },
    );
    await tx.insert(providerGoogleCredentialLifecycles).values({
      id: lifecycleId,
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      providerAccountId: input.providerAccountId ?? null,
      kind: input.kind,
      state: "credential_staged",
      credentialSecretId: secret.id,
      expectedAccountRevision: input.expectedAccountRevision ?? null,
    });
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: `provider.google.${input.kind}.credential_staged`,
      resourceType: "provider_google_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: {
        workspaceId: input.workspaceId,
        providerAccountId: input.providerAccountId ?? null,
      },
    });
  });
  await afterGoogleCredentialStageForTests?.();
  return lifecycleId;
}

function assertScopeSubset(
  granted: string[],
  allowed: readonly string[],
  code: "GOOGLE_TOKEN_EXCHANGE_FAILED" | "GOOGLE_REFRESH_FAILED",
): void {
  const allow = new Set(allowed);
  if (granted.some((scope) => !allow.has(scope))) {
    throw new GoogleConnectError(
      "GOOGLE_SCOPE_WIDENED",
      502,
      `${code}: Google widened OAuth scope`,
    );
  }
}

async function setGoogleLifecycleState(
  tenantId: string,
  lifecycleId: string,
  state: "revocation_pending" | "adopted" | "revoked" | "needs_attention",
  lastErrorCode: string | null = null,
): Promise<void> {
  await withTenantAuditedTransaction(tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const [existing] = await tx
      .select()
      .from(providerGoogleCredentialLifecycles)
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
        ),
      )
      .limit(1)
      .for("update");
    if (!existing) return;
    const [row] = await tx
      .update(providerGoogleCredentialLifecycles)
      .set({
        state,
        lastErrorCode,
        ...(state === "adopted" || state === "revoked" ? { credentialSecretId: null } : {}),
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
        ),
      )
      .returning();
    if (!row) return;
    if ((state === "adopted" || state === "revoked") && existing.credentialSecretId) {
      await tx
        .delete(secrets)
        .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, existing.credentialSecretId)));
    }
    await append({
      tenantId,
      actorType: "system",
      actorId: "system",
      action: `provider.google.lifecycle.${state}`,
      resourceType: "provider_google_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { kind: row.kind, providerAccountId: row.providerAccountId, lastErrorCode },
    });
  });
}

/** Retry a durable revocation handle. Terminal rows are strict single-use. */
export async function reconcileGoogleCredentialRevocation(input: {
  tenantId: string;
  lifecycleId: string;
  vault: SecretVault;
  config: GoogleConnectConfig;
}): Promise<"revoked" | "needs_attention" | "already_terminal"> {
  const db = getDb() as DbExecutor;
  const [row] = await db
    .select()
    .from(providerGoogleCredentialLifecycles)
    .where(
      and(
        eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
        eq(providerGoogleCredentialLifecycles.id, input.lifecycleId),
      ),
    )
    .limit(1);
  if (
    !row ||
    (row.state !== "revocation_pending" &&
      row.state !== "needs_attention" &&
      !(row.kind === "connect_exchange" && row.state === "credential_staged"))
  ) {
    return "already_terminal";
  }
  if (!row.credentialSecretId) {
    await setGoogleLifecycleState(
      input.tenantId,
      input.lifecycleId,
      "needs_attention",
      "MISSING_HANDLE",
    );
    return "needs_attention";
  }
  try {
    const [secret] = (await db
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, row.credentialSecretId)))
      .limit(1)) as Secret[];
    if (!secret) throw new Error("missing encrypted revocation handle");
    const parsed = JSON.parse(
      input.vault.decryptSecretRow(input.tenantId, secret),
    ) as GoogleLifecycleSecret;
    if (parsed.schemaVersion !== "steward.provider-google.lifecycle.v1")
      throw new Error("invalid handle");
    const token = boundedString(parsed.token.refresh_token, 16_384)
      ? parsed.token.refresh_token
      : boundedString(parsed.token.access_token, 16_384)
        ? parsed.token.access_token
        : null;
    if (!token) throw new Error("invalid handle");
    const response = await forwardImpl({
      url: GOOGLE_REVOKE_URL,
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ token, client_id: input.config.clientId }).toString(),
    });
    if (!response.ok) throw new Error("revoker rejected handle");
    await setGoogleLifecycleState(input.tenantId, input.lifecycleId, "revoked");
    return "revoked";
  } catch {
    await setGoogleLifecycleState(
      input.tenantId,
      input.lifecycleId,
      "needs_attention",
      "REVOCATION_FAILED",
    );
    return "needs_attention";
  }
}

export async function completeGoogleConnect(
  input: CompleteConnectInput,
): Promise<CompleteConnectResult> {
  // 1. Load pending state WITHOUT consuming — a bad provider code must not burn
  //    a live attempt's one-time state.
  const key = stateStoreKey(input.state);
  const raw = await input.store.get(key);
  if (!raw)
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 401, "unknown or expired connect state");

  let record: PendingConnectRecord;
  try {
    record = JSON.parse(raw) as PendingConnectRecord;
  } catch {
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 400, "malformed connect state");
  }
  if (
    record.schemaVersion !== "steward.provider-google.pending-connect.v1" ||
    typeof record.tenantId !== "string" ||
    typeof record.workspaceId !== "string" ||
    typeof record.initiatedByUserId !== "string" ||
    typeof record.redirectUri !== "string" ||
    !/^[a-f0-9]{64}$/.test(record.verifierHash) ||
    !Array.isArray(record.scopes) ||
    record.scopes.length > GOOGLE_DEFAULT_SCOPES.length ||
    !record.scopes.every((scope) => (GOOGLE_DEFAULT_SCOPES as readonly string[]).includes(scope))
  ) {
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 400, "malformed connect state");
  }
  const createdAt = Date.parse(record.createdAt);
  if (!Number.isFinite(createdAt) || createdAt > Date.now() + 60_000) {
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 400, "malformed connect state");
  }
  if (Date.now() - createdAt > GOOGLE_CONNECT_STATE_TTL_MS) {
    throw new GoogleConnectError("GOOGLE_STATE_EXPIRED", 401, "connect state expired");
  }

  // Bind the state to THIS tenant/workspace/caller — a state minted for another
  // workspace cannot be replayed here.
  if (
    record.tenantId !== input.tenantId ||
    record.workspaceId !== input.workspaceId ||
    record.initiatedByUserId !== input.callerUserId
  ) {
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 401, "connect state scope mismatch");
  }
  if (record.redirectUri !== input.redirectUri) {
    throw new GoogleConnectError("GOOGLE_STATE_INVALID", 400, "redirect_uri mismatch");
  }

  // 2. Verify the PKCE verifier carried in the connectToken matches the hash we
  //    stored at initiate. Prevents a stolen state (without the verifier) from
  //    completing the exchange.
  const parsedToken = parseConnectToken(input.connectToken);
  if (!parsedToken || parsedToken.state !== input.state) {
    throw new GoogleConnectError("GOOGLE_PKCE_MISMATCH", 400, "connect token mismatch");
  }
  if (sha256Hex(parsedToken.verifier) !== record.verifierHash) {
    throw new GoogleConnectError("GOOGLE_PKCE_MISMATCH", 400, "PKCE verifier mismatch");
  }

  // 3. Exchange the code (PKCE). Failure here does NOT consume the state.
  const tokenRes = await exchangeAuthorizationCode({
    config: input.config,
    code: input.code,
    redirectUri: input.redirectUri,
    verifier: parsedToken.verifier,
  });
  // The code exchange is a one-way boundary. Encrypt its response immediately,
  // before identity lookup or state consumption, so every later failure has a
  // durable revocation handle instead of relying on process-local best effort.
  const lifecycleId = await stageGoogleCredentialResponse({
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    vault: input.vault,
    kind: "connect_exchange",
    token: tokenRes,
  });
  const failIssuedCredential = async (reason: string): Promise<void> => {
    await setGoogleLifecycleState(input.tenantId, lifecycleId, "revocation_pending", reason);
    await reconcileGoogleCredentialRevocation({
      tenantId: input.tenantId,
      lifecycleId,
      vault: input.vault,
      config: input.config,
    });
  };
  if (typeof tokenRes.refresh_token !== "string" || tokenRes.refresh_token.length === 0) {
    await failIssuedCredential("REFRESH_TOKEN_MISSING");
    throw new GoogleConnectError(
      "GOOGLE_REFRESH_TOKEN_MISSING",
      502,
      "Google authorization did not issue offline access; reconnect with consent required",
    );
  }

  let scopesGranted: string[];
  try {
    validateTokenEnvelope(tokenRes, "GOOGLE_TOKEN_EXCHANGE_FAILED");
    scopesGranted = parseGrantedScopes(
      tokenRes.scope,
      record.scopes,
      "GOOGLE_TOKEN_EXCHANGE_FAILED",
    );
    assertScopeSubset(scopesGranted, record.scopes, "GOOGLE_TOKEN_EXCHANGE_FAILED");
  } catch (error) {
    await failIssuedCredential("SCOPE_WIDENED");
    throw error;
  }

  // 4. Identify the connected account.
  let identity: GoogleIdentity;
  try {
    identity = await fetchGoogleIdentity(tokenRes.access_token);
  } catch (error) {
    await failIssuedCredential("IDENTITY_FAILED");
    throw error;
  }

  // 5. Consume the state EXACTLY ONCE, only after upstream success. A concurrent
  //    duplicate callback loses the race and gets GOOGLE_STATE_REUSED.
  const consumed = await input.store.consume(key);
  if (consumed !== raw) {
    // This callback already obtained live credentials before it lost the
    // single-use-state race. Revoke them so a duplicate callback cannot leave
    // an untracked grant at Google.
    await failIssuedCredential("STATE_REUSED");
    throw new GoogleConnectError("GOOGLE_STATE_REUSED", 401, "connect state already used");
  }
  const obtainedAt = new Date();
  const expiresAt =
    typeof tokenRes.expires_in === "number"
      ? new Date(obtainedAt.getTime() + tokenRes.expires_in * 1000)
      : null;

  const payload: GoogleCredentialPayload = {
    schemaVersion: "steward.provider-google.credential.v1",
    accessToken: tokenRes.access_token,
    refreshToken: tokenRes.refresh_token ?? null,
    scopesGranted,
    googleUserId: identity.id,
    googleEmail: identity.email,
    obtainedAt: obtainedAt.toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  };
  // Validate the exact persisted envelope before encrypting it. This applies
  // the same bounds used on every later decrypt/refresh path.
  parseGoogleCredential(JSON.stringify(payload));

  // 6. Persist tokens as a versioned vault secret + create/update the account,
  //    all inside one tenant-audited transaction so the audit event commits with
  //    the state mutation.
  try {
    const result = await persistConnectedAccount({
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      callerUserId: input.callerUserId,
      vault: input.vault,
      identity,
      payload,
      scopesGranted,
      requestId: input.requestId ?? null,
      lifecycleId,
    });
    return result;
  } catch (error) {
    // The authorization code has already been exchanged and the state consumed,
    // so persistence cannot be retried safely. Compensate by revoking the newly
    // issued Google grant. The database transaction below guarantees the old
    // account/credential remains intact on reconnect failure.
    await failIssuedCredential("PERSIST_FAILED");
    throw error;
  }
}

interface GoogleIdentity {
  id: string;
  email: string;
  name: string;
}

async function fetchGoogleIdentity(accessToken: string): Promise<GoogleIdentity> {
  const res = await forwardImpl({
    url: GOOGLE_USERINFO_URL,
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
  });
  if (!res.ok) {
    throw new GoogleConnectError(
      "GOOGLE_IDENTITY_FAILED",
      502,
      `Google identity fetch failed (${res.status})`,
    );
  }
  const data = res.json as GoogleUserResponse | null;
  if (
    !data ||
    data.email_verified !== true ||
    !boundedString(data.sub, 255) ||
    !/^[A-Za-z0-9._~-]+$/.test(data.sub) ||
    !boundedString(data.email, 512) ||
    !isReasonableEmail(data.email) ||
    (data.name !== undefined && (typeof data.name !== "string" || data.name.length > 512))
  ) {
    throw new GoogleConnectError(
      "GOOGLE_IDENTITY_FAILED",
      502,
      "Google identity response missing subject or email",
    );
  }
  return { id: data.sub, email: data.email, name: data.name ?? "" };
}

function validateTokenEnvelope(
  parsed: GoogleTokenResponse,
  code: "GOOGLE_TOKEN_EXCHANGE_FAILED" | "GOOGLE_REFRESH_FAILED",
): void {
  if (
    !boundedString(parsed.access_token, 16_384) ||
    (parsed.refresh_token !== undefined && !boundedString(parsed.refresh_token, 16_384)) ||
    (parsed.token_type !== undefined &&
      (typeof parsed.token_type !== "string" || parsed.token_type.toLowerCase() !== "bearer")) ||
    (parsed.expires_in !== undefined &&
      (!Number.isSafeInteger(parsed.expires_in) ||
        parsed.expires_in < 1 ||
        parsed.expires_in > 31_536_000))
  ) {
    throw new GoogleConnectError(code, 502, "Google token response invalid");
  }
}

interface ExchangeInput {
  config: GoogleConnectConfig;
  code: string;
  redirectUri: string;
  verifier: string;
}

async function exchangeAuthorizationCode(input: ExchangeInput): Promise<GoogleTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.config.clientId,
    client_secret: input.config.clientSecret,
    code_verifier: input.verifier,
  });
  const res = await forwardImpl({
    url: GOOGLE_TOKEN_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });
  const parsed = res.json as GoogleTokenResponse | null;
  if (!res.ok || !parsed || typeof parsed.access_token !== "string") {
    throw new GoogleConnectError(
      "GOOGLE_TOKEN_EXCHANGE_FAILED",
      502,
      `Google token exchange failed (${res.status})`,
    );
  }
  return parsed;
}

// ── Persist / reconnect ───────────────────────────────────────────────────────
interface PersistInput {
  tenantId: string;
  workspaceId: string;
  callerUserId: string;
  vault: SecretVault;
  identity: GoogleIdentity;
  payload: GoogleCredentialPayload;
  scopesGranted: string[];
  requestId: string | null;
  lifecycleId: string;
}

/** Deterministic per-account secret name so reconnect targets the same lineage. */
export function googleCredentialSecretName(workspaceId: string, googleUserId: string): string {
  return `provider-google/${workspaceId}/${googleUserId}`;
}

async function persistConnectedAccount(input: PersistInput): Promise<CompleteConnectResult> {
  // Serialize on the tenant audit lock, then write/rotate the credential,
  // account link, and audit event in ONE transaction. A failed reconnect leaves
  // the old ciphertext active and the account pointing at it; a failed initial
  // connect leaves no orphan secret.
  const secretName = googleCredentialSecretName(input.workspaceId, input.identity.id);
  const serialized = JSON.stringify(input.payload);

  return withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;

    const [account] = await tx
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.workspaceId, input.workspaceId),
          eq(providerAccounts.adapterKey, GOOGLE_ADAPTER_KEY),
          eq(providerAccounts.externalRef, input.identity.id),
        ),
      )
      .limit(1)
      .for("update");

    const [existingSecret] = await tx
      .select({ id: secrets.id })
      .from(secrets)
      .where(
        and(
          eq(secrets.tenantId, input.tenantId),
          eq(secrets.name, secretName),
          sql`${secrets.deletedAt} IS NULL`,
        ),
      )
      .limit(1)
      .for("update");
    const meta = existingSecret
      ? await input.vault.rotateSecretWithinTx(tx, input.tenantId, secretName, serialized)
      : await input.vault.createSecretWithinTx(tx, input.tenantId, secretName, serialized, {
          description: "Google Workspace provider-account OAuth credential",
        });

    const displayName = input.identity.email || input.identity.id;

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
        throw new GoogleConnectError(
          "GOOGLE_REFRESH_FAILED",
          409,
          "account revision conflict on reconnect",
        );
      }
    } else {
      reconnected = false;
      const [created] = await tx
        .insert(providerAccounts)
        .values({
          tenantId: input.tenantId,
          workspaceId: input.workspaceId,
          adapterKey: GOOGLE_ADAPTER_KEY,
          externalRef: input.identity.id,
          displayName,
          status: "active",
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
        })
        .returning();
      providerAccountId = created.id;
    }

    await beforeConnectCommitForTests?.();
    await append({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.callerUserId,
      action: reconnected
        ? "provider.google.connect.reconnected"
        : "provider.google.connect.completed",
      resourceType: "provider_account",
      resourceId: providerAccountId,
      metadata: {
        workspaceId: input.workspaceId,
        adapterKey: GOOGLE_ADAPTER_KEY,
        googleUserId: input.identity.id,
        googleEmail: input.identity.email,
        scopesGranted: input.scopesGranted,
        credentialSecretId: meta.id,
        credentialVersion: meta.version,
        requestId: input.requestId,
      },
    });

    const [lifecycleBeforeAdoption] = await tx
      .select({ credentialSecretId: providerGoogleCredentialLifecycles.credentialSecretId })
      .from(providerGoogleCredentialLifecycles)
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, input.lifecycleId),
          eq(providerGoogleCredentialLifecycles.state, "credential_staged"),
        ),
      )
      .limit(1)
      .for("update");
    const [lifecycle] = await tx
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "adopted", credentialSecretId: null, updatedAt: new Date() })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, input.lifecycleId),
          eq(providerGoogleCredentialLifecycles.state, "credential_staged"),
        ),
      )
      .returning();
    if (!lifecycle) {
      throw new GoogleConnectError(
        "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "connect lifecycle changed before adoption",
      );
    }
    if (lifecycleBeforeAdoption?.credentialSecretId) {
      await tx
        .delete(secrets)
        .where(
          and(
            eq(secrets.tenantId, input.tenantId),
            eq(secrets.id, lifecycleBeforeAdoption.credentialSecretId),
          ),
        );
    }

    return {
      providerAccountId,
      googleUserId: input.identity.id,
      googleEmail: input.identity.email,
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
   * or refresh fails closed with GOOGLE_ACCOUNT_NOT_FOUND. Prevents a cross-workspace
   * IDOR where a user authorized for workspace A passes an account id from
   * workspace B.
   */
  workspaceId: string;
  accountId: string;
  vault: SecretVault;
  config: GoogleConnectConfig;
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
 * Refresh a connected Google account's access token. SINGLE-FLIGHT per account: the
 * SELECT ... FOR UPDATE on the provider_accounts row inside the tenant-audited
 * transaction serializes concurrent callers, so the rotating refresh token is
 * spent exactly once. A loser blocks until the winner commits, then observes the
 * already-rotated credential version and returns without a second token call.
 *
 * On upstream `invalid_grant` (revoked) the account is degraded + audited and we
 * throw GOOGLE_REFRESH_REVOKED (fail closed). The vault write happens INSIDE the
 * critical section so a crash after the network call cannot leave the DB
 * pointing at a superseded (already-rotated-away) refresh token.
 */
export async function refreshGoogleProviderCredential(input: RefreshInput): Promise<RefreshResult> {
  type Prepared =
    | { kind: "fresh"; result: RefreshResult }
    | { kind: "wait"; lifecycleId: string }
    | { kind: "call"; lifecycleId: string; refreshToken: string; allowedScopes: string[] };
  const prepared = await withTenantAuditedTransaction<Prepared>(
    input.tenantId,
    async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
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
      assertRefreshAccount(account, input.workspaceId);
      if (!account.credentialSecretId || account.credentialVersion == null) {
        throw new GoogleConnectError(
          "GOOGLE_REFRESH_TOKEN_MISSING",
          409,
          "account has no credential",
        );
      }
      const current = await loadCredential(
        input.vault,
        input.tenantId,
        account.credentialSecretId,
        tx,
      );
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
      if (!current.refreshToken)
        throw new GoogleConnectError(
          "GOOGLE_REFRESH_TOKEN_MISSING",
          409,
          "no refresh token on record",
        );
      const [activeLifecycle] = await tx
        .select({ id: providerGoogleCredentialLifecycles.id })
        .from(providerGoogleCredentialLifecycles)
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.providerAccountId, account.id),
            eq(providerGoogleCredentialLifecycles.kind, "refresh_rotation"),
            inArray(providerGoogleCredentialLifecycles.state, ["inflight", "credential_staged"]),
          ),
        )
        .limit(1);
      if (activeLifecycle) return { kind: "wait", lifecycleId: activeLifecycle.id };
      const lifecycleId = randomUUID();
      await tx.insert(providerGoogleCredentialLifecycles).values({
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
        action: "provider.google.refresh.intent_staged",
        resourceType: "provider_google_credential_lifecycle",
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
        .select({ state: providerGoogleCredentialLifecycles.state })
        .from(providerGoogleCredentialLifecycles)
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.id, prepared.lifecycleId),
          ),
        )
        .limit(1);
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
        if (account?.credentialVersion != null) {
          const credential = account.credentialSecretId
            ? await loadCredential(input.vault, input.tenantId, account.credentialSecretId)
            : null;
          return {
            refreshed: false,
            credentialVersion: account.credentialVersion,
            expiresAt: credential?.expiresAt ?? null,
          };
        }
      }
      if (row?.state === "needs_attention" || row?.state === "revoked") {
        throw new GoogleConnectError(
          "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "concurrent refresh did not complete",
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new GoogleConnectError(
      "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
      409,
      "concurrent refresh is still in progress",
    );
  }

  await afterGoogleRefreshIntentForTests?.();

  let tokenRes: RefreshUpstreamResult;
  try {
    tokenRes = await refreshGoogleUpstream(input.config, prepared.refreshToken);
  } catch (error) {
    await disableGoogleAccountForLifecycle(input, prepared.lifecycleId, "REFRESH_OUTCOME_UNKNOWN");
    throw error;
  }
  if (tokenRes.revoked) {
    await revokeGoogleAccountForLifecycle(input, prepared.lifecycleId);
    throw new GoogleConnectError("GOOGLE_REFRESH_REVOKED", 409, "Google refresh token revoked");
  }
  // Encrypt the provider response before any semantic parsing that can fail.
  // A malformed/widened scope must still leave a revocable, single-use handle.
  const staged = await stageRefreshResponse(input, prepared.lifecycleId, tokenRes);
  try {
    validateTokenEnvelope(tokenRes.raw, "GOOGLE_REFRESH_FAILED");
    const returnedScopes = parseGrantedScopes(
      tokenRes.scope,
      prepared.allowedScopes,
      "GOOGLE_REFRESH_FAILED",
    );
    assertScopeSubset(returnedScopes, prepared.allowedScopes, "GOOGLE_REFRESH_FAILED");
  } catch (error) {
    await disableGoogleAccountForLifecycle(input, prepared.lifecycleId, "SCOPE_WIDENED");
    await setGoogleLifecycleState(
      input.tenantId,
      prepared.lifecycleId,
      "revocation_pending",
      "SCOPE_WIDENED",
    );
    await reconcileGoogleCredentialRevocation({
      tenantId: input.tenantId,
      lifecycleId: staged,
      vault: input.vault,
      config: input.config,
    });
    throw error;
  }
  return reconcileGoogleRefreshLifecycle({ ...input, lifecycleId: prepared.lifecycleId });
}

function assertRefreshAccount(
  account: typeof providerAccounts.$inferSelect | undefined,
  workspaceId: string,
): asserts account is typeof providerAccounts.$inferSelect {
  if (!account || account.workspaceId !== workspaceId)
    throw new GoogleConnectError("GOOGLE_ACCOUNT_NOT_FOUND", 404, "provider account not found");
  if (account.adapterKey !== GOOGLE_ADAPTER_KEY)
    throw new GoogleConnectError(
      "GOOGLE_ACCOUNT_NOT_GOOGLE",
      400,
      "provider account is not a Google account",
    );
  if (account.status !== "active")
    throw new GoogleConnectError(
      "GOOGLE_REFRESH_REVOKED",
      409,
      "provider account is not active; reconnect required",
    );
}

async function stageRefreshResponse(
  input: RefreshInput,
  lifecycleId: string,
  token: RefreshUpstreamResult,
): Promise<string> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    const secret = await input.vault.createSecretWithinTx(
      tx,
      input.tenantId,
      `provider-google-lifecycle:${lifecycleId}`,
      JSON.stringify({
        schemaVersion: "steward.provider-google.lifecycle.v1",
        token: token.raw,
      } satisfies GoogleLifecycleSecret),
      { description: "Encrypted transient Google OAuth recovery material" },
    );
    const [updated] = await tx
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "credential_staged", credentialSecretId: secret.id, updatedAt: new Date() })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
          eq(providerGoogleCredentialLifecycles.state, "inflight"),
        ),
      )
      .returning();
    if (!updated)
      throw new GoogleConnectError(
        "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
        409,
        "refresh lifecycle changed",
      );
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.google.refresh.credential_staged",
      resourceType: "provider_google_credential_lifecycle",
      resourceId: lifecycleId,
      metadata: { providerAccountId: input.accountId },
    });
  });
  await afterGoogleCredentialStageForTests?.();
  return lifecycleId;
}

async function disableGoogleAccountForLifecycle(
  input: RefreshInput,
  lifecycleId: string,
  reason: string,
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    await tx
      .update(providerAccounts)
      .set({
        status: "disabled",
        revision: sql`${providerAccounts.revision} + 1`,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.id, input.accountId),
        ),
      );
    await tx
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "needs_attention", lastErrorCode: reason, updatedAt: new Date() })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
        ),
      );
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.google.refresh.needs_attention",
      resourceType: "provider_account",
      resourceId: input.accountId,
      metadata: { lifecycleId, reason, workspaceId: input.workspaceId },
    });
  });
}

async function revokeGoogleAccountForLifecycle(
  input: RefreshInput,
  lifecycleId: string,
): Promise<void> {
  await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;
    await tx
      .update(providerAccounts)
      .set({
        status: "revoked",
        revision: sql`${providerAccounts.revision} + 1`,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.id, input.accountId),
        ),
      );
    await tx
      .update(providerGoogleCredentialLifecycles)
      .set({ state: "revoked", updatedAt: new Date() })
      .where(
        and(
          eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
          eq(providerGoogleCredentialLifecycles.id, lifecycleId),
        ),
      );
    await append({
      tenantId: input.tenantId,
      actorType: "system",
      actorId: "system",
      action: "provider.google.refresh.revoked",
      resourceType: "provider_account",
      resourceId: input.accountId,
      metadata: { lifecycleId, workspaceId: input.workspaceId },
    });
  });
}

/** Adopt a staged rotating response without making another provider call. */
export async function reconcileGoogleRefreshLifecycle(
  input: RefreshInput & { lifecycleId: string },
): Promise<RefreshResult> {
  const [snapshot] = await (getDb() as DbExecutor)
    .select({ state: providerGoogleCredentialLifecycles.state })
    .from(providerGoogleCredentialLifecycles)
    .where(
      and(
        eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
        eq(providerGoogleCredentialLifecycles.id, input.lifecycleId),
      ),
    )
    .limit(1);
  if (snapshot?.state === "inflight") {
    // An intent without a staged response may have crossed the provider
    // boundary before the process died. Never spend its refresh token again.
    await disableGoogleAccountForLifecycle(input, input.lifecycleId, "REFRESH_OUTCOME_UNKNOWN");
    throw new GoogleConnectError(
      "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
      409,
      "refresh outcome is unknown; reconnect required",
    );
  }
  try {
    return await withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
      const tx = txRaw as DbExecutor;
      const [lifecycle] = await tx
        .select()
        .from(providerGoogleCredentialLifecycles)
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.id, input.lifecycleId),
          ),
        )
        .limit(1)
        .for("update");
      if (!lifecycle || lifecycle.state !== "credential_staged" || !lifecycle.credentialSecretId)
        throw new GoogleConnectError(
          "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "no staged refresh credential",
        );
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
      assertRefreshAccount(account, input.workspaceId);
      if (account.revision !== lifecycle.expectedAccountRevision || !account.credentialSecretId)
        throw new GoogleConnectError(
          "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "refresh account revision changed",
        );
      const current = await loadCredential(
        input.vault,
        input.tenantId,
        account.credentialSecretId,
        tx,
      );
      const [secret] = (await tx
        .select()
        .from(secrets)
        .where(
          and(eq(secrets.tenantId, input.tenantId), eq(secrets.id, lifecycle.credentialSecretId)),
        )
        .limit(1)) as Secret[];
      if (!secret)
        throw new GoogleConnectError(
          "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "staged refresh credential missing",
        );
      const staged = JSON.parse(
        input.vault.decryptSecretRow(input.tenantId, secret),
      ) as GoogleLifecycleSecret;
      validateTokenEnvelope(staged.token, "GOOGLE_REFRESH_FAILED");
      const scopes = parseGrantedScopes(
        staged.token.scope,
        current.payload.scopesGranted,
        "GOOGLE_REFRESH_FAILED",
      );
      assertScopeSubset(scopes, current.payload.scopesGranted, "GOOGLE_REFRESH_FAILED");
      const obtainedAt = new Date();
      const expiresAt =
        typeof staged.token.expires_in === "number"
          ? new Date(obtainedAt.getTime() + staged.token.expires_in * 1000)
          : null;
      const payload: GoogleCredentialPayload = {
        ...current.payload,
        accessToken: staged.token.access_token,
        refreshToken: staged.token.refresh_token ?? current.refreshToken,
        scopesGranted: scopes,
        obtainedAt: obtainedAt.toISOString(),
        expiresAt: expiresAt?.toISOString() ?? null,
      };
      const meta = await input.vault.rotateSecretWithinTx(
        tx,
        input.tenantId,
        current.secretName,
        JSON.stringify(payload),
      );
      const [updated] = await tx
        .update(providerAccounts)
        .set({
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
          revision: account.revision + 1,
          status: "active",
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
        throw new GoogleConnectError(
          "GOOGLE_CREDENTIAL_NEEDS_ATTENTION",
          409,
          "refresh account changed before adoption",
        );
      }
      await tx
        .update(providerGoogleCredentialLifecycles)
        .set({ state: "adopted", credentialSecretId: null, updatedAt: new Date() })
        .where(
          and(
            eq(providerGoogleCredentialLifecycles.tenantId, input.tenantId),
            eq(providerGoogleCredentialLifecycles.id, lifecycle.id),
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
        action: "provider.google.refresh.completed",
        resourceType: "provider_account",
        resourceId: account.id,
        metadata: {
          lifecycleId: lifecycle.id,
          credentialVersion: meta.version,
          workspaceId: input.workspaceId,
          requestId: input.requestId ?? null,
        },
      });
      return { refreshed: true, credentialVersion: meta.version, expiresAt: payload.expiresAt };
    });
  } catch (error) {
    if (snapshot?.state === "credential_staged") {
      // The one-time response exists but could not be adopted (scope mismatch,
      // revision race, corrupt payload, or DB failure after staging). Freeze the
      // local authority and compensate from the encrypted handle; never retry
      // the old rotating refresh token.
      await disableGoogleAccountForLifecycle(input, input.lifecycleId, "STAGED_ADOPTION_FAILED");
      await setGoogleLifecycleState(
        input.tenantId,
        input.lifecycleId,
        "revocation_pending",
        "STAGED_ADOPTION_FAILED",
      );
      await reconcileGoogleCredentialRevocation({
        tenantId: input.tenantId,
        lifecycleId: input.lifecycleId,
        vault: input.vault,
        config: input.config,
      });
    }
    throw error;
  }
}

interface LoadedCredential {
  secretName: string;
  payload: GoogleCredentialPayload;
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
  if (!row)
    throw new GoogleConnectError("GOOGLE_REFRESH_TOKEN_MISSING", 409, "credential secret missing");
  // Decrypt from the ALREADY-READ row so we do not issue a second getDb() read
  // that would block behind an outer transaction on single-connection PGLite.
  const decrypted = vault.decryptSecretRow(tenantId, row);
  const payload = parseGoogleCredential(decrypted);
  return {
    secretName: row.name,
    payload,
    refreshToken: payload.refreshToken,
    expiresAt: payload.expiresAt,
  };
}

function parseGoogleCredential(value: string): GoogleCredentialPayload {
  let raw: unknown;
  try {
    raw = JSON.parse(value);
  } catch {
    throw new GoogleConnectError("GOOGLE_REFRESH_TOKEN_MISSING", 409, "credential payload invalid");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new GoogleConnectError("GOOGLE_REFRESH_TOKEN_MISSING", 409, "credential payload invalid");
  }
  const p = raw as Record<string, unknown>;
  const bounded = (v: unknown, max: number): v is string =>
    typeof v === "string" && v.length > 0 && v.length <= max;
  const validIso = (v: unknown): v is string => {
    if (!bounded(v, 64)) return false;
    // RFC 3339 date-time with a mandatory zone. Date.parse alone accepts local
    // timestamps and normalizes impossible calendar dates, neither of which is
    // valid for a persisted security credential.
    const match =
      /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(
        v,
      );
    if (!match) return false;
    const instant = Date.parse(v);
    if (!Number.isFinite(instant)) return false;
    const [, year, month, day, hour, minute, second, , zone] = match;
    if (Number(month) < 1 || Number(month) > 12 || Number(day) < 1 || Number(day) > 31)
      return false;
    if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return false;
    // Validate calendar normalization in the value's own offset.
    const offsetMinutes =
      zone === "Z"
        ? 0
        : (zone.startsWith("-") ? -1 : 1) *
          (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
    if (Math.abs(offsetMinutes) > 14 * 60) return false;
    const local = new Date(instant + offsetMinutes * 60_000);
    return (
      local.getUTCFullYear() === Number(year) &&
      local.getUTCMonth() + 1 === Number(month) &&
      local.getUTCDate() === Number(day) &&
      local.getUTCHours() === Number(hour) &&
      local.getUTCMinutes() === Number(minute) &&
      local.getUTCSeconds() === Number(second)
    );
  };
  if (
    p.schemaVersion !== "steward.provider-google.credential.v1" ||
    !bounded(p.accessToken, 16_384) ||
    !(p.refreshToken === null || bounded(p.refreshToken, 16_384)) ||
    !Array.isArray(p.scopesGranted) ||
    p.scopesGranted.length === 0 ||
    p.scopesGranted.length > GOOGLE_DEFAULT_SCOPES.length ||
    !p.scopesGranted.every(
      (s) => bounded(s, 512) && (GOOGLE_DEFAULT_SCOPES as readonly string[]).includes(s),
    ) ||
    new Set(p.scopesGranted).size !== p.scopesGranted.length ||
    !bounded(p.googleUserId, 512) ||
    !bounded(p.googleEmail, 512) ||
    !validIso(p.obtainedAt) ||
    !(p.expiresAt === null || validIso(p.expiresAt))
  ) {
    throw new GoogleConnectError("GOOGLE_REFRESH_TOKEN_MISSING", 409, "credential payload invalid");
  }
  return p as unknown as GoogleCredentialPayload;
}

function isNearExpiry(expiresAtIso: string | null): boolean {
  if (!expiresAtIso) return true;
  const expiresAt = new Date(expiresAtIso).getTime();
  return Number.isNaN(expiresAt) || expiresAt - Date.now() <= GOOGLE_REFRESH_SKEW_MS;
}

interface RefreshUpstreamResult {
  revoked: boolean;
  accessToken: string;
  refreshToken?: string;
  scope?: string;
  expiresIn?: number;
  raw: GoogleTokenResponse;
}

async function refreshGoogleUpstream(
  config: GoogleConnectConfig,
  refreshToken: string,
): Promise<RefreshUpstreamResult> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: config.clientId,
    client_secret: config.clientSecret,
  });
  const res = await forwardImpl({
    url: GOOGLE_TOKEN_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });
  const parsed = res.json as GoogleTokenResponse | null;
  if (!res.ok) {
    // invalid_grant => the refresh token was revoked or already rotated away.
    if (parsed?.error === "invalid_grant") {
      return { revoked: true, accessToken: "", raw: parsed };
    }
    throw new GoogleConnectError(
      "GOOGLE_REFRESH_FAILED",
      502,
      `Google refresh failed (${res.status})`,
    );
  }
  if (!parsed || typeof parsed !== "object") {
    throw new GoogleConnectError(
      "GOOGLE_REFRESH_FAILED",
      502,
      "Google refresh response was not an object",
    );
  }
  return {
    revoked: false,
    accessToken: typeof parsed.access_token === "string" ? parsed.access_token : "",
    refreshToken: parsed.refresh_token,
    scope: parsed.scope,
    expiresIn: parsed.expires_in,
    raw: parsed,
  };
}

// ── Disconnect ────────────────────────────────────────────────────────────────
export interface DisconnectInput {
  tenantId: string;
  workspaceId: string;
  accountId: string;
  callerUserId: string;
  vault: SecretVault;
  config: GoogleConnectConfig;
  requestId?: string | null;
}

export interface DisconnectResult {
  providerAccountId: string;
  revoked: boolean;
}

/**
 * Disconnect a connected Google account: best-effort revoke at Google, degrade the account
 * (status revoked), bump revision, audit. Revocation failure at Google does NOT block
 * the local degrade — we fail CLOSED locally regardless.
 */
export async function disconnectGoogleProviderCredential(
  input: DisconnectInput,
): Promise<DisconnectResult> {
  return withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
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
    if (!account)
      throw new GoogleConnectError("GOOGLE_ACCOUNT_NOT_FOUND", 404, "provider account not found");
    if (account.adapterKey !== GOOGLE_ADAPTER_KEY) {
      throw new GoogleConnectError(
        "GOOGLE_ACCOUNT_NOT_GOOGLE",
        400,
        "provider account is not a Google account",
      );
    }

    let revokedAtUpstream = false;
    if (account.credentialSecretId) {
      try {
        const cred = await loadCredential(
          input.vault,
          input.tenantId,
          account.credentialSecretId,
          tx,
        );
        revokedAtUpstream = await revokeUpstreamBestEffort(
          cred.payload.accessToken,
          cred.refreshToken,
        );
      } catch {
        // Best-effort only. Local degrade proceeds regardless.
        revokedAtUpstream = false;
      }
    }

    const [degraded] = await tx
      .update(providerAccounts)
      .set({ status: "revoked", revision: account.revision + 1, updatedAt: new Date() })
      .where(
        and(
          eq(providerAccounts.tenantId, input.tenantId),
          eq(providerAccounts.id, account.id),
          eq(providerAccounts.revision, account.revision),
        ),
      )
      .returning();
    if (!degraded) {
      throw new GoogleConnectError(
        "GOOGLE_REFRESH_FAILED",
        409,
        "account revision conflict on disconnect",
      );
    }

    await append({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.callerUserId,
      action: "provider.google.disconnect.completed",
      resourceType: "provider_account",
      resourceId: account.id,
      metadata: {
        workspaceId: input.workspaceId,
        googleUserId: account.externalRef,
        revokedAtUpstream,
        previousRevision: account.revision,
        newRevision: degraded.revision,
        requestId: input.requestId ?? null,
      },
    });

    return { providerAccountId: account.id, revoked: revokedAtUpstream };
  });
}

async function revokeUpstreamBestEffort(
  accessToken: string,
  refreshToken: string | null,
): Promise<boolean> {
  // Revoke the refresh token when present (invalidates the whole grant); else
  // revoke the access token.
  const token = refreshToken ?? accessToken;
  const body = new URLSearchParams({ token });
  const res = await forwardImpl({
    url: GOOGLE_REVOKE_URL,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: body.toString(),
  });
  return res.ok;
}

// re-export sql for callers/tests that need raw predicates
export { sql };
