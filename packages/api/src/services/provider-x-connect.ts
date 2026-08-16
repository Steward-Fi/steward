/**
 * Provider-account X (Twitter) OAuth connect + token lifecycle (issue #195
 * workstream A).
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
 *   - State is consumed exactly once, only after the upstream token exchange and
 *     identity fetch succeed, so a bad provider code cannot burn a live attempt.
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

import { createHash, randomBytes } from "node:crypto";
import {
  and,
  eq,
  getDb,
  providerAccounts,
  type Secret,
  secrets,
  sql,
  withTenantAuditedTransaction,
} from "@stwd/db";
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
    const json = base64ToUtf8(token);
    const parsed = JSON.parse(json) as ParsedConnectToken;
    if (typeof parsed.state !== "string" || typeof parsed.verifier !== "string") {
      return null;
    }
    return parsed;
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

export async function completeXConnect(
  input: CompleteConnectInput,
): Promise<CompleteConnectResult> {
  // 1. Load pending state WITHOUT consuming — a bad provider code must not burn
  //    a live attempt's one-time state.
  const key = stateStoreKey(input.state);
  const raw = await input.store.get(key);
  if (!raw) throw new XConnectError("X_STATE_INVALID", 401, "unknown or expired connect state");

  let record: PendingConnectRecord;
  try {
    record = JSON.parse(raw) as PendingConnectRecord;
  } catch {
    throw new XConnectError("X_STATE_INVALID", 400, "malformed connect state");
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

  // 3. Exchange the code (PKCE). Failure here does NOT consume the state.
  const tokenRes = await exchangeAuthorizationCode({
    config: input.config,
    code: input.code,
    redirectUri: input.redirectUri,
    verifier: parsedToken.verifier,
  });

  // 4. Identify the connected account.
  const identity = await fetchXIdentity(tokenRes.access_token);

  // 5. Consume the state EXACTLY ONCE, only after upstream success. A concurrent
  //    duplicate callback loses the race and gets X_STATE_REUSED.
  const consumed = await input.store.consume(key);
  if (consumed !== raw) {
    throw new XConnectError("X_STATE_REUSED", 401, "connect state already used");
  }

  const scopesGranted = tokenRes.scope
    ? tokenRes.scope.split(/\s+/).filter(Boolean)
    : record.scopes;
  const obtainedAt = new Date();
  const expiresAt =
    typeof tokenRes.expires_in === "number"
      ? new Date(obtainedAt.getTime() + tokenRes.expires_in * 1000)
      : null;

  const payload: XCredentialPayload = {
    schemaVersion: "steward.provider-x.credential.v1",
    accessToken: tokenRes.access_token,
    refreshToken: tokenRes.refresh_token ?? null,
    scopesGranted,
    xUserId: identity.id,
    xUsername: identity.username,
    obtainedAt: obtainedAt.toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null,
  };

  // 6. Persist tokens as a versioned vault secret + create/update the account,
  //    all inside one tenant-audited transaction so the audit event commits with
  //    the state mutation.
  return persistConnectedAccount({
    tenantId: input.tenantId,
    workspaceId: input.workspaceId,
    callerUserId: input.callerUserId,
    vault: input.vault,
    identity,
    payload,
    scopesGranted,
    requestId: input.requestId ?? null,
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
  if (!data || !data.id) {
    throw new XConnectError("X_IDENTITY_FAILED", 502, "X identity response missing user id");
  }
  return { id: data.id, username: data.username ?? "", name: data.name ?? "" };
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
  const parsed = res.json as XTokenResponse | null;
  if (!res.ok || !parsed || typeof parsed.access_token !== "string") {
    throw new XConnectError(
      "X_TOKEN_EXCHANGE_FAILED",
      502,
      `X token exchange failed (${res.status})`,
    );
  }
  return parsed;
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
}

/** Deterministic per-account secret name so reconnect targets the same lineage. */
export function xCredentialSecretName(workspaceId: string, xUserId: string): string {
  return `provider-x/${workspaceId}/${xUserId}`;
}

async function persistConnectedAccount(input: PersistInput): Promise<CompleteConnectResult> {
  // Write the credential secret OUTSIDE the audited tx (the vault owns its own
  // encryption + version row); then link + audit atomically. createSecret always
  // writes version 1; a reconnect uses rotateSecret to bump the version so the
  // lineage (secret name) is stable and the OLD ciphertext is soft-deleted.
  const secretName = xCredentialSecretName(input.workspaceId, input.identity.id);
  const serialized = JSON.stringify(input.payload);

  const existing = await input.vault.getSecret(input.tenantId, secretName);
  const meta = existing
    ? await input.vault.rotateSecret(input.tenantId, secretName, serialized)
    : await input.vault.createSecret(input.tenantId, secretName, serialized, {
        description: "X (Twitter) provider-account OAuth credential",
      });

  return withTenantAuditedTransaction(input.tenantId, async (txRaw, append) => {
    const tx = txRaw as DbExecutor;

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
 * SELECT ... FOR UPDATE on the provider_accounts row inside the tenant-audited
 * transaction serializes concurrent callers, so the rotating refresh token is
 * spent exactly once. A loser blocks until the winner commits, then observes the
 * already-rotated credential version and returns without a second token call.
 *
 * On upstream `invalid_grant` (revoked) the account is degraded + audited and we
 * throw X_REFRESH_REVOKED (fail closed). The vault write happens INSIDE the
 * critical section so a crash after the network call cannot leave the DB
 * pointing at a superseded (already-rotated-away) refresh token.
 */
export async function refreshXProviderCredential(input: RefreshInput): Promise<RefreshResult> {
  // The tx returns a discriminated outcome. A `revoked` outcome COMMITS the
  // degrade + audit, then we throw AFTER the commit so the failure signal does
  // not roll back the very degrade it is reporting (fail closed + durable).
  type Outcome = { kind: "ok"; result: RefreshResult } | { kind: "revoked" };
  const outcome = await withTenantAuditedTransaction<Outcome>(
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

      if (!account)
        throw new XConnectError("X_ACCOUNT_NOT_FOUND", 404, "provider account not found");
      // Cross-workspace IDOR guard: the account MUST belong to the workspace the
      // caller was authorized for. 404 (not 403) so account existence in another
      // workspace does not leak.
      if (account.workspaceId !== input.workspaceId) {
        throw new XConnectError("X_ACCOUNT_NOT_FOUND", 404, "provider account not found");
      }
      if (account.adapterKey !== X_ADAPTER_KEY) {
        throw new XConnectError("X_ACCOUNT_NOT_X", 400, "provider account is not an X account");
      }
      // Do NOT resurrect a locally revoked/disconnected account via refresh. A
      // revoked account requires a fresh OAuth connect to become active again;
      // silently reactivating it (especially after a best-effort upstream revoke
      // failed) would restore an account the operator intended to kill.
      if (account.status !== "active") {
        throw new XConnectError(
          "X_REFRESH_REVOKED",
          409,
          "provider account is not active; reconnect required",
        );
      }
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

      // Single-flight fast path: a concurrent winner already rotated us to a fresh
      // token while we waited for the lock. If not forced and the token is still
      // valid, skip the network call entirely.
      if (!input.force && !isNearExpiry(current.expiresAt)) {
        return {
          kind: "ok",
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

      // Spend the rotating refresh token exactly once (still holding the lock).
      const tokenRes = await refreshUpstream(input.config, current.refreshToken);

      if (tokenRes.revoked) {
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
        await append({
          tenantId: input.tenantId,
          actorType: input.actorId ? "user" : "system",
          actorId: input.actorId ?? "system",
          action: "provider.x.refresh.revoked",
          resourceType: "provider_account",
          resourceId: account.id,
          metadata: {
            workspaceId: account.workspaceId,
            xUserId: account.externalRef,
            previousRevision: account.revision,
            newRevision: degraded?.revision ?? null,
            requestId: input.requestId ?? null,
          },
        });
        // COMMIT the degrade + audit; the caller-facing failure is thrown below.
        return { kind: "revoked" };
      }

      // Rotate the vault secret to a new version with the freshly issued tokens.
      const obtainedAt = new Date();
      const expiresAt =
        typeof tokenRes.expiresIn === "number"
          ? new Date(obtainedAt.getTime() + tokenRes.expiresIn * 1000)
          : null;
      const newPayload: XCredentialPayload = {
        ...current.payload,
        accessToken: tokenRes.accessToken,
        // X rotates the refresh token; fall back to the prior one only if upstream
        // omits it (should not happen with offline.access).
        refreshToken: tokenRes.refreshToken ?? current.refreshToken,
        scopesGranted: tokenRes.scopes ?? current.payload.scopesGranted,
        obtainedAt: obtainedAt.toISOString(),
        expiresAt: expiresAt ? expiresAt.toISOString() : null,
      };
      const meta = await input.vault.rotateSecretWithinTx(
        tx,
        input.tenantId,
        current.secretName,
        JSON.stringify(newPayload),
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
        .returning();
      if (!updated) {
        throw new XConnectError("X_REFRESH_FAILED", 409, "account revision conflict on refresh");
      }

      await append({
        tenantId: input.tenantId,
        actorType: input.actorId ? "user" : "system",
        actorId: input.actorId ?? "system",
        action: "provider.x.refresh.completed",
        resourceType: "provider_account",
        resourceId: account.id,
        metadata: {
          workspaceId: account.workspaceId,
          xUserId: account.externalRef,
          credentialSecretId: meta.id,
          credentialVersion: meta.version,
          requestId: input.requestId ?? null,
        },
      });

      return {
        kind: "ok",
        result: {
          refreshed: true,
          credentialVersion: meta.version,
          expiresAt: newPayload.expiresAt,
        },
      };
    },
  );

  if (outcome.kind === "revoked") {
    throw new XConnectError("X_REFRESH_REVOKED", 409, "X refresh token revoked");
  }
  return outcome.result;
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
  const payload = JSON.parse(decrypted) as XCredentialPayload;
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
  accessToken: string;
  refreshToken?: string;
  scopes?: string[];
  expiresIn?: number;
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
      return { revoked: true, accessToken: "" };
    }
    throw new XConnectError("X_REFRESH_FAILED", 502, `X refresh failed (${res.status})`);
  }
  if (!parsed || typeof parsed.access_token !== "string") {
    throw new XConnectError("X_REFRESH_FAILED", 502, "X refresh response missing access_token");
  }
  return {
    revoked: false,
    accessToken: parsed.access_token,
    refreshToken: parsed.refresh_token,
    scopes: parsed.scope ? parsed.scope.split(/\s+/).filter(Boolean) : undefined,
    expiresIn: parsed.expires_in,
  };
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
 * Disconnect a connected X account: best-effort revoke at X, degrade the account
 * (status revoked), bump revision, audit. Revocation failure at X does NOT block
 * the local degrade — we fail CLOSED locally regardless.
 */
export async function disconnectXProviderCredential(
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
    if (!account) throw new XConnectError("X_ACCOUNT_NOT_FOUND", 404, "provider account not found");
    if (account.adapterKey !== X_ADAPTER_KEY) {
      throw new XConnectError("X_ACCOUNT_NOT_X", 400, "provider account is not an X account");
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
          input.config,
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
      throw new XConnectError("X_REFRESH_FAILED", 409, "account revision conflict on disconnect");
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
  return res.ok;
}

// re-export sql for callers/tests that need raw predicates
export { sql };
