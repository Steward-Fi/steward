/**
 * auth.ts — Complete authentication route group
 *
 * Mounts at /auth via `app.route("/auth", authRoutes)` in packages/api/src/index.ts.
 *
 * Routes
 * ──────
 * GET  /nonce                       — fresh nonce for SIWE
 * POST /verify                      — SIWE signature verification, returns JWT
 * GET  /session                     — inspect current JWT session
 * GET  /providers                   — available auth methods (passkey/email/siwe/google/discord)
 * POST /logout                      — client-side logout (no-op server side)
 *
 * POST /passkey/register/options    — { email } → WebAuthn creation options
 * POST /passkey/register/verify     — { email, response } → { token, user }
 * POST /passkey/login/options       — { email } → WebAuthn request options
 * POST /passkey/login/verify        — { email, response } → { token, user }
 *
 * POST /email/send                  — { email } → { ok, expiresAt }
 * POST /email/verify                — { token, email } → { token (JWT), user }
 * GET  /callback/email              — ?token=...&email=... → 302 redirect with session tokens
 *
 * Tenant context
 * ──────────────
 * All email/passkey routes accept an optional tenant hint via:
 *   - Header: X-Steward-Tenant: <tenantId>
 *   - Body field: tenantId: "<tenantId>"
 * If neither is present the user's personal tenant (personal-<userId>) is used
 * as the fallback so existing integrations continue to work unchanged.
 *
 * On each auth event (signup or login):
 *   1. The user record is created/found globally in `users`.
 *   2. A `user_tenants` link is upserted for the resolved tenant (role = "member").
 *   3. The JWT's `tenantId` claim is the resolved tenant, not the personal tenant.
 */

// node:crypto under Cloudflare nodejs_compat (GA Sept 2024):
//   - randomBytes        — supported.
//   - createPublicKey    — supported, including ed25519 JWK import (workerd
//                          shipped X25519/Ed25519 in late 2024).
//   - verify             — supported for ed25519. The (null, msg, key, sig)
//                          signature is the standard Node form.
// If any of these fail at runtime on Workers, fall back to tweetnacl for
// ed25519 verify (lightweight, edge-compatible).
import { createPublicKey, randomBytes, verify as verifySignature } from "node:crypto";
import type { AuthenticatorTransportFuture } from "@stwd/auth";
import {
  assertTokenNotRevoked,
  buildBackend,
  ChallengeStore,
  EmailAuth,
  generateApiKey,
  getProviderConfig,
  hashSha256Hex,
  isBuiltInProvider,
  MockEmailInbox,
  MockEmailProvider,
  OAuthClient,
  PasskeyAuth,
  ResendProvider,
  revocationStore,
  signAccessToken,
  TokenStore,
  uint8ArrayToBase64url,
  verifyToken,
} from "@stwd/auth";
import {
  accounts,
  authenticators,
  getDb,
  refreshTokens,
  type TenantEmailConfig,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import type { ApiResponse } from "@stwd/shared";
import { KeyStore, provisionUserWallet, Vault } from "@stwd/vault";
import bs58 from "bs58";
import { and, eq, gte, lt } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { generateNonce, SiweMessage } from "siwe";
import { getAddress, verifyMessage as viemVerifyMessage } from "viem";
import { trackAuditEvent } from "../services/audit";
import { verifyEip1271 } from "../services/eip1271";

// ─── Constants ────────────────────────────────────────────────────────────────

const _DEFAULT_TENANT_ID = process.env.STEWARD_DEFAULT_TENANT_ID || "default";

// ─── IP-based auth rate limiting ─────────────────────────────────────────────

/**
 * Check a per-IP rate limit for auth endpoints, backed by the Redis sliding
 * window. When Redis is unavailable the request is allowed — the existing
 * Bun-side global rate limiter (in index.ts) and the upstream platform
 * (Cloudflare, ALB, etc.) are still in front of this. We deliberately do not
 * keep an in-memory fallback Map: it is incorrect across multiple instances
 * and impossible on Cloudflare Workers (no shared state across isolates).
 *
 * @param c        - Hono context (used to read client IP headers)
 * @param endpoint - Short name used as part of the Redis key
 * @param windowMs - Window length in milliseconds
 * @param max      - Maximum allowed requests in the window
 */
async function checkAuthRateLimit(
  c: Context,
  endpoint: string,
  windowMs: number,
  max: number,
): Promise<{ allowed: boolean; retryAfterSecs?: number }> {
  const ip =
    c.req.header("x-forwarded-for")?.split(",")[0].trim() ?? c.req.header("x-real-ip") ?? "unknown";
  const key = `ratelimit:auth:${endpoint}:${ip}:${windowMs}`;

  try {
    const redisMw = await import("../middleware/redis.js");
    if (!redisMw.isRedisAvailable()) return { allowed: true };

    const { checkRateLimit } = await import("@stwd/redis");
    const result = await checkRateLimit(key, windowMs, max);
    if (!result.allowed) {
      return {
        allowed: false,
        retryAfterSecs: Math.ceil(result.resetMs / 1000),
      };
    }
    return { allowed: true };
  } catch {
    // Treat Redis errors as soft-fail (allow the request) so a transient
    // Redis outage doesn't lock users out of authentication.
    return { allowed: true };
  }
}

// ─── JWT helpers ──────────────────────────────────────────────────────────────

/** Access token lifetime: 24 hours */
const ACCESS_TOKEN_EXPIRY = "24h";
const ACCESS_TOKEN_EXPIRY_SECONDS = 86400;

/** Refresh token lifetime: 30 days */
const REFRESH_TOKEN_EXPIRY_DAYS = 30;

export async function createSessionToken(
  address: string,
  tenantId: string,
  extra?: Record<string, unknown>,
): Promise<string> {
  return signAccessToken({ address, tenantId, ...extra }, ACCESS_TOKEN_EXPIRY);
}

// ─── Refresh token helpers ────────────────────────────────────────────────────

function hashToken(raw: string): string {
  return hashSha256Hex(raw);
}

/**
 * Generate a random refresh token, persist its hash in DB, return the raw value.
 * The raw token is sent to the client; only the hash is stored server-side.
 */
async function createRefreshToken(userId: string, tenantId: string): Promise<string> {
  const db = getDb();
  const raw = randomBytes(40).toString("hex");
  const id = randomBytes(16).toString("hex");
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_DAYS * 86400 * 1000);
  await db
    .insert(refreshTokens)
    .values({ id, userId, tenantId, tokenHash: hashToken(raw), expiresAt });
  return raw;
}

/**
 * Atomically consume a raw refresh token.
 * Deletes and returns the row in one statement so concurrent refresh attempts
 * cannot both validate the same one-time token and mint parallel successors.
 */
async function consumeRefreshToken(raw: string): Promise<typeof refreshTokens.$inferSelect | null> {
  const db = getDb();
  const now = new Date();
  const [record] = await db
    .delete(refreshTokens)
    .where(and(eq(refreshTokens.tokenHash, hashToken(raw)), gte(refreshTokens.expiresAt, now)))
    .returning();

  // Best-effort cleanup for expired rows so they do not linger forever.
  if (!record) {
    await db
      .delete(refreshTokens)
      .where(and(eq(refreshTokens.tokenHash, hashToken(raw)), lt(refreshTokens.expiresAt, now)));
    return null;
  }

  return record;
}

/** Build the standard dual-token auth response. */
function buildAuthResponse(
  token: string,
  refreshToken: string,
  user: Record<string, unknown>,
): Record<string, unknown> {
  return {
    ok: true,
    token,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
    user,
  };
}

export async function verifySessionToken(token: string): Promise<{
  address: string;
  tenantId: string;
  userId?: string;
  email?: string;
} | null> {
  try {
    const payload = (await verifyToken(token)) as {
      address: string;
      tenantId: string;
      userId?: string;
      email?: string;
      jti?: string;
      exp?: number;
      iat?: number;
    };
    await assertTokenNotRevoked(payload);
    return payload;
  } catch {
    return null;
  }
}

// ─── Nonce store (SIWE / SIWS) ───────────────────────────────────────────────
//
// Backed by the same StoreBackend abstraction the challenge/token stores use,
// so nonces persist across instances on Workers (Upstash) and across restarts
// in production (Postgres `auth_kv_store`). The default is in-memory for
// dev/test — initAuthStores() upgrades it once Redis/Postgres availability
// is known.
//
// TTL matches the previous Map GC interval (5 minutes), enforced by the
// backend itself so no setInterval cleanup is needed.

const SIWE_NONCE_TTL_MS = 5 * 60 * 1000;
let _nonceBackend: import("@stwd/auth").StoreBackend | null = null;

function getNonceBackend(): import("@stwd/auth").StoreBackend {
  if (_nonceBackend) return _nonceBackend;
  // Lazily fall back to a fresh in-memory backend if initAuthStores() hasn't
  // been called yet (e.g. tests or Workers cold-boot before middleware runs).
  // initAuthStores() will replace this with a Redis or Postgres-backed one.
  // Imported via require to avoid a circular dep with @stwd/auth at module init.
  const { MemoryBackend } = require("@stwd/auth") as typeof import("@stwd/auth");
  _nonceBackend = new MemoryBackend();
  return _nonceBackend;
}

async function setSiweNonce(nonce: string): Promise<void> {
  await getNonceBackend().set(nonce, "1", SIWE_NONCE_TTL_MS);
}

/**
 * Atomically consume a SIWE nonce. Returns true if the nonce was present and
 * unexpired (and is now deleted), false otherwise.
 *
 * The check-then-delete is not strictly atomic across instances — Upstash and
 * Postgres do both, but with a small window. For SIWE this is acceptable: the
 * surrounding signature check is the actual authentication, and a leaked nonce
 * is useless without the corresponding wallet signature.
 */
async function consumeSiweNonce(nonce: string): Promise<boolean> {
  const backend = getNonceBackend();
  const value = await backend.get(nonce);
  if (!value) return false;
  await backend.delete(nonce);
  return true;
}

// ─── PasskeyAuth singleton ────────────────────────────────────────────────────

// ─── Store backend initialization ────────────────────────────────────────────

let _challengeStore: ChallengeStore | null = null;
let _tokenStore: TokenStore | null = null;
let _oauthCodeStore: ChallengeStore | null = null;

/**
 * One-time OAuth nonce-exchange codes (response_type=code) live for 60s —
 * long enough for the user's browser to redirect back and the caller's
 * backend to POST the code to /oauth/exchange, short enough that a captured
 * code in an access log or Referer leak is useless by the time anyone reads
 * it. Codes are single-use (consume() deletes on first read).
 */
const OAUTH_CODE_TTL_MS = 60 * 1000;

/**
 * Initialize auth token/challenge stores with the best available backend.
 * Call this during server startup AFTER initRedis() has been called.
 *
 * @param usePostgres  Pass true if the DB connection is known to be available.
 */
export async function initAuthStores(usePostgres = false): Promise<void> {
  const { getRedisClient } = await import("../middleware/redis.js");
  const redisClient = getRedisClient();

  const [
    { backend: challengeBackend, source: challengeSource },
    { backend: tokenBackend, source: tokenSource },
    { backend: nonceBackend, source: nonceSource },
  ] = await Promise.all([
    buildBackend("challenge", redisClient, usePostgres),
    buildBackend("token", redisClient, usePostgres),
    buildBackend("siwe-nonce", redisClient, usePostgres),
  ]);

  console.log(
    `[steward:auth] challenge store: ${challengeSource}, token store: ${tokenSource}, ` +
      `siwe-nonce store: ${nonceSource}`,
  );

  _challengeStore = new ChallengeStore({ backend: challengeBackend });
  _tokenStore = new TokenStore({ backend: tokenBackend });
  _nonceBackend = nonceBackend;
  // Reuse the challenge backend (Redis when available) for OAuth nonce codes
  // so they survive worker restarts and round-robin between isolates. The
  // 60s TTL is enforced at write time by ChallengeStore.
  _oauthCodeStore = new ChallengeStore({
    backend: challengeBackend,
    ttlMs: OAUTH_CODE_TTL_MS,
  });

  // Reset singletons so they pick up the new stores on next use
  _passkeyAuth = null;
  _passkeyAuthByOrigin.clear();
  _emailAuthByTenant.clear();
}

function getChallengeStore(): ChallengeStore {
  _challengeStore ??= new ChallengeStore();
  return _challengeStore;
}

function getOAuthCodeStore(): ChallengeStore {
  _oauthCodeStore ??= new ChallengeStore({ ttlMs: OAUTH_CODE_TTL_MS });
  return _oauthCodeStore;
}

function getTokenStore(): TokenStore {
  _tokenStore ??= new TokenStore();
  return _tokenStore;
}

let _passkeyAuth: PasskeyAuth | null = null;
const _passkeyAuthByOrigin = new Map<string, PasskeyAuth>();

/**
 * Get PasskeyAuth for a specific origin (multi-tenant passkey support).
 * Derives rpID from the Origin header so passkeys work on waifu.fun,
 * elizacloud.ai, or any other tenant domain.
 *
 * Allowed origins: PASSKEY_ALLOWED_ORIGINS env (comma-separated),
 * defaults to PASSKEY_ORIGIN.
 *
 * rpID resolution rule (apex-folding):
 *   When the request hostname is a strict subdomain of an allowed origin's
 *   hostname (e.g. request `www.waifu.fun`, allowed `https://waifu.fun`),
 *   we use the SHORTER allowed hostname as rpID. This keeps a single
 *   credential valid across apex + www and avoids breaking users who
 *   registered under one form when their canonical host changes (e.g.
 *   apex 307s to www, or vice versa).
 *
 *   WebAuthn allows rpID to be any registrable suffix of the request
 *   origin hostname, and the resulting credential is then scoped to
 *   apex + all subdomains.
 */
function resolveRpID(requestHostname: string, allowedOrigins: string[], fallback: string): string {
  let best = requestHostname;
  for (const o of allowedOrigins) {
    let host: string;
    try {
      host = new URL(o).hostname;
    } catch {
      continue;
    }
    if (host === requestHostname) {
      // Exact match. Prefer shortest match seen so far so apex wins over www.
      if (host.length < best.length || best === requestHostname) best = host;
    } else if (
      requestHostname.endsWith(`.${host}`) &&
      // shortest match wins
      (best === requestHostname || host.length < best.length)
    ) {
      best = host;
    }
  }
  if (!best) return fallback;
  return best;
}

function getPasskeyAuth(requestOrigin?: string): PasskeyAuth {
  const defaultRpID = process.env.PASSKEY_RP_ID || "steward.fi";
  const defaultOrigin = process.env.PASSKEY_ORIGIN || "https://steward.fi";
  const rpName = process.env.PASSKEY_RP_NAME || "Steward";

  // If no origin provided, use the default singleton
  if (!requestOrigin) {
    if (!_passkeyAuth) {
      const origins = (process.env.PASSKEY_ALLOWED_ORIGINS || defaultOrigin)
        .split(",")
        .map((o) => o.trim())
        .filter(Boolean);
      _passkeyAuth = new PasskeyAuth({
        rpName,
        rpID: defaultRpID,
        origin: origins.length > 1 ? origins : defaultOrigin,
        challengeStore: getChallengeStore(),
      });
    }
    return _passkeyAuth;
  }

  // Parse origin to get hostname
  let requestHostname: string;
  try {
    requestHostname = new URL(requestOrigin).hostname;
  } catch {
    return getPasskeyAuth(); // invalid origin, fall back to default
  }

  // Validate against allowed origins
  const allowed = (process.env.PASSKEY_ALLOWED_ORIGINS || defaultOrigin)
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  if (!allowed.includes(requestOrigin) && requestHostname !== defaultRpID) {
    return getPasskeyAuth(); // not in allowed list, use default
  }

  // Apex-fold: if the request hostname is a subdomain of any allowed origin,
  // use the allowed origin's apex hostname as rpID so the credential is
  // shared across apex + all subdomains.
  const rpID = resolveRpID(requestHostname, allowed, defaultRpID);

  // Cache per rpID
  const cached = _passkeyAuthByOrigin.get(rpID);
  if (cached) return cached;

  // Origin list passed to PasskeyAuth covers all variants the browser may
  // present (apex + www) so SimpleWebAuthn accepts assertions from either.
  const acceptedOrigins = allowed.length > 0 ? allowed : [requestOrigin];

  const auth = new PasskeyAuth({
    rpName,
    rpID,
    origin: acceptedOrigins,
    challengeStore: getChallengeStore(),
  });
  _passkeyAuthByOrigin.set(rpID, auth);
  return auth;
}

// ─── EmailAuth cache ──────────────────────────────────────────────────────────

const _emailAuthByTenant = new Map<string, Promise<EmailAuth>>();
let _emailKeyStore: KeyStore | null = null;
let _oauthKeyStore: KeyStore | null = null;

function getEmailKeyStore(): KeyStore {
  if (_emailKeyStore) return _emailKeyStore;

  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("STEWARD_MASTER_PASSWORD is required");
    }
    _emailKeyStore = new KeyStore("dev-secret");
    return _emailKeyStore;
  }

  _emailKeyStore = new KeyStore(masterPassword);
  return _emailKeyStore;
}

function getOAuthKeyStore(): KeyStore {
  if (_oauthKeyStore) return _oauthKeyStore;

  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("STEWARD_MASTER_PASSWORD is required to encrypt OAuth provider tokens");
    }
    _oauthKeyStore = new KeyStore("dev-secret");
    return _oauthKeyStore;
  }

  _oauthKeyStore = new KeyStore(masterPassword);
  return _oauthKeyStore;
}

type OAuthEncryptedTokenFields = Pick<
  typeof accounts.$inferInsert,
  | "accessTokenEncrypted"
  | "accessTokenIv"
  | "accessTokenTag"
  | "accessTokenSalt"
  | "refreshTokenEncrypted"
  | "refreshTokenIv"
  | "refreshTokenTag"
  | "refreshTokenSalt"
>;

export function encryptOAuthProviderTokens(
  accessToken: string,
  refreshToken?: string | null,
): OAuthEncryptedTokenFields {
  const keyStore = getOAuthKeyStore();
  const encryptedAccessToken = keyStore.encrypt(accessToken);
  const encryptedRefreshToken = refreshToken ? keyStore.encrypt(refreshToken) : null;

  return {
    accessTokenEncrypted: encryptedAccessToken.ciphertext,
    accessTokenIv: encryptedAccessToken.iv,
    accessTokenTag: encryptedAccessToken.tag,
    accessTokenSalt: encryptedAccessToken.salt,
    refreshTokenEncrypted: encryptedRefreshToken?.ciphertext ?? null,
    refreshTokenIv: encryptedRefreshToken?.iv ?? null,
    refreshTokenTag: encryptedRefreshToken?.tag ?? null,
    refreshTokenSalt: encryptedRefreshToken?.salt ?? null,
  };
}

export function decryptOAuthProviderToken(encrypted: {
  ciphertext: string | null;
  iv: string | null;
  tag: string | null;
  salt: string | null;
}): string | null {
  if (!encrypted.ciphertext) return null;
  if (!encrypted.iv || !encrypted.tag || !encrypted.salt) {
    throw new Error("OAuth provider token is not encrypted or is missing encryption metadata");
  }

  try {
    return getOAuthKeyStore().decrypt({
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      tag: encrypted.tag,
      salt: encrypted.salt,
    });
  } catch (err) {
    throw new Error(
      `Failed to decrypt OAuth provider token: check STEWARD_MASTER_PASSWORD${
        err instanceof Error ? ` (${err.message})` : ""
      }`,
    );
  }
}

function isMockEmailEnabled(): boolean {
  if (process.env.EMAIL_PROVIDER === "mock" && process.env.NODE_ENV === "production") {
    throw new Error(
      "EMAIL_PROVIDER=mock is forbidden in production. Unset EMAIL_PROVIDER or set RESEND_API_KEY.",
    );
  }
  return process.env.EMAIL_PROVIDER === "mock" && process.env.NODE_ENV !== "production";
}

function buildGlobalEmailAuth(overrides?: { baseUrl?: string; callbackPath?: string }): EmailAuth {
  const resendKey = process.env.RESEND_API_KEY;
  // Mock takes precedence in non-production for deterministic e2e testing.
  const provider = isMockEmailEnabled()
    ? new MockEmailProvider()
    : resendKey
      ? new ResendProvider({
          apiKey: resendKey,
          from: process.env.EMAIL_FROM || "login@steward.fi",
        })
      : undefined;

  return new EmailAuth({
    from: process.env.EMAIL_FROM || "login@steward.fi",
    baseUrl: overrides?.baseUrl?.replace(/\/$/, "") || process.env.APP_URL || "https://steward.fi",
    callbackPath: overrides?.callbackPath,
    provider,
    tokenStore: getTokenStore(),
  });
}

function parseEncryptedEmailApiKey(value: string): {
  ciphertext: string;
  iv: string;
  tag: string;
  salt: string;
} {
  const parsed = JSON.parse(value) as Partial<{
    ciphertext: string;
    iv: string;
    tag: string;
    salt: string;
  }>;

  if (!parsed.ciphertext || !parsed.iv || !parsed.tag || !parsed.salt) {
    throw new Error("Invalid tenant email config encryption payload");
  }

  return {
    ciphertext: parsed.ciphertext,
    iv: parsed.iv,
    tag: parsed.tag,
    salt: parsed.salt,
  };
}

async function loadTenantEmailConfig(tenantId: string): Promise<TenantEmailConfig | null> {
  const db = getDb();
  const [row] = await db
    .select({ emailConfig: tenantConfigs.emailConfig })
    .from(tenantConfigs)
    .where(eq(tenantConfigs.tenantId, tenantId));

  return row?.emailConfig ?? null;
}

async function createEmailAuthForTenant(tenantId: string): Promise<EmailAuth> {
  const emailConfig = await loadTenantEmailConfig(tenantId);

  // Per-tenant magic-link override: when a tenant supplies its own
  // `magicLinkBaseUrl` we build the link against that origin so the click
  // lands on the tenant's app (e.g. https://waifu.fun/auth/email/verify)
  // instead of Steward's built-in callback (which redirects to
  // EMAIL_AUTH_REDIRECT_BASE_URL and is hard-defaulted to elizacloud.ai).
  const magicLinkBaseUrl = emailConfig?.magicLinkBaseUrl;
  const callbackPath = magicLinkBaseUrl
    ? emailConfig?.magicLinkCallbackPath || "/auth/email/verify"
    : undefined; // let EmailAuth fall through to its DEFAULT_CALLBACK

  if (!emailConfig || !emailConfig.apiKeyEncrypted) {
    // No per-tenant Resend config (or only magic-link override) — use the
    // global env-backed provider but still honor the per-tenant magic-link
    // overrides if present.
    return buildGlobalEmailAuth({
      baseUrl: magicLinkBaseUrl,
      callbackPath,
    });
  }

  // We've already returned via buildGlobalEmailAuth above when apiKeyEncrypted
  // is missing, so it's safe to assume `emailConfig.from + apiKeyEncrypted`
  // are both present here.
  const from = emailConfig.from || process.env.EMAIL_FROM || "login@steward.fi";
  const provider =
    emailConfig.provider === "resend" && emailConfig.apiKeyEncrypted
      ? new ResendProvider({
          apiKey: getEmailKeyStore().decrypt(
            parseEncryptedEmailApiKey(emailConfig.apiKeyEncrypted),
          ),
          from,
          replyTo: emailConfig.replyTo,
        })
      : undefined;

  const baseUrl =
    magicLinkBaseUrl?.replace(/\/$/, "") || process.env.APP_URL || "https://steward.fi";

  return new EmailAuth({
    from,
    baseUrl,
    callbackPath,
    provider,
    tokenStore: getTokenStore(),
    templateId: emailConfig.templateId,
    subjectOverride: emailConfig.subjectOverride,
    replyTo: emailConfig.replyTo,
  });
}

export async function getEmailAuthForTenant(tenantId: string): Promise<EmailAuth> {
  const cached = _emailAuthByTenant.get(tenantId);
  if (cached) return cached;

  const pending = createEmailAuthForTenant(tenantId).catch((error) => {
    _emailAuthByTenant.delete(tenantId);
    throw error;
  });
  _emailAuthByTenant.set(tenantId, pending);
  return pending;
}

export function invalidateEmailAuthForTenant(tenantId: string): void {
  _emailAuthByTenant.delete(tenantId);
}

export function clearEmailAuthTenantCacheForTests(): void {
  _emailAuthByTenant.clear();
}

export function clearOAuthTokenKeyStoreForTests(): void {
  _oauthKeyStore = null;
}

/**
 * Test-only seam: write a fully-formed OAuth nonce payload into the code
 * store so the /oauth/exchange route can be exercised end-to-end without
 * running a real provider callback. Production callers should never use
 * this — the only writer of the code store is the `/oauth/<provider>/callback`
 * handler.
 */
export function _seedOAuthExchangeCodeForTests(
  code: string,
  payload: {
    token: string;
    refreshToken: string;
    redirectUri: string;
    tenantId: string | null;
    expiresAt?: number;
    expiresIn?: number;
  },
): void {
  const fullPayload = {
    token: payload.token,
    refreshToken: payload.refreshToken,
    redirectUri: payload.redirectUri,
    tenantId: payload.tenantId,
    expiresAt: payload.expiresAt ?? Date.now() + OAUTH_CODE_TTL_MS,
    expiresIn: payload.expiresIn ?? ACCESS_TOKEN_EXPIRY_SECONDS,
  };
  getOAuthCodeStore().set(`oauth-code:${code}`, JSON.stringify(fullPayload));
}

export function _clearOAuthCodeStoreForTests(): void {
  _oauthCodeStore?.destroy();
  _oauthCodeStore = null;
}

// ─── Vault helper ─────────────────────────────────────────────────────────────

function getVault(): Vault {
  const masterPassword = process.env.STEWARD_MASTER_PASSWORD;
  if (!masterPassword) throw new Error("STEWARD_MASTER_PASSWORD is required");
  return new Vault({
    masterPassword,
    rpcUrl: process.env.RPC_URL || "https://sepolia.base.org",
    chainId: parseInt(process.env.CHAIN_ID || "84532", 10),
  });
}

// ─── Tenant resolution ────────────────────────────────────────────────────────

/**
 * Resolve the tenant the user is signing into.
 * Priority: X-Steward-Tenant header > body.tenantId > personal-<userId> fallback.
 * Returns null if the resolved tenant doesn't exist in the DB (caller should 404).
 */
type TenantResolutionOk = { ok: true; tenantId: string; isPersonal: boolean };
type TenantResolutionErr = { ok: false; status: 403 | 404; error: string };
type TenantResolutionResult = TenantResolutionOk | TenantResolutionErr;

/**
 * Resolve and validate the tenant a user is authenticating into.
 *
 * Priority: X-Steward-Tenant header > body.tenantId > personal-<userId> fallback.
 *
 * When an explicit tenantId is requested:
 *   1. Verify the tenant exists in the `tenants` table (404 if not)
 *   2. Check if user already has a user_tenants link (always allowed if so)
 *   3. Look up join_mode from tenant_configs (default 'open')
 *   4. If join_mode is 'open', auto-link is allowed
 *   5. If join_mode is 'invite', 403 (must be pre-invited)
 *   6. If join_mode is 'closed', 403 always
 */
async function resolveAndValidateTenant(
  c: Context,
  userId: string,
  bodyTenantId?: string,
): Promise<TenantResolutionResult> {
  const headerTenant = c.req.header("X-Steward-Tenant")?.trim();
  const requested = headerTenant || bodyTenantId?.trim() || undefined;

  if (!requested) {
    return { ok: true, tenantId: `personal-${userId}`, isPersonal: true };
  }

  const db = getDb();

  // 1. Verify the tenant exists
  const [tenant] = await db
    .select({ id: tenants.id })
    .from(tenants)
    .where(eq(tenants.id, requested));
  if (!tenant) {
    return { ok: false, status: 404, error: `Tenant '${requested}' not found` };
  }

  // 2. Check if user already has a link (always allowed regardless of join_mode)
  const [existingLink] = await db
    .select({ id: userTenants.id })
    .from(userTenants)
    .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, requested)));

  if (existingLink) {
    return { ok: true, tenantId: requested, isPersonal: false };
  }

  // 3. No existing link; check join_mode from tenant_configs
  const [config] = await db
    .select({ joinMode: tenantConfigs.joinMode })
    .from(tenantConfigs)
    .where(eq(tenantConfigs.tenantId, requested));

  const joinMode = config?.joinMode ?? "open"; // default open if no config row

  if (joinMode === "open") {
    return { ok: true, tenantId: requested, isPersonal: false };
  }

  if (joinMode === "invite") {
    return {
      ok: false,
      status: 403,
      error: `Tenant '${requested}' requires an invitation to join`,
    };
  }

  // joinMode === "closed"
  return {
    ok: false,
    status: 403,
    error: `Tenant '${requested}' is not accepting new members`,
  };
}

// ─── User / tenant provisioning helpers ──────────────────────────────────────

async function findOrCreateUser(email: string): Promise<typeof users.$inferSelect> {
  const db = getDb();
  const [existing] = await db.select().from(users).where(eq(users.email, email));
  if (existing) return existing;
  const [newUser] = await db.insert(users).values({ email, emailVerified: false }).returning();
  return newUser;
}

async function findOrCreateWalletUser(
  walletAddress: string,
  walletChain: "ethereum" | "solana",
): Promise<typeof users.$inferSelect> {
  const db = getDb();
  const [existing] = await db.select().from(users).where(eq(users.walletAddress, walletAddress));
  if (existing) {
    if (existing.walletChain !== walletChain) {
      await db.update(users).set({ walletChain }).where(eq(users.id, existing.id));
      const [updated] = await db.select().from(users).where(eq(users.id, existing.id));
      return updated ?? { ...existing, walletChain };
    }
    return existing;
  }

  const [created] = await db
    .insert(users)
    .values({
      walletAddress,
      walletChain,
      email: null,
      emailVerified: false,
    })
    .returning();
  return created;
}

type WalletTenantResult = {
  tenant: typeof tenants.$inferSelect;
  isNewTenant: boolean;
  rawApiKey?: string;
};

async function findOrCreateWalletTenant(opts: {
  ownerAddress: string;
  tenantId: string;
  tenantName: string;
}): Promise<WalletTenantResult> {
  const db = getDb();
  const [existingTenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.ownerAddress, opts.ownerAddress));
  if (existingTenant) {
    return { tenant: existingTenant, isNewTenant: false };
  }

  const apiKeyPair = generateApiKey();
  const [newTenant] = await db
    .insert(tenants)
    .values({
      id: opts.tenantId,
      name: opts.tenantName,
      apiKeyHash: apiKeyPair.hash,
      ownerAddress: opts.ownerAddress,
    })
    .onConflictDoNothing()
    .returning();

  if (newTenant) {
    return { tenant: newTenant, isNewTenant: true, rawApiKey: apiKeyPair.key };
  }

  const [retryTenant] = await db.select().from(tenants).where(eq(tenants.id, opts.tenantId));
  if (!retryTenant) {
    throw new Error("Failed to create tenant");
  }

  return { tenant: retryTenant, isNewTenant: false };
}

function getAllowedSiweDomains(): string[] | null {
  const raw = process.env.SIWE_ALLOWED_DOMAINS?.trim();
  if (!raw) return null;
  const domains = raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
  return domains.length > 0 ? domains : null;
}

type ParsedSiwsMessage = {
  domain: string;
  publicKey: string;
  nonce: string;
  issuedAt?: string;
  uri?: string;
  version?: string;
  chainId?: string;
  statement?: string;
};

const ALLOWED_SOLANA_CHAIN_IDS = new Set(["solana", "mainnet", "devnet"]);

function isAllowedSiwsUri(uri: string | undefined, domain: string): boolean {
  if (!uri) return false;
  try {
    const parsedUri = new URL(uri);
    if (parsedUri.host !== domain) return false;
    if (parsedUri.protocol === "https:") return true;
    // http:// is only acceptable for loopback hosts. Production deployments
    // never see localhost here, so the relaxation is naturally scoped to
    // dev / e2e — no env flag needed.
    if (parsedUri.protocol === "http:") {
      const host = parsedUri.hostname;
      return host === "localhost" || host === "127.0.0.1" || host === "::1";
    }
    return false;
  } catch {
    return false;
  }
}

function isAllowedSiwsChainId(chainId: string | undefined): boolean {
  if (!chainId) return true;
  return ALLOWED_SOLANA_CHAIN_IDS.has(chainId.trim().toLowerCase());
}

function parseSiwsMessage(message: string): ParsedSiwsMessage | null {
  const lines = message.split(/\r?\n/);
  if (lines.length < 2) return null;

  const firstLine = lines[0]?.trim();
  const publicKey = lines[1]?.trim();
  const match = firstLine?.match(/^(.*) wants you to sign in with your Solana account:$/);
  if (!match || !publicKey) return null;

  const statementLines: string[] = [];
  const fields = new Map<string, string>();
  let inFields = false;

  for (const rawLine of lines.slice(2)) {
    const line = rawLine.trim();
    if (!line) continue;

    const fieldMatch = line.match(/^([A-Za-z ]+):\s*(.+)$/);
    if (fieldMatch) {
      inFields = true;
      fields.set(fieldMatch[1].toLowerCase().replace(/\s+/g, ""), fieldMatch[2]);
      continue;
    }

    if (!inFields) {
      statementLines.push(line);
    }
  }

  const nonce = fields.get("nonce");
  if (!nonce) return null;

  return {
    domain: match[1].trim(),
    publicKey,
    nonce,
    issuedAt: fields.get("issuedat"),
    uri: fields.get("uri"),
    version: fields.get("version"),
    chainId: fields.get("chainid"),
    statement: statementLines.length > 0 ? statementLines.join("\n") : undefined,
  };
}

function verifySolanaMessageSignature(
  message: string,
  signature: string,
  publicKey: string,
): boolean {
  try {
    const publicKeyBytes = bs58.decode(publicKey);
    const signatureBytes = bs58.decode(signature);
    if (publicKeyBytes.length !== 32) return false;

    const keyObject = createPublicKey({
      key: {
        kty: "OKP",
        crv: "Ed25519",
        x: uint8ArrayToBase64url(publicKeyBytes),
      },
      format: "jwk",
    });

    return verifySignature(null, Buffer.from(message, "utf8"), keyObject, signatureBytes);
  } catch {
    return false;
  }
}

/**
 * Ensure the user's personal tenant exists.
 * Used as a fallback when no explicit tenant is requested AND as the home for
 * the user's provisioned wallet agent (wallet always lives under personal tenant).
 */
async function ensurePersonalTenant(userId: string, displayName: string): Promise<string> {
  const db = getDb();
  const tenantId = `personal-${userId}`;
  const { hash } = generateApiKey();
  await db
    .insert(tenants)
    .values({ id: tenantId, name: displayName, apiKeyHash: hash })
    .onConflictDoNothing();
  return tenantId;
}

/**
 * Link a user to a tenant in the user_tenants junction table (idempotent).
 * If the tenant doesn't exist yet, silently skips — caller must ensure the
 * tenant exists before calling this.
 */
async function ensureUserTenantLink(
  userId: string,
  tenantId: string,
  role: string = "member",
): Promise<void> {
  const db = getDb();
  await db.insert(userTenants).values({ userId, tenantId, role }).onConflictDoNothing();
}

/**
 * Provision the user's personal wallet (idempotent).
 * The wallet agent always lives under `personal-<userId>` regardless of which
 * tenant the user authenticated through — the JWT tenantId is the requesting
 * tenant, but the wallet itself stays in the personal namespace.
 */
async function provisionWalletForUser(
  userId: string,
  email: string,
): Promise<{ walletAddress: string; personalTenantId: string }> {
  const personalTenantId = await ensurePersonalTenant(userId, email);
  const vault = getVault();
  const result = await provisionUserWallet(vault, userId, email, personalTenantId);
  const db = getDb();
  await db
    .update(users)
    .set({
      walletAddress: result.walletAddress,
      stewardWalletId: result.agentId,
    })
    .where(eq(users.id, userId));
  // Also link user to their personal tenant
  await ensureUserTenantLink(userId, personalTenantId, "owner");
  return { walletAddress: result.walletAddress, personalTenantId };
}

// ─── Request body helper ──────────────────────────────────────────────────────

async function safeJsonParse<T>(c: Context): Promise<T | null> {
  try {
    return await c.req.json<T>();
  } catch {
    return null;
  }
}

type CompletedEmailAuthResult =
  | {
      ok: true;
      token: string;
      refreshToken: string;
      user: { id: string; email: string; walletAddress?: string | null };
    }
  | { ok: false; status: 403 | 404; error: string };

async function completeEmailAuth(
  c: Context,
  email: string,
  tenantId?: string,
): Promise<CompletedEmailAuthResult> {
  const user = await findOrCreateUser(email);
  const db = getDb();
  await db.update(users).set({ emailVerified: true }).where(eq(users.id, user.id));

  // Provision wallet (idempotent, always under personal tenant)
  let walletAddress = user.walletAddress;
  try {
    const w = await provisionWalletForUser(user.id, email);
    walletAddress = w.walletAddress;
  } catch (err) {
    console.error("[EmailAuth] Wallet provision failed:", err);
  }

  // Resolve requesting tenant and link user
  const tenantResult = await resolveAndValidateTenant(c, user.id, tenantId);
  if (!tenantResult.ok) {
    return { ok: false, status: tenantResult.status, error: tenantResult.error };
  }
  const { tenantId: resolvedTenantId } = tenantResult;
  await ensureUserTenantLink(user.id, resolvedTenantId);

  const token = await createSessionToken(walletAddress ?? "", resolvedTenantId, {
    userId: user.id,
    email,
  });
  const refreshToken = await createRefreshToken(user.id, resolvedTenantId);

  return {
    ok: true,
    token,
    refreshToken,
    user: { id: user.id, email, walletAddress },
  };
}

function getEmailAuthRedirectBaseUrl(): string {
  return (process.env.EMAIL_AUTH_REDIRECT_BASE_URL || "https://www.elizacloud.ai").replace(
    /\/$/,
    "",
  );
}

function buildEmailAuthRedirectUrl(params?: Record<string, string | undefined>): string {
  const redirectUrl = new URL("/login", `${getEmailAuthRedirectBaseUrl()}/`);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value) redirectUrl.searchParams.set(key, value);
  }
  return redirectUrl.toString();
}

function redirectEmailAuthFailure(c: Context, reason: string): Response {
  return c.redirect(
    buildEmailAuthRedirectUrl({
      error: "email_auth_failed",
      reason,
    }),
    302,
  );
}

// ─── Route group ──────────────────────────────────────────────────────────────

const auth = new Hono();

// ── Discovery ─────────────────────────────────────────────────────────────────

/**
 * GET /providers
 * Public endpoint. Returns which authentication methods are enabled on this
 * server so a client SDK (e.g. @stwd/sdk) can render the right sign-in UI.
 *
 * Passkey/email/SIWE/SIWS are always wired in this build. OAuth providers are
 * advertised when their credentials are configured.
 *
 * Env var resolution mirrors `getProviderConfig` in @stwd/auth/oauth.ts: the
 * canonical names are `<PROVIDER>_CLIENT_ID` / `<PROVIDER>_CLIENT_SECRET`.
 * `STEWARD_OAUTH_<PROVIDER>_CLIENT_ID` is also accepted for backwards-compat
 * with older deployments. Reading only the prefixed form caused production
 * to advertise OAuth as disabled even though the underlying authorize
 * endpoints had working credentials.
 */
auth.get("/providers", (c) => {
  const oauthClientIds: Record<string, string | undefined> = {
    google: process.env.GOOGLE_CLIENT_ID || process.env.STEWARD_OAUTH_GOOGLE_CLIENT_ID,
    discord: process.env.DISCORD_CLIENT_ID || process.env.STEWARD_OAUTH_DISCORD_CLIENT_ID,
    github: process.env.GITHUB_CLIENT_ID || process.env.STEWARD_OAUTH_GITHUB_CLIENT_ID,
    twitter: process.env.TWITTER_CLIENT_ID || process.env.STEWARD_OAUTH_TWITTER_CLIENT_ID,
  };
  const oauth = Object.entries(oauthClientIds)
    .filter(([, value]) => typeof value === "string" && value.trim().length > 0)
    .map(([name]) => name);

  // Returns the providers payload at the top level, NOT wrapped in { ok, data }.
  // The @stwd/sdk authRequest helper returns the full parsed body as `res.data`,
  // so callers like `getProviders()` then read `res.data` and expect the
  // StewardProviders shape directly. Wrapping here in ApiResponse caused the
  // SDK to receive `{ok:true, data: {...providers}}` and treat the wrapper as
  // the provider object: every provider field became undefined and SPAs hid
  // the OAuth buttons even when the credentials were configured.
  // The `ok: true` field is preserved at the top level so older clients that
  // were checking for it keep working.
  return c.json({
    ok: true,
    passkey: true,
    email: true,
    siwe: true,
    siws: true,
    google: oauth.includes("google"),
    discord: oauth.includes("discord"),
    github: oauth.includes("github"),
    twitter: oauth.includes("twitter"),
    oauth,
  });
});

/**
 * GET /test/inbox/:email
 *
 * Test-only endpoint. Returns the most recent magic-link email captured by
 * the in-memory MockEmailProvider. Gated by EMAIL_PROVIDER=mock + non-production
 * — returns 404 in any other configuration so it cannot leak in prod.
 */
auth.get("/test/inbox/:email", (c) => {
  if (!isMockEmailEnabled()) {
    return c.json<ApiResponse>({ ok: false, error: "Not found" }, 404);
  }
  const email = decodeURIComponent(c.req.param("email"));
  const msg = MockEmailInbox.last(email);
  if (!msg) {
    return c.json<ApiResponse>({ ok: false, error: "No message" }, 404);
  }
  return c.json({
    ok: true,
    to: msg.to,
    subject: msg.subject,
    text: msg.text,
    token: msg.token,
    magicLink: msg.magicLink,
    sentAt: msg.sentAt.toISOString(),
  });
});

// ── SIWE ──────────────────────────────────────────────────────────────────────

/**
 * GET /nonce
 * Returns a fresh one-time nonce for SIWE message construction.
 */
auth.get("/nonce", async (c) => {
  const nonce = generateNonce();
  await setSiweNonce(nonce);
  return c.json({ nonce });
});

/**
 * POST /verify
 * Body: { message: string; signature: string }
 * Verifies SIWE, auto-creates tenant (per wallet address), returns JWT.
 *
 * SIWE flow is wallet-address-centric: each unique address gets its own tenant.
 * If X-Steward-Tenant is provided and the tenant exists, the user is also linked
 * to that tenant and the JWT reflects the requested tenant instead.
 */
auth.post("/verify", async (c) => {
  const db = getDb();
  const body = await safeJsonParse<{ message: string; signature: string }>(c);
  if (!body?.message || !body?.signature) {
    return c.json<ApiResponse>({ ok: false, error: "message and signature are required" }, 400);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Lenient EIP-55 path: the `siwe` library strictly enforces EIP-55 checksum
  // on the address line and throws "invalid EIP-55 address" when wallets emit
  // a lower-case address (wagmi default for many adapters, including the most
  // common MetaMask path). The signature is over the EXACT bytes the user
  // signed, so we MUST verify against `body.message` literally, not against a
  // normalized copy. We split the work:
  //   1. Try parsing as-is. If that works, fall through to the canonical path.
  //   2. If parsing fails because of EIP-55 casing, build a normalized copy
  //      with the address line re-checksummed via viem, parse THAT to extract
  //      fields (nonce / domain / chainId / etc), and verify the signature
  //      against the ORIGINAL untouched message with viem's verifyMessage.
  // This preserves cryptographic integrity while accepting SDK clients that
  // forgot to checksum.
  // ──────────────────────────────────────────────────────────────────────────
  function normalizeAddressLine(msg: string): string {
    const lines = msg.split("\n");
    if (lines.length < 2) return msg;
    const candidate = lines[1].trim();
    if (!/^0x[a-fA-F0-9]{40}$/.test(candidate)) return msg;
    try {
      lines[1] = getAddress(candidate);
    } catch {
      // not a valid hex address; let siwe surface the right error
    }
    return lines.join("\n");
  }

  let siweMessage: SiweMessage;
  let usedNormalizedParse = false;
  try {
    siweMessage = new SiweMessage(body.message);
  } catch {
    // Retry with EIP-55 normalized address line.
    try {
      siweMessage = new SiweMessage(normalizeAddressLine(body.message));
      usedNormalizedParse = true;
    } catch {
      return c.json<ApiResponse>({ ok: false, error: "Invalid SIWE message format" }, 400);
    }
  }

  const allowedDomains = getAllowedSiweDomains();
  if (allowedDomains && !allowedDomains.includes(siweMessage.domain)) {
    return c.json<ApiResponse>({ ok: false, error: "SIWE domain not allowed" }, 401);
  }

  const nonceOk = await consumeSiweNonce(siweMessage.nonce);
  if (!nonceOk) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired nonce" }, 401);
  }

  // Enforce SIWE temporal constraints before any signature verification path.
  // siwe.verify() bundles temporal + signature checks together, but that means
  // a signature-only fallback (EIP-1271) would silently bypass time bounds.
  // Check expiration / notBefore first so smart contract wallets cannot use
  // an expired or not-yet-valid message.
  const now = new Date();
  if (siweMessage.expirationTime) {
    const exp = new Date(siweMessage.expirationTime);
    if (Number.isNaN(exp.getTime())) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid expirationTime" }, 401);
    }
    if (now >= exp) {
      return c.json<ApiResponse>({ ok: false, error: "Message expired" }, 401);
    }
  }
  if (siweMessage.notBefore) {
    const nb = new Date(siweMessage.notBefore);
    if (Number.isNaN(nb.getTime())) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid notBefore" }, 401);
    }
    if (now < nb) {
      return c.json<ApiResponse>({ ok: false, error: "Message not yet valid" }, 401);
    }
  }

  // Try EOA verification first (siwe uses ECDSA recover internally). If that
  // fails, fall back to EIP-1271 for smart contract wallets (Safes, Argent, etc).
  //
  // When we used the EIP-55 normalized parse path above, siwe.verify would
  // reconstruct the message FROM the normalized fields and recover against
  // that, which won't match a signature taken over the original lower-case
  // bytes. So in that path we use viem's verifyMessage which verifies the
  // signature against the raw `body.message` literally.
  let eoaVerified = false;
  if (usedNormalizedParse) {
    try {
      eoaVerified = await viemVerifyMessage({
        address: siweMessage.address as `0x${string}`,
        message: body.message,
        signature: body.signature as `0x${string}`,
      });
    } catch {
      eoaVerified = false;
    }
  } else {
    try {
      await siweMessage.verify({ signature: body.signature });
      eoaVerified = true;
    } catch {
      eoaVerified = false;
    }
  }

  if (!eoaVerified) {
    const eip1271Result = await verifyEip1271({
      address: siweMessage.address as `0x${string}`,
      message: body.message,
      signature: body.signature as `0x${string}`,
      chainId: siweMessage.chainId,
    });
    if (!eip1271Result.ok) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid signature" }, 401);
    }
  }

  const address = siweMessage.address.toLowerCase();
  let tenantResult: WalletTenantResult;
  try {
    tenantResult = await findOrCreateWalletTenant({
      ownerAddress: address,
      tenantId: `t-${address.slice(2, 10)}`,
      tenantName: `${address.slice(0, 6)}...${address.slice(-4)}`,
    });
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Failed to create tenant" }, 500);
  }

  const requestedTenantId = c.req.header("X-Steward-Tenant");
  let effectiveTenantId = tenantResult.tenant.id;
  if (requestedTenantId && requestedTenantId !== tenantResult.tenant.id) {
    const [requestedTenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, requestedTenantId));
    if (requestedTenant) {
      effectiveTenantId = requestedTenantId;
    }
  }

  const user = await findOrCreateWalletUser(address, "ethereum");
  await ensureUserTenantLink(
    user.id,
    effectiveTenantId,
    effectiveTenantId === tenantResult.tenant.id ? "owner" : "member",
  );

  const token = await createSessionToken(address, effectiveTenantId, {
    userId: user.id,
  });
  const refreshToken = await createRefreshToken(user.id, effectiveTenantId);

  trackAuditEvent({
    tenantId: effectiveTenantId,
    actorType: "user",
    actorId: user.id,
    action: "auth.login",
    resourceType: "session",
    metadata: { method: "siwe", address, walletChain: "ethereum" },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  const responseData: Record<string, unknown> = {
    ok: true,
    token,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
    userId: user.id,
    address,
    walletChain: "ethereum",
    tenant: { id: tenantResult.tenant.id, name: tenantResult.tenant.name },
  };

  if (tenantResult.isNewTenant && tenantResult.rawApiKey) {
    (responseData.tenant as Record<string, unknown>).apiKey = tenantResult.rawApiKey;
  }

  return c.json(responseData);
});

auth.post("/verify/solana", async (c) => {
  const db = getDb();
  const body = await safeJsonParse<{ message: string; signature: string; publicKey: string }>(c);
  if (!body?.message || !body?.signature || !body?.publicKey) {
    return c.json<ApiResponse>(
      { ok: false, error: "message, signature, and publicKey are required" },
      400,
    );
  }

  const parsed = parseSiwsMessage(body.message);
  if (!parsed) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid SIWS message format" }, 400);
  }

  if (parsed.publicKey !== body.publicKey) {
    return c.json<ApiResponse>(
      { ok: false, error: "publicKey does not match signed message" },
      401,
    );
  }

  const allowedDomains = getAllowedSiweDomains();
  if (allowedDomains && !allowedDomains.includes(parsed.domain)) {
    return c.json<ApiResponse>({ ok: false, error: "SIWS domain not allowed" }, 401);
  }

  if (!isAllowedSiwsUri(parsed.uri, parsed.domain)) {
    return c.json<ApiResponse>({ ok: false, error: "SIWS uri must match the signed domain" }, 401);
  }

  if (parsed.version !== "1") {
    return c.json<ApiResponse>({ ok: false, error: 'SIWS version must be "1"' }, 401);
  }

  if (!isAllowedSiwsChainId(parsed.chainId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "SIWS chainId must be one of: solana, mainnet, devnet" },
      401,
    );
  }

  const nonceOk = await consumeSiweNonce(parsed.nonce);
  if (!nonceOk) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired nonce" }, 401);
  }

  if (!verifySolanaMessageSignature(body.message, body.signature, body.publicKey)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid signature" }, 401);
  }

  let tenantResult: WalletTenantResult;
  try {
    tenantResult = await findOrCreateWalletTenant({
      ownerAddress: `solana:${body.publicKey}`,
      tenantId: `solana:${body.publicKey}`,
      tenantName: `${body.publicKey.slice(0, 4)}...${body.publicKey.slice(-4)}`,
    });
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Failed to create tenant" }, 500);
  }

  const requestedTenantId = c.req.header("X-Steward-Tenant");
  let effectiveTenantId = tenantResult.tenant.id;
  if (requestedTenantId && requestedTenantId !== tenantResult.tenant.id) {
    const [requestedTenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, requestedTenantId));
    if (requestedTenant) {
      effectiveTenantId = requestedTenantId;
    }
  }

  const user = await findOrCreateWalletUser(body.publicKey, "solana");
  await ensureUserTenantLink(
    user.id,
    effectiveTenantId,
    effectiveTenantId === tenantResult.tenant.id ? "owner" : "member",
  );

  const token = await createSessionToken(body.publicKey, effectiveTenantId, {
    userId: user.id,
  });
  const refreshToken = await createRefreshToken(user.id, effectiveTenantId);

  const responseData: Record<string, unknown> = {
    ok: true,
    token,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
    userId: user.id,
    address: body.publicKey,
    publicKey: body.publicKey,
    walletChain: "solana",
    tenant: { id: tenantResult.tenant.id, name: tenantResult.tenant.name },
  };

  if (tenantResult.isNewTenant && tenantResult.rawApiKey) {
    (responseData.tenant as Record<string, unknown>).apiKey = tenantResult.rawApiKey;
  }

  return c.json(responseData);
});

/**
 * GET /session
 * Requires: Authorization: Bearer <token>
 */
auth.get("/session", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return c.json({ authenticated: false });

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);
  if (!payload) return c.json({ authenticated: false });

  return c.json({
    authenticated: true,
    address: payload.address,
    tenantId: payload.tenantId,
    ...(payload.email ? { email: payload.email } : {}),
    ...(payload.userId ? { userId: payload.userId } : {}),
  });
});

/**
 * POST /logout
 * Revokes the presented access token's JTI until its natural expiry. Refresh
 * token revocation is handled by /refresh/revoke and /refresh/revoke-all.
 */
auth.post("/logout", async (c) => {
  const authHeader = c.req.header("Authorization");
  let auditCtx: { tenantId?: string; userId?: string; jti?: string } = {};
  if (authHeader?.startsWith("Bearer ")) {
    try {
      const payload = (await verifyToken(authHeader.slice(7))) as {
        jti?: string;
        exp?: number;
        userId?: string;
        tenantId?: string;
      };
      if (typeof payload.jti === "string" && typeof payload.exp === "number") {
        await revocationStore.revokeToken(payload.jti, payload.exp);
        auditCtx = {
          tenantId: payload.tenantId,
          userId: payload.userId,
          jti: payload.jti,
        };
      }
    } catch {
      // Logout remains idempotent: invalid/expired tokens are already unusable.
    }
  }
  if (auditCtx.tenantId) {
    trackAuditEvent({
      tenantId: auditCtx.tenantId,
      actorType: "user",
      actorId: auditCtx.userId ?? null,
      action: "auth.logout",
      resourceType: "session",
      resourceId: auditCtx.jti ?? null,
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  }
  return c.json<ApiResponse>({ ok: true });
});

/**
 * POST /refresh
 * Body: { refreshToken: string }
 * Validates the refresh token, rotates it (one-time use), issues new access + refresh tokens.
 * Supports silent re-auth without user interaction when the access token nears expiry.
 */
auth.post("/refresh", async (c) => {
  const rl = await checkAuthRateLimit(c, "refresh", 60_000, 30);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many requests. Please try again later." },
      429,
    );
  }
  const body = await safeJsonParse<{ refreshToken: string }>(c);
  if (!body?.refreshToken) {
    return c.json<ApiResponse>({ ok: false, error: "refreshToken is required" }, 400);
  }

  const record = await consumeRefreshToken(body.refreshToken);
  if (!record) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired refresh token" }, 401);
  }

  const db = getDb();

  // Fetch user for token claims
  const [user] = await db.select().from(users).where(eq(users.id, record.userId));
  const walletAddress = user?.walletAddress ?? "";
  const email = user?.email ?? undefined;

  // Issue new access token (24h)
  const newAccessToken = await createSessionToken(walletAddress, record.tenantId, {
    userId: record.userId,
    ...(email ? { email } : {}),
  });

  // Issue new refresh token (rotation)
  const newRefreshToken = await createRefreshToken(record.userId, record.tenantId);

  return c.json({
    ok: true,
    token: newAccessToken,
    refreshToken: newRefreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
  });
});

/**
 * POST /revoke
 * Body: { refreshToken: string }
 * Revokes a specific refresh token (sign out from this session/device).
 */
auth.post("/revoke", async (c) => {
  const body = await safeJsonParse<{ refreshToken: string }>(c);
  if (!body?.refreshToken) {
    return c.json<ApiResponse>({ ok: false, error: "refreshToken is required" }, 400);
  }

  const db = getDb();
  await db.delete(refreshTokens).where(eq(refreshTokens.tokenHash, hashToken(body.refreshToken)));

  return c.json<ApiResponse>({ ok: true });
});

/**
 * DELETE /sessions
 * Requires: Authorization: Bearer <access-token>
 * Revokes ALL refresh tokens for the authenticated user (sign out everywhere / all devices).
 */
auth.delete("/sessions", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json<ApiResponse>({ ok: false, error: "Authorization header required" }, 401);
  }

  const payload = await verifySessionToken(authHeader.slice(7));
  if (!payload) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired token" }, 401);
  }

  if (!payload.userId) {
    return c.json<ApiResponse>({ ok: false, error: "Token does not contain userId" }, 400);
  }

  const db = getDb();
  await db.delete(refreshTokens).where(eq(refreshTokens.userId, payload.userId));

  return c.json<ApiResponse>({ ok: true });
});

// ── Passkey registration ───────────────────────────────────────────────────────

/**
 * POST /passkey/register/options
 * Body: { email }
 * Finds or creates user, returns WebAuthn registration options.
 */
auth.post("/passkey/register/options", async (c) => {
  const body = await safeJsonParse<{
    email: string;
    authenticatorAttachment?: "platform" | "cross-platform";
  }>(c);
  if (!body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const user = await findOrCreateUser(email);

  const db = getDb();
  const existingCreds = await db
    .select({ credentialId: authenticators.credentialId })
    .from(authenticators)
    .where(eq(authenticators.userId, user.id));

  const attachment =
    body.authenticatorAttachment === "platform" || body.authenticatorAttachment === "cross-platform"
      ? body.authenticatorAttachment
      : undefined;

  const options = await getPasskeyAuth(c.req.header("origin")).generateRegistrationOptions(
    user.id,
    email,
    existingCreds.map((cred) => cred.credentialId),
    attachment ? { authenticatorAttachment: attachment } : undefined,
  );

  return c.json(options);
});

/**
 * POST /passkey/register/verify
 * Body: { email, response, tenantId? }
 * Headers: X-Steward-Tenant (optional)
 * Verifies registration, stores credential, provisions wallet, returns JWT.
 */
auth.post("/passkey/register/verify", async (c) => {
  const rl = await checkAuthRateLimit(c, "passkey-verify", 60_000, 10);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many requests. Please try again later." },
      429,
    );
  }
  const body = await safeJsonParse<{
    email: string;
    response: Record<string, unknown>;
    tenantId?: string;
  }>(c);

  if (!body?.email || !body?.response) {
    return c.json<ApiResponse>({ ok: false, error: "email and response are required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const db = getDb();

  const [user] = await db.select().from(users).where(eq(users.email, email));
  if (!user) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "User not found — call /passkey/register/options first",
      },
      404,
    );
  }

  let verification: Awaited<ReturnType<PasskeyAuth["verifyRegistration"]>>;
  try {
    verification = await getPasskeyAuth(c.req.header("origin")).verifyRegistration(
      user.id,
      body.response as unknown as Parameters<PasskeyAuth["verifyRegistration"]>[1],
    );
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Verification failed",
      },
      400,
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json<ApiResponse>({ ok: false, error: "Registration verification failed" }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

  await db
    .insert(authenticators)
    .values({
      userId: user.id,
      credentialId: credential.id,
      credentialPublicKey: uint8ArrayToBase64url(credential.publicKey),
      counter: credential.counter,
      credentialDeviceType,
      credentialBackedUp,
      transports:
        (body.response.response as { transports?: string[] } | undefined)?.transports ?? [],
    })
    .onConflictDoNothing();

  await db.update(users).set({ emailVerified: true }).where(eq(users.id, user.id));

  // Provision the user's personal wallet (idempotent)
  let walletAddress = user.walletAddress;
  try {
    const w = await provisionWalletForUser(user.id, email);
    walletAddress = w.walletAddress;
  } catch (err) {
    console.error("[PasskeyAuth] Wallet provision failed on register:", err);
  }

  // Resolve which tenant this auth is for and link the user
  const tenantResult = await resolveAndValidateTenant(c, user.id, body.tenantId);
  if (!tenantResult.ok) {
    return c.json<ApiResponse>({ ok: false, error: tenantResult.error }, tenantResult.status);
  }
  const { tenantId } = tenantResult;
  await ensureUserTenantLink(user.id, tenantId);

  const token = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });
  const registerRefreshToken = await createRefreshToken(user.id, tenantId);

  return c.json(
    buildAuthResponse(token, registerRefreshToken, {
      id: user.id,
      email,
      walletAddress,
    }),
  );
});

// ── Passkey authentication ────────────────────────────────────────────────────

/**
 * POST /passkey/login/options
 * Body: { email }
 * Returns WebAuthn authentication options with allowed credentials.
 */
auth.post("/passkey/login/options", async (c) => {
  const body = await safeJsonParse<{ email: string }>(c);
  if (!body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const db = getDb();

  const [user] = await db.select().from(users).where(eq(users.email, email));
  if (!user) {
    return c.json<ApiResponse>({ ok: false, error: "No account found for this email" }, 404);
  }

  // Select transports alongside credentialId. WebAuthn browsers use the
  // transports hint to know that a credential lives on the local platform
  // authenticator (e.g. Touch ID, Windows Hello). Without it the browser
  // conservatively shows the cross-device QR picker even for credentials
  // that were registered on this device, which is a major UX regression.
  const creds = await db
    .select({
      credentialId: authenticators.credentialId,
      transports: authenticators.transports,
    })
    .from(authenticators)
    .where(eq(authenticators.userId, user.id));

  if (creds.length === 0) {
    return c.json<ApiResponse>({ ok: false, error: "No passkeys registered for this email" }, 404);
  }

  const options = await getPasskeyAuth(c.req.header("origin")).generateAuthenticationOptions(
    email,
    {
      allowCredentials: creds.map((cred) => ({
        id: cred.credentialId,
        ...(cred.transports && cred.transports.length > 0
          ? { transports: cred.transports as AuthenticatorTransportFuture[] }
          : {}),
      })),
    },
  );

  return c.json(options);
});

/**
 * POST /passkey/login/verify
 * Body: { email, response, tenantId? }
 * Headers: X-Steward-Tenant (optional)
 * Verifies authentication, updates counter, links user to tenant, returns JWT.
 */
auth.post("/passkey/login/verify", async (c) => {
  const rl = await checkAuthRateLimit(c, "passkey-verify", 60_000, 10);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many requests. Please try again later." },
      429,
    );
  }
  const body = await safeJsonParse<{
    email: string;
    response: { id: string; [key: string]: unknown };
    tenantId?: string;
  }>(c);

  if (!body?.email || !body?.response) {
    return c.json<ApiResponse>({ ok: false, error: "email and response are required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const db = getDb();

  const [user] = await db.select().from(users).where(eq(users.email, email));
  if (!user) {
    return c.json<ApiResponse>({ ok: false, error: "User not found" }, 404);
  }

  const [cred] = await db
    .select()
    .from(authenticators)
    .where(
      and(eq(authenticators.userId, user.id), eq(authenticators.credentialId, body.response.id)),
    );

  if (!cred) {
    return c.json<ApiResponse>({ ok: false, error: "Credential not found" }, 404);
  }

  let verification: Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>;
  try {
    verification = await getPasskeyAuth(c.req.header("origin")).verifyAuthentication(
      body.response as unknown as Parameters<PasskeyAuth["verifyAuthentication"]>[0],
      undefined,
      cred.credentialPublicKey,
      cred.counter,
      email,
    );
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Authentication failed",
      },
      400,
    );
  }

  if (!verification.verified) {
    return c.json<ApiResponse>({ ok: false, error: "Authentication verification failed" }, 401);
  }

  // Update counter to prevent replay attacks
  await db
    .update(authenticators)
    .set({ counter: verification.authenticationInfo.newCounter })
    .where(eq(authenticators.id, cred.id));

  // Ensure wallet is provisioned (idempotent)
  let walletAddress = user.walletAddress;
  if (!walletAddress) {
    try {
      const w = await provisionWalletForUser(user.id, email);
      walletAddress = w.walletAddress;
    } catch (err) {
      console.error("[PasskeyAuth] Wallet provision failed on login:", err);
    }
  } else {
    // Wallet exists — still ensure personal tenant is in place
    await ensurePersonalTenant(user.id, email);
  }

  // Resolve the requesting tenant and auto-link if user isn't already a member
  const tenantResult = await resolveAndValidateTenant(c, user.id, body.tenantId);
  if (!tenantResult.ok) {
    return c.json<ApiResponse>({ ok: false, error: tenantResult.error }, tenantResult.status);
  }
  const { tenantId } = tenantResult;
  await ensureUserTenantLink(user.id, tenantId);

  const token = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });
  const loginRefreshToken = await createRefreshToken(user.id, tenantId);

  return c.json(
    buildAuthResponse(token, loginRefreshToken, {
      id: user.id,
      email,
      walletAddress,
    }),
  );
});

// ── Email magic link ──────────────────────────────────────────────────────────

/**
 * POST /email/send
 * Body: { email, tenantId? }
 * Sends a magic link email, returns expiry time.
 */
auth.post("/email/send", async (c) => {
  const rl = await checkAuthRateLimit(c, "email-send", 60_000, 3);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many requests. Please try again later." },
      429,
    );
  }
  const body = await safeJsonParse<{ email: string; tenantId?: string }>(c);
  if (!body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const resolvedTenantId = c.req.header("X-Steward-Tenant") || body.tenantId || _DEFAULT_TENANT_ID;
  const emailAuth = await getEmailAuthForTenant(resolvedTenantId);
  const { expiresAt } = await emailAuth.sendMagicLink(email);

  return c.json<ApiResponse<{ expiresAt: string }>>({
    ok: true,
    data: { expiresAt: expiresAt.toISOString() },
  });
});

/**
 * GET /callback/email
 * Query: ?token=<token>&email=<email>&tenantId=<tenantId?>
 * Mirrors POST /email/verify for browser clicks from magic link emails,
 * but redirects to the dashboard login page instead of returning JSON.
 */
auth.get("/callback/email", async (c) => {
  const token = c.req.query("token");
  const emailParam = c.req.query("email");
  const tenantId = c.req.query("tenantId");

  if (!token || !emailParam) {
    return redirectEmailAuthFailure(c, "missing_params");
  }

  const email = emailParam.toLowerCase().trim();

  let result: Awaited<ReturnType<EmailAuth["verifyMagicLink"]>>;
  try {
    const emailAuth = await getEmailAuthForTenant(tenantId || _DEFAULT_TENANT_ID);
    result = await emailAuth.verifyMagicLink(token);
  } catch {
    return redirectEmailAuthFailure(c, "invalid_link");
  }

  if (!result.valid) {
    return redirectEmailAuthFailure(c, "invalid_link");
  }

  if (result.email.toLowerCase().trim() !== email) {
    return redirectEmailAuthFailure(c, "email_mismatch");
  }

  const authResult = await completeEmailAuth(c, email, tenantId);
  if (!authResult.ok) {
    const reason = authResult.status === 404 ? "tenant_not_found" : "tenant_forbidden";
    return redirectEmailAuthFailure(c, reason);
  }

  return c.redirect(
    buildEmailAuthRedirectUrl({
      token: authResult.token,
      refreshToken: authResult.refreshToken,
    }),
    302,
  );
});

/**
 * POST /email/verify
 * Body: { token, email, tenantId? }
 * Headers: X-Steward-Tenant (optional)
 * Verifies the magic link token, provisions user + wallet, links to tenant, returns JWT.
 */
auth.post("/email/verify", async (c) => {
  const body = await safeJsonParse<{
    token: string;
    email: string;
    tenantId?: string;
  }>(c);
  if (!body?.token || !body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "token and email are required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const resolvedTenantId = c.req.header("X-Steward-Tenant") || body.tenantId || _DEFAULT_TENANT_ID;
  const emailAuth = await getEmailAuthForTenant(resolvedTenantId);
  const result = await emailAuth.verifyMagicLink(body.token);

  if (!result.valid || result.email.toLowerCase().trim() !== email) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired magic link" }, 401);
  }

  const authResult = await completeEmailAuth(c, email, body.tenantId);
  if (!authResult.ok) {
    return c.json<ApiResponse>({ ok: false, error: authResult.error }, authResult.status);
  }

  return c.json(buildAuthResponse(authResult.token, authResult.refreshToken, authResult.user));
});

// ── OAuth authorization-code flow ─────────────────────────────────────────────

/**
 * GET /oauth/:provider/authorize
 * Query: ?redirect_uri=<url>&tenant_id=<id>
 *
 * Generates an OAuth authorization URL, stores the CSRF state in the challenge
 * store (keyed as `oauth:<state>`), then redirects the user to the provider.
 */
auth.get("/oauth/:provider/authorize", async (c) => {
  const providerName = c.req.param("provider");
  if (!isBuiltInProvider(providerName)) {
    return c.json<ApiResponse>({ ok: false, error: `Unknown provider: ${providerName}` }, 400);
  }

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Provider not configured",
      },
      503,
    );
  }

  const redirectUri = c.req.query("redirect_uri");
  // Accept both `tenant_id` (snake_case, canonical) and `tenantId` (camelCase)
  // so integrators sending either shape land on the right tenant. Whitespace
  // is trimmed defensively for the same reason we trim headers elsewhere.
  const tenantId = c.req.query("tenant_id")?.trim() || c.req.query("tenantId")?.trim() || undefined;

  // `response_type=code` opts the caller into the nonce-exchange flow. Instead
  // of leaking `?token=...&refreshToken=...` in the redirect URL (which gets
  // captured by browser history, server access logs, Referer headers from any
  // resource the landing page loads, and the user clipboard), the callback
  // issues a one-time `?code=<nonce>` that the caller's backend exchanges for
  // the real tokens server-side via POST /oauth/exchange. Legacy callers that
  // omit response_type still get the token-in-query redirect for one release.
  const responseType = c.req.query("response_type")?.trim() || undefined;

  if (!redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "redirect_uri is required" }, 400);
  }

  try {
    await assertAllowedOAuthRedirectUri(redirectUri, tenantId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirect_uri" },
      400,
    );
  }

  if (responseType !== undefined && responseType !== "code" && responseType !== "token") {
    return c.json<ApiResponse>(
      { ok: false, error: "response_type must be 'code' or 'token'" },
      400,
    );
  }

  // Generate a cryptographically random state value
  const stateBytes = new Uint8Array(16);
  crypto.getRandomValues(stateBytes);
  const state = Array.from(stateBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const callbackUrl = buildOAuthCallbackUrl(c, providerName);
  const { url: authUrl, codeVerifier } = oauthClient.generateAuthUrl(state, callbackUrl);

  // Store state metadata in the challenge store — include PKCE verifier when present
  const statePayload = JSON.stringify({
    provider: providerName,
    tenantId,
    redirectUri,
    responseType,
    ...(codeVerifier ? { codeVerifier } : {}),
  });
  getChallengeStore().set(`oauth:${state}`, statePayload);

  return c.redirect(authUrl, 302);
});

/**
 * GET /oauth/:provider/callback
 * Handles the redirect from the OAuth provider.
 *
 * Flow:
 *   1. Validate state (CSRF)
 *   2. Exchange code for access token
 *   3. Fetch user profile from provider
 *   4. Find/create user by email
 *   5. Upsert entry in `accounts` table
 *   6. Link user to requested tenant
 *   7. Mint JWT → redirect to app redirect_uri with ?token=<jwt>
 */
auth.get("/oauth/:provider/callback", async (c) => {
  const providerName = c.req.param("provider");
  const code = c.req.query("code");
  const state = c.req.query("state");
  const errorParam = c.req.query("error");

  if (errorParam) {
    return c.json<ApiResponse>({ ok: false, error: `OAuth error: ${errorParam}` }, 400);
  }

  if (!isBuiltInProvider(providerName)) {
    return c.json<ApiResponse>({ ok: false, error: `Unknown provider: ${providerName}` }, 400);
  }

  if (!code || !state) {
    return c.json<ApiResponse>({ ok: false, error: "code and state are required" }, 400);
  }

  // Validate and consume the state (one-time use)
  const rawPayload = await getChallengeStore().consume(`oauth:${state}`);
  if (!rawPayload) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired OAuth state" }, 401);
  }

  let stateData: {
    provider: string;
    tenantId?: string;
    redirectUri: string;
    responseType?: string;
    codeVerifier?: string;
  };
  try {
    stateData = JSON.parse(rawPayload) as typeof stateData;
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Malformed OAuth state payload" }, 400);
  }

  if (stateData.provider !== providerName) {
    return c.json<ApiResponse>({ ok: false, error: "Provider mismatch in state" }, 400);
  }

  let redirectUrl: URL;
  try {
    redirectUrl = await assertAllowedOAuthRedirectUri(stateData.redirectUri, stateData.tenantId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirect_uri" },
      400,
    );
  }

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Provider not configured",
      },
      503,
    );
  }

  const callbackUrl = buildOAuthCallbackUrl(c, providerName);

  // Exchange code for access token — pass codeVerifier for PKCE providers (e.g. Twitter)
  let tokenResponse: Awaited<ReturnType<OAuthClient["exchangeCode"]>>;
  try {
    tokenResponse = await oauthClient.exchangeCode(code, callbackUrl, stateData.codeVerifier);
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Token exchange failed",
      },
      502,
    );
  }

  // Fetch user info from provider
  let providerUser: Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
  try {
    providerUser = await oauthClient.getUserInfo(tokenResponse.access_token);
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Failed to fetch user info",
      },
      502,
    );
  }

  // Twitter and some providers do not return an email address.
  // Generate a synthetic internal email so findOrCreateUser() can still work.
  // This email is never displayed or sent — it is purely an internal identity key.
  if (!providerUser.email) {
    if (!providerUser.id) {
      return c.json<ApiResponse>(
        { ok: false, error: "Provider returned neither email nor user ID" },
        400,
      );
    }
    providerUser = {
      ...providerUser,
      email: `${providerName}.${providerUser.id}@id.steward.internal`,
    };
  }

  // Create/find user + provision wallet + link tenant
  const result = await provisionOAuthUser({
    c,
    providerName,
    providerUser,
    tokenResponse,
    tenantId: stateData.tenantId,
  });

  if (!result.ok) {
    return c.json<ApiResponse>({ ok: false, error: result.error }, 500);
  }

  // Branch: nonce-exchange (`response_type=code`) vs legacy token-in-query.
  //
  // Nonce-exchange path: issue a one-time, short-lived (60s) code that the
  // caller's backend trades for the real tokens via POST /oauth/exchange.
  // This keeps the tokens off the address bar / browser history / Referer /
  // upstream access logs / any window the user copy-pastes. The pair
  // {redirectUri, tenantId} is bound to the code so a stolen code cannot be
  // redeemed against a different redirect_uri or pivoted to another tenant.
  if (stateData.responseType === "code") {
    const nonceBytes = new Uint8Array(32);
    crypto.getRandomValues(nonceBytes);
    const code = uint8ArrayToBase64url(nonceBytes);
    const issuedAt = Date.now();
    const expiresAt = issuedAt + OAUTH_CODE_TTL_MS;
    const codePayload = JSON.stringify({
      token: result.token,
      refreshToken: result.refreshToken,
      redirectUri: stateData.redirectUri,
      tenantId: stateData.tenantId ?? null,
      expiresAt,
      expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
    });
    getOAuthCodeStore().set(`oauth-code:${code}`, codePayload);
    redirectUrl.searchParams.set("code", code);
    return c.redirect(redirectUrl.toString(), 302);
  }

  // Legacy: redirect with tokens directly in the query string. Kept for one
  // release cycle so existing integrators don't break. Mark for removal in a
  // follow-up once all callers have moved to `response_type=code`.
  redirectUrl.searchParams.set("token", result.token);
  redirectUrl.searchParams.set("refreshToken", result.refreshToken);
  return c.redirect(redirectUrl.toString(), 302);
});

/**
 * POST /auth/oauth/exchange
 *
 * Nonce-exchange endpoint for the `response_type=code` OAuth flow above.
 * Trades a one-time `code` for the real `{token, refreshToken, expiresAt}`
 * payload. The code is bound to the `redirect_uri` and `tenant_id` that were
 * supplied at /authorize time; both must match or the exchange is rejected.
 *
 * Body: { code: string; redirect_uri: string; tenant_id?: string | null }
 * Returns 200 { ok: true, token, refreshToken, expiresIn, expiresAt }
 * Errors:
 *   400 invalid_request        — missing/blank `code` or `redirect_uri`
 *   401 code_invalid           — unknown / already-consumed / expired code
 *   401 code_expired           — found but past `expiresAt` (defense-in-depth;
 *                                the store TTL already evicts these)
 *   401 code_redirect_mismatch — `redirect_uri` does not match
 *   401 code_tenant_mismatch   — `tenant_id` does not match
 *
 * The code is consumed (deleted) on the FIRST lookup, before any validation,
 * so a redirect_uri / tenant mismatch still burns the nonce. This prevents an
 * attacker who guesses or steals a code from probing for the bound redirect.
 */
auth.post("/oauth/exchange", async (c) => {
  const body = await safeJsonParse<{
    code?: unknown;
    redirect_uri?: unknown;
    redirectUri?: unknown;
    tenant_id?: unknown;
    tenantId?: unknown;
  }>(c);

  const code = typeof body?.code === "string" ? body.code.trim() : "";
  const redirectUri =
    typeof body?.redirect_uri === "string"
      ? body.redirect_uri.trim()
      : typeof body?.redirectUri === "string"
        ? body.redirectUri.trim()
        : "";
  const rawTenantId =
    typeof body?.tenant_id === "string"
      ? body.tenant_id.trim()
      : typeof body?.tenantId === "string"
        ? body.tenantId.trim()
        : "";
  const tenantId = rawTenantId.length > 0 ? rawTenantId : null;

  if (!code || !redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "code and redirect_uri are required" }, 400);
  }

  // One-shot consume — even on mismatch, the code is burned so an attacker
  // cannot retry with corrected parameters.
  const raw = await getOAuthCodeStore().consume(`oauth-code:${code}`);
  if (!raw) {
    return c.json<ApiResponse & { code: string }>(
      { ok: false, error: "Invalid or already-used code", code: "code_invalid" },
      401,
    );
  }

  let payload: {
    token: string;
    refreshToken: string;
    redirectUri: string;
    tenantId: string | null;
    expiresAt: number;
    expiresIn: number;
  };
  try {
    payload = JSON.parse(raw);
  } catch {
    return c.json<ApiResponse & { code: string }>(
      { ok: false, error: "Malformed code payload", code: "code_invalid" },
      401,
    );
  }

  if (Date.now() > payload.expiresAt) {
    return c.json<ApiResponse & { code: string }>(
      { ok: false, error: "Code expired", code: "code_expired" },
      401,
    );
  }

  if (payload.redirectUri !== redirectUri) {
    return c.json<ApiResponse & { code: string }>(
      {
        ok: false,
        error: "redirect_uri does not match the one issued with the code",
        code: "code_redirect_mismatch",
      },
      401,
    );
  }

  if ((payload.tenantId ?? null) !== tenantId) {
    return c.json<ApiResponse & { code: string }>(
      {
        ok: false,
        error: "tenant_id does not match the one issued with the code",
        code: "code_tenant_mismatch",
      },
      401,
    );
  }

  return c.json({
    ok: true,
    token: payload.token,
    refreshToken: payload.refreshToken,
    expiresIn: payload.expiresIn,
    expiresAt: payload.expiresAt,
  });
});

/**
 * POST /oauth/:provider/token
 * SPA / popup flow — the client has already obtained the code.
 *
 * Body: { code: string; redirectUri: string; tenantId?: string; codeVerifier?: string }
 * Returns: { ok: true; token: string; user: { id, email, walletAddress } }
 */
auth.post("/oauth/:provider/token", async (c) => {
  const providerName = c.req.param("provider");
  if (!isBuiltInProvider(providerName)) {
    return c.json<ApiResponse>({ ok: false, error: `Unknown provider: ${providerName}` }, 400);
  }

  const body = await safeJsonParse<{
    code: string;
    redirectUri: string;
    tenantId?: string;
    codeVerifier?: string;
  }>(c);

  if (!body?.code || !body?.redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "code and redirectUri are required" }, 400);
  }

  const requestedTenantId =
    body.tenantId?.trim() || c.req.header("X-Steward-Tenant")?.trim() || undefined;
  try {
    await assertAllowedOAuthRedirectUri(body.redirectUri, requestedTenantId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Invalid redirectUri" },
      400,
    );
  }

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Provider not configured",
      },
      503,
    );
  }

  let tokenResponse: Awaited<ReturnType<OAuthClient["exchangeCode"]>>;
  try {
    tokenResponse = await oauthClient.exchangeCode(body.code, body.redirectUri, body.codeVerifier);
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Token exchange failed",
      },
      502,
    );
  }

  let providerUser: Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
  try {
    providerUser = await oauthClient.getUserInfo(tokenResponse.access_token);
  } catch (err) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Failed to fetch user info",
      },
      502,
    );
  }

  // Twitter and some providers do not return an email address.
  // Generate a synthetic internal email so findOrCreateUser() can still work.
  if (!providerUser.email) {
    if (!providerUser.id) {
      return c.json<ApiResponse>(
        { ok: false, error: "Provider returned neither email nor user ID" },
        400,
      );
    }
    providerUser = {
      ...providerUser,
      email: `${providerName}.${providerUser.id}@id.steward.internal`,
    };
  }

  const result = await provisionOAuthUser({
    c,
    providerName,
    providerUser,
    tokenResponse,
    tenantId: body.tenantId,
  });

  if (!result.ok) {
    return c.json<ApiResponse>({ ok: false, error: result.error }, 500);
  }

  return c.json(
    buildAuthResponse(result.token, result.refreshToken, result.user as Record<string, unknown>),
  );
});

// ─── OAuth helper: provision user + account + tenant link ─────────────────────

type OAuthUserInfo = Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
type OAuthTokenResponse = Awaited<ReturnType<OAuthClient["exchangeCode"]>>;

async function provisionOAuthUser(opts: {
  c: Context;
  providerName: string;
  providerUser: OAuthUserInfo;
  tokenResponse: OAuthTokenResponse;
  tenantId?: string;
}): Promise<
  | {
      ok: true;
      token: string;
      refreshToken: string;
      user: { id: string; email: string; walletAddress?: string | null };
    }
  | { ok: false; error: string }
> {
  const { c, providerName, providerUser, tokenResponse, tenantId } = opts;
  const db = getDb();
  const email = providerUser.email.toLowerCase().trim();

  try {
    // 1. Find or create global user record
    const user = await findOrCreateUser(email);

    // Update name/image if we have richer data from the provider and the user doesn't have it yet
    const updates: Partial<typeof users.$inferInsert> = {};
    if (!user.name && providerUser.name) updates.name = providerUser.name;
    if (!user.image && providerUser.picture) updates.image = providerUser.picture;
    if (!user.emailVerified && providerUser.verified_email) updates.emailVerified = true;
    if (Object.keys(updates).length > 0) {
      await db.update(users).set(updates).where(eq(users.id, user.id));
    }

    // 2. Upsert the OAuth account link (provider + providerAccountId → user).
    // Provider tokens are stored encrypted with the deployment master password.
    // If STEWARD_MASTER_PASSWORD changes, operators must run a decrypt +
    // re-encrypt rotation pass before switching the application to the new
    // password, otherwise existing OAuth provider tokens cannot be decrypted.
    const encryptedProviderTokens = encryptOAuthProviderTokens(
      tokenResponse.access_token,
      tokenResponse.refresh_token ?? null,
    );
    await db
      .insert(accounts)
      .values({
        userId: user.id,
        provider: providerName,
        providerAccountId: providerUser.id,
        ...encryptedProviderTokens,
        expiresAt: tokenResponse.expires_in
          ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
          : null,
      })
      .onConflictDoUpdate({
        target: [accounts.provider, accounts.providerAccountId],
        set: {
          userId: user.id,
          ...encryptedProviderTokens,
          expiresAt: tokenResponse.expires_in
            ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
            : null,
        },
      });

    // 3. Provision personal wallet (idempotent)
    let walletAddress = user.walletAddress;
    try {
      const w = await provisionWalletForUser(user.id, email);
      walletAddress = w.walletAddress;
    } catch (err) {
      console.error(`[OAuthAuth:${providerName}] Wallet provision failed:`, err);
    }

    // 4. Resolve requesting tenant and link user
    const tenantResult = await resolveAndValidateTenant(c, user.id, tenantId);
    if (!tenantResult.ok) {
      return { ok: false as const, error: tenantResult.error };
    }
    const resolvedTenantId = tenantResult.tenantId;
    await ensureUserTenantLink(user.id, resolvedTenantId);

    // 5. Mint JWT + refresh token
    const token = await createSessionToken(walletAddress ?? "", resolvedTenantId, {
      userId: user.id,
      email,
    });
    const oauthRefreshToken = await createRefreshToken(user.id, resolvedTenantId);

    return {
      ok: true,
      token,
      refreshToken: oauthRefreshToken,
      user: { id: user.id, email, walletAddress },
    };
  } catch (err) {
    console.error(`[OAuthAuth:${providerName}] provisionOAuthUser failed:`, err);
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Internal server error",
    };
  }
}

/**
 * Build the canonical OAuth callback URL for the given provider.
 * Uses the APP_URL env var (preferred) or reconstructs from the request host.
 */
function buildOAuthCallbackUrl(c: Context, providerName: string): string {
  const appUrl = process.env.APP_URL
    ? process.env.APP_URL.replace(/\/$/, "")
    : `${c.req.header("x-forwarded-proto") ?? "https"}://${c.req.header("host") ?? "localhost"}`;
  return `${appUrl}/auth/oauth/${providerName}/callback`;
}

const OAUTH_REDIRECT_ALLOWLIST_ENV_KEYS = [
  "STEWARD_OAUTH_ALLOWED_REDIRECTS",
  "STEWARD_OAUTH_REDIRECT_ALLOWLIST",
] as const;

function parseOAuthRedirectAllowlistEnv(): string[] {
  const entries = new Set<string>();

  for (const envName of OAUTH_REDIRECT_ALLOWLIST_ENV_KEYS) {
    const raw = process.env[envName];
    if (!raw) continue;

    for (const entry of raw.split(",")) {
      const trimmed = entry.trim();
      if (trimmed && trimmed !== "*") {
        entries.add(trimmed);
      }
    }
  }

  return [...entries];
}

function parseOAuthRedirectUri(redirectUri: string): URL {
  let redirectUrl: URL;
  try {
    redirectUrl = new URL(redirectUri);
  } catch {
    throw new Error("redirect_uri must be a valid absolute URL");
  }

  if (redirectUrl.protocol !== "https:" && redirectUrl.protocol !== "http:") {
    throw new Error("redirect_uri must use http or https");
  }

  if (redirectUrl.username || redirectUrl.password) {
    throw new Error("redirect_uri must not contain credentials");
  }

  return redirectUrl;
}

function isOAuthRedirectEntryMatch(redirectUrl: URL, allowedEntry: string): boolean {
  let allowedUrl: URL;
  try {
    allowedUrl = new URL(allowedEntry);
  } catch {
    return false;
  }

  if (allowedUrl.protocol !== "https:" && allowedUrl.protocol !== "http:") {
    return false;
  }

  const isOriginOnly =
    allowedUrl.pathname === "/" && !allowedUrl.search && !allowedUrl.hash && !allowedUrl.username;

  if (isOriginOnly) {
    return allowedUrl.origin === redirectUrl.origin;
  }

  return (
    allowedUrl.origin === redirectUrl.origin &&
    allowedUrl.pathname === redirectUrl.pathname &&
    allowedUrl.search === redirectUrl.search
  );
}

async function getAllowedOAuthRedirectEntries(tenantId?: string): Promise<string[]> {
  const entries = new Set(parseOAuthRedirectAllowlistEnv());
  const resolvedTenantId = tenantId?.trim() || _DEFAULT_TENANT_ID;

  const [row] = await getDb()
    .select({ allowedOrigins: tenantConfigs.allowedOrigins })
    .from(tenantConfigs)
    .where(eq(tenantConfigs.tenantId, resolvedTenantId));

  for (const origin of row?.allowedOrigins ?? []) {
    const trimmed = origin.trim();
    if (trimmed && trimmed !== "*") {
      entries.add(trimmed);
    }
  }

  return [...entries];
}

async function assertAllowedOAuthRedirectUri(redirectUri: string, tenantId?: string): Promise<URL> {
  const redirectUrl = parseOAuthRedirectUri(redirectUri);
  const allowlist = await getAllowedOAuthRedirectEntries(tenantId);

  if (allowlist.length === 0) {
    throw new Error(
      "OAuth redirect_uri allowlist is not configured for this tenant. Configure tenant allowedOrigins or STEWARD_OAUTH_ALLOWED_REDIRECTS.",
    );
  }

  if (!allowlist.some((entry) => isOAuthRedirectEntryMatch(redirectUrl, entry))) {
    throw new Error("redirect_uri is not allowed for this tenant");
  }

  return redirectUrl;
}

export { auth as authRoutes };
