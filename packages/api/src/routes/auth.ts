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

import { and, eq } from "drizzle-orm";
import { createHash, randomBytes } from "node:crypto";
import { Hono, type Context } from "hono";
import { SignJWT, jwtVerify } from "jose";
import { generateNonce, SiweMessage } from "siwe";

import {
  EmailAuth,
  PasskeyAuth,
  ResendProvider,
  generateApiKey,
  uint8ArrayToBase64url,
  ChallengeStore,
  TokenStore,
  buildBackend,
  OAuthClient,
  getProviderConfig,
  getEnabledProviders,
  isBuiltInProvider,
} from "@stwd/auth";
import { accounts, authenticators, getDb, refreshTokens, tenants, tenantConfigs, userTenants, users } from "@stwd/db";
import type { ApiResponse } from "@stwd/shared";
import { Vault, provisionUserWallet } from "@stwd/vault";

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TENANT_ID = process.env.STEWARD_DEFAULT_TENANT_ID || "default";

// ─── IP-based auth rate limiting ─────────────────────────────────────────────

// In-memory fallback store for when Redis is unavailable
const _authRateLimitStore = new Map<string, { count: number; resetAt: number }>();

/**
 * Check a per-IP rate limit for auth endpoints.
 * Uses Redis sliding-window when available; falls back to in-memory counter.
 *
 * @param c        - Hono context (used to read client IP headers)
 * @param endpoint - Short name used as part of the Redis/memory key
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
    (c.req.header("x-forwarded-for")?.split(",")[0].trim()) ??
    c.req.header("x-real-ip") ??
    "unknown";
  const key = `ratelimit:auth:${endpoint}:${ip}:${windowMs}`;

  // Try Redis first
  try {
    const redisMw = await import("../middleware/redis.js");
    if (redisMw.isRedisAvailable()) {
      const { checkRateLimit } = await import("@stwd/redis");
      const result = await checkRateLimit(key, windowMs, max);
      if (!result.allowed) {
        return { allowed: false, retryAfterSecs: Math.ceil(result.resetMs / 1000) };
      }
      return { allowed: true };
    }
  } catch {
    // Redis unavailable — fall through to in-memory
  }

  // In-memory sliding-window fallback
  const now = Date.now();
  const entry = _authRateLimitStore.get(key);
  if (!entry || entry.resetAt <= now) {
    _authRateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true };
  }
  if (entry.count >= max) {
    return { allowed: false, retryAfterSecs: Math.ceil((entry.resetAt - now) / 1000) };
  }
  entry.count++;
  return { allowed: true };
}

// ─── JWT helpers ──────────────────────────────────────────────────────────────

// JWT secret: all modules MUST use STEWARD_SESSION_SECRET (with STEWARD_MASTER_PASSWORD fallback)
// to ensure tokens minted by auth routes validate in user routes and vice versa.
const jwtSecretSource = process.env.STEWARD_SESSION_SECRET || process.env.STEWARD_MASTER_PASSWORD;
if (!process.env.STEWARD_SESSION_SECRET && process.env.STEWARD_MASTER_PASSWORD) {
  console.warn("⚠️ STEWARD_SESSION_SECRET not set, falling back to master password. Set a separate JWT secret for production.");
}
if (!jwtSecretSource) {
  if (process.env.NODE_ENV === "production") {
    throw new Error("⛔ STEWARD_SESSION_SECRET (or STEWARD_MASTER_PASSWORD) must be set in production");
  }
  console.warn("⚠️  [DEV ONLY] Using insecure 'dev-secret' for JWT signing. Set STEWARD_SESSION_SECRET before going to production!");
}
const JWT_SECRET = new TextEncoder().encode(jwtSecretSource || "dev-secret");
const JWT_ISSUER = "steward";

/** Access token lifetime: 15 minutes */
const ACCESS_TOKEN_EXPIRY = "15m";
const ACCESS_TOKEN_EXPIRY_SECONDS = 900;

/** Refresh token lifetime: 30 days */
const REFRESH_TOKEN_EXPIRY_DAYS = 30;

export async function createSessionToken(
  address: string,
  tenantId: string,
  extra?: Record<string, unknown>,
): Promise<string> {
  return new SignJWT({ address, tenantId, ...extra })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime(ACCESS_TOKEN_EXPIRY)
    .sign(JWT_SECRET);
}

// ─── Refresh token helpers ────────────────────────────────────────────────────

function hashToken(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
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
  await db.insert(refreshTokens).values({ id, userId, tenantId, tokenHash: hashToken(raw), expiresAt });
  return raw;
}

/**
 * Validate a raw refresh token. Returns the stored record or null if missing/expired.
 * Does NOT delete the token — caller must do that on successful use (one-time use).
 */
async function validateRefreshToken(
  raw: string,
): Promise<typeof refreshTokens.$inferSelect | null> {
  const db = getDb();
  const hash = hashToken(raw);
  const [record] = await db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, hash));
  if (!record) return null;
  if (record.expiresAt < new Date()) {
    await db.delete(refreshTokens).where(eq(refreshTokens.id, record.id));
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
  return { ok: true, token, refreshToken, expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS, user };
}

export async function verifySessionToken(
  token: string,
): Promise<{ address: string; tenantId: string; userId?: string; email?: string } | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });
    return payload as { address: string; tenantId: string; userId?: string; email?: string };
  } catch {
    return null;
  }
}

// ─── Nonce store (SIWE) ───────────────────────────────────────────────────────

const nonceStore = new Map<string, { nonce: string; expiresAt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of nonceStore.entries()) {
    if (entry.expiresAt <= now) nonceStore.delete(key);
  }
}, 5 * 60 * 1000);

// ─── PasskeyAuth singleton ────────────────────────────────────────────────────

// ─── Store backend initialization ────────────────────────────────────────────

let _challengeStore: ChallengeStore | null = null;
let _tokenStore: TokenStore | null = null;

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
  ] = await Promise.all([
    buildBackend("challenge", redisClient, usePostgres),
    buildBackend("token", redisClient, usePostgres),
  ]);

  console.log(
    `[steward:auth] challenge store: ${challengeSource}, token store: ${tokenSource}`,
  );

  _challengeStore = new ChallengeStore({ backend: challengeBackend });
  _tokenStore = new TokenStore({ backend: tokenBackend });

  // Reset singletons so they pick up the new stores on next use
  _passkeyAuth = null;
  _emailAuth = null;
}

function getChallengeStore(): ChallengeStore {
  _challengeStore ??= new ChallengeStore();
  return _challengeStore;
}

function getTokenStore(): TokenStore {
  _tokenStore ??= new TokenStore();
  return _tokenStore;
}

let _passkeyAuth: PasskeyAuth | null = null;

function getPasskeyAuth(): PasskeyAuth {
  if (!_passkeyAuth) {
    _passkeyAuth = new PasskeyAuth({
      rpName: process.env.PASSKEY_RP_NAME || "Steward",
      rpID: process.env.PASSKEY_RP_ID || "steward.fi",
      origin: process.env.PASSKEY_ORIGIN || "https://steward.fi",
      challengeStore: getChallengeStore(),
    });
  }
  return _passkeyAuth;
}

// ─── EmailAuth singleton ──────────────────────────────────────────────────────

let _emailAuth: EmailAuth | null = null;

function getEmailAuth(): EmailAuth {
  if (!_emailAuth) {
    const resendKey = process.env.RESEND_API_KEY;
    const provider = resendKey
      ? new ResendProvider({
          apiKey: resendKey,
          from: process.env.EMAIL_FROM || "login@steward.fi",
        })
      : undefined;
    _emailAuth = new EmailAuth({
      from: process.env.EMAIL_FROM || "login@steward.fi",
      baseUrl: process.env.APP_URL || "https://steward.fi",
      provider,
      tokenStore: getTokenStore(),
    });
  }
  return _emailAuth;
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
  const headerTenant = c.req.header("X-Steward-Tenant");
  const requested = headerTenant || bodyTenantId;

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
    return { ok: false, status: 403, error: `Tenant '${requested}' requires an invitation to join` };
  }

  // joinMode === "closed"
  return { ok: false, status: 403, error: `Tenant '${requested}' is not accepting new members` };
}

/** @deprecated Use resolveAndValidateTenant instead */
const resolveTenantForUser = resolveAndValidateTenant;

// ─── User / tenant provisioning helpers ──────────────────────────────────────

async function findOrCreateUser(
  email: string,
): Promise<typeof users.$inferSelect> {
  const db = getDb();
  const [existing] = await db.select().from(users).where(eq(users.email, email));
  if (existing) return existing;
  const [newUser] = await db
    .insert(users)
    .values({ email, emailVerified: false })
    .returning();
  return newUser;
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
  await db
    .insert(userTenants)
    .values({ userId, tenantId, role })
    .onConflictDoNothing();
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
    .set({ walletAddress: result.walletAddress, stewardWalletId: result.agentId })
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

// ─── Route group ──────────────────────────────────────────────────────────────

const auth = new Hono();

// ── SIWE ──────────────────────────────────────────────────────────────────────

/**
 * GET /nonce
 * Returns a fresh one-time nonce for SIWE message construction.
 */
auth.get("/nonce", (c) => {
  const nonce = generateNonce();
  nonceStore.set(nonce, { nonce, expiresAt: Date.now() + 5 * 60 * 1000 });
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

  let siweMessage: SiweMessage;
  try {
    siweMessage = new SiweMessage(body.message);
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Invalid SIWE message format" }, 400);
  }

  const storedNonce = nonceStore.get(siweMessage.nonce);
  if (!storedNonce || storedNonce.expiresAt <= Date.now()) {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired nonce" }, 401);
  }

  try {
    await siweMessage.verify({ signature: body.signature });
  } catch {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>({ ok: false, error: "Invalid signature" }, 401);
  }

  nonceStore.delete(siweMessage.nonce);

  const address = siweMessage.address;
  let isNewTenant = false;
  let rawApiKey: string | undefined;

  const [existingTenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.ownerAddress, address));

  let tenant = existingTenant;

  if (!tenant) {
    isNewTenant = true;
    const tenantId = `t-${address.slice(2, 10).toLowerCase()}`;
    const tenantName = `${address.slice(0, 6)}...${address.slice(-4)}`;
    const apiKeyPair = generateApiKey();
    rawApiKey = apiKeyPair.key;

    const [newTenant] = await db
      .insert(tenants)
      .values({
        id: tenantId,
        name: tenantName,
        apiKeyHash: apiKeyPair.hash,
        ownerAddress: address,
      })
      .onConflictDoNothing()
      .returning();

    if (!newTenant) {
      const [retryTenant] = await db
        .select()
        .from(tenants)
        .where(eq(tenants.ownerAddress, address));
      if (retryTenant) {
        tenant = retryTenant;
        isNewTenant = false;
      } else {
        return c.json<ApiResponse>({ ok: false, error: "Failed to create tenant" }, 500);
      }
    } else {
      tenant = newTenant;
    }
  }

  // If an explicit requesting tenant was provided and it exists, use that instead
  const requestedTenantId = c.req.header("X-Steward-Tenant");
  let effectiveTenantId = tenant.id;
  if (requestedTenantId && requestedTenantId !== tenant.id) {
    const [requestedTenant] = await db
      .select()
      .from(tenants)
      .where(eq(tenants.id, requestedTenantId));
    if (requestedTenant) {
      effectiveTenantId = requestedTenantId;
    }
  }

  const token = await createSessionToken(address, effectiveTenantId);

  // For SIWE, find a user by wallet address (may not exist if SIWE-only user)
  const [siweUser] = await db.select().from(users).where(eq(users.walletAddress, address));
  const siweUserId = siweUser?.id ?? tenant.id; // fall back to tenant.id as a stable identifier
  const siweRefreshToken = await createRefreshToken(siweUserId, effectiveTenantId);

  const responseData: Record<string, unknown> = {
    ok: true,
    token,
    refreshToken: siweRefreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY_SECONDS,
    address,
    tenant: { id: tenant.id, name: tenant.name },
  };

  if (isNewTenant && rawApiKey) {
    (responseData.tenant as Record<string, unknown>).apiKey = rawApiKey;
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
 * JWT is stateless — client drops the token.
 */
auth.post("/logout", (c) => c.json<ApiResponse>({ ok: true }));

/**
 * POST /refresh
 * Body: { refreshToken: string }
 * Validates the refresh token, rotates it (one-time use), issues new access + refresh tokens.
 * Supports silent re-auth without user interaction when the access token nears expiry.
 */
auth.post("/refresh", async (c) => {
  const rl = await checkAuthRateLimit(c, "refresh", 60_000, 30);
  if (!rl.allowed) {
    return c.json<ApiResponse>({ ok: false, error: "Too many requests. Please try again later." }, 429);
  }
  const body = await safeJsonParse<{ refreshToken: string }>(c);
  if (!body?.refreshToken) {
    return c.json<ApiResponse>({ ok: false, error: "refreshToken is required" }, 400);
  }

  const record = await validateRefreshToken(body.refreshToken);
  if (!record) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired refresh token" }, 401);
  }

  const db = getDb();
  // Rotate: delete old token immediately (one-time use)
  await db.delete(refreshTokens).where(eq(refreshTokens.id, record.id));

  // Fetch user for token claims
  const [user] = await db.select().from(users).where(eq(users.id, record.userId));
  const walletAddress = user?.walletAddress ?? "";
  const email = user?.email ?? undefined;

  // Issue new access token (15min)
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
  await db
    .delete(refreshTokens)
    .where(eq(refreshTokens.tokenHash, hashToken(body.refreshToken)));

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
  const body = await safeJsonParse<{ email: string }>(c);
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

  const options = await getPasskeyAuth().generateRegistrationOptions(
    user.id,
    email,
    existingCreds.map((cred) => cred.credentialId),
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
    return c.json<ApiResponse>({ ok: false, error: "Too many requests. Please try again later." }, 429);
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
      { ok: false, error: "User not found — call /passkey/register/options first" },
      404,
    );
  }

  let verification: Awaited<ReturnType<PasskeyAuth["verifyRegistration"]>>;
  try {
    verification = await getPasskeyAuth().verifyRegistration(
      user.id,
      body.response as unknown as Parameters<PasskeyAuth["verifyRegistration"]>[1],
    );
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Verification failed" },
      400,
    );
  }

  if (!verification.verified || !verification.registrationInfo) {
    return c.json<ApiResponse>({ ok: false, error: "Registration verification failed" }, 400);
  }

  const { credential, credentialDeviceType, credentialBackedUp } =
    verification.registrationInfo;

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

  return c.json(buildAuthResponse(token, registerRefreshToken, { id: user.id, email, walletAddress }));
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

  const creds = await db
    .select({ credentialId: authenticators.credentialId })
    .from(authenticators)
    .where(eq(authenticators.userId, user.id));

  if (creds.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "No passkeys registered for this email" },
      404,
    );
  }

  const options = await getPasskeyAuth().generateAuthenticationOptions(email, {
    allowCredentials: creds.map((cred) => ({ id: cred.credentialId })),
  });

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
    return c.json<ApiResponse>({ ok: false, error: "Too many requests. Please try again later." }, 429);
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
      and(
        eq(authenticators.userId, user.id),
        eq(authenticators.credentialId, body.response.id),
      ),
    );

  if (!cred) {
    return c.json<ApiResponse>({ ok: false, error: "Credential not found" }, 404);
  }

  let verification: Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>;
  try {
    verification = await getPasskeyAuth().verifyAuthentication(
      body.response as unknown as Parameters<PasskeyAuth["verifyAuthentication"]>[0],
      undefined,
      cred.credentialPublicKey,
      cred.counter,
      email,
    );
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Authentication failed" },
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

  return c.json(buildAuthResponse(token, loginRefreshToken, { id: user.id, email, walletAddress }));
});

// ── Email magic link ──────────────────────────────────────────────────────────

/**
 * POST /email/send
 * Body: { email }
 * Sends a magic link email, returns expiry time.
 */
auth.post("/email/send", async (c) => {
  const rl = await checkAuthRateLimit(c, "email-send", 60_000, 3);
  if (!rl.allowed) {
    return c.json<ApiResponse>({ ok: false, error: "Too many requests. Please try again later." }, 429);
  }
  const body = await safeJsonParse<{ email: string }>(c);
  if (!body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "email is required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const { expiresAt } = await getEmailAuth().sendMagicLink(email);

  return c.json<ApiResponse<{ expiresAt: string }>>({
    ok: true,
    data: { expiresAt: expiresAt.toISOString() },
  });
});

/**
 * POST /email/verify
 * Body: { token, email, tenantId? }
 * Headers: X-Steward-Tenant (optional)
 * Verifies the magic link token, provisions user + wallet, links to tenant, returns JWT.
 */
auth.post("/email/verify", async (c) => {
  const body = await safeJsonParse<{ token: string; email: string; tenantId?: string }>(c);
  if (!body?.token || !body?.email) {
    return c.json<ApiResponse>({ ok: false, error: "token and email are required" }, 400);
  }

  const email = body.email.toLowerCase().trim();
  const result = await getEmailAuth().verifyMagicLink(body.token);

  if (!result.valid || result.email !== email) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid or expired magic link" }, 401);
  }

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
  const tenantResult = await resolveAndValidateTenant(c, user.id, body.tenantId);
  if (!tenantResult.ok) {
    return c.json<ApiResponse>({ ok: false, error: tenantResult.error }, tenantResult.status);
  }
  const { tenantId } = tenantResult;
  await ensureUserTenantLink(user.id, tenantId);

  const jwtToken = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });
  const refreshToken = await createRefreshToken(user.id, tenantId);

  return c.json(buildAuthResponse(jwtToken, refreshToken, { id: user.id, email, walletAddress }));
});

// ── OAuth providers list ─────────────────────────────────────────────────────

/**
 * GET /providers
 * Returns which auth methods are enabled based on environment configuration.
 * Used by the React widget to decide which login buttons to show.
 *
 * Response: { passkey: true, email: bool, siwe: true, google: bool, discord: bool, oauth: string[] }
 */
auth.get("/providers", (c) => {
  const oauthProviders = getEnabledProviders();
  return c.json({
    passkey: true,
    email: Boolean(process.env.RESEND_API_KEY),
    siwe: true,
    google: Boolean(process.env.GOOGLE_CLIENT_ID),
    discord: Boolean(process.env.DISCORD_CLIENT_ID),
    oauth: oauthProviders,
  });
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
      { ok: false, error: err instanceof Error ? err.message : "Provider not configured" },
      503,
    );
  }

  const redirectUri = c.req.query("redirect_uri");
  const tenantId = c.req.query("tenant_id");

  if (!redirectUri) {
    return c.json<ApiResponse>({ ok: false, error: "redirect_uri is required" }, 400);
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

  let stateData: { provider: string; tenantId?: string; redirectUri: string; codeVerifier?: string };
  try {
    stateData = JSON.parse(rawPayload) as typeof stateData;
  } catch {
    return c.json<ApiResponse>({ ok: false, error: "Malformed OAuth state payload" }, 400);
  }

  if (stateData.provider !== providerName) {
    return c.json<ApiResponse>({ ok: false, error: "Provider mismatch in state" }, 400);
  }

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Provider not configured" },
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
      { ok: false, error: err instanceof Error ? err.message : "Token exchange failed" },
      502,
    );
  }

  // Fetch user info from provider
  let providerUser: Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
  try {
    providerUser = await oauthClient.getUserInfo(tokenResponse.access_token);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Failed to fetch user info" },
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
    providerUser = { ...providerUser, email: `${providerName}.${providerUser.id}@id.steward.internal` };
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

  // Redirect to the app with the JWT
  const redirectUrl = new URL(stateData.redirectUri);
  redirectUrl.searchParams.set("token", result.token);
  redirectUrl.searchParams.set("refreshToken", result.refreshToken);
  return c.redirect(redirectUrl.toString(), 302);
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

  let oauthClient: OAuthClient;
  try {
    oauthClient = new OAuthClient(getProviderConfig(providerName));
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Provider not configured" },
      503,
    );
  }

  let tokenResponse: Awaited<ReturnType<OAuthClient["exchangeCode"]>>;
  try {
    tokenResponse = await oauthClient.exchangeCode(
      body.code,
      body.redirectUri,
      body.codeVerifier,
    );
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Token exchange failed" },
      502,
    );
  }

  let providerUser: Awaited<ReturnType<OAuthClient["getUserInfo"]>>;
  try {
    providerUser = await oauthClient.getUserInfo(tokenResponse.access_token);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Failed to fetch user info" },
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
    providerUser = { ...providerUser, email: `${providerName}.${providerUser.id}@id.steward.internal` };
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

  return c.json(buildAuthResponse(result.token, result.refreshToken, result.user as Record<string, unknown>));
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
  | { ok: true; token: string; refreshToken: string; user: { id: string; email: string; walletAddress?: string | null } }
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

    // 2. Upsert the OAuth account link (provider + providerAccountId → user)
    await db
      .insert(accounts)
      .values({
        userId: user.id,
        provider: providerName,
        providerAccountId: providerUser.id,
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token ?? null,
        expiresAt: tokenResponse.expires_in
          ? Math.floor(Date.now() / 1000) + tokenResponse.expires_in
          : null,
      })
      .onConflictDoUpdate({
        target: [accounts.provider, accounts.providerAccountId],
        set: {
          userId: user.id,
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token ?? null,
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

    return { ok: true, token, refreshToken: oauthRefreshToken, user: { id: user.id, email, walletAddress } };
  } catch (err) {
    console.error(`[OAuthAuth:${providerName}] provisionOAuthUser failed:`, err);
    return { ok: false, error: err instanceof Error ? err.message : "Internal server error" };
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

export { auth as authRoutes };
