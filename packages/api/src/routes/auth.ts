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
} from "@stwd/auth";
import { authenticators, getDb, tenants, userTenants, users } from "@stwd/db";
import type { ApiResponse } from "@stwd/shared";
import { Vault, provisionUserWallet } from "@stwd/vault";

// ─── Constants ────────────────────────────────────────────────────────────────

const DEFAULT_TENANT_ID = process.env.STEWARD_DEFAULT_TENANT_ID || "default";

// ─── JWT helpers ──────────────────────────────────────────────────────────────

// JWT secret: prefer dedicated STEWARD_JWT_SECRET, fall back to master password with warning
const jwtSecretSource = process.env.STEWARD_JWT_SECRET || process.env.STEWARD_MASTER_PASSWORD;
if (!process.env.STEWARD_JWT_SECRET && process.env.STEWARD_MASTER_PASSWORD) {
  console.warn("⚠️ STEWARD_JWT_SECRET not set, falling back to master password. Set a separate JWT secret for production.");
}
const JWT_SECRET = new TextEncoder().encode(jwtSecretSource || "dev-secret");
const JWT_ISSUER = "steward";
const JWT_EXPIRY = "24h";

export async function createSessionToken(
  address: string,
  tenantId: string,
  extra?: Record<string, unknown>,
): Promise<string> {
  return new SignJWT({ address, tenantId, ...extra })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime(JWT_EXPIRY)
    .sign(JWT_SECRET);
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
async function resolveTenantForUser(
  c: Context,
  userId: string,
  bodyTenantId?: string,
): Promise<{ tenantId: string; isPersonal: boolean }> {
  const headerTenant = c.req.header("X-Steward-Tenant");
  const requested = headerTenant || bodyTenantId;

  if (requested) {
    return { tenantId: requested, isPersonal: false };
  }

  // Fall back to the user's personal tenant
  return { tenantId: `personal-${userId}`, isPersonal: true };
}

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

  const responseData: Record<string, unknown> = {
    ok: true,
    token,
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
  const { tenantId } = await resolveTenantForUser(c, user.id, body.tenantId);
  await ensureUserTenantLink(user.id, tenantId);

  const token = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });

  return c.json({ ok: true, token, user: { id: user.id, email, walletAddress } });
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
  const { tenantId } = await resolveTenantForUser(c, user.id, body.tenantId);
  await ensureUserTenantLink(user.id, tenantId);

  const token = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });

  return c.json({ ok: true, token, user: { id: user.id, email, walletAddress } });
});

// ── Email magic link ──────────────────────────────────────────────────────────

/**
 * POST /email/send
 * Body: { email }
 * Sends a magic link email, returns expiry time.
 */
auth.post("/email/send", async (c) => {
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
  const { tenantId } = await resolveTenantForUser(c, user.id, body.tenantId);
  await ensureUserTenantLink(user.id, tenantId);

  const jwtToken = await createSessionToken(walletAddress ?? "", tenantId, {
    userId: user.id,
    email,
  });

  return c.json({
    ok: true,
    token: jwtToken,
    user: { id: user.id, email, walletAddress },
  });
});

export { auth as authRoutes };
