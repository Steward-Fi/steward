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
} from "@stwd/auth";
import { authenticators, getDb, tenants, users } from "@stwd/db";
import type { ApiResponse } from "@stwd/shared";
import { Vault, provisionUserWallet } from "@stwd/vault";

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

let _passkeyAuth: PasskeyAuth | null = null;

function getPasskeyAuth(): PasskeyAuth {
  if (!_passkeyAuth) {
    _passkeyAuth = new PasskeyAuth({
      rpName: process.env.PASSKEY_RP_NAME || "Steward",
      rpID: process.env.PASSKEY_RP_ID || "steward.fi",
      origin: process.env.PASSKEY_ORIGIN || "https://steward.fi",
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

async function provisionWalletForUser(
  userId: string,
  email: string,
): Promise<{ walletAddress: string; tenantId: string }> {
  const tenantId = await ensurePersonalTenant(userId, email);
  const vault = getVault();
  const result = await provisionUserWallet(vault, userId, email, tenantId);
  const db = getDb();
  await db
    .update(users)
    .set({ walletAddress: result.walletAddress, stewardWalletId: result.agentId })
    .where(eq(users.id, userId));
  return { walletAddress: result.walletAddress, tenantId };
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
 * Verifies SIWE, auto-creates tenant, returns JWT.
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

  const token = await createSessionToken(address, tenant.id);

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
 * Body: { email, response }
 * Verifies registration, stores credential, provisions wallet, returns JWT.
 */
auth.post("/passkey/register/verify", async (c) => {
  const body = await safeJsonParse<{
    email: string;
    response: Record<string, unknown>;
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

  let walletAddress = user.walletAddress;
  let tenantId = `personal-${user.id}`;
  try {
    const w = await provisionWalletForUser(user.id, email);
    walletAddress = w.walletAddress;
    tenantId = w.tenantId;
  } catch (err) {
    console.error("[PasskeyAuth] Wallet provision failed on register:", err);
  }

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
 * Body: { email, response }
 * Verifies authentication, updates counter, returns JWT.
 */
auth.post("/passkey/login/verify", async (c) => {
  const body = await safeJsonParse<{
    email: string;
    response: { id: string; [key: string]: unknown };
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
  let tenantId = `personal-${user.id}`;
  if (!walletAddress) {
    try {
      const w = await provisionWalletForUser(user.id, email);
      walletAddress = w.walletAddress;
      tenantId = w.tenantId;
    } catch (err) {
      console.error("[PasskeyAuth] Wallet provision failed on login:", err);
    }
  } else {
    tenantId = await ensurePersonalTenant(user.id, email);
  }

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
 * Body: { token, email }
 * Verifies the magic link token, provisions user + wallet, returns JWT.
 */
auth.post("/email/verify", async (c) => {
  const body = await safeJsonParse<{ token: string; email: string }>(c);
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

  let walletAddress = user.walletAddress;
  let tenantId = `personal-${user.id}`;
  try {
    const w = await provisionWalletForUser(user.id, email);
    walletAddress = w.walletAddress;
    tenantId = w.tenantId;
  } catch (err) {
    console.error("[EmailAuth] Wallet provision failed:", err);
  }

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
