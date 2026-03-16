/**
 * SIWE (Sign-In With Ethereum) auth routes.
 *
 * Extracted from packages/api/src/index.ts so they can be mounted cleanly:
 *   app.route("/auth", authRoutes)
 *
 * Routes
 * ──────
 * GET  /nonce    — get a fresh one-time nonce for SIWE
 * POST /verify   — verify SIWE message + signature, return JWT session token
 * GET  /session  — inspect current JWT session
 * POST /logout   — invalidate session (client-side; server returns ok)
 */

import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { SignJWT, jwtVerify } from "jose";
import { generateNonce, SiweMessage } from "siwe";

import { generateApiKey } from "@stwd/auth";
import { getDb, tenants } from "@stwd/db";
import type { ApiResponse } from "@stwd/shared";

// ─── Nonce store ──────────────────────────────────────────────────────────────

/** In-memory nonce store with TTL.  Keyed by nonce string. */
const nonceStore = new Map<string, { nonce: string; expiresAt: number }>();

// Clean up expired nonces every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of nonceStore.entries()) {
    if (entry.expiresAt <= now) nonceStore.delete(key);
  }
}, 5 * 60 * 1000);

// ─── JWT helpers ──────────────────────────────────────────────────────────────

const JWT_SECRET = new TextEncoder().encode(
  process.env.STEWARD_MASTER_PASSWORD || "dev-secret",
);
const JWT_ISSUER = "steward";
const JWT_EXPIRY = "24h";

export async function createSessionToken(
  address: string,
  tenantId: string,
): Promise<string> {
  return new SignJWT({ address, tenantId })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime(JWT_EXPIRY)
    .sign(JWT_SECRET);
}

export async function verifySessionToken(
  token: string,
): Promise<{ address: string; tenantId: string } | null> {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
    });
    return payload as { address: string; tenantId: string };
  } catch {
    return null;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function safeJsonParse<T>(c: { req: { json: <X>() => Promise<X> } }): Promise<T | null> {
  try {
    return await (c.req.json as () => Promise<T>)();
  } catch {
    return null;
  }
}

// ─── Route group ─────────────────────────────────────────────────────────────

const auth = new Hono();

/**
 * GET /nonce
 * Returns a fresh nonce for the client to embed in a SIWE message.
 */
auth.get("/nonce", (c) => {
  const nonce = generateNonce();
  nonceStore.set(nonce, {
    nonce,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5-minute TTL
  });
  return c.json({ nonce });
});

/**
 * POST /verify
 * Body: { message: string; signature: string }
 *
 * Verifies the SIWE message + signature.  If the wallet has no tenant yet,
 * auto-creates one and returns the raw API key (once, on first creation).
 * Returns a JWT session token on success.
 */
auth.post("/verify", async (c) => {
  const db = getDb();
  const body = await safeJsonParse<{ message: string; signature: string }>(c);

  if (!body || !body.message || !body.signature) {
    return c.json<ApiResponse>(
      { ok: false, error: "message and signature are required" },
      400,
    );
  }

  let siweMessage: SiweMessage;
  try {
    siweMessage = new SiweMessage(body.message);
  } catch {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid SIWE message format" },
      400,
    );
  }

  // Verify nonce existence and freshness
  const storedNonce = nonceStore.get(siweMessage.nonce);
  if (!storedNonce || storedNonce.expiresAt <= Date.now()) {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid or expired nonce" },
      401,
    );
  }

  // Verify SIWE signature
  try {
    await siweMessage.verify({ signature: body.signature });
  } catch {
    nonceStore.delete(siweMessage.nonce);
    return c.json<ApiResponse>({ ok: false, error: "Invalid signature" }, 401);
  }

  // Nonce consumed — delete it
  nonceStore.delete(siweMessage.nonce);

  const address = siweMessage.address;
  let isNewTenant = false;
  let rawApiKey: string | undefined;

  // Look up tenant by ownerAddress
  const [existingTenant] = await db
    .select()
    .from(tenants)
    .where(eq(tenants.ownerAddress, address));

  let tenant = existingTenant;

  if (!tenant) {
    // Auto-provision a new tenant for this wallet
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
      // Race condition — another request created it, fetch by address
      const [retryTenant] = await db
        .select()
        .from(tenants)
        .where(eq(tenants.ownerAddress, address));
      if (retryTenant) {
        tenant = retryTenant;
        isNewTenant = false;
      } else {
        return c.json<ApiResponse>(
          { ok: false, error: "Failed to create tenant" },
          500,
        );
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
    tenant: {
      id: tenant.id,
      name: tenant.name,
    },
  };

  // Raw API key returned only on initial tenant creation
  if (isNewTenant && rawApiKey) {
    (responseData.tenant as Record<string, unknown>).apiKey = rawApiKey;
  }

  return c.json(responseData);
});

/**
 * GET /session
 * Requires: Authorization: Bearer <token>
 * Returns current session info if the token is valid.
 */
auth.get("/session", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ authenticated: false });
  }

  const token = authHeader.slice(7);
  const payload = await verifySessionToken(token);

  if (!payload) {
    return c.json({ authenticated: false });
  }

  return c.json({
    authenticated: true,
    address: payload.address,
    tenantId: payload.tenantId,
  });
});

/**
 * POST /logout
 * JWT is stateless — invalidation is client-side (drop the token).
 * This endpoint exists for symmetry and future server-side blocklist support.
 */
auth.post("/logout", (c) => c.json<ApiResponse>({ ok: true }));

export { auth as authRoutes };
