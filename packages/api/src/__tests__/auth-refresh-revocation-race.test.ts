import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { randomUUID } from "node:crypto";
import { hashSha256Hex } from "@stwd/auth";
import {
  auditEvents,
  closeDb,
  eq,
  getDb,
  refreshTokens,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

setDefaultTimeout(30_000);

process.env.STEWARD_MASTER_PASSWORD ??= "refresh-revocation-race-master-password";
process.env.STEWARD_JWT_SECRET ??=
  "refresh-revocation-race-jwt-secret-with-enough-entropy-0123456789";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "b".repeat(64);
if (!process.env.DATABASE_URL) process.env.STEWARD_PGLITE_MEMORY = "true";

let authRoutes: typeof import("../routes/auth").authRoutes;
let createSessionToken: typeof import("../routes/auth").createSessionToken;
let verifySessionToken: typeof import("../routes/auth").verifySessionToken;

beforeAll(async () => {
  if (!process.env.DATABASE_URL) {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  }
  const auth = await import("../routes/auth");
  authRoutes = auth.authRoutes;
  createSessionToken = auth.createSessionToken;
  verifySessionToken = auth.verifySessionToken;
});

afterAll(async () => {
  await closeDb();
});

describe("auth refresh revocation race hardening", () => {
  it("leaves no usable refresh token when rotate races revoke-all", async () => {
    const userId = randomUUID();
    const tenantId = `refresh-revoke-race-${randomUUID()}`;
    const rawRefreshToken = `refresh-${randomUUID()}`;
    const db = getDb();

    await db.insert(tenants).values({
      id: tenantId,
      name: "Refresh Revocation Race",
      apiKeyHash: `hash-${tenantId}`,
    });
    await db.insert(users).values({ id: userId, email: `${userId}@example.test` });
    await db.insert(userTenants).values({ userId, tenantId, role: "owner" });
    await db.insert(refreshTokens).values({
      id: randomUUID(),
      userId,
      tenantId,
      tokenHash: hashSha256Hex(rawRefreshToken),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const accessToken = await createSessionToken("", tenantId, { userId });
    const [rotate, revoke] = await Promise.all([
      authRoutes.request("/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: rawRefreshToken }),
      }),
      authRoutes.request("/sessions", {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    ]);

    expect(revoke.status).toBe(200);
    expect([200, 401]).toContain(rotate.status);
    expect(await db.select().from(refreshTokens).where(eq(refreshTokens.userId, userId))).toEqual(
      [],
    );

    const revocationAudits = await db
      .select({ action: auditEvents.action, actorId: auditEvents.actorId })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, tenantId));
    expect(revocationAudits).toContainEqual({
      action: "auth.sessions.revoke_all.authorized",
      actorId: userId,
    });

    if (rotate.status === 200) {
      const rotated = (await rotate.json()) as { refreshToken: string };
      const replay = await authRoutes.request("/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: rotated.refreshToken }),
      });
      expect(replay.status).toBe(401);
    }
  });

  it("detects a consumed refresh token, revokes its replacement, and records the event", async () => {
    const userId = randomUUID();
    const tenantId = `refresh-reuse-${randomUUID()}`;
    const rawRefreshToken = `refresh-${randomUUID()}`;
    const db = getDb();

    await db.insert(tenants).values({
      id: tenantId,
      name: "Refresh Reuse",
      apiKeyHash: `hash-${tenantId}`,
    });
    await db.insert(users).values({ id: userId, email: `${userId}@example.test` });
    await db.insert(userTenants).values({ userId, tenantId, role: "owner" });
    await db.insert(refreshTokens).values({
      id: randomUUID(),
      userId,
      tenantId,
      tokenHash: hashSha256Hex(rawRefreshToken),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const first = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken }),
    });
    expect(first.status).toBe(200);
    const rotated = (await first.json()) as { refreshToken: string };

    const replay = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken }),
    });
    expect(replay.status).toBe(401);
    await expect(replay.json()).resolves.toMatchObject({
      ok: false,
      error: "Refresh token reuse detected. Please sign in again.",
    });

    const replacement = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rotated.refreshToken }),
    });
    expect(replacement.status).toBe(401);
    expect(await db.select().from(refreshTokens).where(eq(refreshTokens.userId, userId))).toEqual(
      [],
    );

    const events = await db
      .select({ action: auditEvents.action, actorId: auditEvents.actorId })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, tenantId));
    expect(events).toContainEqual({ action: "auth.refresh.reuse_detected", actorId: userId });
  });

  it("validates and atomically rotates an authorized tenant switch", async () => {
    const userId = randomUUID();
    const sourceTenantId = `refresh-switch-source-${randomUUID()}`;
    const targetTenantId = `refresh-switch-target-${randomUUID()}`;
    const rawRefreshToken = `refresh-${randomUUID()}`;
    const db = getDb();

    await db.insert(tenants).values([
      { id: sourceTenantId, name: "Refresh Switch Source", apiKeyHash: `hash-${sourceTenantId}` },
      { id: targetTenantId, name: "Refresh Switch Target", apiKeyHash: `hash-${targetTenantId}` },
    ]);
    await db.insert(users).values({ id: userId, email: `${userId}@example.test` });
    await db.insert(userTenants).values([
      { userId, tenantId: sourceTenantId, role: "owner" },
      { userId, tenantId: targetTenantId, role: "member" },
    ]);
    await db.insert(refreshTokens).values({
      id: randomUUID(),
      userId,
      tenantId: sourceTenantId,
      tokenHash: hashSha256Hex(rawRefreshToken),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const response = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken, tenantId: targetTenantId }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string; refreshToken: string };
    await expect(verifySessionToken(body.token)).resolves.toMatchObject({
      userId,
      tenantId: targetTenantId,
    });
    const activeTokens = await db
      .select({ tenantId: refreshTokens.tenantId, tokenHash: refreshTokens.tokenHash })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, userId));
    expect(activeTokens).toEqual([
      { tenantId: targetTenantId, tokenHash: hashSha256Hex(body.refreshToken) },
    ]);
  });

  it("binds single-session revoke to a rotated successor", async () => {
    const userId = randomUUID();
    const tenantId = `refresh-successor-${randomUUID()}`;
    const rawRefreshToken = `refresh-${randomUUID()}`;
    const db = getDb();

    await db.insert(tenants).values({
      id: tenantId,
      name: "Refresh Successor Revoke",
      apiKeyHash: `hash-${tenantId}`,
    });
    await db.insert(users).values({ id: userId, email: `${userId}@example.test` });
    await db.insert(userTenants).values({ userId, tenantId, role: "owner" });
    await db.insert(refreshTokens).values({
      id: randomUUID(),
      userId,
      tenantId,
      tokenHash: hashSha256Hex(rawRefreshToken),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const rotate = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken }),
    });
    expect(rotate.status).toBe(200);

    const revoke = await authRoutes.request("/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken }),
    });
    expect(revoke.status).toBe(200);
    expect(await db.select().from(refreshTokens).where(eq(refreshTokens.userId, userId))).toEqual(
      [],
    );
  });
});
