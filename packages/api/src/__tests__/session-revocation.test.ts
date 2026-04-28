import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { randomUUID } from "node:crypto";
import { assertTokenNotRevoked, hashSha256Hex, revocationStore } from "@stwd/auth";
import {
  closeDb,
  createPGLiteDb,
  getDb,
  refreshTokens,
  setPGLiteOverride,
  tenants,
  users,
} from "@stwd/db";
import { jwtVerify, SignJWT } from "jose";
import { authRoutes, createSessionToken, verifySessionToken } from "../routes/auth";

const JWT_SECRET = new TextEncoder().encode(
  process.env.STEWARD_SESSION_SECRET || process.env.STEWARD_MASTER_PASSWORD || "dev-secret",
);
const JWT_ISSUER = "steward";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

async function createAgentToken(agentId: string, tenantId: string): Promise<string> {
  return new SignJWT({ agentId, tenantId, scope: "agent" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setJti(randomUUID())
    .setIssuer(JWT_ISSUER)
    .setExpirationTime("1h")
    .sign(JWT_SECRET);
}

async function verifyAgentToken(token: string) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET, { issuer: JWT_ISSUER });
    await assertTokenNotRevoked(payload);
    return payload;
  } catch {
    return null;
  }
}

describe("API access-token revocation", () => {
  it("refresh flow still works without a valid access token", async () => {
    const db = getDb();
    const userId = randomUUID();
    const tenantId = `tenant-refresh-${Date.now()}`;
    const rawRefreshToken = `refresh-${randomUUID()}`;

    await db
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Refresh Test Tenant",
        apiKeyHash: "test-hash",
        ownerAddress: "0x0000000000000000000000000000000000000000",
      })
      .onConflictDoNothing();
    await db.insert(users).values({ id: userId, email: `${userId}@example.com` });
    await db.insert(refreshTokens).values({
      id: randomUUID(),
      userId,
      tenantId,
      tokenHash: hashSha256Hex(rawRefreshToken),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    const expiredAccessToken = await new SignJWT({ address: "0xexpired", tenantId, userId })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
      .setJti(randomUUID())
      .setIssuer(JWT_ISSUER)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 1)
      .sign(JWT_SECRET);
    expect(await verifySessionToken(expiredAccessToken)).toBeNull();

    const res = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: rawRefreshToken }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as {
      ok: boolean;
      token: string;
      refreshToken: string;
      expiresIn: number;
    };
    expect(json.ok).toBe(true);
    expect(json.expiresIn).toBe(900);
    expect(await verifySessionToken(json.token)).toMatchObject({ userId, tenantId });
  });

  it("/auth/logout revokes the presented access token", async () => {
    const token = await createSessionToken("0xlogout", "tenant-logout", { userId: "user-logout" });

    const res = await authRoutes.request("/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    expect(await verifySessionToken(token)).toBeNull();
  });

  it("global agent-token revoke rejects old tokens and permits tokens after the cutoff", async () => {
    const agentId = `agent-revoke-api-${Date.now()}`;
    const oldToken = await createAgentToken(agentId, "tenant-agent-revoke");
    const { payload: oldPayload } = await jwtVerify(oldToken, JWT_SECRET, { issuer: JWT_ISSUER });

    await revocationStore.revokeAgentTokens(
      agentId,
      Number(oldPayload.iat) + 1,
      Date.now() + 60_000,
    );
    expect(await verifyAgentToken(oldToken)).toBeNull();

    const freshAgentId = `${agentId}-fresh`;
    const freshToken = await createAgentToken(freshAgentId, "tenant-agent-revoke");
    const { payload: freshPayload } = await jwtVerify(freshToken, JWT_SECRET, {
      issuer: JWT_ISSUER,
    });
    await revocationStore.revokeAgentTokens(
      freshAgentId,
      Number(freshPayload.iat) - 1,
      Date.now() + 60_000,
    );

    expect(await verifyAgentToken(freshToken)).toMatchObject({ agentId: freshAgentId });
  });
});
