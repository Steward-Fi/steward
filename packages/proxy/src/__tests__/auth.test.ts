import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { revocationStore, verifyToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { PROXY_SCOPE } from "../config";
import { authMiddleware, createProxyAuthorizationSignature } from "../middleware/auth";

const JWT_ISSUER = "steward";
const JWT_AUDIENCE = "steward-api";

setDefaultTimeout(30000);

async function signAgentToken(claims: Record<string, unknown>, jti?: string) {
  const jwtSecret = new TextEncoder().encode(process.env.STEWARD_JWT_SECRET || "dev-secret");
  return new SignJWT({
    agentId: "agent-1",
    tenantId: "tenant-1",
    scope: "agent",
    ...claims,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .setJti(jti ?? crypto.randomUUID())
    .setExpirationTime("1h")
    .sign(jwtSecret);
}

function app() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.get("/", (c) => c.json({ ok: true, agentId: c.get("agentId"), tenantId: c.get("tenantId") }));
  return app;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  // verifyToken now refuses to run without an explicit JWT secret (the dev
  // fallback requires STEWARD_ALLOW_DEV_SECRETS). Set a real secret so the
  // signed tokens here verify against the same key the middleware uses.
  process.env.STEWARD_JWT_SECRET = "proxy-auth-test-jwt-secret-with-enough-bytes";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: "tenant-1",
    name: "Proxy Auth Tenant",
    apiKeyHash: "hash-proxy-auth-tenant-1",
  });
  await getDb()
    .insert(agents)
    .values([
      {
        id: "agent-1",
        tenantId: "tenant-1",
        name: "agent-1",
        walletAddress: `0x${"1".repeat(40)}`,
      },
      {
        id: "revoked-agent",
        tenantId: "tenant-1",
        name: "revoked-agent",
        walletAddress: `0x${"2".repeat(40)}`,
      },
    ]);
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_ALLOW_UNSIGNED_REQUESTS;
});

describe("proxy auth middleware", () => {
  test("rejects token with scopes that omit api:proxy", async () => {
    const token = await signAgentToken({ scopes: ["agent"] });

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain(PROXY_SCOPE);
  });

  test("accepts token with api:proxy scope", async () => {
    const token = await signAgentToken({ scopes: ["agent", PROXY_SCOPE] });

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true, agentId: "agent-1", tenantId: "tenant-1" });
  });

  test("rejects legacy agent token without explicit api:proxy scope", async () => {
    const token = await signAgentToken({});

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain(PROXY_SCOPE);
  });

  test("rejects token for an agent that does not exist in the tenant", async () => {
    const token = await signAgentToken({
      agentId: "missing-agent",
      tenantId: "tenant-1",
      scopes: ["agent", PROXY_SCOPE],
    });

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain("Agent not found");
  });

  test("rejects individually revoked agent tokens", async () => {
    const jti = crypto.randomUUID();
    const token = await signAgentToken({ scopes: ["agent", PROXY_SCOPE] }, jti);
    await revocationStore.revokeToken(jti, Date.now() + 60_000);

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain("revoked");
  });

  test("rejects agent tokens revoked by the agent-wide revocation line", async () => {
    const token = await signAgentToken({
      agentId: "revoked-agent",
      scopes: ["agent", PROXY_SCOPE],
    });
    const payload = await verifyToken(token);
    await revocationStore.revokeAgentTokens(
      String(payload.agentId),
      Number(payload.iat) + 1,
      Date.now() + 60_000,
    );

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error).toContain("revoked");
  });

  test("requires proof-of-possession signatures when configured", async () => {
    try {
      process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
      process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = "proxy-signing-secret";
      const token = await signAgentToken({ scopes: ["agent", PROXY_SCOPE] });

      const missing = await app().request("/", {
        headers: { authorization: `Bearer ${token}` },
      });
      expect(missing.status).toBe(401);

      const timestamp = String(Math.floor(Date.now() / 1000));
      const signature = await createProxyAuthorizationSignature(
        {
          method: "GET",
          url: "https://proxy.test/",
          tenantId: "tenant-1",
          agentId: "agent-1",
          timestamp,
        },
        "proxy-signing-secret",
      );
      const signed = await app().request("/", {
        headers: {
          authorization: `Bearer ${token}`,
          "x-steward-request-timestamp": timestamp,
          "x-steward-signature": signature,
        },
      });

      expect(signed.status).toBe(200);
    } finally {
      delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
      delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
    }
  });

  test("requires production proxy signatures even if unsigned opt-out is set", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalJwtSecret = process.env.STEWARD_JWT_SECRET;
    try {
      process.env.NODE_ENV = "production";
      process.env.STEWARD_JWT_SECRET = "proxy-auth-test-secret-with-at-least-thirty-two-characters";
      process.env.STEWARD_PROXY_ALLOW_UNSIGNED_REQUESTS = "true";
      process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = "proxy-signing-secret";
      const token = await signAgentToken({ scopes: ["agent", PROXY_SCOPE] });

      const missing = await app().request("/", {
        headers: { authorization: `Bearer ${token}` },
      });

      expect(missing.status).toBe(401);
      expect(await missing.json()).toEqual({
        ok: false,
        error: "X-Steward-Signature header required",
      });
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = originalJwtSecret;
      delete process.env.STEWARD_PROXY_ALLOW_UNSIGNED_REQUESTS;
      delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
    }
  });
});
