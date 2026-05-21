import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";

setDefaultTimeout(30000);

import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { authRoutes, clearOAuthTokenKeyStoreForTests } from "../routes/auth";

const TENANT_ID = "oauth-allowlist-tenant";

async function setupDb() {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
}

describe("OAuth redirect_uri allowlist", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "oauth-allowlist-master-password";
    process.env.STEWARD_JWT_SECRET = "oauth-allowlist-jwt-secret-with-enough-bytes";
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
    clearOAuthTokenKeyStoreForTests();

    await setupDb();
    const db = getDb();
    await db.insert(tenants).values({
      id: TENANT_ID,
      name: "OAuth Allowlist Tenant",
      apiKeyHash: "hash",
    });
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
    });
  });

  afterEach(() => {
    mock.restore();
    clearOAuthTokenKeyStoreForTests();
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
  });

  afterAll(async () => {
    await closeDb().catch(() => {});
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.APP_URL;
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
  });

  it("rejects /authorize when redirect_uri origin is outside the tenant allowlist", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
    });

    const res = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://evil.example/callback")}`,
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });

  it("re-validates the stored redirect_uri during /callback before redirecting tokens", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
    });

    const authorizeRes = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://app.example.test/callback")}`,
    );

    expect(authorizeRes.status).toBe(302);
    const location = authorizeRes.headers.get("location");
    expect(location).toBeTruthy();
    const state = new URL(location as string).searchParams.get("state");
    expect(state).toBeTruthy();

    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://other.example.test"],
    });

    const callbackRes = await authRoutes.request(
      `/oauth/google/callback?code=test-code&state=${state as string}`,
    );

    expect(callbackRes.status).toBe(400);
    const body = (await callbackRes.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });

  it("rejects /token when redirectUri is outside the tenant allowlist", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
    });

    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://evil.example/callback",
        tenantId: TENANT_ID,
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });
});
