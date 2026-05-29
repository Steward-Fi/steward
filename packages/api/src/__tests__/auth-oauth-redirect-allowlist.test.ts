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

process.env.NODE_ENV = "test";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_MASTER_PASSWORD =
  process.env.STEWARD_MASTER_PASSWORD || "oauth-allowlist-master-password";
process.env.STEWARD_JWT_SECRET =
  process.env.STEWARD_JWT_SECRET || "oauth-allowlist-jwt-secret-with-enough-bytes";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgres://test:test@localhost:5432/test";

import { closeDb, getDb, tenantConfigs, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const { authRoutes, clearOAuthTokenKeyStoreForTests } = await import("../routes/auth");

const TENANT_ID = "test-oauth-allowlist";
// PKCE is mandatory for response_type=code; a syntactically valid S256
// challenge lets requests reach redirect_uri allowlist validation.
const CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const PKCE_QS = `&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256`;

describe("OAuth redirect_uri allowlist", () => {
  beforeAll(async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
    clearOAuthTokenKeyStoreForTests();

    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "OAuth Allowlist Tenant",
        apiKeyHash: "hash",
      })
      .onConflictDoNothing();
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        allowedOrigins: ["https://app.example.test"],
        allowedRedirectUrls: ["https://app.example.test/"],
      })
      .onConflictDoNothing();
  });

  afterEach(() => {
    mock.restore();
    clearOAuthTokenKeyStoreForTests();
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.APP_URL;
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  it("rejects /authorize when redirect_uri origin is outside the tenant allowlist", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
    });

    const res = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://evil.example/callback")}${PKCE_QS}`,
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });

  it("does not allow global OAuth redirects to satisfy a tenant-scoped /authorize request", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
    });
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://global.example.test/callback";

    const res = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://global.example.test/callback")}${PKCE_QS}`,
    );

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });

  it("rejects tenant origin-only entries for non-root OAuth redirect_uri paths", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/"],
    });

    const res = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://app.example.test/callback")}${PKCE_QS}`,
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
      allowedRedirectUrls: ["https://app.example.test/"],
    });

    const authorizeRes = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://app.example.test/")}${PKCE_QS}`,
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
      allowedRedirectUrls: ["https://other.example.test/"],
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
      allowedRedirectUrls: ["https://app.example.test/callback"],
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

  it("does not allow global OAuth redirects to satisfy a tenant-scoped /token request", async () => {
    const db = getDb();
    await db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    await db.insert(tenantConfigs).values({
      tenantId: TENANT_ID,
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
    });
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://global.example.test/callback";

    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://global.example.test/callback",
        tenantId: TENANT_ID,
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("redirect_uri is not allowed");
  });

  it("rejects /token when body tenantId and X-Steward-Tenant disagree", async () => {
    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Steward-Tenant": "other-tenant",
      },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://app.example.test/callback",
        tenantId: TENANT_ID,
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("must match");
  });
});
