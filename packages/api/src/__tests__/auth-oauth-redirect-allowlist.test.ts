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

import { getDb, tenantConfigs, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";
import { authRoutes, clearOAuthTokenKeyStoreForTests } from "../routes/auth";

/**
 * NOTE on test isolation:
 *   Uses the ambient `DATABASE_URL` from the `Integration Tests (Postgres)`
 *   CI job rather than swapping pglite into the global handle. Closing a
 *   pglite handle in `afterAll` previously poisoned every subsequent test
 *   in `bun test packages/api` with `error: PGlite is closed`. We use a
 *   unique tenant prefix and clean up the rows in `afterAll` instead.
 */

const TENANT_ID = "test-oauth-allowlist";
const PKCE_QUERY = "&response_type=code&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256";
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

describeWithDatabase("OAuth redirect_uri allowlist", () => {
  beforeAll(async () => {
    process.env.STEWARD_MASTER_PASSWORD =
      process.env.STEWARD_MASTER_PASSWORD || "oauth-allowlist-master-password";
    process.env.STEWARD_JWT_SECRET =
      process.env.STEWARD_JWT_SECRET || "oauth-allowlist-jwt-secret-with-enough-bytes";
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_OAUTH_REDIRECT_ALLOWLIST;
    clearOAuthTokenKeyStoreForTests();

    const db = getDb();
    await db
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "OAuth Allowlist Tenant",
        apiKeyHash: "hash",
      })
      .onConflictDoNothing();
    await db
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
    const db = getDb();
    await db
      .delete(tenantConfigs)
      .where(eq(tenantConfigs.tenantId, TENANT_ID))
      .catch(() => {});
    await db
      .delete(tenants)
      .where(eq(tenants.id, TENANT_ID))
      .catch(() => {});
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
      allowedRedirectUrls: ["https://app.example.test/callback"],
    });

    const res = await authRoutes.request(
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://evil.example/callback")}${PKCE_QUERY}`,
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
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://global.example.test/callback")}${PKCE_QUERY}`,
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
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://app.example.test/callback")}${PKCE_QUERY}`,
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
      `/oauth/google/authorize?tenant_id=${TENANT_ID}&redirect_uri=${encodeURIComponent("https://app.example.test/")}${PKCE_QUERY}`,
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
