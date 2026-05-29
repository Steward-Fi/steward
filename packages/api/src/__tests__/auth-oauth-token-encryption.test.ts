import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";
import { accounts, closeDb, tenantConfigs, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import {
  authRoutes,
  clearOAuthTokenKeyStoreForTests,
  decryptOAuthProviderToken,
  encryptOAuthProviderTokens,
} from "../routes/auth";

const MASTER_PASSWORD = "oauth-token-test-master";
const originalFetch = globalThis.fetch;

async function setupDb() {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  return db;
}

describe("OAuth provider token encryption", () => {
  beforeEach(() => {
    process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
    process.env.JWT_SECRET = "oauth-token-test-jwt-secret-with-enough-bytes";
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE = "true";
    clearOAuthTokenKeyStoreForTests();
  });

  afterEach(async () => {
    mock.restore();
    globalThis.fetch = originalFetch;
    clearOAuthTokenKeyStoreForTests();
    await closeDb().catch(() => {});
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.JWT_SECRET;
    delete process.env.APP_URL;
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE;
  });

  it("encrypts OAuth tokens and rejects the wrong master password with a clear error", () => {
    const encrypted = encryptOAuthProviderTokens(
      "access-token-plaintext",
      "refresh-token-plaintext",
    );

    expect(encrypted.accessTokenEncrypted).not.toBe("access-token-plaintext");
    expect(encrypted.refreshTokenEncrypted).not.toBe("refresh-token-plaintext");
    expect(encrypted.accessTokenEncrypted).toMatch(/^[0-9a-f]+$/);
    expect(encrypted.accessTokenIv).toMatch(/^[0-9a-f]{32}$/);
    expect(encrypted.accessTokenTag).toMatch(/^[0-9a-f]{32}$/);
    expect(encrypted.accessTokenSalt).toMatch(/^[0-9a-f]{32}$/);

    expect(
      decryptOAuthProviderToken({
        ciphertext: encrypted.accessTokenEncrypted ?? null,
        iv: encrypted.accessTokenIv ?? null,
        tag: encrypted.accessTokenTag ?? null,
        salt: encrypted.accessTokenSalt ?? null,
      }),
    ).toBe("access-token-plaintext");

    process.env.STEWARD_MASTER_PASSWORD = "wrong-master-password";
    clearOAuthTokenKeyStoreForTests();
    expect(() =>
      decryptOAuthProviderToken({
        ciphertext: encrypted.accessTokenEncrypted ?? null,
        iv: encrypted.accessTokenIv ?? null,
        tag: encrypted.accessTokenTag ?? null,
        salt: encrypted.accessTokenSalt ?? null,
      }),
    ).toThrow(/Failed to decrypt OAuth provider token: check STEWARD_MASTER_PASSWORD/);
  });

  it("completes the mocked OAuth token flow and stores provider tokens encrypted", async () => {
    const db = await setupDb();
    await db.insert(tenants).values({
      id: "oauth-test-tenant",
      name: "OAuth Test Tenant",
      apiKeyHash: "hash",
    });
    // OAuth redirect_uri allowlist now requires either a tenant config
    // entry or the STEWARD_OAUTH_ALLOWED_REDIRECTS env var. Configure the
    // tenant explicitly so the redirect target this test uses is allowed.
    await db.insert(tenantConfigs).values({
      tenantId: "oauth-test-tenant",
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
      joinMode: "open",
    });

    mock.restore();
    globalThis.fetch = mock(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "provider-access-token",
            refresh_token: "provider-refresh-token",
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
        return new Response(
          JSON.stringify({
            id: "google-user-1",
            email: "oauth-user@example.com",
            name: "OAuth User",
            verified_email: true,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as unknown as typeof fetch;

    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://app.example.test/callback",
        tenantId: "oauth-test-tenant",
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; token?: string; refreshToken?: string };
    expect(body.ok).toBe(true);
    expect(body.token).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();

    const [account] = await db.select().from(accounts).where(eq(accounts.provider, "google"));
    expect(account.accessTokenEncrypted).not.toBe("provider-access-token");
    expect(account.refreshTokenEncrypted).not.toBe("provider-refresh-token");
    expect(account.accessTokenIv).toMatch(/^[0-9a-f]{32}$/);
    expect(account.refreshTokenSalt).toMatch(/^[0-9a-f]{32}$/);
    expect(
      decryptOAuthProviderToken({
        ciphertext: account.accessTokenEncrypted,
        iv: account.accessTokenIv,
        tag: account.accessTokenTag,
        salt: account.accessTokenSalt,
      }),
    ).toBe("provider-access-token");
  });

  it("rejects OAuth sign-in when the provider email is unverified", async () => {
    const db = await setupDb();
    await db.insert(tenants).values({
      id: "oauth-unverified-tenant",
      name: "OAuth Unverified Tenant",
      apiKeyHash: "hash",
    });
    await db.insert(tenantConfigs).values({
      tenantId: "oauth-unverified-tenant",
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
      joinMode: "open",
    });

    mock.restore();
    globalThis.fetch = mock(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "provider-access-token",
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
        return new Response(
          JSON.stringify({
            id: "google-user-unverified",
            email: "victim@example.com",
            name: "Unverified OAuth User",
            verified_email: false,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as unknown as typeof fetch;

    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://app.example.test/callback",
        tenantId: "oauth-unverified-tenant",
      }),
    });

    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Provider email must be verified");
  });

  it("rejects provider-supplied emails in the reserved synthetic identity domain", async () => {
    const db = await setupDb();
    await db.insert(tenants).values({
      id: "oauth-internal-email-tenant",
      name: "OAuth Internal Email Tenant",
      apiKeyHash: "hash",
    });
    await db.insert(tenantConfigs).values({
      tenantId: "oauth-internal-email-tenant",
      allowedOrigins: ["https://app.example.test"],
      allowedRedirectUrls: ["https://app.example.test/callback"],
      joinMode: "open",
    });
    const [victim] = await db
      .insert(users)
      .values({ email: "twitter.12345@id.steward.internal" })
      .returning({ id: users.id });

    mock.restore();
    globalThis.fetch = mock(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "provider-access-token",
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
        return new Response(
          JSON.stringify({
            id: "attacker-google-account",
            email: "twitter.12345@id.steward.internal",
            name: "Internal Collision",
            verified_email: false,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as unknown as typeof fetch;

    const res = await authRoutes.request("/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: "auth-code",
        redirectUri: "https://app.example.test/callback",
        tenantId: "oauth-internal-email-tenant",
      }),
    });

    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("reserved internal domain");

    const linkedAccounts = await db
      .select()
      .from(accounts)
      .where(eq(accounts.userId, victim.id));
    expect(linkedAccounts).toHaveLength(0);
  });
});
