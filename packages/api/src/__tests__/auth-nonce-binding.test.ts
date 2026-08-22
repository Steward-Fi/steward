import { afterAll, afterEach, beforeAll, describe, expect, it, mock } from "bun:test";
import { createHash } from "node:crypto";
import { clearOidcJwksCacheForTests } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";

process.env.NODE_ENV = "test";
process.env.STEWARD_MASTER_PASSWORD = "nonce-binding-master-password";
process.env.STEWARD_JWT_SECRET = "nonce-binding-jwt-secret-with-enough-entropy";
// OAuth success writes the user-created audit event. Keep the mounted fixture
// truthful when invoked outside packages/api's preload: production correctly
// fails closed if the audit-chain HMAC authority is absent.
process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.SIWE_ALLOWED_DOMAINS = "steward.fi,www.steward.fi";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";

const originalFetch = globalThis.fetch;
let auth: typeof import("../routes/auth");

function siweMessage(domain: string, address: string, nonce: string) {
  return [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    "",
    "Sign in to Steward",
    "",
    `URI: https://${domain}`,
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}

async function nonce(headers: HeadersInit = {}) {
  const response = await auth.authRoutes.request("/nonce", {
    headers: { origin: "https://steward.fi", ...headers },
  });
  return { response, body: (await response.json()) as { nonce?: string; error?: string } };
}

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  auth = await import("../routes/auth");
  await getDb().insert(tenants).values({
    id: "bound-tenant",
    name: "Bound tenant",
    apiKeyHash: "nonce-binding-api-key-hash",
    ownerAddress: "0x0000000000000000000000000000000000000742",
  });
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete process.env.APP_URL;
  delete process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_SECRET;
  delete process.env.APPLE_CLIENT_ID;
  delete process.env.APPLE_CLIENT_SECRET;
  delete process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH;
  delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
  clearOidcJwksCacheForTests();
});

afterAll(async () => {
  await closeDb();
});

describe("mounted nonce and OAuth state boundaries", () => {
  it("requires an allowlisted origin and binds a nonce to domain and tenant", async () => {
    const denied = await auth.authRoutes.request("/nonce", {
      headers: { origin: "https://attacker.example" },
    });
    expect(denied.status).toBe(400);
    expect(await denied.json()).toMatchObject({
      ok: false,
      error: "SIWE nonce requests require an allowed Origin or Referer",
    });

    const domainBound = await nonce();
    const disallowedDomain = await auth.authRoutes.request("/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: siweMessage(
          "attacker.example",
          "0x0000000000000000000000000000000000000742",
          domainBound.body.nonce!,
        ),
        signature: `0x${"00".repeat(65)}`,
      }),
    });
    expect(disallowedDomain.status).toBe(401);
    expect(((await disallowedDomain.json()) as { error: string }).error).toContain("domain");

    const originBound = await nonce();
    const originMismatch = await auth.authRoutes.request("/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: siweMessage(
          "www.steward.fi",
          "0x0000000000000000000000000000000000000742",
          originBound.body.nonce!,
        ),
        signature: `0x${"00".repeat(65)}`,
      }),
    });
    expect(originMismatch.status).toBe(401);
    expect(((await originMismatch.json()) as { error: string }).error).toContain("origin");

    const issued = await nonce({ "x-steward-tenant": "bound-tenant" });
    expect(issued.response.status).toBe(200);
    expect(issued.body.nonce).toMatch(/^[A-Za-z0-9]{8,}$/);
    const mismatch = await auth.authRoutes.request("/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: siweMessage(
          "steward.fi",
          "0x0000000000000000000000000000000000000742",
          issued.body.nonce!,
        ),
        signature: `0x${"00".repeat(65)}`,
      }),
    });
    expect(mismatch.status).toBe(401);
    const mismatchBody = (await mismatch.json()) as { error: string; token?: string };
    expect(mismatchBody.error).toContain("tenant");
    expect(mismatchBody.token).toBeUndefined();
    const replay = await auth.authRoutes.request("/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        message: siweMessage(
          "steward.fi",
          "0x0000000000000000000000000000000000000742",
          issued.body.nonce!,
        ),
        signature: `0x${"00".repeat(65)}`,
      }),
    });
    expect(replay.status).toBe(401);
    expect(((await replay.json()) as { token?: string }).token).toBeUndefined();
  });

  it("uses APP_URL for provider callbacks even with a hostile Host", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://app.example.test/callback";
    const response = await auth.authRoutes.request(
      "/oauth/google/authorize?redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFG0123456789-_&code_challenge_method=S256",
      { headers: { host: "attacker.example" } },
    );
    expect(response.status).toBe(302);
    const provider = new URL(response.headers.get("location")!);
    expect(provider.searchParams.get("redirect_uri")).toBe(
      "https://api.example.test/auth/oauth/google/callback",
    );
    expect(provider.searchParams.get("redirect_uri")).not.toContain("attacker.example");
  });

  it("keeps callback state retryable when provider verification fails", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://app.example.test/callback";
    const state = "retryable-provider-state";
    const payload = JSON.stringify({
      provider: "google",
      redirectUri: "https://app.example.test/callback",
    });
    await auth.getAuthChallengeStore().set(`oauth:${state}`, payload);
    globalThis.fetch = mock(async () => new Response("provider rejected code", { status: 401 }));

    const failed = await auth.authRoutes.request(
      `/oauth/google/callback?code=bad-code&state=${state}`,
    );
    expect(failed.status).toBe(502);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).toBe(payload);
  });

  it("binds Apple callbacks to nonce, issuer, and audience before one-time state consume", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.APPLE_CLIENT_ID = "com.example.steward";
    process.env.APPLE_CLIENT_SECRET = "apple-client-secret-jwt";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = "https://app.example.test/callback";
    process.env.STEWARD_ALLOW_INSECURE_OIDC_JWKS_FETCH = "true";

    const keyPair = await generateKeyPair("ES256");
    const publicJwk = (await exportJWK(keyPair.publicKey)) as JWK;
    Object.assign(publicJwk, { kid: "apple-mounted-key", alg: "ES256", use: "sig" });
    let nextToken = "";
    const codeVerifier = "mounted-apple-pkce-verifier-abcdefghijklmnopqrstuvwxyz0123456789";
    const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");
    globalThis.fetch = mock(async (input: RequestInfo | URL) => {
      const url =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url === "https://appleid.apple.com/auth/keys") {
        return Response.json({ keys: [publicJwk] });
      }
      if (url === "https://appleid.apple.com/auth/token") {
        return Response.json({
          access_token: "apple-access",
          token_type: "Bearer",
          id_token: nextToken,
        });
      }
      throw new Error(`unexpected mounted Apple fetch: ${url}`);
    });

    const authorize = await auth.authRoutes.request(
      `/oauth/apple/authorize?redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&code_challenge=${codeChallenge}&code_challenge_method=S256`,
    );
    expect(authorize.status).toBe(302);
    const provider = new URL(authorize.headers.get("location")!);
    const state = provider.searchParams.get("state")!;
    const expectedNonce = provider.searchParams.get("nonce")!;
    expect(expectedNonce).toBeString();

    const idToken = (claims: { nonce: string; issuer?: string; audience?: string }) =>
      new SignJWT({
        email: "mounted-apple@privaterelay.appleid.com",
        email_verified: true,
        nonce: claims.nonce,
      })
        .setProtectedHeader({ alg: "ES256", kid: "apple-mounted-key" })
        .setIssuer(claims.issuer ?? "https://appleid.apple.com")
        .setAudience(claims.audience ?? "com.example.steward")
        .setSubject("mounted-apple-subject")
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(keyPair.privateKey);

    nextToken = await idToken({ nonce: "wrong-nonce" });
    const nonceMismatch = await auth.authRoutes.request(
      `/oauth/apple/callback?code=provider-code&state=${state}`,
    );
    expect(nonceMismatch.status).toBe(502);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).not.toBeNull();

    clearOidcJwksCacheForTests();
    nextToken = await idToken({ nonce: expectedNonce, issuer: "https://issuer.example.test" });
    const issuerMismatch = await auth.authRoutes.request(
      `/oauth/apple/callback?code=provider-code&state=${state}`,
    );
    expect(issuerMismatch.status).toBe(502);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).not.toBeNull();

    clearOidcJwksCacheForTests();
    nextToken = await idToken({ nonce: expectedNonce, audience: "com.attacker.service" });
    const audienceMismatch = await auth.authRoutes.request(
      `/oauth/apple/callback?code=provider-code&state=${state}`,
    );
    expect(audienceMismatch.status).toBe(502);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).not.toBeNull();

    clearOidcJwksCacheForTests();
    nextToken = await idToken({ nonce: expectedNonce });
    const success = await auth.authRoutes.request(
      `/oauth/apple/callback?code=provider-code&state=${state}`,
    );
    expect(success.status).toBe(302);
    expect(await auth.getAuthChallengeStore().get(`oauth:${state}`)).toBeNull();
    const callbackRedirect = new URL(success.headers.get("location")!);
    const exchangeCode = new URLSearchParams(callbackRedirect.hash.slice(1)).get("code");
    expect(exchangeCode).toBeString();
    const exchange = await auth.authRoutes.request("/oauth/exchange", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        code: exchangeCode,
        redirect_uri: "https://app.example.test/callback",
        code_verifier: codeVerifier,
      }),
    });
    expect(exchange.status).toBe(200);
    expect(await exchange.json()).toMatchObject({
      ok: true,
      token: expect.any(String),
      refreshToken: expect.any(String),
      user: {
        email: "mounted-apple@privaterelay.appleid.com",
      },
    });
    expect(
      (await auth.authRoutes.request(`/oauth/apple/callback?code=provider-code&state=${state}`))
        .status,
    ).toBe(401);
  });

  it("rate-limits challenge allocation without returning an extra nonce", async () => {
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    const originalOutageValveMax = process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX;
    process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX = "0";
    process.env.NODE_ENV = "production";
    try {
      const blocked = await nonce();
      expect(blocked.response.status).toBe(429);
      expect(blocked.body.nonce).toBeUndefined();
      expect(blocked.body.error).toContain("Too many nonce requests");
    } finally {
      process.env.NODE_ENV = "test";
      process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
      if (originalOutageValveMax === undefined) {
        delete process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX;
      } else {
        process.env.STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX = originalOutageValveMax;
      }
    }
  });
});
