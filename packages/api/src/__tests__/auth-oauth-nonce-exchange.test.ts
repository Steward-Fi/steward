/**
 * /oauth/exchange — nonce-exchange round-trip.
 *
 * Covers the new `response_type=code` flow: a one-time code is bound to
 * {redirectUri, tenantId} at issue time and consumed atomically by the
 * exchange route. Tests focus on the validation contract — single-use,
 * redirect/tenant/PKCE binding, TTL — without standing up a real provider.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  setDefaultTimeout,
  spyOn,
} from "bun:test";
import { ChallengeStore } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

setDefaultTimeout(30000);

const REDIRECT_URI = "https://app.example.test/checkout";
const TENANT_ID = "elizacloud";

let authRoutes: typeof import("../routes/auth").authRoutes;
let _clearOAuthCodeStoreForTests: typeof import("../routes/auth")._clearOAuthCodeStoreForTests;
let _seedOAuthExchangeCodeForTests: typeof import("../routes/auth")._seedOAuthExchangeCodeForTests;

function failOAuthLockDeletion() {
  const originalDelete = ChallengeStore.prototype.delete;
  return spyOn(ChallengeStore.prototype, "delete").mockImplementation(async function (key) {
    if (key.startsWith("oauth-code-lock:")) {
      throw new Error("lock delete failed with bearer sk-cleanup-canary");
    }
    return originalDelete.call(this, key);
  });
}

function hangOAuthLockDeletion() {
  const originalDelete = ChallengeStore.prototype.delete;
  return spyOn(ChallengeStore.prototype, "delete").mockImplementation(async function (key) {
    if (key.startsWith("oauth-code-lock:")) {
      return new Promise<void>(() => {});
    }
    return originalDelete.call(this, key);
  });
}

function makeApp(): Hono {
  const app = new Hono();
  app.route("/auth", authRoutes);
  return app;
}

async function postExchange(
  app: Hono,
  body: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, unknown>; headers: Headers }> {
  const res = await app.request("/auth/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return {
    status: res.status,
    json: (await res.json()) as Record<string, unknown>,
    headers: res.headers,
  };
}

describe("POST /auth/oauth/exchange", () => {
  beforeAll(async () => {
    process.env.STEWARD_MASTER_PASSWORD ??= "dev-secret";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    const auth = await import("../routes/auth");
    authRoutes = auth.authRoutes;
    _clearOAuthCodeStoreForTests = auth._clearOAuthCodeStoreForTests;
    _seedOAuthExchangeCodeForTests = auth._seedOAuthExchangeCodeForTests;
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  beforeEach(() => {
    _clearOAuthCodeStoreForTests();
    delete process.env.STEWARD_ALLOW_OAUTH_TOKEN_REDIRECTS;
  });

  afterEach(() => {
    _clearOAuthCodeStoreForTests();
    delete process.env.APP_URL;
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
    delete process.env.STEWARD_ALLOW_OAUTH_TOKEN_REDIRECTS;
  });

  it("rejects token-in-query OAuth redirects even when the legacy env flag is enabled", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    process.env.STEWARD_ALLOW_OAUTH_TOKEN_REDIRECTS = "true";

    const app = makeApp();
    const res = await app.request(
      `/auth/oauth/google/authorize?redirect_uri=${encodeURIComponent(
        REDIRECT_URI,
      )}&response_type=token`,
    );
    const json = (await res.json()) as Record<string, unknown>;

    expect(res.status).toBe(400);
    expect(json.ok).toBe(false);
    expect(json.error).toContain("response_type=token is disabled");
  });

  it("requires S256 PKCE at the mounted authorize boundary", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const base = `/auth/oauth/google/authorize?redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code`;

    const missing = await makeApp().request(base);
    expect(missing.status).toBe(400);
    expect(((await missing.json()) as { error: string }).error).toContain(
      "code_challenge is required",
    );

    const plain = await makeApp().request(
      `${base}&code_challenge=abcdefghijklmnopqrstuvwxyzABCDEFG0123456789-_&code_challenge_method=plain`,
    );
    expect(plain.status).toBe(400);
    expect(((await plain.json()) as { error: string }).error).toBe(
      "code_challenge_method must be 'S256'",
    );
  });

  it("does not exchange a raw provider code without explicit unsafe opt-in", async () => {
    delete process.env.STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE;
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const providerFetch = spyOn(globalThis, "fetch");
    const response = await makeApp().request("/auth/oauth/google/token", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: "raw-provider-code", redirectUri: REDIRECT_URI }),
    });
    expect(response.status).toBe(401);
    expect(((await response.json()) as { error: string }).error).toContain(
      "Unbound OAuth provider code exchange is disabled",
    );
    expect(providerFetch).toHaveBeenCalledTimes(0);
    providerFetch.mockRestore();
  });

  it("returns the bound tokens when code + redirect_uri + tenant_id all match", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-happy-path", {
      token: "access-jwt",
      refreshToken: "refresh-raw",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });

    const { status, json, headers } = await postExchange(app, {
      code: "nonce-happy-path",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });

    expect(status).toBe(200);
    expect(headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(headers.get("Pragma")).toBe("no-cache");
    expect(headers.get("Expires")).toBe("0");
    expect(json.ok).toBe(true);
    expect(json.token).toBe("access-jwt");
    expect(json.refreshToken).toBe("refresh-raw");
    expect(typeof json.expiresAt).toBe("number");
    expect(json.expiresIn).toBe(900);
  });

  it("rejects unknown / already-consumed codes with code_invalid", async () => {
    const app = makeApp();
    const { status, json } = await postExchange(app, {
      code: "never-issued",
      redirect_uri: REDIRECT_URI,
    });
    expect(status).toBe(401);
    expect(json.code).toBe("code_invalid");
  });

  it("is single-use: a second exchange of the same code fails with code_invalid", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-once", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });

    const first = await postExchange(app, {
      code: "nonce-once",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(first.status).toBe(200);

    const second = await postExchange(app, {
      code: "nonce-once",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(second.status).toBe(401);
    expect(second.json.code).toBe("code_invalid");
  });

  it("allows exactly one concurrent redemption of the same code", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-concurrent", {
      token: "concurrent-access",
      refreshToken: "concurrent-refresh",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });
    const redeem = () =>
      postExchange(app, {
        code: "nonce-concurrent",
        redirect_uri: REDIRECT_URI,
        tenant_id: TENANT_ID,
      });

    const responses = await Promise.all([redeem(), redeem()]);
    expect(responses.filter(({ status }) => status === 200)).toHaveLength(1);
    expect(responses.filter(({ json }) => json.token === "concurrent-access")).toHaveLength(1);
    const rejected = responses.find(({ status }) => status !== 200);
    expect([401, 409]).toContain(rejected?.status);
    expect(rejected?.json.token).toBeUndefined();

    const replay = await redeem();
    expect(replay).toMatchObject({ status: 401, json: { code: "code_invalid" } });
  });

  it("returns a consumed nonce exchange when ancillary lock cleanup fails", async () => {
    _seedOAuthExchangeCodeForTests("nonce-cleanup-failure", {
      token: "access-after-cleanup-failure",
      refreshToken: "refresh-after-cleanup-failure",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });
    const deleteFailure = failOAuthLockDeletion();
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const first = await postExchange(makeApp(), {
        code: "nonce-cleanup-failure",
        redirect_uri: REDIRECT_URI,
        tenant_id: TENANT_ID,
      });

      expect(first).toMatchObject({
        status: 200,
        json: {
          ok: true,
          token: "access-after-cleanup-failure",
          refreshToken: "refresh-after-cleanup-failure",
        },
      });
      expect(JSON.stringify(warn.mock.calls)).not.toContain("sk-cleanup-canary");

      const second = await postExchange(makeApp(), {
        code: "nonce-cleanup-failure",
        redirect_uri: REDIRECT_URI,
        tenant_id: TENANT_ID,
      });
      expect(second.status).toBe(401);
      expect(second.json.code).toBe("code_invalid");
    } finally {
      deleteFailure.mockRestore();
      warn.mockRestore();
    }
  });

  it("bounds a lock cleanup that never settles after consuming the code", async () => {
    _seedOAuthExchangeCodeForTests("nonce-cleanup-hang", {
      token: "access-after-cleanup-hang",
      refreshToken: "refresh-after-cleanup-hang",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });
    const deleteHang = hangOAuthLockDeletion();
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const startedAt = Date.now();
      const response = await postExchange(makeApp(), {
        code: "nonce-cleanup-hang",
        redirect_uri: REDIRECT_URI,
        tenant_id: TENANT_ID,
      });

      expect(Date.now() - startedAt).toBeLessThan(1_000);
      expect(response).toMatchObject({
        status: 200,
        json: {
          ok: true,
          token: "access-after-cleanup-hang",
          refreshToken: "refresh-after-cleanup-hang",
        },
      });
      expect(JSON.stringify(warn.mock.calls)).not.toContain("access-after-cleanup-hang");
    } finally {
      deleteHang.mockRestore();
      warn.mockRestore();
    }
  });

  it("returns a consumed provider-token exchange when ancillary lock cleanup fails", async () => {
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    _seedOAuthExchangeCodeForTests("provider-cleanup-failure", {
      token: "provider-access-after-cleanup-failure",
      refreshToken: "provider-refresh-after-cleanup-failure",
      redirectUri: REDIRECT_URI,
      tenantId: null,
      providerName: "google",
    });
    const deleteFailure = failOAuthLockDeletion();
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    try {
      const response = await makeApp().request("/auth/oauth/google/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "provider-cleanup-failure",
          redirectUri: REDIRECT_URI,
        }),
      });
      const json = (await response.json()) as Record<string, unknown>;

      expect(response.status).toBe(200);
      expect(json.token).toBe("provider-access-after-cleanup-failure");
      expect(json.refreshToken).toBe("provider-refresh-after-cleanup-failure");
      expect(JSON.stringify(warn.mock.calls)).not.toContain("sk-cleanup-canary");
      const second = await makeApp().request("/auth/oauth/google/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "provider-cleanup-failure",
          redirectUri: REDIRECT_URI,
        }),
      });
      expect(second.status).toBe(401);
    } finally {
      deleteFailure.mockRestore();
      warn.mockRestore();
    }
  });

  it("still fails closed and preserves the code when atomic consume fails", async () => {
    _seedOAuthExchangeCodeForTests("nonce-consume-failure", {
      token: "must-not-be-returned",
      refreshToken: "must-not-be-returned-either",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });
    const originalConsume = ChallengeStore.prototype.consume;
    const consumeFailure = spyOn(ChallengeStore.prototype, "consume").mockImplementation(
      async function (key) {
        if (key === "oauth-code:nonce-consume-failure") {
          throw new Error("consume backend unavailable");
        }
        return originalConsume.call(this, key);
      },
    );

    try {
      const response = await makeApp().request("/auth/oauth/exchange", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "nonce-consume-failure",
          redirect_uri: REDIRECT_URI,
          tenant_id: TENANT_ID,
        }),
      });
      const text = await response.text();

      expect(response.status).toBe(500);
      expect(text).not.toContain("must-not-be-returned");
    } finally {
      consumeFailure.mockRestore();
    }

    const retry = await postExchange(makeApp(), {
      code: "nonce-consume-failure",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(retry).toMatchObject({
      status: 200,
      json: { token: "must-not-be-returned", refreshToken: "must-not-be-returned-either" },
    });
  });

  it("rejects a redirect_uri mismatch with code_redirect_mismatch without burning the nonce", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-bad-redirect", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });

    const bad = await postExchange(app, {
      code: "nonce-bad-redirect",
      redirect_uri: "https://attacker.example/landing",
      tenant_id: TENANT_ID,
    });
    expect(bad.status).toBe(401);
    expect(bad.json.code).toBe("code_redirect_mismatch");

    const retry = await postExchange(app, {
      code: "nonce-bad-redirect",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(retry.status).toBe(200);
    expect(retry.json.ok).toBe(true);
  });

  it("rejects a bad PKCE verifier without burning the nonce", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-bad-pkce", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
      codeChallenge: "expected-challenge",
      codeChallengeMethod: "S256",
    });

    const bad = await postExchange(app, {
      code: "nonce-bad-pkce",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
      code_verifier: "invalid-invalid-invalid-invalid-invalid-invalid",
    });
    expect(bad.status).toBe(401);
    expect(bad.json.code).toBe("code_verifier_mismatch");

    const retryWithoutVerifier = await postExchange(app, {
      code: "nonce-bad-pkce",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(retryWithoutVerifier.status).toBe(401);
    expect(retryWithoutVerifier.json.code).toBe("code_verifier_invalid");
  });

  it("rejects a tenant_id mismatch with code_tenant_mismatch", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-bad-tenant", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });

    const bad = await postExchange(app, {
      code: "nonce-bad-tenant",
      redirect_uri: REDIRECT_URI,
      tenant_id: "different-tenant",
    });
    expect(bad.status).toBe(401);
    expect(bad.json.code).toBe("code_tenant_mismatch");
  });

  it("rejects provider-token redemption when the path provider differs from the issued provider", async () => {
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-bad-provider", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: null,
      providerName: "google",
    });

    const res = await app.request("/auth/oauth/discord/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: "nonce-bad-provider",
        redirectUri: REDIRECT_URI,
      }),
    });
    const json = (await res.json()) as Record<string, unknown>;

    expect(res.status).toBe(401);
    expect(json.ok).toBe(false);
    expect(json.error).toBe("OAuth code provider mismatch");
  });

  it("rejects an expired code with code_expired", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-expired", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
      expiresAt: Date.now() - 1000,
    });

    const { status, json } = await postExchange(app, {
      code: "nonce-expired",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(status).toBe(401);
    expect(json.code).toBe("code_expired");
  });

  it("treats a missing/null tenant on issue as matching no tenant on exchange", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-no-tenant", {
      token: "t",
      refreshToken: "r",
      redirectUri: REDIRECT_URI,
      tenantId: null,
    });

    const { status, json } = await postExchange(app, {
      code: "nonce-no-tenant",
      redirect_uri: REDIRECT_URI,
      // tenant_id omitted
    });
    expect(status).toBe(200);
    expect(json.ok).toBe(true);
  });

  it("400s when code or redirect_uri is missing", async () => {
    const app = makeApp();
    const missingCode = await postExchange(app, { redirect_uri: REDIRECT_URI });
    expect(missingCode.status).toBe(400);

    const missingRedirect = await postExchange(app, { code: "x" });
    expect(missingRedirect.status).toBe(400);
  });
});
