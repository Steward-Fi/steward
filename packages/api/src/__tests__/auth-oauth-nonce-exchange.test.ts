/**
 * /oauth/exchange — nonce-exchange round-trip.
 *
 * Covers the new `response_type=code` flow: a one-time code is bound to
 * {redirectUri, tenantId} at issue time and consumed atomically by the
 * exchange route. Tests focus on the validation contract — single-use,
 * redirect/tenant binding, TTL — without standing up a real provider.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Hono } from "hono";
import {
  _clearOAuthCodeStoreForTests,
  _seedOAuthExchangeCodeForTests,
  authRoutes,
} from "../routes/auth";

const REDIRECT_URI = "https://app.example.test/checkout";
const TENANT_ID = "elizacloud";

function makeApp(): Hono {
  const app = new Hono();
  app.route("/auth", authRoutes);
  return app;
}

async function postExchange(
  app: Hono,
  body: Record<string, unknown>,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const res = await app.request("/auth/oauth/exchange", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

describe("POST /auth/oauth/exchange", () => {
  beforeEach(() => {
    _clearOAuthCodeStoreForTests();
  });

  afterEach(() => {
    _clearOAuthCodeStoreForTests();
  });

  it("returns the bound tokens when code + redirect_uri + tenant_id all match", async () => {
    const app = makeApp();
    _seedOAuthExchangeCodeForTests("nonce-happy-path", {
      token: "access-jwt",
      refreshToken: "refresh-raw",
      redirectUri: REDIRECT_URI,
      tenantId: TENANT_ID,
    });

    const { status, json } = await postExchange(app, {
      code: "nonce-happy-path",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });

    expect(status).toBe(200);
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

  it("rejects a redirect_uri mismatch with code_redirect_mismatch and still burns the nonce", async () => {
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

    // Defense in depth: even the correct redirect_uri cannot retry — the
    // first lookup consumed (deleted) the code.
    const retry = await postExchange(app, {
      code: "nonce-bad-redirect",
      redirect_uri: REDIRECT_URI,
      tenant_id: TENANT_ID,
    });
    expect(retry.status).toBe(401);
    expect(retry.json.code).toBe("code_invalid");
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
