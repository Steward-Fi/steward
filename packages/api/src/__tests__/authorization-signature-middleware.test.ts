import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import {
  authorizationSignature,
  createAuthorizationSignature,
} from "../middleware/authorization-signature";

const SECRET = "request-signing-secret-with-enough-entropy";
const BODY = JSON.stringify({ value: "1000" });
// Use a fresh timestamp so the middleware's freshness enforcement does not reject as stale.
const TIMESTAMP = String(Math.floor(Date.now() / 1000));

function makeApp(required = false) {
  const app = new Hono<{ Variables: { requestSignatureVerified?: boolean } }>();
  app.use("*", authorizationSignature({ required, secrets: [SECRET] }));
  app.post("/vault/:agentId/sign", (c) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) }),
  );
  app.post("/condition-sets", (c) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) }),
  );
  app.post("/user/me/wallet/sign", (c) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) }),
  );
  app.post("/webhooks", (c) => c.json({ ok: true }));
  app.post("/intents", (c) => c.json({ ok: true }));
  app.post("/intents/:intentId/authorize", (c) => c.json({ ok: true }));
  app.post("/audit/verify", (c) => c.json({ ok: true }));
  app.post("/auth/refresh", (c) => c.json({ ok: true }));
  app.post("/auth/mfa/totp/unenroll", (c) => c.json({ ok: true }));
  app.put("/tenants/:id/config", (c) => c.json({ ok: true }));
  app.post("/platform/tenants", (c) => c.json({ ok: true }));
  app.post("/agents", (c) => c.json({ ok: true }));
  app.post("/health", (c) => c.json({ ok: true }));
  return app;
}

function makeDefaultApp() {
  const app = new Hono<{ Variables: { requestSignatureVerified?: boolean } }>();
  app.use("*", authorizationSignature({ secrets: [SECRET] }));
  app.post("/vault/:agentId/sign", (c) =>
    c.json({ ok: true, verified: Boolean(c.get("requestSignatureVerified")) }),
  );
  return app;
}

async function signedHeaders(path = "/vault/agent-1/sign", body = BODY) {
  const authorization = "Bearer token-a";
  const signature = await createAuthorizationSignature(
    {
      method: "POST",
      url: `https://api.test${path}`,
      tenantId: "tenant-1",
      authorization,
      timestamp: TIMESTAMP,
      idempotencyKey: "idem-key-123",
      body,
    },
    SECRET,
  );
  return {
    "content-type": "application/json",
    authorization,
    "x-steward-tenant": "tenant-1",
    "x-steward-request-timestamp": TIMESTAMP,
    "idempotency-key": "idem-key-123",
    "x-steward-signature": signature,
  };
}

async function signedDelegatedHeaders(path = "/vault/agent-1/sign", body = BODY) {
  const apiKey = "stw_key_a";
  const signerId = "signer-a";
  const signerSecret = "secret-a";
  const signature = await createAuthorizationSignature(
    {
      method: "POST",
      url: `https://api.test${path}`,
      tenantId: "tenant-1",
      apiKey,
      signerId,
      signerSecret,
      timestamp: TIMESTAMP,
      idempotencyKey: "idem-key-123",
      body,
    },
    SECRET,
  );
  return {
    "content-type": "application/json",
    "x-steward-tenant": "tenant-1",
    "x-steward-key": apiKey,
    "x-steward-signer-id": signerId,
    "x-steward-signer-secret": signerSecret,
    "x-steward-request-timestamp": TIMESTAMP,
    "idempotency-key": "idem-key-123",
    "x-steward-signature": signature,
  };
}

describe("authorizationSignature", () => {
  it("allows sensitive mutating requests without a signature while optional", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", { method: "POST", body: BODY });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: false });
  });

  it("verifies signed sensitive mutating requests", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: await signedHeaders(),
      body: BODY,
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, verified: true });
  });

  it("rejects tampered signed bodies", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: await signedHeaders(),
      body: JSON.stringify({ value: "2000" }),
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("rejects signed request replay with different bearer auth material", async () => {
    const app = makeApp();
    const headers = await signedHeaders();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: { ...headers, authorization: "Bearer token-b" },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("rejects signed request replay with different tenant API key material", async () => {
    const app = makeApp();
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        apiKey: "stw_key_a",
        timestamp: TIMESTAMP,
        idempotencyKey: "idem-key-123",
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": "tenant-1",
        "x-steward-key": "stw_key_b",
        "x-steward-request-timestamp": TIMESTAMP,
        "idempotency-key": "idem-key-123",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("rejects signed delegated requests with different signer credentials", async () => {
    const app = makeApp();
    const headers = await signedDelegatedHeaders();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: { ...headers, "x-steward-signer-secret": "secret-b" },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Invalid request signature" });
  });

  it("requires timestamp or expiry on signed requests", async () => {
    const app = makeApp();
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": "tenant-1",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      ok: false,
      error: "Signed requests require a timestamp or expiry header",
    });
  });

  it("requires idempotency keys on signed sensitive requests to prevent freshness-window replay", async () => {
    const app = makeApp();
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        timestamp: TIMESTAMP,
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-tenant": "tenant-1",
        "x-steward-request-timestamp": TIMESTAMP,
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      ok: false,
      error: "Signed requests require an Idempotency-Key header",
    });
  });

  it("rejects validly-signed but stale signed requests to prevent indefinite replay", async () => {
    const app = makeApp();
    const staleTs = String(Math.floor(Date.now() / 1000) - 24 * 60 * 60); // 1 day old
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        authorization: "Bearer token-a",
        timestamp: staleTs,
        idempotencyKey: "idem-key-123",
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token-a",
        "x-steward-tenant": "tenant-1",
        "x-steward-request-timestamp": staleTs,
        "idempotency-key": "idem-key-123",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({
      ok: false,
      error: "Signed request timestamp is stale",
    });
  });

  it("rejects validly-signed requests whose expiry has already passed", async () => {
    const app = makeApp();
    const expiredAt = String(Math.floor(Date.now() / 1000) - 24 * 60 * 60);
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        authorization: "Bearer token-a",
        expiresAt: expiredAt,
        idempotencyKey: "idem-key-123",
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token-a",
        "x-steward-tenant": "tenant-1",
        "x-steward-request-expires-at": expiredAt,
        "idempotency-key": "idem-key-123",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ ok: false, error: "Signed request has expired" });
  });

  it("rejects validly-signed requests with a far-future timestamp (clock-skew bound)", async () => {
    const app = makeApp();
    const futureTs = String(Math.floor(Date.now() / 1000) + 24 * 60 * 60);
    const signature = await createAuthorizationSignature(
      {
        method: "POST",
        url: "https://api.test/vault/agent-1/sign",
        tenantId: "tenant-1",
        authorization: "Bearer token-a",
        timestamp: futureTs,
        idempotencyKey: "idem-key-123",
        body: BODY,
      },
      SECRET,
    );

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer token-a",
        "x-steward-tenant": "tenant-1",
        "x-steward-request-timestamp": futureTs,
        "idempotency-key": "idem-key-123",
        "x-steward-signature": signature,
      },
      body: BODY,
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      ok: false,
      error: "Signed request timestamp is too far in the future",
    });
  });

  it("can require signatures for sensitive routes while leaving non-sensitive routes alone", async () => {
    const app = makeApp(true);

    const sensitive = await app.request("/vault/agent-1/sign", { method: "POST", body: BODY });
    const conditionSet = await app.request("/condition-sets", { method: "POST", body: BODY });
    const userWalletSign = await app.request("/user/me/wallet/sign", {
      method: "POST",
      body: BODY,
    });
    const webhook = await app.request("/webhooks", { method: "POST", body: BODY });
    const intent = await app.request("/intents", { method: "POST", body: BODY });
    const intentAuthorize = await app.request("/intents/intent-1/authorize", {
      method: "POST",
      body: BODY,
    });
    const auditVerify = await app.request("/audit/verify", { method: "POST", body: BODY });
    const authRefresh = await app.request("/auth/refresh", { method: "POST", body: BODY });
    const authMfaUnenroll = await app.request("/auth/mfa/totp/unenroll", {
      method: "POST",
      body: BODY,
    });
    const tenantConfig = await app.request("/tenants/tenant-1/config", {
      method: "PUT",
      body: BODY,
    });
    const platformTenant = await app.request("/platform/tenants", {
      method: "POST",
      body: BODY,
    });
    const agent = await app.request("/agents", { method: "POST" });
    const nonSensitive = await app.request("/health", { method: "POST" });

    expect(sensitive.status).toBe(401);
    expect(await sensitive.json()).toEqual({
      ok: false,
      error: "X-Steward-Signature header required",
    });
    expect(conditionSet.status).toBe(401);
    expect(userWalletSign.status).toBe(401);
    expect(webhook.status).toBe(401);
    expect(intent.status).toBe(401);
    expect(intentAuthorize.status).toBe(401);
    expect(auditVerify.status).toBe(401);
    expect(authRefresh.status).toBe(401);
    expect(authMfaUnenroll.status).toBe(401);
    expect(tenantConfig.status).toBe(401);
    expect(platformTenant.status).toBe(401);
    expect(agent.status).toBe(401);
    expect(nonSensitive.status).toBe(200);
  });

  it("requires signatures for sensitive production mutations even if unsigned opt-out is set", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalRequire = process.env.STEWARD_REQUIRE_AUTH_SIGNATURE;
    const originalAllow = process.env.STEWARD_ALLOW_UNSIGNED_SENSITIVE_REQUESTS;
    try {
      process.env.NODE_ENV = "production";
      delete process.env.STEWARD_REQUIRE_AUTH_SIGNATURE;
      process.env.STEWARD_ALLOW_UNSIGNED_SENSITIVE_REQUESTS = "true";
      const app = makeDefaultApp();

      const res = await app.request("/vault/agent-1/sign", { method: "POST", body: BODY });

      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({
        ok: false,
        error: "X-Steward-Signature header required",
      });
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalRequire === undefined) delete process.env.STEWARD_REQUIRE_AUTH_SIGNATURE;
      else process.env.STEWARD_REQUIRE_AUTH_SIGNATURE = originalRequire;
      if (originalAllow === undefined) delete process.env.STEWARD_ALLOW_UNSIGNED_SENSITIVE_REQUESTS;
      else process.env.STEWARD_ALLOW_UNSIGNED_SENSITIVE_REQUESTS = originalAllow;
    }
  });
});
