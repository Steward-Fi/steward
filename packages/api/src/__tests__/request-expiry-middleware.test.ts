import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { requestExpiry } from "../middleware/request-expiry";

const NOW = Date.UTC(2026, 4, 24, 12, 0, 0);

function makeApp(required = false) {
  const app = new Hono();
  app.use(
    "*",
    requestExpiry({
      required,
      now: () => NOW,
      maxClockSkewMs: 1_000,
      timestampTtlMs: 60_000,
    }),
  );
  app.post("/vault/:agentId/sign", (c) => c.json({ ok: true }));
  app.post("/condition-sets", (c) => c.json({ ok: true }));
  app.post("/user/me/wallet/sign", (c) => c.json({ ok: true }));
  app.post("/webhooks", (c) => c.json({ ok: true }));
  app.post("/intents", (c) => c.json({ ok: true }));
  app.post("/intents/intent-1/authorize", (c) => c.json({ ok: true }));
  app.post("/audit/verify", (c) => c.json({ ok: true }));
  app.post("/auth/refresh", (c) => c.json({ ok: true }));
  app.post("/auth/mfa/totp/unenroll", (c) => c.json({ ok: true }));
  app.post("/global-wallet/rpc", (c) => c.json({ ok: true }));
  app.post("/adapters/swap/build", (c) => c.json({ ok: true }));
  app.put("/tenants/:id/config", (c) => c.json({ ok: true }));
  app.post("/platform/tenants", (c) => c.json({ ok: true }));
  app.post("/agents", (c) => c.json({ ok: true }));
  app.post("/v1/agents", (c) => c.json({ ok: true }));
  app.post("/health", (c) => c.json({ ok: true }));
  return app;
}

function makeDefaultApp() {
  const app = new Hono();
  app.use(
    "*",
    requestExpiry({
      now: () => NOW,
      maxClockSkewMs: 1_000,
      timestampTtlMs: 60_000,
    }),
  );
  app.post("/vault/:agentId/sign", (c) => c.json({ ok: true }));
  return app;
}

describe("requestExpiry", () => {
  it("allows sensitive mutating requests without expiry while hook is optional", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", { method: "POST" });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("rejects expired sensitive mutating requests", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "X-Steward-Request-Expires-At": new Date(NOW - 5_000).toISOString(),
      },
    });

    expect(res.status).toBe(408);
    expect(await res.json()).toEqual({ ok: false, error: "Request has expired" });
  });

  it("accepts unix-second expiry timestamps within the allowed window", async () => {
    const app = makeApp();

    const res = await app.request("/vault/agent-1/sign", {
      method: "POST",
      headers: {
        "X-Steward-Request-Expires-At": String(Math.floor((NOW + 30_000) / 1000)),
      },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("can require expiry headers for sensitive routes", async () => {
    const app = makeApp(true);

    const sensitive = await app.request("/vault/agent-1/sign", { method: "POST" });
    const conditionSet = await app.request("/condition-sets", { method: "POST" });
    const userWalletSign = await app.request("/user/me/wallet/sign", { method: "POST" });
    const webhook = await app.request("/webhooks", { method: "POST" });
    const intent = await app.request("/intents", { method: "POST" });
    const intentAuthorize = await app.request("/intents/intent-1/authorize", { method: "POST" });
    const auditVerify = await app.request("/audit/verify", { method: "POST" });
    const authRefresh = await app.request("/auth/refresh", { method: "POST" });
    const authMfaUnenroll = await app.request("/auth/mfa/totp/unenroll", { method: "POST" });
    const globalWalletRpc = await app.request("/global-wallet/rpc", { method: "POST" });
    const adapterBuild = await app.request("/adapters/swap/build", { method: "POST" });
    const tenantConfig = await app.request("/tenants/tenant-1/config", { method: "PUT" });
    const platformTenant = await app.request("/platform/tenants", { method: "POST" });
    const agent = await app.request("/agents", { method: "POST" });
    const versionedAgent = await app.request("/v1/agents", { method: "POST" });
    const nonSensitive = await app.request("/health", { method: "POST" });

    expect(sensitive.status).toBe(400);
    expect(await sensitive.json()).toEqual({
      ok: false,
      error: "Request expiry header required",
    });
    expect(conditionSet.status).toBe(400);
    expect(userWalletSign.status).toBe(400);
    expect(webhook.status).toBe(400);
    expect(intent.status).toBe(400);
    expect(intentAuthorize.status).toBe(400);
    expect(auditVerify.status).toBe(400);
    expect(authRefresh.status).toBe(400);
    expect(authMfaUnenroll.status).toBe(400);
    expect(globalWalletRpc.status).toBe(400);
    expect(adapterBuild.status).toBe(400);
    expect(tenantConfig.status).toBe(400);
    expect(platformTenant.status).toBe(400);
    expect(agent.status).toBe(400);
    expect(versionedAgent.status).toBe(400);
    expect(nonSensitive.status).toBe(200);
  });

  it("requires expiry headers by default for sensitive production mutations", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalRequire = process.env.STEWARD_REQUIRE_REQUEST_EXPIRY;
    const originalAllow = process.env.STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS;
    try {
      process.env.NODE_ENV = "production";
      delete process.env.STEWARD_REQUIRE_REQUEST_EXPIRY;
      delete process.env.STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS;
      const app = makeDefaultApp();

      const res = await app.request("/vault/agent-1/sign", { method: "POST" });

      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        ok: false,
        error: "Request expiry header required",
      });
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalRequire === undefined) delete process.env.STEWARD_REQUIRE_REQUEST_EXPIRY;
      else process.env.STEWARD_REQUIRE_REQUEST_EXPIRY = originalRequire;
      if (originalAllow === undefined) delete process.env.STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS;
      else process.env.STEWARD_ALLOW_STALE_SENSITIVE_REQUESTS = originalAllow;
    }
  });
});
