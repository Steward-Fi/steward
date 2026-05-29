import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { agents, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const TENANT_ID = `vault-mfa-tenant-${Date.now()}`;
const AGENT_ID = `vault-mfa-agent-${Date.now()}`;
const USER_ID = crypto.randomUUID();

let apiKey = "";
let createSessionToken: typeof import("../routes/auth").createSessionToken;
let tenantAuth: typeof import("../services/context").tenantAuth;
let vaultRoutes: typeof import("../routes/vault").vaultRoutes;

async function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", tenantAuth);
  app.route("/vault", vaultRoutes);
  return app;
}

async function sessionToken(extra?: Record<string, unknown>) {
  return createSessionToken("0x0000000000000000000000000000000000000001", TENANT_ID, {
    userId: USER_ID,
    ...extra,
  });
}

describe("vault MFA-sensitive actions", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-mfa-master-password";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT = "true";
    process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const keyPair = generateApiKey();
    apiKey = keyPair.key;
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Vault MFA Tenant",
      apiKeyHash: keyPair.hash,
    });
    await getDb().insert(users).values({
      id: USER_ID,
      email: "vault-mfa@example.test",
      emailVerified: true,
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: TENANT_ID,
      role: "admin",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Vault MFA Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });

    ({ createSessionToken } = await import("../routes/auth"));
    ({ tenantAuth } = await import("../services/context"));
    ({ vaultRoutes } = await import("../routes/vault"));
    app = await makeApp();
  });

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
    delete process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT;
    delete process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT;
  });

  it("rejects API-key auth for vault private-key export even when export flags are enabled", async () => {
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { "X-Steward-Tenant": TENANT_ID, "X-Steward-Key": apiKey },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("tenant admin session authentication");
  });

  it("rejects tenant admin session export without recent MFA", async () => {
    const token = await sessionToken();
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA step-up");
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("allows recent MFA to reach vault export handling", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).not.toBe(403);
    expect(body.error ?? "").not.toContain("recent MFA step-up");
    expect(body.error ?? "").not.toContain("tenant admin session authentication");
  });

  it("dispatches private_key.exported after successful vault export", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const privateKey = `0x${"1".repeat(64)}`;
    const importRes = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ privateKey, chain: "evm" }),
    });
    const importBody = (await importRes.json()) as { ok: boolean; error?: string };
    expect(importBody.ok).toBe(true);
    dispatchWebhookMock.mockClear();

    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(TENANT_ID, AGENT_ID, "private_key.exported", {
      agentId: AGENT_ID,
      breakGlass: true,
    });
  });

  it("rejects API-key auth for vault private-key import even when import flags are enabled", async () => {
    const res = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ privateKey: "0x" + "1".repeat(64), chain: "evm" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("tenant admin session authentication");
  });
});
