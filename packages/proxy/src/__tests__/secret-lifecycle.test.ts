import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, eq, getDb, secrets, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-secret-lifecycle-master";
let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-secret-lifecycle-jwt-secret-with-enough-bytes";
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.example.com,api.deleted.example.com";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("../middleware/auth"));
  ({ handleProxy } = await import("../handlers/proxy"));
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
});

function buildApp() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.all("*", handleProxy);
  return app;
}

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: "hash" })
    .onConflictDoNothing();
}

async function ensureAgent(tenantId: string, agentId: string) {
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: `0x${"1".repeat(40)}`,
    })
    .onConflictDoNothing();
}

describe("proxy secret lifecycle enforcement", () => {
  it("does not let a sibling tenant agent use another agent's credential route", async () => {
    const tenantId = `tenant-route-scope-${crypto.randomUUID()}`;
    const ownerAgentId = `agent-owner-${crypto.randomUUID()}`;
    const attackerAgentId = `agent-attacker-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, ownerAgentId);
    await ensureAgent(tenantId, attackerAgentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "openai", "sk-live");
    await vault.createRoute(tenantId, secret.id, {
      agentId: ownerAgentId,
      hostPattern: "api.openai.com",
      pathPattern: "/*",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const token = await signAgentToken(
      { agentId: attackerAgentId, tenantId, scopes: ["agent", PROXY_SCOPE] },
      "1h",
    );
    const res = await buildApp().request("/openai/v1/models", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("No credential route configured");
  });

  it("stops matching a route once its secret has expired", async () => {
    const tenantId = `tenant-expired-route-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "openai", "sk-live");
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.example.com",
      pathPattern: "/*",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    await getDb()
      .update(secrets)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(secrets.id, secret.id));

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const res = await buildApp().request("/proxy/api.example.com/v1/test", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("No credential route configured");
  });

  it("stops matching routes after the secret is deleted", async () => {
    const tenantId = `tenant-deleted-route-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "anthropic", "sk-live");
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.deleted.example.com",
      pathPattern: "/*",
      injectAs: "header",
      injectKey: "x-api-key",
    });

    expect(await vault.deleteSecret(tenantId, secret.id)).toBe(true);

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const res = await buildApp().request("/proxy/api.deleted.example.com/v1/test", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("No credential route configured");
  });
});
