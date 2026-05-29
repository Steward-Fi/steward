import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentSigners, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `delegated-signer-tenant-${Date.now()}`;
const AGENT_ID = `delegated-signer-agent-${Date.now()}`;
const MESSAGE = "steward delegated signer test";

async function makeApp() {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "api-key");
    await next();
  });
  app.route("/vault", vaultRoutes);
  return app;
}

describe("vault delegated signer enforcement", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let signerId = "";
  let noPermissionSignerId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-delegated-signer-master-password";
    process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Delegated Signer Tenant",
      apiKeyHash: "hash",
    });
    await new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
    }).createAgent(TENANT_ID, AGENT_ID, "Delegated Signer Agent");
    const [signer] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:primary",
        permissions: ["sign_message"],
      })
      .returning();
    signerId = signer.id;
    const [noPermissionSigner] = await getDb()
      .insert(agentSigners)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        signerType: "delegated",
        subjectType: "api_key",
        subjectId: "api-key:read-only",
        permissions: ["read_account"],
      })
      .returning();
    noPermissionSignerId = noPermissionSigner.id;
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING;
    delete process.env.STEWARD_ALLOW_VAULT_UNSAFE_MESSAGE_SIGNING;
  });

  it("rejects unsafe message signing without signer-bound authentication", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-message`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ message: MESSAGE }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner/admin session with recent MFA");
  });

  it("rejects bare delegated signer ids even when the id exists", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-message`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": noPermissionSignerId,
      },
      body: JSON.stringify({ message: MESSAGE }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner/admin session with recent MFA");
  });

  it("rejects forged delegated signer ids even when the signer has permission", async () => {
    const response = await app.request(`/vault/${AGENT_ID}/sign-message`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-signer-id": signerId,
      },
      body: JSON.stringify({ message: MESSAGE }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner/admin session with recent MFA");
  });
});
