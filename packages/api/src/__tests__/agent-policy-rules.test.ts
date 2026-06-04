import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `policy-rules-tenant-${Date.now()}`;
const AGENT_ID = `policy-rules-agent-${Date.now()}`;

async function makeApp() {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "00000000-0000-4000-8000-000000000001");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent policy rule CRUD", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-policy-rules-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-policy-rules-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Policy Rules Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Policy Rules Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    await getDb()
      .insert(policies)
      .values({
        id: "existing-spend",
        agentId: AGENT_ID,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "1000" },
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("creates, lists, gets, updates, and deletes nested policy rules", async () => {
    const createResponse = await app.request(`/agents/${AGENT_ID}/policies/rules`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "allowed-base",
        type: "approved-addresses",
        config: {
          addresses: ["0x1234567890123456789012345678901234567890"],
          mode: "whitelist",
        },
      }),
    });
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; enabled: boolean };
    };
    expect(createResponse.status).toBe(201);
    expect(created.ok).toBe(true);
    expect(created.data.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(created.data.enabled).toBe(true);
    const createdRuleId = created.data.id;

    const listResponse = await app.request(`/agents/${AGENT_ID}/policies/rules`);
    const listed = (await listResponse.json()) as {
      ok: boolean;
      data: { rules: Array<{ id: string }> };
    };
    expect(listResponse.status).toBe(200);
    expect(listed.data.rules.map((rule) => rule.id).sort()).toEqual(
      [createdRuleId, "existing-spend"].sort(),
    );

    const getResponse = await app.request(`/agents/${AGENT_ID}/policies/rules/${createdRuleId}`);
    const fetched = (await getResponse.json()) as { ok: boolean; data: { id: string } };
    expect(getResponse.status).toBe(200);
    expect(fetched.data.id).toBe(createdRuleId);

    const updateResponse = await app.request(
      `/agents/${AGENT_ID}/policies/rules/${createdRuleId}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      },
    );
    const updated = (await updateResponse.json()) as {
      ok: boolean;
      data: { id: string; enabled: boolean };
    };
    expect(updateResponse.status).toBe(200);
    expect(updated.data.enabled).toBe(false);

    const deleteResponse = await app.request(
      `/agents/${AGENT_ID}/policies/rules/${createdRuleId}`,
      {
        method: "DELETE",
      },
    );
    const deleted = (await deleteResponse.json()) as { ok: boolean; data: { id: string } };
    expect(deleteResponse.status).toBe(200);
    expect(deleted.data.id).toBe(createdRuleId);

    const missingResponse = await app.request(
      `/agents/${AGENT_ID}/policies/rules/${createdRuleId}`,
    );
    expect(missingResponse.status).toBe(404);
  });

  it("rejects invalid rule updates without mutating the stored rule", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/policies/rules/existing-spend`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ config: { maxPerTx: "not-wei" } }),
    });
    const body = (await response.json()) as { ok: boolean; error?: string };
    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("spending-limit");

    const [stored] = await getDb().select().from(policies).where(eq(policies.id, "existing-spend"));
    expect(stored.config).toEqual({ maxPerTx: "1000" });
  });

  it("ignores caller-supplied policy rule ids to avoid global id probes", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/policies/rules`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "existing-spend",
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "1" },
      }),
    });
    const body = (await response.json()) as { ok: boolean; data: { id: string } };
    expect(response.status).toBe(201);
    expect(body.ok).toBe(true);
    expect(body.data.id).not.toBe("existing-spend");
  });
});
