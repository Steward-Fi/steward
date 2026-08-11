import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants, vaultSigningFreezes } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, isNull } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `agent-freeze-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `agent-freeze-other-${Date.now()}`;
const AGENT_ID = `agent-freeze-agent-${Date.now()}`;
const OTHER_AGENT_ID = `agent-freeze-other-agent-${Date.now()}`;

setDefaultTimeout(30000);

type AuthMode = "admin" | "admin-no-mfa" | "member" | "api-key";

async function makeApp(authMode: AuthMode = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      c.set("tenantRole", authMode === "member" ? "member" : "owner");
      c.set("userId", "freeze-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

async function activeAgentFreezes(): Promise<Array<{ id: string }>> {
  return getDb()
    .select({ id: vaultSigningFreezes.id })
    .from(vaultSigningFreezes)
    .where(
      and(
        eq(vaultSigningFreezes.tenantId, TENANT_ID),
        eq(vaultSigningFreezes.scopeType, "agent"),
        eq(vaultSigningFreezes.agentId, AGENT_ID),
        isNull(vaultSigningFreezes.liftedAt),
      ),
    );
}

describe("agent freeze API", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-freeze-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-freeze-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Agent Freeze Tenant", apiKeyHash: "hash" },
        { id: OTHER_TENANT_ID, name: "Other Freeze Tenant", apiKeyHash: "hash2" },
      ]);
    await getDb()
      .insert(agents)
      .values([
        {
          id: AGENT_ID,
          tenantId: TENANT_ID,
          name: "Agent Freeze Agent",
          walletAddress: "0x1234567890123456789012345678901234567890",
        },
        {
          id: OTHER_AGENT_ID,
          tenantId: OTHER_TENANT_ID,
          name: "Other Tenant Agent",
          walletAddress: "0x9876543210987654321098765432109876543210",
        },
      ]);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  beforeEach(async () => {
    await getDb().delete(vaultSigningFreezes).where(eq(vaultSigningFreezes.tenantId, TENANT_ID));
  });

  it("rejects an api-key caller (not a human admin session) with 403", async () => {
    const app = await makeApp("api-key");
    const res = await app.request(`/agents/${AGENT_ID}/freeze`, { method: "POST" });
    expect(res.status).toBe(403);
    expect(await activeAgentFreezes()).toHaveLength(0);
  });

  it("rejects a non-admin session with 403", async () => {
    const app = await makeApp("member");
    const res = await app.request(`/agents/${AGENT_ID}/freeze`, { method: "POST" });
    expect(res.status).toBe(403);
    expect(await activeAgentFreezes()).toHaveLength(0);
  });

  it("rejects an admin session without recent MFA with 403", async () => {
    const app = await makeApp("admin-no-mfa");
    const res = await app.request(`/agents/${AGENT_ID}/freeze`, { method: "POST" });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({ ok: false });
    expect(await activeAgentFreezes()).toHaveLength(0);
  });

  it("freezes an agent, writes an audit event, and is idempotent", async () => {
    const app = await makeApp("admin");
    const res = await app.request(`/agents/${AGENT_ID}/freeze`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: "compromised key" }),
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      data: { agentId: AGENT_ID, scopeType: "agent", signingState: "frozen" },
    });

    const freezes = await activeAgentFreezes();
    expect(freezes).toHaveLength(1);

    const audit = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "agent.freeze")));
    expect(audit.length).toBeGreaterThanOrEqual(1);

    // Idempotent: a second freeze does not create a duplicate active row.
    const res2 = await app.request(`/agents/${AGENT_ID}/freeze`, { method: "POST" });
    expect(res2.status).toBe(200);
    expect(await activeAgentFreezes()).toHaveLength(1);
  });

  it("unfreezes an agent and lifts the active freeze", async () => {
    const app = await makeApp("admin");
    await app.request(`/agents/${AGENT_ID}/freeze`, { method: "POST" });
    expect(await activeAgentFreezes()).toHaveLength(1);

    const res = await app.request(`/agents/${AGENT_ID}/unfreeze`, { method: "POST" });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      ok: true,
      data: { agentId: AGENT_ID, scopeType: "agent", signingState: "active" },
    });
    expect(await activeAgentFreezes()).toHaveLength(0);

    const audit = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "agent.unfreeze")));
    expect(audit.length).toBeGreaterThanOrEqual(1);
  });

  it("rejects a cross-tenant freeze attempt with 404", async () => {
    const app = await makeApp("admin");
    const res = await app.request(`/agents/${OTHER_AGENT_ID}/freeze`, { method: "POST" });
    expect(res.status).toBe(404);
  });
});
