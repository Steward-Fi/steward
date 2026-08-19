import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

/**
 * SEC-209 regression: minting agent tokens, replacing an agent's vault policy
 * set, and deleting agents are root-equivalent mutations. A bare tenant API
 * key is no longer sufficient by default — they require a human owner/admin
 * session with recent MFA. STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS=true is the
 * explicit operator opt-in that restores the legacy api-key path.
 */

const TENANT_ID = `agent-admin-mutations-${Date.now()}`;
const AGENT_ID = `agent-admin-mutations-agent-${Date.now()}`;

setDefaultTimeout(30000);

type AuthMode = "admin" | "admin-no-mfa" | "member" | "api-key";

async function makeApp(authMode: AuthMode) {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      c.set("tenantRole", authMode === "member" ? "member" : "owner");
      c.set("userId", "admin-mutations-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent admin mutations require human session + MFA (SEC-209)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-admin-mutations-master-password";
    process.env.STEWARD_JWT_SECRET = "agent-admin-mutations-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-admin-mutations-audit-hmac-key-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Admin Mutations Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Admin Mutations Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS;
  });

  it("rejects a bare tenant API key on all three root-equivalent mutations", async () => {
    const app = await makeApp("api-key");

    const tokenRes = await app.request(`/agents/${AGENT_ID}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "1h" }),
    });
    expect(tokenRes.status).toBe(403);

    const policiesRes = await app.request(`/agents/${AGENT_ID}/policies`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([]),
    });
    expect(policiesRes.status).toBe(403);

    const deleteRes = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(deleteRes.status).toBe(403);
  });

  it("rejects admin sessions without recent MFA", async () => {
    const app = await makeApp("admin-no-mfa");
    const before = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.token.create.authorized", "agent.token.create"]),
        ),
      );
    const res = await app.request(`/agents/${AGENT_ID}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "1h" }),
    });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      ok: false,
      error: "Agent token creation requires recent MFA verification",
    });
    const after = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.token.create.authorized", "agent.token.create"]),
        ),
      );
    expect(after).toEqual(before);
  });

  it("rejects non-admin sessions", async () => {
    const app = await makeApp("member");
    const res = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(res.status).toBe(403);
  });

  it("allows the explicit api-key opt-in (documented fully-root escape hatch)", async () => {
    process.env.STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS = "true";
    try {
      const app = await makeApp("api-key");
      const res = await app.request(`/agents/${AGENT_ID}/policies`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([]),
      });
      expect(res.status).toBe(200);
    } finally {
      delete process.env.STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS;
    }
  });

  it("allows an owner/admin session with recent MFA", async () => {
    const app = await makeApp("admin");
    const tokenRes = await app.request(`/agents/${AGENT_ID}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ expiresIn: "1h" }),
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(tokenRes.headers.get("Pragma")).toBe("no-cache");
    expect(tokenRes.headers.get("Expires")).toBe("0");
    const tokenAudits = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.token.create.authorized", "agent.token.create"]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(tokenAudits.map(({ action }) => action)).toEqual([
      "agent.token.create.authorized",
      "agent.token.create",
    ]);
    expect(tokenAudits[1]?.seq).toBe(tokenAudits[0]?.seq + 1);

    const deleteRes = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(deleteRes.status).toBe(200);
  });
});
