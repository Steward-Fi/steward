import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { revocationStore } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  agentWallets,
  approvalQueue,
  auditEvents,
  closeDb,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  policies,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
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
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_ALLOW_API_KEY_ADMIN_MUTATIONS",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

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
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  return app;
}

describe("agent admin mutations require human session + MFA (SEC-209)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-admin-mutations-master-password";
    process.env.STEWARD_JWT_SECRET = "agent-admin-mutations-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-admin-mutations-audit-hmac-key-entropy";
    __resetAuditHmacKeyCacheForTests();
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
    for (const [name, value] of originalEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    __resetAuditHmacKeyCacheForTests();
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

  it("rejects agent, wallet, batch, and token provisioning without recent MFA", async () => {
    const app = await makeApp("admin-no-mfa");
    const beforeAgents = await getDb().select({ id: agents.id }).from(agents);
    const beforeWallets = await getDb()
      .select({ id: agentWallets.id })
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));

    const requests = [
      app.request("/agents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Rejected agent" }),
      }),
      app.request(`/agents/${AGENT_ID}/wallets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chainType: "evm", venue: "rejected" }),
      }),
      app.request("/agents/batch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agents: [{ name: "Rejected batch agent" }] }),
      }),
      app.request(`/agents/${AGENT_ID}/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ expiresIn: "1h" }),
      }),
    ];
    for (const response of await Promise.all(requests)) {
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: expect.stringContaining("recent MFA verification"),
      });
    }

    expect(await getDb().select({ id: agents.id }).from(agents)).toEqual(beforeAgents);
    expect(
      await getDb()
        .select({ id: agentWallets.id })
        .from(agentWallets)
        .where(eq(agentWallets.agentId, AGENT_ID)),
    ).toEqual(beforeWallets);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
  });

  it("rejects deletion without recent MFA before revocation or database mutation", async () => {
    const app = await makeApp("admin-no-mfa");
    const beforeAgent = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();

    const response = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA verification"),
    });
    expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toEqual(beforeAgent);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();
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

  it("does not mutate agents, wallets, policies, or revocation state when authorization audit fails", async () => {
    const app = await makeApp("admin");
    const canary = "postgres://agent-authorization-audit-secret";
    const beforeAgents = await getDb().select({ id: agents.id }).from(agents);
    const beforeWallets = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_authorization_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action IN (
            'agent.create.authorized',
            'agent.wallet.create.authorized',
            'agent.policies.update.authorized',
            'agent.delete.authorized'
          ) THEN
            RAISE EXCEPTION '${canary}';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_authorization_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_authorization_audit()
        `),
      );
      const responses = [
        await app.request("/agents", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ name: "Audit-blocked agent" }),
        }),
        await app.request(`/agents/${AGENT_ID}/wallets`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chainType: "evm", venue: "audit-blocked" }),
        }),
        await app.request(`/agents/${AGENT_ID}/policies`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify([
            {
              type: "spending-limit",
              enabled: true,
              config: { maxPerTx: "1" },
            },
          ]),
        }),
        await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" }),
      ];
      for (const response of responses) {
        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(await response.text()).not.toContain(canary);
      }

      expect(await getDb().select({ id: agents.id }).from(agents)).toEqual(beforeAgents);
      expect(
        await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
      ).toEqual(beforeWallets);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        beforePolicies,
      );
      expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).toBeNull();
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS agent_authorization_audit_failure ON audit_events"),
      );
      await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS fail_agent_authorization_audit()"));
    }
  });

  it("removes newly created agent and wallet records when completion audit fails", async () => {
    const app = await makeApp("admin");
    const beforeAgents = await getDb().select().from(agents);
    const beforeWallets = await getDb().select().from(agentWallets);
    const beforeEvmKeys = await getDb().select().from(encryptedKeys);
    const beforeChainKeys = await getDb().select().from(encryptedChainKeys);

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_completion_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action IN ('agent.create', 'agent.wallet.create') THEN
            RAISE EXCEPTION 'required agent completion audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_completion_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_completion_audit()
        `),
      );
      const createResponse = await app.request("/agents", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "Completion-audit-blocked agent" }),
      });
      expect(createResponse.status).toBeGreaterThanOrEqual(400);

      const walletResponse = await app.request(`/agents/${AGENT_ID}/wallets`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chainType: "evm", venue: "completion-audit-blocked" }),
      });
      expect(walletResponse.status).toBeGreaterThanOrEqual(400);

      expect(await getDb().select().from(agents)).toEqual(beforeAgents);
      expect(await getDb().select().from(agentWallets)).toEqual(beforeWallets);
      expect(await getDb().select().from(encryptedKeys)).toEqual(beforeEvmKeys);
      expect(await getDb().select().from(encryptedChainKeys)).toEqual(beforeChainKeys);
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS agent_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(sql.raw("DROP FUNCTION IF EXISTS fail_agent_completion_audit()"));
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
  });

  it("ignores caller agent ids on single and batch creation", async () => {
    const app = await makeApp("admin");
    const single = await app.request("/agents", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: AGENT_ID, name: "Server id single" }),
    });
    expect(single.status).toBe(200);
    const singleBody = (await single.json()) as { data: { id: string } };
    expect(singleBody.data.id).not.toBe(AGENT_ID);

    const batch = await app.request("/agents/batch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agents: [{ id: AGENT_ID, name: "Server id batch" }] }),
    });
    expect(batch.status).toBe(200);
    const batchBody = (await batch.json()) as {
      data: { created: Array<{ id: string }>; errors: unknown[] };
    };
    expect(batchBody.data.errors).toEqual([]);
    expect(batchBody.data.created).toHaveLength(1);
    expect(batchBody.data.created[0]?.id).not.toBe(AGENT_ID);
    expect(batchBody.data.created[0]?.id).not.toBe(singleBody.data.id);

    for (const createdId of [singleBody.data.id, batchBody.data.created[0]!.id]) {
      const auditRows = await getDb()
        .select({ action: auditEvents.action, seq: auditEvents.seq })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT_ID),
            eq(auditEvents.resourceId, createdId),
            inArray(auditEvents.action, ["agent.create.authorized", "agent.create"]),
          ),
        )
        .orderBy(asc(auditEvents.seq));
      expect(auditRows.map(({ action }) => action)).toEqual([
        "agent.create.authorized",
        "agent.create",
      ]);
      expect(auditRows[1]?.seq).toBe(auditRows[0]!.seq + 1);
    }
  });

  it("restores rows after a failed delete audit, retains revocation, and succeeds on retry", async () => {
    const app = await makeApp("admin");
    const walletResponse = await app.request(`/agents/${AGENT_ID}/wallets`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chainType: "evm", venue: "delete-retry" }),
    });
    expect(walletResponse.status).toBe(200);
    const walletAudits = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.wallet.create.authorized", "agent.wallet.create"]),
          sql`${auditEvents.metadata}->>'venue' = 'delete-retry'`,
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(walletAudits.map(({ action }) => action)).toEqual([
      "agent.wallet.create.authorized",
      "agent.wallet.create",
    ]);
    expect(walletAudits[1]?.seq).toBe(walletAudits[0]!.seq + 1);
    await getDb()
      .insert(policies)
      .values({
        id: "delete-retry-policy",
        agentId: AGENT_ID,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "3" },
      });
    await getDb().insert(transactions).values({
      id: "delete-retry-transaction",
      agentId: AGENT_ID,
      status: "pending",
      toAddress: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      value: "3",
      chainId: 1,
      policyResults: [],
    });
    await getDb().insert(approvalQueue).values({
      id: "delete-retry-approval",
      txId: "delete-retry-transaction",
      agentId: AGENT_ID,
      status: "pending",
    });

    const beforeAgent = await getDb().select().from(agents).where(eq(agents.id, AGENT_ID));
    const beforeWallets = await getDb()
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.agentId, AGENT_ID));
    const beforeEvmKeys = await getDb()
      .select()
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, AGENT_ID));
    const beforeChainKeys = await getDb()
      .select()
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, AGENT_ID));
    const beforePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    const beforeTransactions = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.agentId, AGENT_ID));
    const beforeApprovals = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.agentId, AGENT_ID));

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_delete_completion_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action = 'agent.delete' THEN
            RAISE EXCEPTION 'required agent delete audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_delete_completion_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_delete_completion_audit()
        `),
      );
      const failed = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
      expect(failed.status).toBe(500);
      expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toEqual(
        beforeAgent,
      );
      expect(
        await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
      ).toEqual(beforeWallets);
      expect(
        await getDb().select().from(encryptedKeys).where(eq(encryptedKeys.agentId, AGENT_ID)),
      ).toEqual(beforeEvmKeys);
      expect(
        await getDb()
          .select()
          .from(encryptedChainKeys)
          .where(eq(encryptedChainKeys.agentId, AGENT_ID)),
      ).toEqual(beforeChainKeys);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        beforePolicies,
      );
      expect(
        await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID)),
      ).toEqual(beforeTransactions);
      expect(
        await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT_ID)),
      ).toEqual(beforeApprovals);
      expect(await revocationStore.getAgentRevokedBefore(AGENT_ID)).not.toBeNull();
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS agent_delete_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(
        sql.raw("DROP FUNCTION IF EXISTS fail_agent_delete_completion_audit()"),
      );
    }

    const retry = await app.request(`/agents/${AGENT_ID}`, { method: "DELETE" });
    expect(retry.status).toBe(200);
    expect(await getDb().select().from(agents).where(eq(agents.id, AGENT_ID))).toHaveLength(0);
    expect(
      await getDb().select().from(agentWallets).where(eq(agentWallets.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT_ID)),
    ).toHaveLength(0);
    expect(
      await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT_ID)),
    ).toHaveLength(0);

    const deleteAudits = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_ID),
          inArray(auditEvents.action, ["agent.delete.authorized", "agent.delete"]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(deleteAudits.map(({ action }) => action)).toEqual([
      "agent.delete.authorized",
      "agent.delete.authorized",
      "agent.delete",
    ]);
  });
});
