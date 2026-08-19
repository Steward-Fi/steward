import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, auditEvents, closeDb, getDb, policies, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `policy-rules-tenant-${Date.now()}`;
const AGENT_ID = `policy-rules-agent-${Date.now()}`;
const TYPED_DATA_AGENT_ID = `typed-data-policy-agent-${Date.now()}`;

async function makeApp(authMode: "admin" | "admin-no-mfa" = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "00000000-0000-4000-8000-000000000001");
    if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/agents", agentRoutes);
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
  return app;
}

describe("agent policy rule CRUD", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-policy-rules-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "agent-policy-rules-test-audit-hmac-key-0123456789abcdef0123456789";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Policy Rules Tenant",
      apiKeyHash: "hash",
    });
    await getDb()
      .insert(agents)
      .values([
        {
          id: AGENT_ID,
          tenantId: TENANT_ID,
          name: "Policy Rules Agent",
          walletAddress: "0x1234567890123456789012345678901234567890",
        },
        {
          id: TYPED_DATA_AGENT_ID,
          tenantId: TENANT_ID,
          name: "Typed Data Policy Agent",
          walletAddress: "0x1234567890123456789012345678901234567891",
        },
      ]);
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

    const auditRows = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, createdRuleId),
          inArray(auditEvents.action, [
            "agent.policy_rule.create.authorized",
            "agent.policy_rule.create",
            "agent.policy_rule.update.authorized",
            "agent.policy_rule.update",
            "agent.policy_rule.delete.authorized",
            "agent.policy_rule.delete",
          ]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(auditRows.map(({ action }) => action)).toEqual([
      "agent.policy_rule.create.authorized",
      "agent.policy_rule.create",
      "agent.policy_rule.update.authorized",
      "agent.policy_rule.update",
      "agent.policy_rule.delete.authorized",
      "agent.policy_rule.delete",
    ]);
    for (let index = 1; index < auditRows.length; index++) {
      expect(auditRows[index]?.seq).toBe(auditRows[index - 1]!.seq + 1);
    }

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

  it("rejects policy replacement and rule mutations without recent MFA and changes nothing", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const beforePolicies = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, AGENT_ID));
    const beforeAudits = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID));

    const requests = [
      noMfaApp.request(`/agents/${AGENT_ID}/policies`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([]),
      }),
      noMfaApp.request(`/agents/${AGENT_ID}/policies/rules`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "rate-limit", config: { maxTxPerHour: 1 } }),
      }),
      noMfaApp.request(`/agents/${AGENT_ID}/policies/rules/existing-spend`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      }),
      noMfaApp.request(`/agents/${AGENT_ID}/policies/rules/existing-spend`, {
        method: "DELETE",
      }),
    ];

    for (const response of await Promise.all(requests)) {
      expect(response.status).toBe(403);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: expect.stringContaining("recent MFA"),
      });
    }
    expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
      beforePolicies,
    );
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toEqual(beforeAudits);
  });

  it("restores policy replacement and rule mutations when completion audits fail", async () => {
    const [seeded] = await getDb()
      .insert(policies)
      .values({
        id: "audit-rollback-policy",
        agentId: AGENT_ID,
        type: "rate-limit",
        enabled: true,
        config: { maxTxPerHour: 3, maxTxPerDay: 10 },
      })
      .returning();
    const before = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));

    await getDb().execute(
      sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_policy_rule_completion_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action IN (
            'agent.policies.update',
            'agent.policy_rule.create',
            'agent.policy_rule.update',
            'agent.policy_rule.delete'
          ) THEN
            RAISE EXCEPTION 'required agent policy rule audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
      `),
    );
    await getDb().execute(
      sql.raw(`
        CREATE TRIGGER agent_policy_rule_completion_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_policy_rule_completion_audit()
      `),
    );

    try {
      const replace = await app.request(`/agents/${AGENT_ID}/policies`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify([
          { type: "spending-limit", enabled: true, config: { maxPerTx: "9" } },
        ]),
      });
      expect(replace.status).toBe(500);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        before,
      );

      const create = await app.request(`/agents/${AGENT_ID}/policies/rules`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          id: "caller-ignored-audit-rollback",
          type: "approved-addresses",
          config: {
            addresses: ["0x1234567890123456789012345678901234567890"],
            mode: "whitelist",
          },
        }),
      });
      expect(create.status).toBe(500);
      expect(await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID))).toEqual(
        before,
      );

      const update = await app.request(`/agents/${AGENT_ID}/policies/rules/${seeded.id}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ enabled: false }),
      });
      expect(update.status).toBe(500);
      expect(await getDb().select().from(policies).where(eq(policies.id, seeded.id))).toEqual([
        seeded,
      ]);

      const remove = await app.request(`/agents/${AGENT_ID}/policies/rules/${seeded.id}`, {
        method: "DELETE",
      });
      expect(remove.status).toBe(500);
      expect(await getDb().select().from(policies).where(eq(policies.id, seeded.id))).toEqual([
        seeded,
      ]);
    } finally {
      await getDb().execute(
        sql.raw(
          "DROP TRIGGER IF EXISTS agent_policy_rule_completion_audit_failure ON audit_events",
        ),
      );
      await getDb().execute(
        sql.raw("DROP FUNCTION IF EXISTS fail_agent_policy_rule_completion_audit()"),
      );
    }
  });

  it("stores a valid typed-data policy, rejects malformed replacement, and gates the public sign route", async () => {
    const malformedResponse = await app.request(`/agents/${TYPED_DATA_AGENT_ID}/policies`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([
        {
          id: "malformed",
          type: "typed-data",
          enabled: true,
          config: { allowedChainIds: ["8453"] },
        },
      ]),
    });
    expect(malformedResponse.status).toBe(400);
    expect(
      await getDb().select().from(policies).where(eq(policies.agentId, TYPED_DATA_AGENT_ID)),
    ).toHaveLength(0);

    const allowedContract = "0x000000000022d473030f116ddee9f6b43ac78ba3";
    const allowedSpender = "0x1111111111111111111111111111111111111111";
    const storeResponse = await app.request(`/agents/${TYPED_DATA_AGENT_ID}/policies`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify([
        {
          id: "permit-policy",
          type: "typed-data",
          enabled: true,
          config: {
            verifyingContractAllowlist: [allowedContract],
            allowedChainIds: [8453],
            allowedPrimaryTypes: ["PermitSingle"],
            messageConditions: [
              { field: "spender", operator: "address_in", values: [allowedSpender] },
              { field: "amount", operator: "uint_max", value: "1000" },
            ],
          },
        },
      ]),
    });
    expect(storeResponse.status).toBe(200);
    const replacementAudits = await getDb()
      .select({ action: auditEvents.action, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, TYPED_DATA_AGENT_ID),
          inArray(auditEvents.action, [
            "agent.policies.update.authorized",
            "agent.policies.update",
          ]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(replacementAudits.map(({ action }) => action)).toEqual([
      "agent.policies.update.authorized",
      "agent.policies.update",
    ]);
    expect(replacementAudits[1]?.seq).toBe(replacementAudits[0]!.seq + 1);
    const stored = await getDb()
      .select()
      .from(policies)
      .where(eq(policies.agentId, TYPED_DATA_AGENT_ID));
    expect(stored).toHaveLength(1);
    expect(stored[0]?.type).toBe("typed-data");

    const { vaultRoutes } = await import("../routes/vault");
    const vaultApp = new Hono<{ Variables: AppVariables }>();
    vaultApp.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "00000000-0000-4000-8000-000000000001");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    vaultApp.route("/vault", vaultRoutes);

    const deniedResponse = await vaultApp.request(`/vault/${TYPED_DATA_AGENT_ID}/sign-typed-data`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        domain: { name: "Permit2", chainId: 8453, verifyingContract: allowedContract },
        types: {
          PermitSingle: [
            { name: "spender", type: "address" },
            { name: "amount", type: "uint256" },
          ],
        },
        primaryType: "PermitSingle",
        value: {
          spender: "0x2222222222222222222222222222222222222222",
          amount: "1001",
        },
      }),
    });
    expect(deniedResponse.status).toBe(403);
    const deniedBody = (await deniedResponse.json()) as { ok: boolean; error?: string };
    expect(deniedBody.ok).toBe(false);
    expect(deniedBody.error).toBe("Transaction rejected by policy");
  });
});
