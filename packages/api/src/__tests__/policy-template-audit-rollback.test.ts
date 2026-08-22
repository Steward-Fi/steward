import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  closeDb,
  getDb,
  policies,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = "policy-template-audit-atomic";
const AGENT_ID = "policy-template-audit-agent";
const TEMPLATE_ID = "11111111-1111-4111-8111-111111111111";

describe("policy template audit atomicity", () => {
  let app: Hono<{ Variables: AppVariables }>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "policy-template-audit-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "policy-template-audit-key-with-enough-entropy";
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: TENANT_ID, name: TENANT_ID, apiKeyHash: "hash" });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: AGENT_ID,
      walletAddress: "0x1111111111111111111111111111111111111111",
    });
    await getDb().execute(sql`
      INSERT INTO policy_templates (id, tenant_id, name, description, rules, is_default)
      VALUES (${TEMPLATE_ID}::uuid, ${TENANT_ID}, 'original', null,
        '[{"type":"approved-addresses","enabled":true,"config":{"mode":"whitelist","addresses":["0x1111111111111111111111111111111111111111"]}}]'::jsonb, false)
    `);
    const { policiesStandaloneRoutes } = await import("../routes/policies-standalone");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("userId", "22222222-2222-4222-8222-222222222222");
      await next();
    });
    app.route("/policies", policiesStandaloneRoutes);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    __resetAuditHmacKeyCacheForTests();
  });

  async function rejectCompletion(action: string) {
    const quotedAction = sql.raw(`'${action}'`);
    await getDb().execute(sql`
      CREATE OR REPLACE FUNCTION reject_policy_completion() RETURNS trigger AS $$
      BEGIN
        IF NEW.action = ${quotedAction} THEN RAISE EXCEPTION 'injected completion audit failure'; END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `);
    await getDb().execute(sql`
      CREATE TRIGGER reject_policy_completion BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_policy_completion()
    `);
  }

  async function allowCompletion() {
    await getDb().execute(sql`DROP TRIGGER IF EXISTS reject_policy_completion ON audit_events`);
    await getDb().execute(sql`DROP FUNCTION IF EXISTS reject_policy_completion()`);
  }

  it("does not commit creation when the required audit fails", async () => {
    await rejectCompletion("policy.template.create");
    try {
      const creation = await app.request("/policies", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "uncommitted create", rules: [] }),
      });
      expect(creation.status, await creation.clone().text()).toBe(400);
      const result = await getDb().execute(
        sql`SELECT id FROM policy_templates WHERE tenant_id = ${TENANT_ID} AND name = 'uncommitted create'`,
      );
      const rows = Array.isArray(result) ? result : ((result as { rows?: unknown[] }).rows ?? []);
      expect(rows).toHaveLength(0);
    } finally {
      await allowCompletion();
    }
  });

  it("does not commit update or delete when the required audit fails", async () => {
    await rejectCompletion("policy.template.update");
    try {
      const update = await app.request(`/policies/${TEMPLATE_ID}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "uncommitted" }),
      });
      expect(update.status, await update.clone().text()).toBe(400);
      const result = await getDb().execute(
        sql`SELECT name FROM policy_templates WHERE id = ${TEMPLATE_ID}::uuid`,
      );
      const rows = (
        Array.isArray(result) ? result : ((result as { rows?: Array<{ name: string }> }).rows ?? [])
      ) as Array<{ name: string }>;
      expect(rows[0]?.name).toBe("original");
    } finally {
      await allowCompletion();
    }

    await rejectCompletion("policy.template.delete");
    try {
      const deletion = await app.request(`/policies/${TEMPLATE_ID}`, { method: "DELETE" });
      expect(deletion.status).toBe(500);
      const result = await getDb().execute(
        sql`SELECT id FROM policy_templates WHERE id = ${TEMPLATE_ID}::uuid`,
      );
      const rows = Array.isArray(result) ? result : ((result as { rows?: unknown[] }).rows ?? []);
      expect(rows).toHaveLength(1);
    } finally {
      await allowCompletion();
    }
  });

  it("does not replace agent policy authority when assignment audit fails", async () => {
    await getDb()
      .insert(policies)
      .values({
        id: "33333333-3333-4333-8333-333333333333",
        agentId: AGENT_ID,
        type: "allowed-chains",
        enabled: true,
        config: { chainIds: [1] },
      });
    await rejectCompletion("policy.template.assign");
    try {
      const response = await app.request(`/policies/${TEMPLATE_ID}/assign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentIds: [AGENT_ID] }),
      });
      expect(response.status, await response.clone().text()).toBe(500);
      const stored = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
      expect(stored).toHaveLength(1);
      expect(stored[0]?.type).toBe("allowed-chains");
    } finally {
      await allowCompletion();
    }
  });

  it("assigns through the mounted route in persistent PGLite mode", async () => {
    const previousDbMode = process.env.STEWARD_DB_MODE;
    const previousPgliteMemory = process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_DB_MODE = "pglite";
    delete process.env.STEWARD_PGLITE_MEMORY;
    try {
      const response = await app.request(`/policies/${TEMPLATE_ID}/assign`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentIds: [AGENT_ID] }),
      });
      expect(response.status, await response.clone().text()).toBe(200);
      expect(await response.json()).toMatchObject({
        ok: true,
        data: { templateId: TEMPLATE_ID, assignedAgents: [AGENT_ID], rulesApplied: 1 },
      });
      const stored = await getDb().select().from(policies).where(eq(policies.agentId, AGENT_ID));
      expect(stored).toHaveLength(1);
      expect(stored[0]?.type).toBe("approved-addresses");
    } finally {
      if (previousDbMode === undefined) delete process.env.STEWARD_DB_MODE;
      else process.env.STEWARD_DB_MODE = previousDbMode;
      if (previousPgliteMemory === undefined) delete process.env.STEWARD_PGLITE_MEMORY;
      else process.env.STEWARD_PGLITE_MEMORY = previousPgliteMemory;
    }
  });
});
