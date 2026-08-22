import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  agents,
  auditEvents,
  closeDb,
  conditionSetItems,
  conditionSets,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, count, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const RUN_ISOLATED = process.env.STEWARD_RUN_CONDITION_SET_INTEGRATION === "1";
const TENANT_ID = `condition-sets-tenant-${Date.now()}`;
const AGENT_ID = `condition-sets-agent-${Date.now()}`;

async function makeApp() {
  const [{ conditionSetRoutes }, { policiesStandaloneRoutes }] = await Promise.all([
    import("../routes/condition-sets"),
    import("../routes/policies-standalone"),
  ]);
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", c.req.header("x-test-auth-type") === "agent" ? "agent-token" : "session-jwt");
    c.set("tenantRole", "admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "11111111-1111-4111-8111-111111111111");
    await next();
  });
  app.route("/condition-sets", conditionSetRoutes);
  app.route("/policies", policiesStandaloneRoutes);
  return app;
}

const describeConditionSets = RUN_ISOLATED ? describe : describe.skip;

describeConditionSets("condition sets", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "condition-sets-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "condition-sets-audit-hmac-key-with-enough-entropy";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Condition Sets Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Condition Sets Agent",
      walletAddress: "0x1111111111111111111111111111111111111111",
    });

    app = await makeApp();
  });

  afterAll(async () => {
    const { tenantConfigs } = await import("../services/context");
    tenantConfigs.delete(TENANT_ID);
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("creates condition sets, upserts items, replaces items, and evaluates policies", async () => {
    const createResponse = await app.request("/condition-sets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Approved recipients",
        ownerId: "owner-key-1",
        description: "Addresses allowed for production transfers",
      }),
    });
    expect(createResponse.status).toBe(201);
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { id: string; name: string; ownerId: string };
    };
    expect(createBody.ok).toBe(true);
    expect(createBody.data.name).toBe("Approved recipients");
    const conditionSetId = createBody.data.id;

    const upsertResponse = await app.request(`/condition-sets/${conditionSetId}/items`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        value: "0x1234567890123456789012345678901234567890",
        label: "treasury",
      }),
    });
    expect(upsertResponse.status).toBe(201);
    const upsertBody = (await upsertResponse.json()) as {
      ok: boolean;
      data: { id: string; value: string; label: string | null };
    };
    expect(upsertBody.ok).toBe(true);
    const itemId = upsertBody.data.id;

    const getItemResponse = await app.request(`/condition-sets/${conditionSetId}/items/${itemId}`);
    expect(getItemResponse.status).toBe(200);
    const getItemBody = (await getItemResponse.json()) as {
      ok: boolean;
      data: { id: string; value: string; label: string | null };
    };
    expect(getItemBody.data).toMatchObject({
      id: itemId,
      value: "0x1234567890123456789012345678901234567890",
      label: "treasury",
    });

    const updateItemResponse = await app.request(
      `/condition-sets/${conditionSetId}/items/${itemId}`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          label: "treasury hot wallet",
          metadata: { risk: "low" },
        }),
      },
    );
    expect(updateItemResponse.status).toBe(200);
    const updateItemBody = (await updateItemResponse.json()) as {
      data: { label: string | null; metadata: Record<string, unknown> };
    };
    expect(updateItemBody.data).toMatchObject({
      label: "treasury hot wallet",
      metadata: { risk: "low" },
    });

    const listItemsResponse = await app.request(
      `/condition-sets/${conditionSetId}/items?limit=1&offset=0`,
    );
    expect(listItemsResponse.status).toBe(200);
    const listItemsBody = (await listItemsResponse.json()) as {
      data: { items: unknown[]; limit: number; offset: number };
    };
    expect(listItemsBody.data.items).toHaveLength(1);
    expect(listItemsBody.data.limit).toBe(1);
    expect(listItemsBody.data.offset).toBe(0);

    const replaceResponse = await app.request(`/condition-sets/${conditionSetId}/items`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        items: [
          { value: "0x1234567890123456789012345678901234567890", label: "treasury" },
          { value: "0x9999999999999999999999999999999999999999", label: "ops" },
        ],
      }),
    });
    expect(replaceResponse.status).toBe(200);
    const replaceBody = (await replaceResponse.json()) as { ok: boolean; data: unknown[] };
    expect(replaceBody.ok).toBe(true);
    expect(replaceBody.data).toHaveLength(2);

    const passResponse = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rules: [
          {
            id: "approved-recipient-set",
            type: "condition-set",
            enabled: true,
            config: {
              conditionSetId,
              field: "ethereum_transaction.to",
              operator: "in_condition_set",
            },
          },
        ],
        request: {
          kind: "transaction",
          to: "0x1234567890123456789012345678901234567890",
          value: "1",
          chainId: 8453,
        },
      }),
    });
    expect(passResponse.status).toBe(200);
    const passBody = (await passResponse.json()) as {
      ok: boolean;
      data: { approved: boolean; results: Array<{ passed: boolean }> };
    };
    expect(passBody.ok).toBe(true);
    expect(passBody.data.approved).toBe(true);
    expect(passBody.data.results[0].passed).toBe(true);

    const failResponse = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rules: [
          {
            id: "approved-recipient-set",
            type: "condition-set",
            enabled: true,
            config: { conditionSetId },
          },
        ],
        request: {
          kind: "transaction",
          to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          value: "1",
          chainId: 8453,
        },
      }),
    });
    expect(failResponse.status).toBe(200);
    const failBody = (await failResponse.json()) as {
      ok: boolean;
      data: { approved: boolean; results: Array<{ passed: boolean; reason?: string }> };
    };
    expect(failBody.ok).toBe(true);
    expect(failBody.data.approved).toBe(false);
    expect(failBody.data.results[0].passed).toBe(false);
    expect(failBody.data.results[0].reason).toContain("not present in condition set");
  });

  it("rejects agent-token reads of tenant-wide condition set data", async () => {
    const response = await app.request("/condition-sets", {
      headers: { "x-test-auth-type": "agent" },
    });
    expect(response.status).toBe(403);
  });

  it("returns a generic 500 and rolls back creation when the required audit fails", async () => {
    const canary = "postgres://internal.example/condition-set-secret";
    await getDb().execute(
      sql.raw(`
      CREATE OR REPLACE FUNCTION fail_condition_set_completion_audit()
      RETURNS trigger AS $$
      BEGIN
        IF NEW.action = 'condition_set.create' THEN
          RAISE EXCEPTION '${canary}';
        END IF;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql
    `),
    );
    await getDb().execute(
      sql.raw(`
      CREATE TRIGGER condition_set_completion_audit_failure
      BEFORE INSERT ON audit_events
      FOR EACH ROW EXECUTE FUNCTION fail_condition_set_completion_audit()
    `),
    );

    try {
      const response = await app.request("/condition-sets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: "must roll back",
          ownerId: "owner-key-rollback",
        }),
      });

      expect(response.status).toBe(500);
      const body = (await response.json()) as { ok: boolean; error: string };
      expect(body).toEqual({ ok: false, error: "Internal server error" });
      expect(JSON.stringify(body)).not.toContain(canary);

      const surviving = await getDb()
        .select({ id: conditionSets.id })
        .from(conditionSets)
        .where(
          and(eq(conditionSets.tenantId, TENANT_ID), eq(conditionSets.name, "must roll back")),
        );
      expect(surviving).toHaveLength(0);
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS condition_set_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(
        sql.raw("DROP FUNCTION IF EXISTS fail_condition_set_completion_audit()"),
      );
    }
  });

  it("rolls back every set and item mutation when its required completion audit fails", async () => {
    const [set] = await getDb()
      .insert(conditionSets)
      .values({
        tenantId: TENANT_ID,
        name: "atomic mutation set",
        description: "original description",
        ownerId: "atomic-owner",
      })
      .returning();
    const [item] = await getDb()
      .insert(conditionSetItems)
      .values({
        tenantId: TENANT_ID,
        conditionSetId: set.id,
        value: "original-value",
        label: "original-label",
      })
      .returning();

    async function withFailingCompletionAudit(action: string, request: () => Promise<Response>) {
      const [{ total: beforeTotal }] = await getDb()
        .select({ total: count() })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, action)));
      await getDb().execute(
        sql.raw(`
          CREATE OR REPLACE FUNCTION fail_condition_set_mutation_audit()
          RETURNS trigger AS $$
          BEGIN
            IF NEW.tenant_id = '${TENANT_ID}' AND NEW.action = '${action}' THEN
              RAISE EXCEPTION 'forced condition set mutation audit failure';
            END IF;
            RETURN NEW;
          END;
          $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
          CREATE TRIGGER condition_set_mutation_audit_failure
          BEFORE INSERT ON audit_events
          FOR EACH ROW EXECUTE FUNCTION fail_condition_set_mutation_audit()
        `),
      );
      try {
        const response = await request();
        expect(response.status).toBe(500);
        await expect(response.json()).resolves.toEqual({
          ok: false,
          error: "Internal server error",
        });
        const [{ total: afterTotal }] = await getDb()
          .select({ total: count() })
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, action)));
        expect(Number(afterTotal)).toBe(Number(beforeTotal));
      } finally {
        await getDb().execute(
          sql.raw("DROP TRIGGER IF EXISTS condition_set_mutation_audit_failure ON audit_events"),
        );
        await getDb().execute(
          sql.raw("DROP FUNCTION IF EXISTS fail_condition_set_mutation_audit()"),
        );
      }
    }

    await withFailingCompletionAudit("condition_set.update", () =>
      app.request(`/condition-sets/${set.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: "must roll back" }),
      }),
    );
    expect(
      await getDb()
        .select({ description: conditionSets.description })
        .from(conditionSets)
        .where(eq(conditionSets.id, set.id)),
    ).toEqual([{ description: "original description" }]);

    await withFailingCompletionAudit("condition_set.item.upsert", () =>
      app.request(`/condition-sets/${set.id}/items`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: "must-not-commit" }),
      }),
    );
    expect(
      await getDb()
        .select({ value: conditionSetItems.value })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.conditionSetId, set.id)),
    ).toEqual([{ value: "original-value" }]);

    await withFailingCompletionAudit("condition_set.items.replace", () =>
      app.request(`/condition-sets/${set.id}/items`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ items: [{ value: "replacement" }] }),
      }),
    );
    expect(
      await getDb()
        .select({ value: conditionSetItems.value })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.conditionSetId, set.id)),
    ).toEqual([{ value: "original-value" }]);

    await withFailingCompletionAudit("condition_set.item.update", () =>
      app.request(`/condition-sets/${set.id}/items/${item.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: "must roll back" }),
      }),
    );
    expect(
      await getDb()
        .select({ label: conditionSetItems.label })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.id, item.id)),
    ).toEqual([{ label: "original-label" }]);

    await withFailingCompletionAudit("condition_set.item.delete", () =>
      app.request(`/condition-sets/${set.id}/items/${item.id}`, { method: "DELETE" }),
    );
    expect(
      await getDb()
        .select({ id: conditionSetItems.id })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.id, item.id)),
    ).toEqual([{ id: item.id }]);

    await withFailingCompletionAudit("condition_set.delete", () =>
      app.request(`/condition-sets/${set.id}`, { method: "DELETE" }),
    );
    expect(
      await getDb()
        .select({ id: conditionSets.id })
        .from(conditionSets)
        .where(eq(conditionSets.id, set.id)),
    ).toEqual([{ id: set.id }]);
    expect(
      await getDb()
        .select({ id: conditionSetItems.id })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.id, item.id)),
    ).toEqual([{ id: item.id }]);
  });

  it("rejects policy templates that reference missing condition sets", async () => {
    const response = await app.request("/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Missing blocklist",
        rules: [
          {
            id: "missing-blocklist",
            type: "condition-set",
            enabled: true,
            config: {
              conditionSetId: "10000000-0000-4000-8000-000000000000",
              operator: "not_in_condition_set",
            },
          },
        ],
      }),
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("condition-set.conditionSetId not found for tenant");
  });

  it("rejects oversized policy template fields", async () => {
    const longNameResponse = await app.request("/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "x".repeat(121),
        rules: [],
      }),
    });
    expect(longNameResponse.status).toBe(400);
    expect(((await longNameResponse.json()) as { error: string }).error).toContain("name");

    const longDescriptionResponse = await app.request("/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "Bounded description",
        description: "x".repeat(2_001),
        rules: [],
      }),
    });
    expect(longDescriptionResponse.status).toBe(400);
    expect(((await longDescriptionResponse.json()) as { error: string }).error).toContain(
      "description",
    );
  });

  it("bounds policy template list pagination parameters", async () => {
    const response = await app.request("/policies?limit=100000", {
      headers: { "Content-Type": "application/json" },
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("limit");
  });

  it("rejects inline simulations that reference missing condition sets", async () => {
    const response = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rules: [
          {
            id: "missing-blocklist",
            type: "condition-set",
            enabled: true,
            config: {
              conditionSetId: "10000000-0000-4000-8000-000000000000",
              operator: "not_in_condition_set",
            },
          },
        ],
        request: {
          kind: "transaction",
          to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          value: "1",
          chainId: 8453,
        },
      }),
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("condition-set.conditionSetId not found for tenant");
  });

  it("simulates an agent with tenant default policies when no agent policies are stored", async () => {
    const { tenantConfigs } = await import("../services/context");
    tenantConfigs.set(TENANT_ID, {
      id: TENANT_ID,
      name: "Condition Sets Tenant",
      defaultPolicies: [
        {
          id: "tenant-default-limit",
          type: "spending-limit",
          enabled: true,
          config: {
            maxPerTx: "10",
            maxPerDay: "1000",
            maxPerWeek: "1000",
          },
        },
      ],
    });

    const response = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId: AGENT_ID,
        request: {
          kind: "transaction",
          to: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          value: "11",
          chainId: 8453,
        },
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { approved: boolean; results: Array<{ passed: boolean; reason?: string }> };
    };
    expect(body.ok).toBe(true);
    expect(body.data.approved).toBe(false);
    expect(body.data.results[0].reason).toContain("per-tx limit");
  });

  it("rejects invalid nested proxy simulation values before evaluation", async () => {
    const response = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rules: [
          {
            id: "proxy-spend",
            type: "spending-limit",
            enabled: true,
            config: { maxPerTx: "10", maxPerDay: "100", maxPerWeek: "100" },
          },
        ],
        request: {
          kind: "proxy",
          method: "POST",
          url: "https://example.com",
          body: { value: "not-a-number" },
        },
      }),
    });

    expect(response.status).toBe(400);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("request must be");
  });
});
