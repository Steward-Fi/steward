import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { auditEvents, closeDb, conditionSetItems, conditionSets, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { count, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `condition-set-quota-${Date.now()}`;

describe("condition set mounted quota enforcement", () => {
  let app: Hono<{ Variables: AppVariables }>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "condition-set-quota-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "condition-set-quota-audit-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: TENANT_ID, name: TENANT_ID, apiKeyHash: "hash" });
    const { conditionSetRoutes } = await import("../routes/condition-sets");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("userId", "condition-set-quota-admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/condition-sets", conditionSetRoutes);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("admits exactly one concurrent 100th condition set", async () => {
    await getDb()
      .insert(conditionSets)
      .values(
        Array.from({ length: 99 }, (_, index) => ({
          tenantId: TENANT_ID,
          name: `seed-set-${index}`,
          ownerId: "quota-test",
        })),
      );

    const responses = await Promise.all(
      ["candidate-a", "candidate-b"].map((name) =>
        app.request("/condition-sets", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name, ownerId: "quota-test" }),
        }),
      ),
    );
    expect(responses.map((response) => response.status).sort()).toEqual([201, 400]);
    const [{ total }] = await getDb()
      .select({ total: count() })
      .from(conditionSets)
      .where(eq(conditionSets.tenantId, TENANT_ID));
    expect(Number(total)).toBe(100);
    const completed = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.action, "condition_set.create"));
    expect(completed).toHaveLength(1);
  });

  it("admits exactly one concurrent 1,000th item", async () => {
    const [set] = await getDb()
      .insert(conditionSets)
      .values({ tenantId: TENANT_ID, name: "item-quota", ownerId: "quota-test" })
      .returning({ id: conditionSets.id });
    await getDb()
      .insert(conditionSetItems)
      .values(
        Array.from({ length: 999 }, (_, index) => ({
          tenantId: TENANT_ID,
          conditionSetId: set.id,
          value: `seed-item-${index}`,
        })),
      );

    const responses = await Promise.all(
      ["candidate-item-a", "candidate-item-b"].map((value) =>
        app.request(`/condition-sets/${set.id}/items`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ value }),
        }),
      ),
    );
    expect(responses.map((response) => response.status).sort()).toEqual([201, 400]);
    const [{ total }] = await getDb()
      .select({ total: count() })
      .from(conditionSetItems)
      .where(eq(conditionSetItems.conditionSetId, set.id));
    expect(Number(total)).toBe(1_000);
    const completed = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(eq(auditEvents.action, "condition_set.item.upsert"));
    expect(completed).toHaveLength(1);
  });
});
