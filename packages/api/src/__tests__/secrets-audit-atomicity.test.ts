import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, auditEvents, closeDb, getDb, secretRoutes, secrets, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { and, eq, isNull, sql } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const tenantId = "secret-audit-atomicity";
const agentId = "secret-audit-agent";
const suffix = crypto.randomUUID().replaceAll("-", "");
const fn = `fail_secret_completion_${suffix}`;
const trigger = fn;
setDefaultTimeout(30_000);

async function rejectAuditActions(actions: string[]): Promise<void> {
  const actionList = actions.map((action) => `'${action}'`).join(",");
  await getDb().execute(
    sql.raw(
      `CREATE OR REPLACE FUNCTION ${fn}() RETURNS trigger AS $$ BEGIN IF NEW.tenant_id='${tenantId}' AND NEW.action IN (${actionList}) THEN RAISE EXCEPTION 'forced secret audit failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql`,
    ),
  );
}

describe("secret CRUD audit atomicity", () => {
  let app: Hono<{ Variables: AppVariables }>;
  let vault: SecretVault;
  beforeAll(async () => {
    process.env.STEWARD_DB_MODE = "pglite";
    delete process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_MASTER_PASSWORD = "secret-audit-atomic-master";
    process.env.STEWARD_AUDIT_HMAC_KEY = "secret-audit-atomic-hmac-key-32-bytes";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: "hash" });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x1111111111111111111111111111111111111111",
    });
    await rejectAuditActions(["secret.create", "secret.rotate", "secret.delete"]);
    await getDb().execute(
      sql.raw(
        `CREATE TRIGGER ${trigger} BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION ${fn}()`,
      ),
    );
    vault = new SecretVault(process.env.STEWARD_MASTER_PASSWORD);
    const { secretsRoutes } = await import("../routes/secrets");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", correlationId);
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", crypto.randomUUID());
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/secrets", secretsRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  });
  afterAll(async () => {
    await getDb().execute(sql.raw(`DROP TRIGGER IF EXISTS ${trigger} ON audit_events`));
    await getDb().execute(sql.raw(`DROP FUNCTION IF EXISTS ${fn}()`));
    await closeDb();
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("rejects authorization-audit failures before create, rotate, or delete mutates state", async () => {
    await rejectAuditActions([
      "secret.create.authorized",
      "secret.rotate.authorized",
      "secret.delete.authorized",
    ]);
    try {
      const create = await app.request("/secrets", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name: "authorization-create", value: "never-persisted" }),
      });
      expect(create.status).toBe(500);
      expect(
        await getDb().select().from(secrets).where(eq(secrets.name, "authorization-create")),
      ).toHaveLength(0);

      const original = await vault.createSecret(tenantId, "authorization-lineage", "old-value");
      const rotate = await app.request(`/secrets/${original.id}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value: "new-value" }),
      });
      expect(rotate.status).toBe(500);
      expect(
        await getDb()
          .select({ id: secrets.id, version: secrets.version })
          .from(secrets)
          .where(and(eq(secrets.name, "authorization-lineage"), isNull(secrets.deletedAt))),
      ).toEqual([{ id: original.id, version: 1 }]);

      const remove = await app.request(`/secrets/${original.id}`, { method: "DELETE" });
      expect(remove.status).toBe(500);
      expect(
        await getDb()
          .select({ id: secrets.id })
          .from(secrets)
          .where(and(eq(secrets.id, original.id), isNull(secrets.deletedAt))),
      ).toEqual([{ id: original.id }]);
    } finally {
      await rejectAuditActions(["secret.create", "secret.rotate", "secret.delete"]);
    }
  });

  it("rolls back create, rotate, route repointing, and delete with failed completion audits", async () => {
    const create = await app.request("/secrets", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "create-failure", value: "never-visible" }),
    });
    expect(create.status).toBe(500);
    expect(
      await getDb().select().from(secrets).where(eq(secrets.name, "create-failure")),
    ).toHaveLength(0);

    const original = await vault.createSecret(tenantId, "lineage", "old-value");
    const route = await vault.createRoute(tenantId, original.id, {
      agentId,
      hostPattern: "api.openai.com",
      pathPattern: "/v1/items",
      method: "GET",
      injectAs: "header",
      injectKey: "Authorization",
    });
    const rotate = await app.request(`/secrets/${original.id}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: "new-value" }),
    });
    expect(rotate.status).toBe(500);
    expect(
      await getDb()
        .select({ id: secrets.id, version: secrets.version })
        .from(secrets)
        .where(and(eq(secrets.name, "lineage"), isNull(secrets.deletedAt))),
    ).toEqual([{ id: original.id, version: 1 }]);
    expect(
      await getDb()
        .select({ secretId: secretRoutes.secretId })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, route.id)),
    ).toEqual([{ secretId: original.id }]);

    const remove = await app.request(`/secrets/${original.id}`, { method: "DELETE" });
    expect(remove.status).toBe(500);
    expect(
      await getDb()
        .select({ id: secrets.id })
        .from(secrets)
        .where(and(eq(secrets.id, original.id), isNull(secrets.deletedAt))),
    ).toEqual([{ id: original.id }]);
    expect(
      await getDb()
        .select({ id: secretRoutes.id })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, route.id)),
    ).toEqual([{ id: route.id }]);
    expect(
      await getDb()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "secret.rotate"))),
    ).toHaveLength(0);
  });
  it("uses the transaction lock path supported by file-backed PGLite", async () => {
    const previousMemory = process.env.STEWARD_PGLITE_MEMORY;
    const previousMode = process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_DB_MODE = "pglite";
    let createdId: string | undefined;
    try {
      const created = await getDb().transaction((tx) =>
        vault.createSecretWithinTx(
          tx,
          tenantId,
          `file-backed-${suffix}`,
          "file-backed-pglite-value",
        ),
      );
      createdId = created.id;
      expect(created.version).toBe(1);
    } finally {
      if (createdId) {
        await getDb().delete(secrets).where(eq(secrets.id, createdId));
      }
      if (previousMemory === undefined) delete process.env.STEWARD_PGLITE_MEMORY;
      else process.env.STEWARD_PGLITE_MEMORY = previousMemory;
      if (previousMode === undefined) delete process.env.STEWARD_DB_MODE;
      else process.env.STEWARD_DB_MODE = previousMode;
    }
  });

  it("audits create, rotate, and delete in explicit PGLite mode", async () => {
    const name = `explicit-pglite-${crypto.randomUUID()}`;
    await rejectAuditActions(["__never_reject_explicit_pglite__"]);
    try {
      const create = await app.request("/secrets", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name, value: "initial-explicit-pglite-value" }),
      });
      expect(create.status).toBe(201);
      const createBody = (await create.json()) as { data: { id: string } };

      const rotate = await app.request(`/secrets/${createBody.data.id}`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value: "rotated-explicit-pglite-value" }),
      });
      expect(rotate.status).toBe(200);
      const rotateBody = (await rotate.json()) as { data: { id: string } };

      const remove = await app.request(`/secrets/${rotateBody.data.id}`, { method: "DELETE" });
      expect(remove.status).toBe(200);

      const lifecycle = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.resourceType, "secret")));
      expect(lifecycle.map((row) => row.action)).toEqual(
        expect.arrayContaining(["secret.create", "secret.rotate", "secret.delete"]),
      );
    } finally {
      await rejectAuditActions(["secret.create", "secret.rotate", "secret.delete"]);
    }
  });
});
