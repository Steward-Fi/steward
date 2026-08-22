import { afterAll, beforeAll, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createDb, runPluginMigrations } from "@stwd/db";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresTest = databaseUrl ? test : test.skip;
const suffix = randomUUID().replaceAll("-", "");
const databaseName = `trading_outcome_${suffix}`;
const appRole = `trading_outcome_app_${suffix}`;
const migrationRole = `trading_outcome_migrator_${suffix}`;
const appPassword = randomUUID().replaceAll("-", "");
const migrationPassword = randomUUID().replaceAll("-", "");
let serverAdmin: ReturnType<typeof createDb> | undefined;
let databaseAdmin: ReturnType<typeof createDb> | undefined;
let migration: ReturnType<typeof createDb> | undefined;
let restricted: ReturnType<typeof createDb> | undefined;

setDefaultTimeout(120_000);

function databaseUrlFor(name: string): string {
  const url = new URL(databaseUrl as string);
  url.pathname = `/${name}`;
  return url.toString();
}

function roleUrl(base: string, role: string, password: string): string {
  const url = new URL(base);
  url.username = role;
  url.password = password;
  return url.toString();
}

beforeAll(async () => {
  if (!databaseUrl) return;
  serverAdmin = createDb(databaseUrl);
  await serverAdmin.client.unsafe(`CREATE DATABASE ${databaseName}`);
  const isolatedUrl = databaseUrlFor(databaseName);
  databaseAdmin = createDb(isolatedUrl);
  await databaseAdmin.client.unsafe("CREATE SCHEMA steward_rls");
  await databaseAdmin.client.unsafe("CREATE SCHEMA drizzle");
  await databaseAdmin.client.unsafe(`
    CREATE FUNCTION steward_rls.tenant_id() RETURNS text
    LANGUAGE sql STABLE SET search_path = pg_catalog
    AS $$ SELECT NULLIF(current_setting('steward.tenant_id', true), '') $$
  `);

  await serverAdmin.client.unsafe(
    `CREATE ROLE ${appRole} LOGIN PASSWORD '${appPassword}' ` +
      "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
  );
  await serverAdmin.client.unsafe(
    `CREATE ROLE ${migrationRole} LOGIN PASSWORD '${migrationPassword}' ` +
      "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
  );
  await databaseAdmin.client.unsafe(`GRANT CREATE ON DATABASE ${databaseName} TO ${migrationRole}`);
  await databaseAdmin.client.unsafe(
    `GRANT USAGE, CREATE ON SCHEMA public, drizzle TO ${migrationRole}`,
  );
  await databaseAdmin.client.unsafe(`GRANT USAGE ON SCHEMA steward_rls TO ${migrationRole}`);
  await databaseAdmin.client.unsafe(
    `GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO ${migrationRole}`,
  );
  await databaseAdmin.client.unsafe(`GRANT USAGE ON SCHEMA public, steward_rls TO ${appRole}`);
  await databaseAdmin.client.unsafe(
    `GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO ${appRole}`,
  );
  await databaseAdmin.client.unsafe(
    `ALTER DEFAULT PRIVILEGES FOR ROLE ${migrationRole} IN SCHEMA public ` +
      `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${appRole}`,
  );

  migration = createDb(roleUrl(isolatedUrl, migrationRole, migrationPassword));
  await runPluginMigrations(
    {
      id: "trading",
      migrationsFolder: fileURLToPath(new URL("../../drizzle", import.meta.url)),
    },
    { db: migration.db, client: migration.client },
  );
  restricted = createDb(roleUrl(isolatedUrl, appRole, appPassword));
});

afterAll(async () => {
  await restricted?.client.end();
  await migration?.client.end();
  await databaseAdmin?.client.end();
  if (serverAdmin) {
    await serverAdmin.client.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await serverAdmin.client.unsafe(`DROP ROLE IF EXISTS ${appRole}`);
    await serverAdmin.client.unsafe(`DROP ROLE IF EXISTS ${migrationRole}`);
    await serverAdmin.client.end();
  }
});

realPostgresTest(
  "composed migrator ACL lets the restricted app replay only its tenant outcome",
  async () => {
    if (!databaseAdmin || !restricted) throw new Error("real PostgreSQL harness not initialized");
    const [acl] = await databaseAdmin.client<
      { owner: string; app_select: boolean; app_insert: boolean }[]
    >`
      SELECT owner.rolname AS owner,
        has_table_privilege(${appRole}, 'public.trading_order_outcomes', 'SELECT') AS app_select,
        has_table_privilege(${appRole}, 'public.trading_order_outcomes', 'INSERT') AS app_insert
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      JOIN pg_roles owner ON owner.oid = relation.relowner
      WHERE namespace.nspname = 'public' AND relation.relname = 'trading_order_outcomes'
    `;
    expect(acl).toEqual({ owner: migrationRole, app_select: true, app_insert: true });
    const id = randomUUID().replaceAll("-", "");
    const tenantA = `tenant-a-${suffix}`;
    const tenantB = `tenant-b-${suffix}`;
    const agentId = `agent-${suffix}`;
    const keyHash = "a".repeat(64);
    const requestHash = "b".repeat(64);
    const response = { status: 502, body: { ok: false, error: "Trade submission status unknown" } };

    await restricted.client.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', ${tenantA}, true)`;
      await tx`
        INSERT INTO trading_order_outcomes
          (id, tenant_id, agent_id, venue, phase, idempotency_key_hash, request_hash, http_status, response)
        VALUES
          (${id}, ${tenantA}, ${agentId}, 'hyperliquid', 'claim', ${keyHash}, ${requestHash}, 502,
           ${JSON.stringify(response)}::jsonb)
      `;
      const replay = await tx<{ response: typeof response }[]>`
        SELECT response FROM trading_order_outcomes
        WHERE tenant_id = ${tenantA} AND agent_id = ${agentId}
          AND venue = 'hyperliquid' AND idempotency_key_hash = ${keyHash}
      `;
      expect(replay).toEqual([{ response }]);

      await tx`SELECT set_config('steward.tenant_id', ${tenantB}, true)`;
      const hidden = await tx<{ count: string }[]>`
        SELECT count(*)::text AS count FROM trading_order_outcomes WHERE id = ${id}
      `;
      expect(hidden[0]?.count).toBe("0");
    });

    try {
      await restricted.client.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${tenantB}, true)`;
        await tx`
          INSERT INTO trading_order_outcomes
            (id, tenant_id, agent_id, venue, phase, idempotency_key_hash, request_hash, http_status, response)
          VALUES
            (${"c".repeat(64)}, ${tenantA}, ${agentId}, 'hyperliquid', 'claim', ${"d".repeat(64)},
             ${requestHash}, 502, ${JSON.stringify(response)}::jsonb)
        `;
      });
      throw new Error("expected cross-tenant insert to be denied");
    } catch (error) {
      expect((error as { code?: string }).code).toBe("42501");
    }
  },
);
