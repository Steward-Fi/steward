import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";
import {
  inspectRlsCatalog,
  RLS_ACTIVATION_TABLES,
  type RlsCatalogClient,
  type RlsCatalogInventoryContribution,
} from "../rls-catalog-gate";
import { INTENTIONALLY_GLOBAL_TABLES } from "../rls-inventory";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
const suffix = randomUUID().replaceAll("-", "").slice(0, 20);
const schemaName = `rls_catalog_${suffix}`;
const partitionSchemaName = `rls_partition_${suffix}`;
const ownerRole = `rls_owner_${suffix}`;
const applicationRole = `rls_app_${suffix}`;
const ownerMemberRole = `rls_member_${suffix}`;
const bypassRole = `rls_bypass_${suffix}`;
const pluginContribution: RlsCatalogInventoryContribution = {
  owner: "test-plugin",
  protectedTables: ["capabilities", "capability_grants"],
  rlsExcludedTables: ["example_log"],
};
setDefaultTimeout(30_000);

function identifier(value: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) throw new Error("unsafe test identifier");
  return `"${value}"`;
}

describeWithPostgres("SEC-169 catalog activation gate on real Postgres", () => {
  const client = postgres(process.env.DATABASE_URL as string, { max: 1, prepare: false });
  let administratorRole = "";
  let serverVersionNumber = 0;
  const rootTable = RLS_ACTIVATION_TABLES[0];
  const protectedTables = [...RLS_ACTIVATION_TABLES, ...(pluginContribution.protectedTables ?? [])];
  const excludedTables = [
    ...Object.keys(INTENTIONALLY_GLOBAL_TABLES),
    "auth_kv_store",
    ...(pluginContribution.rlsExcludedTables ?? []),
  ];

  function inspectAs(runtimeRole: string, withPlugin = true) {
    return inspectRlsCatalog(client as unknown as RlsCatalogClient, {
      schema: schemaName,
      runtimeRole,
      inventoryContributions: withPlugin ? [pluginContribution] : [],
    });
  }

  beforeAll(async () => {
    const [identity] = await client<Array<{ current_user: string; server_version_num: number }>>`
      SELECT current_user, current_setting('server_version_num')::integer AS server_version_num
    `;
    administratorRole = identity?.current_user ?? "";
    serverVersionNumber = identity?.server_version_num ?? 0;
    await client.unsafe(`
      CREATE ROLE ${identifier(ownerRole)} NOLOGIN NOSUPERUSER NOBYPASSRLS;
      CREATE ROLE ${identifier(applicationRole)} NOLOGIN NOSUPERUSER NOBYPASSRLS;
      CREATE ROLE ${identifier(ownerMemberRole)} NOLOGIN NOSUPERUSER NOBYPASSRLS;
      CREATE ROLE ${identifier(bypassRole)} NOLOGIN NOSUPERUSER BYPASSRLS;
      CREATE SCHEMA ${identifier(schemaName)};
      CREATE SCHEMA ${identifier(partitionSchemaName)};
    `);
    await client.unsafe(
      serverVersionNumber >= 160000
        ? `GRANT ${identifier(ownerRole)} TO ${identifier(ownerMemberRole)} ` +
            "WITH INHERIT TRUE, SET FALSE"
        : `GRANT ${identifier(ownerRole)} TO ${identifier(ownerMemberRole)}`,
    );
    for (const table of [...protectedTables, ...excludedTables]) {
      const qualified = `${identifier(schemaName)}.${identifier(table)}`;
      if (table === rootTable) {
        await client.unsafe(
          `CREATE TABLE ${qualified} (id integer, tenant_id text) PARTITION BY RANGE (id)`,
        );
      } else {
        await client.unsafe(`CREATE TABLE ${qualified} (id integer PRIMARY KEY, tenant_id text)`);
      }
      await client.unsafe(`ALTER TABLE ${qualified} OWNER TO ${identifier(ownerRole)}`);
    }
    const externalPartition = `${identifier(partitionSchemaName)}.${identifier(`${rootTable}_2026`)}`;
    await client.unsafe(
      `CREATE TABLE ${externalPartition} ` +
        `PARTITION OF ${identifier(schemaName)}.${identifier(rootTable)} ` +
        "FOR VALUES FROM (0) TO (100)",
    );
    await client.unsafe(`ALTER TABLE ${externalPartition} OWNER TO ${identifier(ownerRole)}`);
  });

  afterAll(async () => {
    await client.unsafe(`
      DROP SCHEMA IF EXISTS ${identifier(schemaName)} CASCADE;
      DROP SCHEMA IF EXISTS ${identifier(partitionSchemaName)} CASCADE;
      REVOKE ${identifier(ownerRole)} FROM ${identifier(ownerMemberRole)};
      DROP ROLE IF EXISTS ${identifier(applicationRole)};
      DROP ROLE IF EXISTS ${identifier(ownerMemberRole)};
      DROP ROLE IF EXISTS ${identifier(bypassRole)};
      DROP ROLE IF EXISTS ${identifier(ownerRole)};
    `);
    await client.end();
  });

  test("enforces complete dynamic inventory, partitions, and runtime-role safety", async () => {
    await expect(inspectAs(applicationRole, false)).rejects.toThrow(
      "RLS_CATALOG_INVENTORY_MISMATCH",
    );
    await expect(inspectAs(applicationRole)).resolves.toMatchObject({
      state: "inactive",
      policyCoverageComplete: false,
      protectedTableCount: protectedTables.length,
      partitionCount: 1,
    });

    const externalPartition = `${identifier(partitionSchemaName)}.${identifier(`${rootTable}_2026`)}`;
    await client.unsafe(`
      ALTER TABLE ${externalPartition} ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ${externalPartition} FORCE ROW LEVEL SECURITY;
    `);
    await expect(inspectAs(applicationRole)).rejects.toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    await client.unsafe(`
      ALTER TABLE ${externalPartition} NO FORCE ROW LEVEL SECURITY;
      ALTER TABLE ${externalPartition} DISABLE ROW LEVEL SECURITY;
    `);

    for (const table of protectedTables) {
      const qualified = `${identifier(schemaName)}.${identifier(table)}`;
      await client.unsafe(`
        CREATE POLICY tenant_isolation ON ${qualified} USING (true) WITH CHECK (true);
        ALTER TABLE ${qualified} ENABLE ROW LEVEL SECURITY;
        ALTER TABLE ${qualified} FORCE ROW LEVEL SECURITY;
      `);
    }
    await client.unsafe(`
      ALTER TABLE ${externalPartition} ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ${externalPartition} FORCE ROW LEVEL SECURITY;
    `);

    await expect(inspectAs(applicationRole)).resolves.toMatchObject({
      state: "active",
      policyCoverageComplete: true,
      protectedTableCount: protectedTables.length,
      partitionCount: 1,
    });
    await expect(inspectAs(ownerMemberRole)).rejects.toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE");
    await client.unsafe(
      serverVersionNumber >= 160000
        ? `GRANT ${identifier(bypassRole)} TO ${identifier(applicationRole)} ` +
            "WITH INHERIT FALSE, SET TRUE"
        : `GRANT ${identifier(bypassRole)} TO ${identifier(applicationRole)}`,
    );
    if (serverVersionNumber >= 160000) {
      const [membership] = await client<
        Array<{
          owner_set: boolean;
          owner_usage: boolean;
          bypass_set: boolean;
          bypass_usage: boolean;
        }>
      >`
        SELECT
          pg_has_role(${ownerMemberRole}, ${ownerRole}, 'SET') AS owner_set,
          pg_has_role(${ownerMemberRole}, ${ownerRole}, 'USAGE') AS owner_usage,
          pg_has_role(${applicationRole}, ${bypassRole}, 'SET') AS bypass_set,
          pg_has_role(${applicationRole}, ${bypassRole}, 'USAGE') AS bypass_usage
      `;
      expect(membership).toEqual({
        owner_set: false,
        owner_usage: true,
        bypass_set: true,
        bypass_usage: false,
      });
    }
    await expect(inspectAs(applicationRole)).rejects.toThrow(
      "RLS_CATALOG_UNSAFE_APPLICATION_ROLE: bypassrls",
    );
    await client.unsafe(`REVOKE ${identifier(bypassRole)} FROM ${identifier(applicationRole)}`);
    await expect(inspectAs(administratorRole)).rejects.toThrow("superuser");
  });
});
