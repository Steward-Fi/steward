import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";
import {
  inspectRlsCatalog,
  RLS_ACTIVATION_TABLES,
  type RlsCatalogClient,
} from "../rls-catalog-gate";
import { INTENTIONALLY_GLOBAL_TABLES } from "../rls-inventory";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
const schemaName = `rls_catalog_${randomUUID().replaceAll("-", "")}`;
setDefaultTimeout(30_000);

function identifier(value: string): string {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) throw new Error("unsafe test identifier");
  return `"${value}"`;
}

describeWithPostgres("SEC-169 catalog activation gate on real Postgres", () => {
  const client = postgres(process.env.DATABASE_URL as string, { max: 1, prepare: false });

  beforeAll(async () => {
    await client.unsafe(`CREATE SCHEMA ${identifier(schemaName)}`);
    for (const table of [...RLS_ACTIVATION_TABLES, ...Object.keys(INTENTIONALLY_GLOBAL_TABLES)]) {
      await client.unsafe(
        `CREATE TABLE ${identifier(schemaName)}.${identifier(table)} (id text PRIMARY KEY, tenant_id text)`,
      );
    }
  });

  afterAll(async () => {
    await client.unsafe(`DROP SCHEMA IF EXISTS ${identifier(schemaName)} CASCADE`);
    await client.end();
  });

  test("observes an inactive complete inventory and rejects one-table activation", async () => {
    await expect(
      inspectRlsCatalog(client as unknown as RlsCatalogClient, schemaName),
    ).resolves.toMatchObject({
      state: "inactive",
      policyCoverageComplete: false,
      protectedTableCount: RLS_ACTIVATION_TABLES.length,
    });

    const first = identifier(RLS_ACTIVATION_TABLES[0]);
    await client.unsafe(`
      CREATE POLICY tenant_isolation ON ${identifier(schemaName)}.${first}
        USING (tenant_id = NULLIF(current_setting('steward.tenant_id', true), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('steward.tenant_id', true), ''));
      ALTER TABLE ${identifier(schemaName)}.${first} ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ${identifier(schemaName)}.${first} FORCE ROW LEVEL SECURITY;
    `);
    await expect(
      inspectRlsCatalog(client as unknown as RlsCatalogClient, schemaName),
    ).rejects.toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
  });
});
