import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { createDb } from "../client";
import { tenantContextForInternalJob, withTenantRlsTransaction } from "../tenant-rls-context";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
setDefaultTimeout(30_000);
const schemaName = `rls_test_${randomUUID().replaceAll("-", "")}`;
const tableName = `${schemaName}.records`;
const roleName = `rls_role_${randomUUID().replaceAll("-", "")}`;
const rolePassword = randomUUID().replaceAll("-", "");

function rowsOf(value: unknown): Array<Record<string, unknown>> {
  return Array.isArray(value) ? value : ((value as { rows?: [] } | null)?.rows ?? []);
}

async function expectRlsRejected(operation: Promise<unknown>): Promise<void> {
  try {
    await operation;
    throw new Error("expected RLS rejection");
  } catch (error) {
    const outer = error as { message?: string; code?: string; cause?: unknown };
    const cause = outer.cause as { message?: string; code?: string } | undefined;
    expect(cause?.code ?? outer.code).toBe("42501");
    expect(`${outer.message ?? ""} ${cause?.message ?? ""}`).toMatch(/row-level security policy/);
  }
}

describeWithPostgres("SEC-169 transaction context on a real Postgres pool", () => {
  let handle: ReturnType<typeof createDb>;
  let adminHandle: ReturnType<typeof createDb> | undefined;

  beforeAll(async () => {
    const initialHandle = createDb(process.env.DATABASE_URL as string);
    const initialRoleRows = await initialHandle.client`
      SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    if (initialRoleRows[0]?.rolbypassrls || initialRoleRows[0]?.rolsuper) {
      // GitHub's Postgres service user is the bootstrap superuser. Create the
      // role whose production properties we actually need to prove, then run
      // every RLS assertion through its independent login/pool.
      adminHandle = initialHandle;
      await adminHandle.client.unsafe(
        `CREATE ROLE ${roleName} LOGIN PASSWORD '${rolePassword}' ` +
          "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS",
      );
      await adminHandle.client.unsafe(`CREATE SCHEMA ${schemaName} AUTHORIZATION ${roleName}`);
      const restrictedUrl = new URL(process.env.DATABASE_URL as string);
      restrictedUrl.username = roleName;
      restrictedUrl.password = rolePassword;
      handle = createDb(restrictedUrl.toString());
    } else {
      handle = initialHandle;
      await handle.client.unsafe(`CREATE SCHEMA ${schemaName}`);
    }
    const roleRows = await handle.client`
      SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    expect(roleRows[0]?.rolbypassrls).toBe(false);
    expect(roleRows[0]?.rolsuper).toBe(false);
    await handle.client.unsafe(`
      CREATE TABLE ${tableName} (
        id text PRIMARY KEY,
        tenant_id text NOT NULL,
        value text NOT NULL
      );
      INSERT INTO ${tableName} VALUES ('a-seed', 'tenant-a', 'a'), ('b-seed', 'tenant-b', 'b');
      ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;
      ALTER TABLE ${tableName} FORCE ROW LEVEL SECURITY;
      CREATE POLICY tenant_isolation ON ${tableName}
        USING (tenant_id = NULLIF(current_setting('steward.tenant_id', true), ''))
        WITH CHECK (tenant_id = NULLIF(current_setting('steward.tenant_id', true), ''));
    `);
  });

  afterAll(async () => {
    await handle.client.unsafe(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
    await handle.client.end();
    if (adminHandle) {
      await adminHandle.client.unsafe(`DROP ROLE IF EXISTS ${roleName}`);
      await adminHandle.client.end();
    }
  });

  test("missing context denies reads and writes", async () => {
    const rows = await handle.client.unsafe(`SELECT * FROM ${tableName}`);
    expect(rows).toHaveLength(0);
    await expectRlsRejected(
      handle.client.unsafe(`INSERT INTO ${tableName} VALUES ('missing', 'tenant-a', 'must fail')`),
    );
  });

  test("concurrent pooled transactions cannot cross tenants or leak context", async () => {
    const tasks = Array.from({ length: 24 }, async (_, index) => {
      const tenantId = index % 2 === 0 ? "tenant-a" : "tenant-b";
      const context = tenantContextForInternalJob({ tenantId, job: "rls-concurrency-test" });
      return withTenantRlsTransaction(handle.db as never, "postgres-js", context, async (tx) => {
        const visible = rowsOf(await tx.execute(sql.raw(`SELECT tenant_id FROM ${tableName}`)));
        expect(visible.length).toBeGreaterThan(0);
        expect(visible.every((row) => row.tenant_id === tenantId)).toBe(true);
        return tenantId;
      });
    });
    const results = await Promise.all(tasks);
    expect(results).toHaveLength(24);

    // Every new unit of work starts without context, regardless of which pooled
    // connection served a prior tenant transaction.
    const resetChecks = await Promise.all(
      Array.from({ length: 12 }, () => handle.client.unsafe(`SELECT * FROM ${tableName}`)),
    );
    expect(resetChecks.every((rows) => rows.length === 0)).toBe(true);
  });

  test("WITH CHECK rejects a cross-tenant write", async () => {
    const context = tenantContextForInternalJob({
      tenantId: "tenant-a",
      job: "rls-cross-tenant-write-test",
    });
    await expectRlsRejected(
      withTenantRlsTransaction(handle.db as never, "postgres-js", context, async (tx) =>
        tx.execute(
          sql.raw(`INSERT INTO ${tableName} VALUES ('bad-write', 'tenant-b', 'must fail')`),
        ),
      ),
    );
  });
});
