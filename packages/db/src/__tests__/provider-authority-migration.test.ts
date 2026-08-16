import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { createPGLiteDb } from "../pglite";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const migrationUnderTest = "0079_workspace_provider_authority.sql";

async function applyFile(client: PGlite, file: string) {
  const sql = await readFile(join(migrations, file), "utf8");
  for (const statement of sql.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

async function applyThroughCurrentSchema(client: PGlite) {
  // Build the pre-0079 baseline only. A filename boundary prevents this migration
  // test from sweeping 0080 (or any future migration) ahead of the migration under test.
  const files = (await readdir(migrations))
    .filter((file) => file.endsWith(".sql") && file < migrationUnderTest)
    .sort();
  for (const file of files) await applyFile(client, file);
}

async function seedAuthority(client: PGlite) {
  await client.exec(`
    INSERT INTO tenants(id,name,api_key_hash) VALUES ('ta','A','ha'),('tb','B','hb');
    INSERT INTO users(id,email,created_at,updated_at) VALUES
      ('00000000-0000-4000-8000-000000000001','owner@example.test',now(),now());
    INSERT INTO user_tenants(id,user_id,tenant_id,role) VALUES
      ('00000000-0000-4000-8000-000000000011','00000000-0000-4000-8000-000000000001','ta','owner');
    INSERT INTO agents(id,tenant_id,name,wallet_address) VALUES ('agent-a','ta','A','0xa'),('agent-b','tb','B','0xb');
    INSERT INTO workspaces(id,tenant_id,key,name,environment,created_by) VALUES
      ('00000000-0000-4000-8000-000000000101','ta','client-a','Client A','production','00000000-0000-4000-8000-000000000001'),
      ('00000000-0000-4000-8000-000000000102','tb','client-b','Client B','production','00000000-0000-4000-8000-000000000001');
    INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name) VALUES
      ('00000000-0000-4000-8000-000000000201','ta','00000000-0000-4000-8000-000000000101','github','a','A');
  `);
}

describe("provider authority migration", () => {
  test("migrates an empty database and creates the authority tables", async () => {
    const { client } = await createPGLiteDb("memory://");
    const result = await client.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('workspaces','provider_accounts','provider_operations','provider_role_bindings','provider_grants') ORDER BY table_name`,
    );
    expect(result.rows.map((row) => row.table_name)).toEqual([
      "provider_accounts",
      "provider_grants",
      "provider_operations",
      "provider_role_bindings",
      "workspaces",
    ]);
    await client.close();
  });

  test("upgrades the current schema without changing existing rows", async () => {
    const client = new PGlite("memory://");
    await applyThroughCurrentSchema(client);
    await client.exec(
      `INSERT INTO tenants(id,name,api_key_hash) VALUES ('existing','Existing','existing-hash')`,
    );
    await applyFile(client, migrationUnderTest);
    const tenant = await client.query<{ name: string }>(
      "SELECT name FROM tenants WHERE id='existing'",
    );
    const table = await client.query<{ r: string | null }>(
      "SELECT to_regclass('public.provider_grants')::text AS r",
    );
    expect(tenant.rows[0]?.name).toBe("Existing");
    expect(table.rows[0]?.r).toBe("provider_grants");
    await client.close();
  });

  test("keeps raw-SQL-only invariants present after migration (P1-1)", async () => {
    // These are the invariants that live ONLY in 0079 raw SQL and are invisible
    // to drizzle-kit (see the RAW-SQL-ONLY banner in schema.ts). Asserting they
    // exist post-migration means an accidental drop (e.g. someone regenerating
    // from schema.ts) fails CI instead of silently removing fund-safety guards.
    const { client } = await createPGLiteDb("memory://");

    // 1. All five *_immutable_owner triggers exist.
    const triggers = await client.query<{ tgname: string }>(
      `SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgname LIKE '%_immutable_owner' ORDER BY tgname`,
    );
    expect(triggers.rows.map((row) => row.tgname)).toEqual([
      "provider_accounts_immutable_owner",
      "provider_grants_immutable_owner",
      "provider_operations_immutable_owner",
      "provider_role_bindings_immutable_owner",
      "workspaces_immutable_owner",
    ]);

    // The shared trigger function backing them exists.
    const fn = await client.query<{ proname: string }>(
      `SELECT proname FROM pg_proc WHERE proname='steward_reject_provider_scope_move'`,
    );
    expect(fn.rows.map((row) => row.proname)).toEqual(["steward_reject_provider_scope_move"]);

    // 2. The role-binding lifetime CHECK (raw-SQL-only counterpart to the
    //    in-schema provider_grants lifetime check) exists.
    const lifetimeCheck = await client.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint WHERE contype='c' AND conname='provider_role_bindings_lifetime_check'`,
    );
    expect(lifetimeCheck.rows.map((row) => row.conname)).toEqual([
      "provider_role_bindings_lifetime_check",
    ]);

    await client.close();
  });

  test("enforces the role-binding lifetime CHECK at write time (P1-1)", async () => {
    const { client } = await createPGLiteDb("memory://");
    await seedAuthority(client);
    // expires_at <= not_before must be rejected by the lifetime CHECK.
    await expect(
      client.exec(
        `INSERT INTO provider_role_bindings(id,tenant_id,workspace_id,principal_type,principal_id,role_key,granted_by_user_id,reason,not_before,expires_at) VALUES ('00000000-0000-4000-8000-000000000401','ta','00000000-0000-4000-8000-000000000101','human','user-a','workspace_admin','00000000-0000-4000-8000-000000000001','bad lifetime',now()+interval '2 hour',now()+interval '1 hour')`,
      ),
    ).rejects.toThrow(/lifetime/);
    // A valid ordering (or a NULL bound) is accepted.
    await client.exec(
      `INSERT INTO provider_role_bindings(id,tenant_id,workspace_id,principal_type,principal_id,role_key,granted_by_user_id,reason,not_before,expires_at) VALUES ('00000000-0000-4000-8000-000000000402','ta','00000000-0000-4000-8000-000000000101','human','user-a','workspace_admin','00000000-0000-4000-8000-000000000001','ok lifetime',now(),now()+interval '1 hour')`,
    );
    const ok = await client.query<{ id: string }>(
      `SELECT id FROM provider_role_bindings WHERE id='00000000-0000-4000-8000-000000000402'`,
    );
    expect(ok.rows).toHaveLength(1);
    await client.close();
  });

  test("provider_accounts immutability trigger allows same-table mutation but blocks owner move (P1-2)", async () => {
    const { client } = await createPGLiteDb("memory://");
    await seedAuthority(client);

    // Positive: mutating status + revision on the same row passes the trigger.
    await client.exec(
      `UPDATE provider_accounts SET status='disabled', revision=revision+1 WHERE id='00000000-0000-4000-8000-000000000201'`,
    );
    const updated = await client.query<{ status: string; revision: number }>(
      `SELECT status, revision FROM provider_accounts WHERE id='00000000-0000-4000-8000-000000000201'`,
    );
    expect(updated.rows[0]?.status).toBe("disabled");
    expect(updated.rows[0]?.revision).toBe(2);

    // Negative: moving workspace_id on the same row is rejected as immutable.
    await expect(
      client.exec(
        `UPDATE provider_accounts SET workspace_id='00000000-0000-4000-8000-000000000102' WHERE id='00000000-0000-4000-8000-000000000201'`,
      ),
    ).rejects.toThrow(/immutable/);

    await client.close();
  });

  test("rejects cross-tenant/workspace references and ownership moves", async () => {
    const { client } = await createPGLiteDb("memory://");
    await seedAuthority(client);
    await expect(
      client.exec(
        `INSERT INTO provider_accounts(id,tenant_id,workspace_id,adapter_key,external_ref,display_name) VALUES ('00000000-0000-4000-8000-000000000202','tb','00000000-0000-4000-8000-000000000101','github','bad','bad')`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `INSERT INTO provider_grants(id,tenant_id,workspace_id,provider_account_id,agent_id,operation_keys,expires_at,granted_by_user_id,reason) VALUES ('00000000-0000-4000-8000-000000000301','ta','00000000-0000-4000-8000-000000000101','00000000-0000-4000-8000-000000000201','agent-b',ARRAY['github.issue.list'],now()+interval '1 hour','00000000-0000-4000-8000-000000000001','bad')`,
      ),
    ).rejects.toThrow();
    await expect(
      client.exec(
        `UPDATE provider_accounts SET workspace_id='00000000-0000-4000-8000-000000000102' WHERE id='00000000-0000-4000-8000-000000000201'`,
      ),
    ).rejects.toThrow(/immutable/);
    await client.close();
  });
});
