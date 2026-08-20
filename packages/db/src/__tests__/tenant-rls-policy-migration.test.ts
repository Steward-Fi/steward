import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { createPGLiteDb } from "../pglite";

describe("0111 tenant RLS policy installation", () => {
  let client: Awaited<ReturnType<typeof createPGLiteDb>>["client"];

  beforeAll(async () => {
    ({ client } = await createPGLiteDb("memory://"));
  });

  afterAll(async () => {
    await client.close();
  });

  test("installs the complete policy surface without prematurely activating it", async () => {
    const policies = await client.query<{
      relname: string;
      polname: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
    }>(`
      SELECT c.relname, p.polname, c.relrowsecurity, c.relforcerowsecurity
      FROM pg_policy p
      JOIN pg_class c ON c.oid = p.polrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND p.polname LIKE 'steward_%'
      ORDER BY c.relname, p.polname
    `);
    expect(policies.rows).toHaveLength(73);
    expect(policies.rows.every((row) => !row.relrowsecurity && !row.relforcerowsecurity)).toBe(
      true,
    );
    expect(
      policies.rows.filter((row) => row.relname === "approval_queue").map((row) => row.polname),
    ).toEqual(["steward_tenant_derived", "steward_tenant_direct"]);
    expect(
      policies.rows
        .filter((row) => row.relname === "user_push_subscriptions")
        .map((row) => row.polname),
    ).toEqual(["steward_global_user_subscription", "steward_tenant_subscription"]);
  });

  test("bootstrap functions are fixed-shape SECURITY DEFINER functions with safe search paths", async () => {
    const functions = await client.query<{
      proname: string;
      prosecdef: boolean;
      proconfig: string[] | null;
    }>(`
      SELECT p.proname, p.prosecdef, p.proconfig
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'steward_bootstrap'
      ORDER BY p.proname
    `);
    expect(functions.rows.map((row) => row.proname)).toEqual([
      "agent_subject",
      "agent_tenant_subject",
      "app_client_subject",
      "auth_app_clients_subject",
      "auth_refresh_subject",
      "auth_rotate_refresh_token",
      "auth_sso_discovery_subject",
      "auth_sso_domain_subject",
      "auth_tenant_config_subject",
      "auth_tenant_subject",
      "ensure_default_tenant",
      "ensure_platform_tenant",
      "ensure_system_tenant",
      "platform_delete_user",
      "platform_revoke_user_refresh_tokens",
      "platform_set_user_deactivation",
      "platform_stats",
      "platform_tenants",
      "platform_user_tenant_ids",
      "retention_delete_deactivated_users",
      "session_subject",
      "tenant_api_key_subject",
      "tenant_ids_for_internal_job",
    ]);
    expect(functions.rows.every((row) => row.prosecdef)).toBe(true);
    expect(functions.rows.every((row) => row.proconfig?.includes("search_path=pg_catalog"))).toBe(
      true,
    );
  });

  test("default bootstrap tolerates an occupied empty placeholder without aliasing it", async () => {
    await client.query(`
      INSERT INTO tenants(id, name, api_key_hash)
      VALUES ('fixture-empty-key', 'Fixture', '')
    `);
    await client.query(`SELECT steward_bootstrap.ensure_default_tenant('')`);
    const absent = await client.query<{ id: string }>(
      `SELECT id FROM tenants WHERE id = 'default'`,
    );
    expect(absent.rows).toEqual([]);

    await client.query(`SELECT steward_bootstrap.ensure_default_tenant('configured-default-key')`);
    const [created] = (
      await client.query<{ id: string; api_key_hash: string }>(
        `SELECT id, api_key_hash FROM tenants WHERE id = 'default'`,
      )
    ).rows;
    expect(created).toEqual({ id: "default", api_key_hash: "configured-default-key" });
    await expect(
      client.query(`SELECT steward_bootstrap.ensure_default_tenant('wrong-key')`),
    ).rejects.toThrow("DEFAULT_TENANT_API_KEY_MISMATCH");
  });

  test("operator scripts require no-bypass app/migration roles and atomic activation/rollback", async () => {
    const scripts = new URL("../../../../scripts/postgres/", import.meta.url);
    const bootstrap = await readFile(new URL("rls-bootstrap.sql", scripts), "utf8");
    const activate = await readFile(new URL("rls-activate.sql", scripts), "utf8");
    const rollback = await readFile(new URL("rls-rollback.sql", scripts), "utf8");
    const inventory = await readFile(new URL("rls-policy-inventory.sql", scripts), "utf8");
    expect(bootstrap).toContain("NOINHERIT NOREPLICATION NOBYPASSRLS");
    expect(bootstrap).toContain(
      "app, platform, migration-maintenance, and definer roles must be distinct",
    );
    expect(bootstrap).toContain("app role must not inherit or assume migration role");
    expect(bootstrap).toContain("app role must not inherit or assume platform role");
    expect(bootstrap).toContain("REVOKE EXECUTE ON FUNCTION");
    expect(bootstrap).toContain("platform_set_user_deactivation(uuid,boolean)");
    expect(bootstrap).toContain("BEGIN;");
    expect(bootstrap).toContain("COMMIT;");
    expect(inventory).toContain("core 71/73 and optional capabilities 0/0 or 3/3");
    expect(inventory).toContain("rls-policy-manifest.sql");
    expect(inventory).toContain("pg_get_expr");
    expect(activate).toContain("\\ir rls-policy-inventory.sql");
    expect(rollback).toContain("\\ir rls-policy-inventory.sql");
    expect(activate).toContain("ENABLE ROW LEVEL SECURITY");
    expect(activate).toContain("FORCE ROW LEVEL SECURITY");
    expect(activate).toContain("steward_migration_maintenance");
    expect(rollback).toContain("NO FORCE ROW LEVEL SECURITY");
    expect(rollback).toContain("DISABLE ROW LEVEL SECURITY");
  });
});
