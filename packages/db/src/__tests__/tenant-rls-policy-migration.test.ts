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
      "app_client_subject",
      "auth_refresh_subject",
      "ensure_default_tenant",
      "platform_stats",
      "platform_tenants",
      "session_subject",
      "tenant_api_key_subject",
      "tenant_ids_for_internal_job",
    ]);
    expect(functions.rows.every((row) => row.prosecdef)).toBe(true);
    expect(functions.rows.every((row) => row.proconfig?.includes("search_path=pg_catalog"))).toBe(
      true,
    );
  });

  test("operator scripts require no-bypass app/migration roles and atomic activation/rollback", async () => {
    const scripts = new URL("../../../../scripts/postgres/", import.meta.url);
    const bootstrap = await readFile(new URL("rls-bootstrap.sql", scripts), "utf8");
    const activate = await readFile(new URL("rls-activate.sql", scripts), "utf8");
    const rollback = await readFile(new URL("rls-rollback.sql", scripts), "utf8");
    expect(bootstrap).toContain("NOINHERIT NOBYPASSRLS");
    expect(bootstrap).toContain("app role must not inherit or assume migration role");
    expect(activate).toContain("ENABLE ROW LEVEL SECURITY");
    expect(activate).toContain("FORCE ROW LEVEL SECURITY");
    expect(activate).toContain("steward_migration_maintenance");
    expect(rollback).toContain("NO FORCE ROW LEVEL SECURITY");
    expect(rollback).toContain("DISABLE ROW LEVEL SECURITY");
  });
});
