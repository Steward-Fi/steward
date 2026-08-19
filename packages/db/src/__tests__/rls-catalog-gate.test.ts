import { describe, expect, test } from "bun:test";
import {
  assessRlsCatalogSnapshot,
  composeRlsCatalogInventory,
  inspectRlsCatalog,
  type RlsCatalogInventory,
  type RlsCatalogRow,
} from "../rls-catalog-gate";

function inventory(
  protectedTables: readonly string[],
  rlsExcludedTables: readonly string[] = [],
): RlsCatalogInventory {
  return { protectedTables, rlsExcludedTables };
}

function row(table_name: string, overrides: Partial<RlsCatalogRow> = {}): RlsCatalogRow {
  return {
    relation_oid: table_name,
    table_name,
    table_schema: "public",
    partition_root_oid: null,
    partition_root: null,
    partition_root_schema: null,
    rls_enabled: false,
    rls_forced: false,
    policy_count: 0,
    owned_by_runtime_role: false,
    owner_privileges_available_to_runtime: false,
    runtime_can_assume_superuser: false,
    runtime_can_assume_bypassrls: false,
    ...overrides,
  };
}

describe("SEC-169 catalog activation gate", () => {
  test("permits inactive and fully staged catalogs without enabling partial RLS", () => {
    expect(
      assessRlsCatalogSnapshot(
        [row("a"), row("b"), row("global")],
        inventory(["a", "b"], ["global"]),
      ),
    ).toMatchObject({ state: "inactive", policyCoverageComplete: false });
    expect(
      assessRlsCatalogSnapshot(
        [row("a", { policy_count: 1 }), row("b", { policy_count: 1 }), row("global")],
        inventory(["a", "b"], ["global"]),
      ),
    ).toMatchObject({ state: "policies-staged", policyCoverageComplete: true });
  });

  test("rejects partial flags, missing policies, and unsafe active roles", () => {
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", { rls_enabled: true, rls_forced: true, policy_count: 1 }), row("b")],
        inventory(["a", "b"]),
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", { rls_enabled: true, rls_forced: true, policy_count: 1 }),
          row("b", { rls_enabled: true, rls_forced: true }),
        ],
        inventory(["a", "b"]),
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", {
            rls_enabled: true,
            rls_forced: true,
            policy_count: 1,
            runtime_can_assume_bypassrls: true,
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE");
  });

  test("rejects active SUPERUSER and table-owner application roles", () => {
    const active = { rls_enabled: true, rls_forced: true, policy_count: 1 };
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", { ...active, runtime_can_assume_superuser: true })],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE: superuser");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", {
            ...active,
            owned_by_runtime_role: true,
            owner_privileges_available_to_runtime: true,
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE: owner:a");
  });

  test("rejects an invalid schema before querying the catalog", async () => {
    let queried = false;
    const client = {
      async unsafe() {
        queried = true;
        return [];
      },
    };
    await expect(
      inspectRlsCatalog(client, {
        schema: "public; SET ROLE owner",
        runtimeRole: "app_role",
      }),
    ).rejects.toThrow("RLS_CATALOG_SCHEMA_INVALID");
    expect(queried).toBe(false);
  });

  test("rejects inventory drift, protected global tables, and orphan partitions", () => {
    expect(() => assessRlsCatalogSnapshot([row("a"), row("unexpected")], inventory(["a"]))).toThrow(
      "RLS_CATALOG_INVENTORY_MISMATCH",
    );
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a"), row("global", { rls_enabled: true })],
        inventory(["a"], ["global"]),
      ),
    ).toThrow("RLS_CATALOG_EXCLUDED_TABLE_PROTECTED");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a"),
          row("a_2026", {
            partition_root: "missing",
            partition_root_oid: "missing",
            partition_root_schema: "public",
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_INVENTORY_MISMATCH");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a"),
          row("same_named_external_child", {
            partition_root: "a",
            partition_root_oid: "external-a",
            partition_root_schema: "public",
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_INVENTORY_MISMATCH");
  });

  test("accepts only complete active catalogs and requires partition flags", () => {
    const active = { rls_enabled: true, rls_forced: true, policy_count: 1 };
    expect(
      assessRlsCatalogSnapshot(
        [
          row("a", active),
          row("b", active),
          row("a_2026", {
            ...active,
            partition_root: "a",
            partition_root_oid: "a",
            partition_root_schema: "public",
          }),
        ],
        inventory(["a", "b"]),
      ),
    ).toEqual({
      state: "active",
      policyCoverageComplete: true,
      protectedTableCount: 2,
      partitionCount: 1,
    });
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", active),
          row("a_2026", {
            partition_root: "a",
            partition_root_oid: "a",
            partition_root_schema: "public",
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", active),
          row("a_2026", {
            ...active,
            partition_root: "a",
            partition_root_oid: "a",
            partition_root_schema: "public",
            owned_by_runtime_role: true,
            owner_privileges_available_to_runtime: true,
          }),
        ],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE");
  });

  test("rejects owner-role membership before activation and composes plugin inventory", () => {
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", { owner_privileges_available_to_runtime: true })],
        inventory(["a"]),
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE: owner-role:a");

    const composed = composeRlsCatalogInventory([
      {
        owner: "plugin-example",
        protectedTables: ["plugin_tenant_table"],
        rlsExcludedTables: ["plugin_global_table"],
      },
    ]);
    expect(composed.protectedTables).toContain("plugin_tenant_table");
    expect(composed.rlsExcludedTables).toContain("auth_kv_store");
    expect(composed.rlsExcludedTables).toContain("plugin_global_table");
    expect(() =>
      composeRlsCatalogInventory([{ owner: "invalid-plugin", rlsExcludedTables: ["agents"] }]),
    ).toThrow("RLS_CATALOG_INVENTORY_INVALID: duplicate:agents");
  });
});
