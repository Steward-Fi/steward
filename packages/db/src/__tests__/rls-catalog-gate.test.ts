import { describe, expect, test } from "bun:test";
import { assessRlsCatalogSnapshot, type RlsCatalogRow } from "../rls-catalog-gate";

function row(table_name: string, overrides: Partial<RlsCatalogRow> = {}): RlsCatalogRow {
  return {
    table_name,
    partition_root: null,
    rls_enabled: false,
    rls_forced: false,
    policy_count: 0,
    owned_by_current_role: false,
    role_super: false,
    role_bypass_rls: false,
    ...overrides,
  };
}

describe("SEC-169 catalog activation gate", () => {
  test("permits inactive and fully staged catalogs without enabling partial RLS", () => {
    expect(
      assessRlsCatalogSnapshot([row("a"), row("b"), row("global")], ["a", "b"], ["global"]),
    ).toMatchObject({ state: "inactive", policyCoverageComplete: false });
    expect(
      assessRlsCatalogSnapshot(
        [row("a", { policy_count: 1 }), row("b", { policy_count: 1 }), row("global")],
        ["a", "b"],
        ["global"],
      ),
    ).toMatchObject({ state: "policies-staged", policyCoverageComplete: true });
  });

  test("rejects partial flags, missing policies, and unsafe active roles", () => {
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", { rls_enabled: true, rls_forced: true, policy_count: 1 }), row("b")],
        ["a", "b"],
        [],
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", { rls_enabled: true, rls_forced: true, policy_count: 1 }),
          row("b", { rls_enabled: true, rls_forced: true }),
        ],
        ["a", "b"],
        [],
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", { rls_enabled: true, rls_forced: true, policy_count: 1, role_bypass_rls: true })],
        ["a"],
        [],
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE");
  });

  test("rejects inventory drift, protected global tables, and orphan partitions", () => {
    expect(() => assessRlsCatalogSnapshot([row("a"), row("unexpected")], ["a"], [])).toThrow(
      "RLS_CATALOG_INVENTORY_MISMATCH",
    );
    expect(() =>
      assessRlsCatalogSnapshot([row("a"), row("global", { rls_enabled: true })], ["a"], ["global"]),
    ).toThrow("RLS_CATALOG_GLOBAL_TABLE_PROTECTED");
    expect(() =>
      assessRlsCatalogSnapshot([row("a"), row("a_2026", { partition_root: "missing" })], ["a"], []),
    ).toThrow("RLS_CATALOG_INVENTORY_MISMATCH");
  });

  test("accepts only complete active catalogs and requires partition flags", () => {
    const active = { rls_enabled: true, rls_forced: true, policy_count: 1 };
    expect(
      assessRlsCatalogSnapshot(
        [row("a", active), row("b", active), row("a_2026", { ...active, partition_root: "a" })],
        ["a", "b"],
        [],
      ),
    ).toEqual({
      state: "active",
      policyCoverageComplete: true,
      protectedTableCount: 2,
      partitionCount: 1,
    });
    expect(() =>
      assessRlsCatalogSnapshot(
        [row("a", active), row("a_2026", { partition_root: "a" })],
        ["a"],
        [],
      ),
    ).toThrow("RLS_CATALOG_PARTIAL_ACTIVATION");
    expect(() =>
      assessRlsCatalogSnapshot(
        [
          row("a", active),
          row("a_2026", { ...active, partition_root: "a", owned_by_current_role: true }),
        ],
        ["a"],
        [],
      ),
    ).toThrow("RLS_CATALOG_UNSAFE_APPLICATION_ROLE");
  });
});
