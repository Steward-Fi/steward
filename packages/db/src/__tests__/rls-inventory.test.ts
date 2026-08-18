import { describe, expect, test } from "bun:test";
import { getTableName } from "drizzle-orm";
import {
  ALL_INVENTORIED_TABLES,
  BOOTSTRAP_ROOT_TABLES,
  DIRECT_TENANT_TABLES,
  HYBRID_SCOPE_TABLES,
  INDIRECT_TENANT_TABLES,
  INTENTIONALLY_GLOBAL_TABLES,
  TENANT_COLUMN_BACKFILL_TABLES,
} from "../rls-inventory";
import * as schema from "../schema";
import * as authSchema from "../schema-auth";

function schemaTableNames(): string[] {
  const names: string[] = [];
  for (const value of Object.values({ ...schema, ...authSchema })) {
    try {
      const name = getTableName(value as never);
      if (typeof name === "string") names.push(name);
    } catch {
      // Enums, relations, and helpers are intentionally not tables.
    }
  }
  return [...new Set(names)].sort();
}

describe("SEC-169 RLS inventory", () => {
  test("classifies every schema table exactly once", () => {
    const inventory = [...ALL_INVENTORIED_TABLES].sort();
    expect(inventory).toEqual([...new Set(inventory)]);
    expect(inventory).toEqual(schemaTableNames());
  });

  test("direct tables really expose tenantId and exclusions are justified", () => {
    const tables = Object.values({ ...schema, ...authSchema }) as Array<Record<string, unknown>>;
    const directNames = tables
      .filter((table) => table && typeof table === "object" && "tenantId" in table)
      .map((table) => getTableName(table as never))
      .filter((name): name is string => typeof name === "string")
      .sort();
    expect([...DIRECT_TENANT_TABLES, ...Object.keys(HYBRID_SCOPE_TABLES)].sort()).toEqual(
      directNames,
    );
    for (const table of tables.filter(
      (value) => value && typeof value === "object" && "tenantId" in value,
    )) {
      const name = getTableName(table as never);
      const tenantColumn = table.tenantId as { notNull?: boolean };
      if (name in HYBRID_SCOPE_TABLES) expect(tenantColumn.notNull).toBe(false);
      else expect(tenantColumn.notNull).toBe(true);
    }
    for (const rationale of [
      ...Object.values(INDIRECT_TENANT_TABLES),
      ...Object.values(TENANT_COLUMN_BACKFILL_TABLES),
      ...Object.values(HYBRID_SCOPE_TABLES),
      ...Object.values(BOOTSTRAP_ROOT_TABLES),
      ...Object.values(INTENTIONALLY_GLOBAL_TABLES),
    ]) {
      expect(rationale.length).toBeGreaterThan(20);
    }
  });
});
