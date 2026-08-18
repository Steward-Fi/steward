import { describe, expect, test } from "bun:test";
import { getTableName, is, Table } from "drizzle-orm";
import {
  ALL_INVENTORIED_TABLES,
  DIRECT_TENANT_TABLES,
  HYBRID_SCOPE_TABLES,
} from "../rls-inventory";
import * as schema from "../schema";
import * as authSchema from "../schema-auth";

function schemaTableNames(): string[] {
  return [
    ...new Set(
      Object.values({ ...schema, ...authSchema })
        .filter((value): value is Table => is(value, Table))
        .map((table) => getTableName(table)),
    ),
  ].sort();
}

describe("SEC-169 RLS inventory", () => {
  test("classifies every schema table exactly once", () => {
    const inventory = [...ALL_INVENTORIED_TABLES].sort();
    expect(inventory).toEqual([...new Set(inventory)]);
    expect(inventory).toEqual(schemaTableNames());
  });

  test("direct tables expose tenantId and hybrid tenant columns are nullable", () => {
    const tables = Object.values({ ...schema, ...authSchema }).filter(
      (value): value is Table & Record<string, unknown> => is(value, Table),
    );
    const directNames = tables
      .filter((table) => table && typeof table === "object" && "tenantId" in table)
      .map((table) => getTableName(table))
      .filter((name): name is string => typeof name === "string")
      .sort();
    expect([...DIRECT_TENANT_TABLES, ...Object.keys(HYBRID_SCOPE_TABLES)].sort()).toEqual(
      directNames,
    );
    for (const table of tables.filter(
      (value) => value && typeof value === "object" && "tenantId" in value,
    )) {
      const name = getTableName(table);
      const tenantColumn = table.tenantId as { notNull?: boolean };
      if (name in HYBRID_SCOPE_TABLES) expect(tenantColumn.notNull).toBe(false);
      else expect(tenantColumn.notNull).toBe(true);
    }
  });
});
