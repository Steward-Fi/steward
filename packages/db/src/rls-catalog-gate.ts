import {
  ALL_INVENTORIED_TABLES,
  BOOTSTRAP_ROOT_TABLES,
  DIRECT_TENANT_TABLES,
  HYBRID_SCOPE_TABLES,
  INDIRECT_TENANT_TABLES,
  INTENTIONALLY_GLOBAL_TABLES,
  TENANT_COLUMN_BACKFILL_TABLES,
} from "./rls-inventory";

export const RLS_ACTIVATION_TABLES = [
  ...DIRECT_TENANT_TABLES,
  ...Object.keys(INDIRECT_TENANT_TABLES),
  ...Object.keys(TENANT_COLUMN_BACKFILL_TABLES),
  ...Object.keys(HYBRID_SCOPE_TABLES),
  ...Object.keys(BOOTSTRAP_ROOT_TABLES),
].sort();

export interface RlsCatalogRow {
  table_name: string;
  partition_root: string | null;
  rls_enabled: boolean;
  rls_forced: boolean;
  policy_count: number;
  owned_by_current_role: boolean;
  role_super: boolean;
  role_bypass_rls: boolean;
}

export interface RlsCatalogAssessment {
  state: "inactive" | "policies-staged" | "active";
  policyCoverageComplete: boolean;
  protectedTableCount: number;
  partitionCount: number;
}

export interface RlsCatalogClient {
  unsafe(query: string, parameters: unknown[]): Promise<RlsCatalogRow[]>;
}

const CATALOG_QUERY = `
SELECT
  child.relname AS table_name,
  CASE WHEN child.relispartition THEN root.relname ELSE NULL END AS partition_root,
  child.relrowsecurity AS rls_enabled,
  child.relforcerowsecurity AS rls_forced,
  (SELECT count(*)::int FROM pg_catalog.pg_policy p WHERE p.polrelid = child.oid) AS policy_count,
  child.relowner = current_role_row.oid AS owned_by_current_role,
  current_role_row.rolsuper AS role_super,
  current_role_row.rolbypassrls AS role_bypass_rls
FROM pg_catalog.pg_class child
JOIN pg_catalog.pg_namespace namespace ON namespace.oid = child.relnamespace
JOIN pg_catalog.pg_roles current_role_row ON current_role_row.rolname = current_user
LEFT JOIN pg_catalog.pg_class root ON root.oid = pg_catalog.pg_partition_root(child.oid)
WHERE namespace.nspname = $1
  AND child.relkind IN ('r', 'p')
ORDER BY child.relname`;

function fail(code: string, details: string[]): never {
  throw new Error(`${code}: ${details.sort().join(",")}`);
}

/**
 * Assess a catalog snapshot without changing it. The activation invariant is
 * all-or-nothing: policies may be staged while every table remains disabled,
 * but once any table is enabled, every protected table and partition must be
 * ENABLE+FORCE in the same snapshot. This structural gate deliberately does
 * not claim that staged policy expressions are semantically correct; the
 * policy generator and cross-tenant proofs remain separate activation gates.
 */
export function assessRlsCatalogSnapshot(
  rows: RlsCatalogRow[],
  expectedProtected: readonly string[] = RLS_ACTIVATION_TABLES,
  expectedGlobal: readonly string[] = Object.keys(INTENTIONALLY_GLOBAL_TABLES),
): RlsCatalogAssessment {
  const protectedSet = new Set(expectedProtected);
  const globalSet = new Set(expectedGlobal);
  const inventorySet = new Set([...protectedSet, ...globalSet]);
  const ordinaryRows = rows.filter((row) => row.partition_root === null);
  const partitions = rows.filter((row) => row.partition_root !== null);
  const actual = new Set(ordinaryRows.map((row) => row.table_name));
  const missing = [...inventorySet].filter((table) => !actual.has(table));
  const unknown = [...actual].filter(
    (table) => !inventorySet.has(table) && table !== "__steward_migrations",
  );
  const orphanPartitions = partitions
    .filter((row) => !row.partition_root || !protectedSet.has(row.partition_root))
    .map((row) => row.table_name);
  if (missing.length || unknown.length || orphanPartitions.length) {
    fail("RLS_CATALOG_INVENTORY_MISMATCH", [
      ...missing.map((name) => `missing:${name}`),
      ...unknown.map((name) => `unknown:${name}`),
      ...orphanPartitions.map((name) => `partition:${name}`),
    ]);
  }

  const globalRls = ordinaryRows
    .filter((row) => globalSet.has(row.table_name) && (row.rls_enabled || row.rls_forced))
    .map((row) => row.table_name);
  if (globalRls.length) fail("RLS_CATALOG_GLOBAL_TABLE_PROTECTED", globalRls);

  const protectedRows = ordinaryRows.filter((row) => protectedSet.has(row.table_name));
  const activationRows = [...protectedRows, ...partitions];
  const anyEnabled = activationRows.some((row) => row.rls_enabled || row.rls_forced);
  const staged = protectedRows.some((row) => row.policy_count > 0);
  const policiesComplete = protectedRows.every((row) => row.policy_count > 0);

  if (!anyEnabled) {
    return {
      state: staged ? "policies-staged" : "inactive",
      policyCoverageComplete: policiesComplete,
      protectedTableCount: protectedRows.length,
      partitionCount: partitions.length,
    };
  }

  const incomplete = activationRows
    .filter((row) => !row.rls_enabled || !row.rls_forced)
    .map((row) => row.table_name);
  const missingPolicies = protectedRows
    .filter((row) => row.policy_count === 0)
    .map((row) => row.table_name);
  if (incomplete.length || missingPolicies.length) {
    fail("RLS_CATALOG_PARTIAL_ACTIVATION", [
      ...incomplete.map((name) => `flags:${name}`),
      ...missingPolicies.map((name) => `policy:${name}`),
    ]);
  }

  const unsafeRole = protectedRows[0];
  if (
    unsafeRole?.role_super ||
    unsafeRole?.role_bypass_rls ||
    protectedRows.some((row) => row.owned_by_current_role)
  ) {
    fail(
      "RLS_CATALOG_UNSAFE_APPLICATION_ROLE",
      [
        unsafeRole?.role_super ? "superuser" : "",
        unsafeRole?.role_bypass_rls ? "bypassrls" : "",
        ...protectedRows
          .filter((row) => row.owned_by_current_role)
          .map((row) => `owner:${row.table_name}`),
      ].filter(Boolean),
    );
  }

  return {
    state: "active",
    policyCoverageComplete: true,
    protectedTableCount: protectedRows.length,
    partitionCount: partitions.length,
  };
}

export async function inspectRlsCatalog(
  client: RlsCatalogClient,
  schema = "public",
): Promise<RlsCatalogAssessment> {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(schema)) {
    throw new Error("RLS_CATALOG_SCHEMA_INVALID");
  }
  const rows = await client.unsafe(CATALOG_QUERY, [schema]);
  return assessRlsCatalogSnapshot(rows);
}

// Compile-time/runtime evidence that the activation and global sets still
// cover the inventory; the inventory test provides the schema-table proof.
if (
  new Set([...RLS_ACTIVATION_TABLES, ...Object.keys(INTENTIONALLY_GLOBAL_TABLES)]).size !==
  ALL_INVENTORIED_TABLES.length
) {
  throw new Error("RLS_CATALOG_STATIC_INVENTORY_MISMATCH");
}
