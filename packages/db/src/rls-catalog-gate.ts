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

export const CORE_RLS_EXCLUDED_TABLES = [...Object.keys(INTENTIONALLY_GLOBAL_TABLES)].sort();

export interface RlsCatalogInventory {
  protectedTables: readonly string[];
  rlsExcludedTables: readonly string[];
}

export interface RlsCatalogInventoryContribution {
  owner: string;
  protectedTables?: readonly string[];
  rlsExcludedTables?: readonly string[];
}

export const AUTH_RLS_CATALOG_INVENTORY_CONTRIBUTION: RlsCatalogInventoryContribution = {
  owner: "@stwd/auth",
  // This compatibility store exists only when auth uses PostgreSQL. It has no
  // tenant column; tenant binding lives in opaque, namespaced keys.
  rlsExcludedTables: ["auth_kv_store"],
};

export const CORE_RLS_CATALOG_INVENTORY: RlsCatalogInventory = {
  protectedTables: RLS_ACTIVATION_TABLES,
  rlsExcludedTables: CORE_RLS_EXCLUDED_TABLES,
};

const POSTGRES_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const INVENTORY_OWNER = /^[@A-Za-z0-9_./-]{1,128}$/;

function normalizeRlsCatalogInventory(
  ...inventories: readonly RlsCatalogInventory[]
): RlsCatalogInventory {
  const protectedTables = inventories.flatMap((inventory) => [...inventory.protectedTables]);
  const rlsExcludedTables = inventories.flatMap((inventory) => [...inventory.rlsExcludedTables]);
  const all = [...protectedTables, ...rlsExcludedTables];
  const invalid = all.filter((table) => !POSTGRES_IDENTIFIER.test(table));
  const duplicates = all.filter((table, index) => all.indexOf(table) !== index);
  if (invalid.length || duplicates.length) {
    fail("RLS_CATALOG_INVENTORY_INVALID", [
      ...invalid.map((table) => `invalid:${table}`),
      ...duplicates.map((table) => `duplicate:${table}`),
    ]);
  }
  return {
    protectedTables: [...protectedTables].sort(),
    rlsExcludedTables: [...rlsExcludedTables].sort(),
  };
}

export function composeRlsCatalogInventory(
  contributions: readonly RlsCatalogInventoryContribution[] = [],
): RlsCatalogInventory {
  const invalidOwners = contributions
    .filter((contribution) => !INVENTORY_OWNER.test(contribution.owner))
    .map(() => "owner:invalid");
  if (invalidOwners.length) fail("RLS_CATALOG_INVENTORY_INVALID", invalidOwners);
  const claims = new Map<string, string>(
    [
      ...CORE_RLS_CATALOG_INVENTORY.protectedTables,
      ...CORE_RLS_CATALOG_INVENTORY.rlsExcludedTables,
    ].map((table) => [table, "steward-core"] as const),
  );
  const duplicateClaims: string[] = [];
  for (const contribution of contributions) {
    for (const table of [
      ...(contribution.protectedTables ?? []),
      ...(contribution.rlsExcludedTables ?? []),
    ]) {
      const priorOwner = claims.get(table);
      if (priorOwner)
        duplicateClaims.push(`duplicate:${table}:${priorOwner}/${contribution.owner}`);
      else claims.set(table, contribution.owner);
    }
  }
  if (duplicateClaims.length) fail("RLS_CATALOG_INVENTORY_INVALID", duplicateClaims);
  return normalizeRlsCatalogInventory(
    CORE_RLS_CATALOG_INVENTORY,
    ...contributions.map((contribution) => ({
      protectedTables: contribution.protectedTables ?? [],
      rlsExcludedTables: contribution.rlsExcludedTables ?? [],
    })),
  );
}

export interface RlsCatalogRow {
  relation_oid: string;
  table_name: string;
  table_schema: string;
  partition_root_oid: string | null;
  partition_root: string | null;
  partition_root_schema: string | null;
  rls_enabled: boolean;
  rls_forced: boolean;
  policy_count: number;
  owned_by_runtime_role: boolean;
  owner_privileges_available_to_runtime: boolean;
  runtime_can_assume_superuser: boolean;
  runtime_can_assume_bypassrls: boolean;
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

export interface InspectRlsCatalogOptions {
  schema?: string;
  runtimeRole: string;
  inventoryContributions?: readonly RlsCatalogInventoryContribution[];
}

const CATALOG_QUERY = `
WITH runtime_role AS (
  SELECT oid
    FROM pg_catalog.pg_roles
   WHERE rolname = $2
), assumable_roles AS (
  SELECT candidate.oid, candidate.rolsuper, candidate.rolbypassrls
    FROM pg_catalog.pg_roles candidate
    CROSS JOIN runtime_role runtime
   WHERE candidate.oid = runtime.oid
      OR pg_catalog.pg_has_role(runtime.oid, candidate.oid, 'SET')
), usable_roles AS (
  SELECT candidate.oid
    FROM pg_catalog.pg_roles candidate
    CROSS JOIN runtime_role runtime
   WHERE candidate.oid = runtime.oid
      OR pg_catalog.pg_has_role(runtime.oid, candidate.oid, 'USAGE')
), target_roots AS (
  SELECT relation.oid, relation.relkind
    FROM pg_catalog.pg_class relation
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
   WHERE namespace.nspname = $1
     AND relation.relkind IN ('r', 'p')
     AND NOT relation.relispartition
), catalog_relations AS (
  SELECT root.oid AS root_oid, root.oid AS child_oid
    FROM target_roots root
  UNION
  SELECT root.oid AS root_oid, tree.relid AS child_oid
    FROM target_roots root
    CROSS JOIN LATERAL pg_catalog.pg_partition_tree(root.oid) tree
   WHERE root.relkind = 'p'
  UNION
  SELECT pg_catalog.pg_partition_root(child.oid) AS root_oid, child.oid AS child_oid
    FROM pg_catalog.pg_class child
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = child.relnamespace
   WHERE namespace.nspname = $1
     AND child.relispartition
)
SELECT
  child.oid::text AS relation_oid,
  child.relname AS table_name,
  child_namespace.nspname AS table_schema,
  CASE WHEN child.relispartition THEN root.oid::text ELSE NULL END AS partition_root_oid,
  CASE WHEN child.relispartition THEN root.relname ELSE NULL END AS partition_root,
  CASE WHEN child.relispartition THEN root_namespace.nspname ELSE NULL END
    AS partition_root_schema,
  child.relrowsecurity AS rls_enabled,
  child.relforcerowsecurity AS rls_forced,
  (SELECT count(*)::int FROM pg_catalog.pg_policy p WHERE p.polrelid = child.oid) AS policy_count,
  child.relowner = runtime.oid AS owned_by_runtime_role,
  EXISTS (
    SELECT 1 FROM usable_roles usable WHERE usable.oid = child.relowner
    UNION ALL
    SELECT 1 FROM assumable_roles assumable WHERE assumable.oid = child.relowner
  ) AS owner_privileges_available_to_runtime,
  COALESCE((SELECT bool_or(role.rolsuper) FROM assumable_roles role), false)
    AS runtime_can_assume_superuser,
  COALESCE((SELECT bool_or(role.rolbypassrls) FROM assumable_roles role), false)
    AS runtime_can_assume_bypassrls
FROM catalog_relations relation
JOIN pg_catalog.pg_class child ON child.oid = relation.child_oid
JOIN pg_catalog.pg_namespace child_namespace ON child_namespace.oid = child.relnamespace
CROSS JOIN runtime_role runtime
JOIN pg_catalog.pg_class root ON root.oid = relation.root_oid
JOIN pg_catalog.pg_namespace root_namespace ON root_namespace.oid = root.relnamespace
ORDER BY child_namespace.nspname, child.relname`;

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
  inventory: RlsCatalogInventory = CORE_RLS_CATALOG_INVENTORY,
  schema = "public",
): RlsCatalogAssessment {
  const normalizedInventory = normalizeRlsCatalogInventory(inventory);
  const protectedSet = new Set(normalizedInventory.protectedTables);
  const excludedSet = new Set(normalizedInventory.rlsExcludedTables);
  const inventorySet = new Set([...protectedSet, ...excludedSet]);
  const ordinaryRows = rows.filter((row) => row.partition_root === null);
  const partitions = rows.filter((row) => row.partition_root !== null);
  const protectedRootOids = new Set(
    ordinaryRows.filter((row) => protectedSet.has(row.table_name)).map((row) => row.relation_oid),
  );
  const actual = new Set(ordinaryRows.map((row) => row.table_name));
  const missing = [...inventorySet].filter((table) => !actual.has(table));
  const unknown = [...actual].filter(
    (table) => !inventorySet.has(table) && table !== "__steward_migrations",
  );
  const orphanPartitions = partitions
    .filter(
      (row) =>
        !row.partition_root_oid ||
        !protectedRootOids.has(row.partition_root_oid) ||
        row.partition_root_schema !== schema,
    )
    .map((row) => row.table_name);
  if (missing.length || unknown.length || orphanPartitions.length) {
    fail("RLS_CATALOG_INVENTORY_MISMATCH", [
      ...missing.map((name) => `missing:${name}`),
      ...unknown.map((name) => `unknown:${name}`),
      ...orphanPartitions.map((name) => `partition:${name}`),
    ]);
  }

  const excludedRls = ordinaryRows
    .filter((row) => excludedSet.has(row.table_name) && (row.rls_enabled || row.rls_forced))
    .map((row) => row.table_name);
  if (excludedRls.length) fail("RLS_CATALOG_EXCLUDED_TABLE_PROTECTED", excludedRls);

  const protectedRows = ordinaryRows.filter((row) => protectedSet.has(row.table_name));
  const activationRows = [...protectedRows, ...partitions];
  const anyEnabled = activationRows.some((row) => row.rls_enabled || row.rls_forced);
  const staged = protectedRows.some((row) => row.policy_count > 0);
  const policiesComplete = protectedRows.every((row) => row.policy_count > 0);

  const unsafeRole = activationRows[0];
  if (
    unsafeRole?.runtime_can_assume_superuser ||
    unsafeRole?.runtime_can_assume_bypassrls ||
    activationRows.some((row) => row.owner_privileges_available_to_runtime)
  ) {
    fail(
      "RLS_CATALOG_UNSAFE_APPLICATION_ROLE",
      [
        unsafeRole?.runtime_can_assume_superuser ? "superuser" : "",
        unsafeRole?.runtime_can_assume_bypassrls ? "bypassrls" : "",
        ...activationRows
          .filter((row) => row.owner_privileges_available_to_runtime)
          .map((row) =>
            row.owned_by_runtime_role ? `owner:${row.table_name}` : `owner-role:${row.table_name}`,
          ),
      ].filter(Boolean),
    );
  }

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

  return {
    state: "active",
    policyCoverageComplete: true,
    protectedTableCount: protectedRows.length,
    partitionCount: partitions.length,
  };
}

export async function inspectRlsCatalog(
  client: RlsCatalogClient,
  options: InspectRlsCatalogOptions,
): Promise<RlsCatalogAssessment> {
  const schema = options.schema ?? "public";
  if (!POSTGRES_IDENTIFIER.test(schema)) {
    throw new Error("RLS_CATALOG_SCHEMA_INVALID");
  }
  if (!POSTGRES_IDENTIFIER.test(options.runtimeRole)) {
    throw new Error("RLS_CATALOG_RUNTIME_ROLE_INVALID");
  }
  const rows = await client.unsafe(CATALOG_QUERY, [schema, options.runtimeRole]);
  if (rows.length === 0) throw new Error("RLS_CATALOG_RUNTIME_ROLE_OR_SCHEMA_MISSING");
  return assessRlsCatalogSnapshot(
    rows,
    composeRlsCatalogInventory(options.inventoryContributions),
    schema,
  );
}

// Compile-time/runtime evidence that the activation and global sets still
// cover the inventory; the inventory test provides the schema-table proof.
if (
  new Set([...RLS_ACTIVATION_TABLES, ...Object.keys(INTENTIONALLY_GLOBAL_TABLES)]).size !==
  ALL_INVENTORIED_TABLES.length
) {
  throw new Error("RLS_CATALOG_STATIC_INVENTORY_MISMATCH");
}
