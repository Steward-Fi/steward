import { sql } from "drizzle-orm";
import {
  EXPECTED_PUBLIC_RELATIONS,
  EXPECTED_RLS_POLICY_DEFINITIONS,
} from "./rls-policy-manifest.generated";

type SqlDatabase = { execute(query: unknown): Promise<unknown> };

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: T[] })?.rows ?? [])) as T[];
}

function stable(value: unknown): string {
  return JSON.stringify(value);
}

/**
 * Load-bearing production gate for the SEC-169 deployment role and catalog.
 * It deliberately runs through the exact application connection before traffic
 * is served; operator scripts and migration-role checks are not substitutes.
 */
export async function assertRlsDeploymentSafety(
  db: SqlDatabase,
  options: { expectedRole: string; requireActivated?: boolean },
): Promise<void> {
  if (!/^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/.test(options.expectedRole)) {
    throw new Error("RLS_DEPLOYMENT_ROLE_EXPECTATION_INVALID");
  }
  const [role] = rowsOf<{
    current_user: string;
    session_user: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
    owns_rls_relation: boolean;
  }>(
    await db.execute(sql`
      SELECT current_user::text, session_user::text, role.rolsuper, role.rolbypassrls,
        EXISTS (
          SELECT 1 FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'public'
            AND relation.relname = ANY(${[...new Set(EXPECTED_RLS_POLICY_DEFINITIONS.map((p) => p.relation_name))]})
            AND relation.relowner = role.oid
        ) AS owns_rls_relation
      FROM pg_roles role WHERE role.rolname = current_user
    `),
  );
  if (
    !role ||
    role.current_user !== options.expectedRole ||
    role.session_user !== options.expectedRole ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.owns_rls_relation
  ) {
    throw new Error("RLS_DEPLOYMENT_ROLE_UNSAFE");
  }

  const relations = rowsOf<{
    relation_name: string;
    relation_kind: string;
    partition_parents: string;
    relrowsecurity: boolean;
    relforcerowsecurity: boolean;
  }>(
    await db.execute(sql`
      SELECT relation.relname AS relation_name, relation.relkind::text AS relation_kind,
        COALESCE(string_agg(parent.relname, ',' ORDER BY parent.relname), '') AS partition_parents,
        relation.relrowsecurity, relation.relforcerowsecurity
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      LEFT JOIN pg_inherits inherit ON inherit.inhrelid = relation.oid
      LEFT JOIN pg_class parent ON parent.oid = inherit.inhparent
      LEFT JOIN pg_namespace parent_namespace ON parent_namespace.oid = parent.relnamespace
      WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p')
        AND (parent.oid IS NULL OR parent_namespace.nspname = 'public')
      GROUP BY relation.relname, relation.relkind, relation.relrowsecurity,
               relation.relforcerowsecurity
      ORDER BY relation.relname
    `),
  );
  const optionalGroupsPresent = new Set(
    EXPECTED_PUBLIC_RELATIONS.filter(
      (expected) =>
        expected.policy_group !== "core" &&
        relations.some((actual) => actual.relation_name === expected.relation_name),
    ).map((expected) => expected.policy_group),
  );
  const enabledGroups = new Set(["core", ...optionalGroupsPresent]);
  const expectedRelations = EXPECTED_PUBLIC_RELATIONS.filter((row) =>
    enabledGroups.has(row.policy_group),
  );
  const expectedPolicies = EXPECTED_RLS_POLICY_DEFINITIONS.filter((row) =>
    enabledGroups.has(row.policy_group),
  );
  const relationShape = relations.map(
    ({ relrowsecurity: _enabled, relforcerowsecurity: _forced, ...row }) => row,
  );
  const comparableRelations = expectedRelations.map(({ policy_group: _group, ...row }) => row);
  if (stable(relationShape) !== stable(comparableRelations)) {
    throw new Error("RLS_DEPLOYMENT_RELATION_INVENTORY_DRIFT");
  }
  if (options.requireActivated !== false) {
    const protectedRelations = new Set<string>(
      expectedPolicies.map((policy) => policy.relation_name),
    );
    if (
      relations.some(
        (relation) =>
          protectedRelations.has(relation.relation_name) &&
          (!relation.relrowsecurity || !relation.relforcerowsecurity),
      )
    ) {
      throw new Error("RLS_DEPLOYMENT_NOT_ENABLED_AND_FORCED");
    }
  }

  const policies = rowsOf<{
    relation_name: string;
    policy_name: string;
    command: string;
    permissive: boolean;
    roles: string;
    using_expression: string | null;
    check_expression: string | null;
  }>(
    await db.execute(sql`
      SELECT relation.relname AS relation_name, policy.polname AS policy_name,
        policy.polcmd::text AS command, policy.polpermissive AS permissive,
        CASE WHEN policy.polroles = ARRAY[0::oid] THEN 'PUBLIC'
             ELSE array_to_string(ARRAY(
               SELECT role.rolname FROM pg_roles role
               WHERE role.oid = ANY(policy.polroles) ORDER BY role.rolname
             ), ',') END AS roles,
        pg_get_expr(policy.polqual, policy.polrelid) AS using_expression,
        pg_get_expr(policy.polwithcheck, policy.polrelid) AS check_expression
      FROM pg_policy policy
      JOIN pg_class relation ON relation.oid = policy.polrelid
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public'
        AND policy.polname <> 'steward_migration_maintenance'
      ORDER BY relation.relname, policy.polname
    `),
  );
  const comparablePolicies = expectedPolicies.map(({ policy_group: _group, ...row }) => row);
  if (stable(policies) !== stable(comparablePolicies)) {
    throw new Error("RLS_DEPLOYMENT_POLICY_DEFINITION_DRIFT");
  }
}
