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
  options: { expectedRole: string; expectedPlatformRole: string; requireActivated?: boolean },
): Promise<void> {
  const roleName = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;
  if (!roleName.test(options.expectedRole) || !roleName.test(options.expectedPlatformRole)) {
    throw new Error("RLS_DEPLOYMENT_ROLE_EXPECTATION_INVALID");
  }
  const [role] = rowsOf<{
    current_user: string;
    session_user: string;
    rolcanlogin: boolean;
    rolinherit: boolean;
    rolsuper: boolean;
    rolbypassrls: boolean;
    rolcreatedb: boolean;
    rolcreaterole: boolean;
    rolreplication: boolean;
    owns_rls_relation: boolean;
    has_assumable_privilege: boolean;
    can_create_protected_schema: boolean;
    platform_role_safe: boolean;
  }>(
    await db.execute(sql`
      SELECT current_user::text, session_user::text, role.rolcanlogin, role.rolinherit,
        role.rolsuper, role.rolbypassrls, role.rolcreatedb, role.rolcreaterole,
        role.rolreplication,
        EXISTS (
          SELECT 1 FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'public'
            AND relation.relname = ANY(${[...new Set(EXPECTED_RLS_POLICY_DEFINITIONS.map((p) => p.relation_name))]})
            AND relation.relowner = role.oid
        ) AS owns_rls_relation,
        EXISTS (
          SELECT 1 FROM pg_roles privileged
          WHERE privileged.oid <> role.oid
            AND pg_has_role(session_user, privileged.oid, 'MEMBER')
            AND (privileged.rolsuper OR privileged.rolbypassrls OR privileged.rolcreatedb
              OR privileged.rolcreaterole OR privileged.rolreplication)
        ) AS has_assumable_privilege,
        EXISTS (
          SELECT 1 FROM pg_roles candidate
          CROSS JOIN pg_namespace namespace
          WHERE namespace.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
            AND pg_has_role(session_user, candidate.oid, 'MEMBER')
            AND (candidate.oid = namespace.nspowner
              OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))
        ) AS can_create_protected_schema,
        EXISTS (
          SELECT 1 FROM pg_roles platform
          WHERE platform.rolname = ${options.expectedPlatformRole}
            AND platform.rolcanlogin AND NOT platform.rolinherit
            AND NOT platform.rolsuper AND NOT platform.rolbypassrls
            AND NOT platform.rolcreatedb AND NOT platform.rolcreaterole
            AND NOT platform.rolreplication
            AND NOT pg_has_role(${options.expectedRole}, platform.oid, 'MEMBER')
            AND NOT pg_has_role(${options.expectedPlatformRole}, role.oid, 'MEMBER')
            AND NOT EXISTS (
              SELECT 1 FROM pg_class relation
              JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p')
                AND relation.relowner = platform.oid
            )
        ) AS platform_role_safe
      FROM pg_roles role WHERE role.rolname = current_user
    `),
  );
  if (
    !role ||
    role.current_user !== options.expectedRole ||
    role.session_user !== options.expectedRole ||
    !role.rolcanlogin ||
    role.rolinherit ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcreatedb ||
    role.rolcreaterole ||
    role.rolreplication ||
    role.owns_rls_relation ||
    role.has_assumable_privilege ||
    role.can_create_protected_schema ||
    !role.platform_role_safe
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

  const helperDrift = rowsOf<{ function_name: string }>(
    await db.execute(sql`
      SELECT function.proname::text AS function_name
      FROM pg_proc function
      JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
      JOIN pg_language language ON language.oid = function.prolang
      WHERE namespace.nspname = 'steward_rls'
        AND function.proname IN ('tenant_id', 'user_id')
        AND (
          function.prosecdef OR function.provolatile <> 's' OR function.proparallel <> 's'
          OR language.lanname <> 'sql'
          OR pg_get_function_identity_arguments(function.oid) <> ''
          OR function.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[]
          OR btrim(function.prosrc, E' \t\n\r') <> CASE function.proname
            WHEN 'tenant_id' THEN 'SELECT NULLIF(current_setting(''steward.tenant_id'', true), '''')'
            ELSE 'SELECT NULLIF(current_setting(''steward.user_id'', true), '''')::uuid'
          END
        )
      UNION ALL
      SELECT 'helper_count'
      WHERE (
        SELECT count(*) FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        WHERE namespace.nspname = 'steward_rls'
          AND function.proname IN ('tenant_id', 'user_id')
      ) <> 2
    `),
  );
  if (helperDrift.length > 0) throw new Error("RLS_DEPLOYMENT_HELPER_DRIFT");

  const aclDrift = rowsOf<{ object_name: string }>(
    await db.execute(sql`
      WITH functions AS (
        SELECT function.oid, namespace.nspname, function.proname,
          function.proname IN (
            'platform_set_user_deactivation', 'platform_delete_user',
            'platform_revoke_user_refresh_tokens', 'retention_delete_deactivated_users'
          ) AS destructive
        FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        WHERE namespace.nspname IN ('steward_bootstrap', 'steward_rls')
      ), function_drift AS (
        SELECT format('%I.%I', nspname, proname) AS object_name
        FROM functions
        WHERE has_function_privilege('PUBLIC', oid, 'EXECUTE')
          OR has_function_privilege(${options.expectedRole}, oid, 'EXECUTE') <>
            (nspname = 'steward_rls' OR NOT destructive)
          OR has_function_privilege(${options.expectedPlatformRole}, oid, 'EXECUTE') <>
            ((nspname = 'steward_rls' AND proname = 'tenant_id')
              OR (nspname = 'steward_bootstrap' AND destructive))
      ), schema_drift AS (
        SELECT namespace.nspname::text AS object_name
        FROM pg_namespace namespace
        WHERE namespace.nspname IN ('steward_bootstrap', 'steward_rls')
          AND (
            NOT has_schema_privilege(${options.expectedRole}, namespace.oid, 'USAGE')
            OR has_schema_privilege(${options.expectedRole}, namespace.oid, 'CREATE')
            OR NOT has_schema_privilege(${options.expectedPlatformRole}, namespace.oid, 'USAGE')
            OR has_schema_privilege(${options.expectedPlatformRole}, namespace.oid, 'CREATE')
          )
      )
      SELECT object_name FROM function_drift
      UNION ALL SELECT object_name FROM schema_drift
      ORDER BY object_name
    `),
  );
  if (aclDrift.length > 0) throw new Error("RLS_DEPLOYMENT_ACL_DRIFT");
}
