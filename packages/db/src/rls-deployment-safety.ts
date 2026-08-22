import { sql } from "drizzle-orm";
import { EXPECTED_RLS_FUNCTION_DEFINITIONS } from "./rls-function-manifest";
import {
  EXPECTED_PUBLIC_RELATIONS,
  EXPECTED_RLS_POLICY_DEFINITIONS,
} from "./rls-policy-manifest.generated";

type SqlDatabase = { execute(query: unknown): Promise<unknown> };

const APP_EXECUTABLE_FUNCTIONS = [
  "steward_rls.tenant_id()",
  "steward_rls.user_id()",
  "steward_bootstrap.agent_subject(text,text,text)",
  "steward_bootstrap.agent_tenant_subject(text)",
  "steward_bootstrap.app_client_subject(text,text)",
  "steward_bootstrap.auth_app_clients_subject(text)",
  "steward_bootstrap.auth_refresh_subject(text)",
  "steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamp with time zone)",
  "steward_bootstrap.auth_sso_discovery_subject(text)",
  "steward_bootstrap.auth_sso_domain_subject(text,text)",
  "steward_bootstrap.auth_tenant_config_subject(text)",
  "steward_bootstrap.auth_tenant_subject(text,uuid)",
  "steward_bootstrap.ensure_default_membership(uuid,text)",
  "steward_bootstrap.ensure_default_tenant(text)",
  "steward_bootstrap.ensure_platform_tenant()",
  "steward_bootstrap.ensure_system_tenant()",
  "steward_bootstrap.session_subject(uuid,text)",
  "steward_bootstrap.tenant_api_key_subject(text)",
  "steward_bootstrap.user_token_revocation_subject(uuid)",
] as const;

const PLATFORM_EXECUTABLE_FUNCTIONS = [
  "steward_rls.tenant_id()",
  "steward_bootstrap.platform_delete_user(uuid)",
  "steward_bootstrap.platform_personal_tenant_delete(text,boolean)",
  "steward_bootstrap.platform_provision_user(text,boolean,text,jsonb)",
  "steward_bootstrap.platform_revoke_user_refresh_tokens(uuid)",
  "steward_bootstrap.platform_set_user_deactivation(uuid,boolean)",
  "steward_bootstrap.platform_user_tenant_ids(uuid)",
  "steward_bootstrap.platform_user_identity(uuid)",
  "steward_bootstrap.platform_stats()",
  "steward_bootstrap.platform_tenants(integer,integer)",
  "steward_bootstrap.retention_delete_deactivated_users(integer)",
  "steward_bootstrap.tenant_ids_for_internal_job()",
] as const;

const PERSONAL_LIFECYCLE_LOCK_FUNCTION = "steward_lock_personal_lifecycle(uuid,text,boolean)";
const APP_PUBLIC_EXECUTABLE_FUNCTIONS = [
  "steward_is_authoritative_wallet_identity(text,text,text,text)",
  "steward_is_authoritative_wallet_tenant_owner(text,uuid)",
  "steward_is_reserved_tenant_id(text)",
  "steward_lock_tenant_deletion(text)",
  PERSONAL_LIFECYCLE_LOCK_FUNCTION,
  "steward_reserved_tenant_kind(text)",
] as const;
const APP_USERS_INSERT_COLUMNS = [
  "created_at",
  "custom_metadata",
  "email",
  "email_verified",
  "guest_expires_at",
  "id",
  "image",
  "is_guest",
  "name",
  "steward_wallet_id",
  "updated_at",
  "wallet_address",
  "wallet_chain",
] as const;
const APP_USERS_UPDATE_COLUMNS = [
  "custom_metadata",
  "email",
  "email_verified",
  "guest_expires_at",
  "image",
  "is_guest",
  "name",
  "steward_wallet_id",
  "updated_at",
  "wallet_address",
  "wallet_chain",
] as const;

export const EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION = {
  identity: PERSONAL_LIFECYCLE_LOCK_FUNCTION,
  result: "TABLE(user_exists boolean, tenant_exists boolean)",
  language: "plpgsql",
  volatility: "v",
  parallelism: "u",
  securityDefiner: false,
  settings: "",
  argumentDefaults: "false",
  bodyMd5: "fa9e1a06071746fd3b29dbc4db3706ad",
} as const;

const EXPECTED_PLATFORM_NAMED_ACLS = [
  "function:steward_bootstrap.platform_delete_user(uuid):EXECUTE:false",
  "function:steward_bootstrap.platform_personal_tenant_delete(text,boolean):EXECUTE:false",
  "function:steward_bootstrap.platform_provision_user(text,boolean,text,jsonb):EXECUTE:false",
  "function:steward_bootstrap.platform_revoke_user_refresh_tokens(uuid):EXECUTE:false",
  "function:steward_bootstrap.platform_set_user_deactivation(uuid,boolean):EXECUTE:false",
  "function:steward_bootstrap.platform_stats():EXECUTE:false",
  "function:steward_bootstrap.platform_tenants(integer,integer):EXECUTE:false",
  "function:steward_bootstrap.platform_user_identity(uuid):EXECUTE:false",
  "function:steward_bootstrap.platform_user_tenant_ids(uuid):EXECUTE:false",
  "function:steward_bootstrap.retention_delete_deactivated_users(integer):EXECUTE:false",
  "function:steward_bootstrap.tenant_ids_for_internal_job():EXECUTE:false",
  "function:steward_rls.tenant_id():EXECUTE:false",
  "relation:public.audit_chain_heads:INSERT:false",
  "relation:public.audit_chain_heads:SELECT:false",
  "relation:public.audit_chain_heads:UPDATE:false",
  "relation:public.audit_events:INSERT:false",
  "relation:public.audit_events:SELECT:false",
  "relation:public.audit_events_id_seq:SELECT:false",
  "relation:public.audit_events_id_seq:USAGE:false",
  "relation:public.user_tenants:SELECT:false",
  "relation:public.users:SELECT:false",
  "schema:steward_bootstrap:USAGE:false",
  "schema:steward_rls:USAGE:false",
] as const;

const KNOWN_BOOTSTRAP_FUNCTIONS = [
  ...APP_EXECUTABLE_FUNCTIONS.filter((name) => name.startsWith("steward_bootstrap.")),
  ...PLATFORM_EXECUTABLE_FUNCTIONS.filter((name) => name.startsWith("steward_bootstrap.")),
];

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: T[] })?.rows ?? [])) as T[];
}

function stable(value: unknown): string {
  return JSON.stringify(value);
}

function boundTextArray(values: readonly string[]) {
  return sql`ARRAY[${sql.join(
    values.map((value) => sql`${value}`),
    sql`, `,
  )}]::text[]`;
}

export async function assertPlatformDatabaseAuthority(
  db: SqlDatabase,
  expectedRole: string,
): Promise<void> {
  const roleName = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;
  if (!roleName.test(expectedRole)) throw new Error("PLATFORM_DATABASE_ROLE_UNSAFE");
  const [role] = rowsOf<{
    session_user: string;
    current_user: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
    rolcanlogin: boolean;
    rolinherit: boolean;
    rolcreatedb: boolean;
    rolcreaterole: boolean;
    rolreplication: boolean;
    has_connect: boolean;
    public_connect: boolean;
    has_membership: boolean;
    owns_objects: boolean;
  }>(
    await db.execute(sql`
      SELECT session_user::text, current_user::text, role.rolsuper, role.rolbypassrls,
        role.rolcanlogin, role.rolinherit, role.rolcreatedb, role.rolcreaterole,
        role.rolreplication,
        has_database_privilege(role.oid, current_database(), 'CONNECT') AS has_connect,
        EXISTS (
          SELECT 1 FROM pg_database database_object
          CROSS JOIN LATERAL aclexplode(
            COALESCE(database_object.datacl, acldefault('d', database_object.datdba))
          ) privilege
          WHERE database_object.datname = current_database()
            AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT'
        ) AS public_connect,
        EXISTS (
          SELECT 1 FROM pg_auth_members membership
          WHERE membership.member = role.oid OR membership.roleid = role.oid
        ) AS has_membership,
        EXISTS (
          SELECT 1 FROM pg_database database_object WHERE database_object.datdba = role.oid
          UNION ALL
          SELECT 1 FROM pg_namespace namespace WHERE namespace.nspowner = role.oid
          UNION ALL
          SELECT 1 FROM pg_class relation WHERE relation.relowner = role.oid
          UNION ALL
          SELECT 1 FROM pg_proc function_object WHERE function_object.proowner = role.oid
        ) AS owns_objects
      FROM pg_roles role WHERE role.rolname = session_user
    `),
  );
  if (
    !role ||
    role.session_user !== expectedRole ||
    role.current_user !== expectedRole ||
    !role.rolcanlogin ||
    role.rolinherit ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcreatedb ||
    role.rolcreaterole ||
    role.rolreplication ||
    !role.has_connect ||
    role.public_connect ||
    role.has_membership ||
    role.owns_objects
  ) {
    throw new Error("PLATFORM_DATABASE_ROLE_UNSAFE");
  }

  const databaseAndDefaultAclDrift = rowsOf<{ object_name: string }>(
    await db.execute(sql`
      SELECT 'database:' || database_object.datname AS object_name
      FROM pg_database database_object
      CROSS JOIN LATERAL aclexplode(database_object.datacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${expectedRole}
        AND (database_object.datname <> current_database()
          OR privilege.privilege_type <> 'CONNECT' OR privilege.is_grantable)
      UNION ALL
      SELECT 'default:' || owner_role.rolname || ':' || defaults.defaclobjtype::text || ':' ||
        COALESCE(namespace.nspname, '') || ':' || privilege.privilege_type::text || ':' ||
        privilege.is_grantable
      FROM pg_default_acl defaults
      JOIN pg_roles owner_role ON owner_role.oid = defaults.defaclrole
      LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${expectedRole}
      ORDER BY object_name
    `),
  );
  if (databaseAndDefaultAclDrift.length > 0) {
    throw new Error("PLATFORM_DATABASE_ACL_UNSAFE");
  }

  const namedAcls = rowsOf<{ acl: string }>(
    await db.execute(sql`
      SELECT 'schema:' || namespace.nspname || ':' || privilege.privilege_type || ':' ||
        privilege.is_grantable AS acl
      FROM pg_namespace namespace
      CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${expectedRole}
      UNION ALL
      SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND granted_role.rolname = ${expectedRole}
      UNION ALL
      SELECT 'function:' || function_object.oid::regprocedure::text || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_proc function_object
      JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
      CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${expectedRole}
      ORDER BY acl
    `),
  );
  if (stable(namedAcls.map((row) => row.acl)) !== stable(EXPECTED_PLATFORM_NAMED_ACLS)) {
    throw new Error("PLATFORM_DATABASE_ACL_UNSAFE");
  }
}

/**
 * Load-bearing production gate for the SEC-169 deployment role and catalog.
 * It deliberately runs through the exact application connection before traffic
 * is served; operator scripts and migration-role checks are not substitutes.
 */
export async function assertRlsDeploymentSafety(
  db: SqlDatabase,
  options: {
    expectedRole: string;
    expectedPlatformRole: string;
    expectedBootstrapRole: string;
    expectedMigrationRole: string;
    requireActivated?: boolean;
  },
): Promise<void> {
  const roleName = /^[A-Za-z_][A-Za-z0-9_$-]{0,62}$/;
  if (
    !roleName.test(options.expectedRole) ||
    !roleName.test(options.expectedPlatformRole) ||
    !roleName.test(options.expectedBootstrapRole) ||
    !roleName.test(options.expectedMigrationRole)
  ) {
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
    owns_database: boolean;
    owns_rls_relation: boolean;
    has_assumable_privilege: boolean;
    can_create_protected_schema: boolean;
    platform_role_safe: boolean;
    migration_role_safe: boolean;
    bootstrap_role_safe: boolean;
    migration_assumable_authority: boolean;
    app_membership_drift: boolean;
    bootstrap_membership_drift: boolean;
  }>(
    await db.execute(sql`
      SELECT current_user::text, session_user::text, role.rolcanlogin, role.rolinherit,
        role.rolsuper, role.rolbypassrls, role.rolcreatedb, role.rolcreaterole,
        role.rolreplication,
        EXISTS (
          SELECT 1 FROM pg_database database_object
          WHERE database_object.datname = current_database()
            AND database_object.datdba = role.oid
        ) AS owns_database,
        EXISTS (
          SELECT 1 FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = 'public'
            AND relation.relname = ANY(${boundTextArray([
              ...new Set(EXPECTED_RLS_POLICY_DEFINITIONS.map((p) => p.relation_name)),
            ])})
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
        ) AS platform_role_safe,
        EXISTS (
          SELECT 1 FROM pg_roles migration
          WHERE migration.rolname = ${options.expectedMigrationRole}
            AND migration.rolcanlogin AND NOT migration.rolinherit
            AND NOT migration.rolsuper AND NOT migration.rolbypassrls
            AND NOT migration.rolcreatedb AND NOT migration.rolcreaterole
            AND NOT migration.rolreplication
            AND NOT pg_has_role(${options.expectedRole}, migration.oid, 'MEMBER')
            AND NOT pg_has_role(
              migration.oid, ${options.expectedBootstrapRole}, 'MEMBER'
            )
        ) AS migration_role_safe,
        EXISTS (
          SELECT 1 FROM pg_roles bootstrap
          WHERE bootstrap.rolname = ${options.expectedBootstrapRole}
            AND NOT bootstrap.rolcanlogin AND NOT bootstrap.rolinherit
            AND NOT bootstrap.rolsuper AND bootstrap.rolbypassrls
            AND NOT bootstrap.rolcreatedb AND NOT bootstrap.rolcreaterole
            AND NOT bootstrap.rolreplication
            AND NOT pg_has_role(${options.expectedRole}, bootstrap.oid, 'MEMBER')
            AND NOT pg_has_role(${options.expectedPlatformRole}, bootstrap.oid, 'MEMBER')
        ) AS bootstrap_role_safe
        , EXISTS (
          SELECT 1 FROM pg_roles migration
          JOIN pg_roles candidate ON candidate.oid <> migration.oid
          WHERE migration.rolname = ${options.expectedMigrationRole}
            AND pg_has_role(migration.oid, candidate.oid, 'MEMBER')
            AND (
              candidate.rolsuper OR candidate.rolbypassrls OR candidate.rolcreatedb
              OR candidate.rolcreaterole OR candidate.rolreplication
              OR EXISTS (
                SELECT 1 FROM pg_database database_object
                WHERE database_object.datname = current_database()
                  AND database_object.datdba = candidate.oid
              )
              OR EXISTS (
                SELECT 1 FROM pg_namespace namespace
                WHERE namespace.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
                  AND (namespace.nspowner = candidate.oid
                    OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))
              )
            )
        ) AS migration_assumable_authority,
        EXISTS (
          SELECT 1 FROM pg_auth_members membership
          WHERE membership.member = role.oid OR membership.roleid = role.oid
        ) AS app_membership_drift,
        EXISTS (
          SELECT 1 FROM pg_auth_members membership
          JOIN pg_roles bootstrap ON bootstrap.rolname = ${options.expectedBootstrapRole}
          WHERE membership.member = bootstrap.oid OR membership.roleid = bootstrap.oid
        ) AS bootstrap_membership_drift
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
    role.owns_database ||
    role.owns_rls_relation ||
    role.has_assumable_privilege ||
    role.can_create_protected_schema ||
    !role.platform_role_safe ||
    !role.migration_role_safe ||
    !role.bootstrap_role_safe ||
    role.migration_assumable_authority ||
    role.app_membership_drift ||
    role.bootstrap_membership_drift
  ) {
    throw new Error("RLS_DEPLOYMENT_ROLE_UNSAFE");
  }

  const databaseAclDrift = rowsOf<{ object_name: string }>(
    await db.execute(sql`
      SELECT current_database()::text AS object_name
      WHERE NOT has_database_privilege(${options.expectedRole}, current_database(), 'CONNECT')
         OR NOT has_database_privilege(${options.expectedPlatformRole}, current_database(), 'CONNECT')
         OR EXISTS (
           SELECT 1 FROM pg_database database_object
           CROSS JOIN LATERAL aclexplode(
             COALESCE(database_object.datacl, acldefault('d', database_object.datdba))
           ) privilege
           WHERE database_object.datname = current_database()
             AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT'
         )
    `),
  );
  if (databaseAclDrift.length > 0) throw new Error("RLS_DEPLOYMENT_DATABASE_ACL_DRIFT");

  const appDatabaseAndDefaultAcls = rowsOf<{ acl: string }>(
    await db.execute(sql`
      SELECT 'database:' || database_object.datname || ':' || privilege.privilege_type || ':' ||
        privilege.is_grantable AS acl
      FROM pg_database database_object
      CROSS JOIN LATERAL aclexplode(database_object.datacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedRole}
      UNION ALL
      SELECT 'default:' || owner_role.rolname || ':' || defaults.defaclobjtype::text || ':' ||
        COALESCE(namespace.nspname, '') || ':' || privilege.privilege_type::text || ':' ||
        privilege.is_grantable
      FROM pg_default_acl defaults
      JOIN pg_roles owner_role ON owner_role.oid = defaults.defaclrole
      LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedRole}
      ORDER BY acl
    `),
  );
  const expectedAppDatabaseAndDefaultAcls = [
    `database:${
      rowsOf<{ database_name: string }>(
        await db.execute(sql`SELECT current_database()::text AS database_name`),
      )[0]?.database_name
    }:CONNECT:false`,
  ].sort();
  if (
    stable(appDatabaseAndDefaultAcls.map((row) => row.acl)) !==
    stable(expectedAppDatabaseAndDefaultAcls)
  ) {
    throw new Error("RLS_DEPLOYMENT_APP_DATABASE_ACL_DRIFT");
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

  const functions = rowsOf<{
    identity: string;
    result: string;
    language: string;
    volatility: string;
    parallelism: string;
    security_definer: boolean;
    settings: string;
    owner: string;
    body_md5: string;
    public_execute: boolean;
    app_execute: boolean;
    platform_execute: boolean;
  }>(
    await db.execute(sql`
      SELECT function.oid::regprocedure::text AS identity,
        pg_get_function_result(function.oid) AS result,
        language.lanname::text AS language,
        function.provolatile::text AS volatility,
        function.proparallel::text AS parallelism,
        function.prosecdef AS security_definer,
        COALESCE(array_to_string(function.proconfig, E'\\n'), '') AS settings,
        pg_get_userbyid(function.proowner) AS owner,
        md5(btrim(function.prosrc, E' \t\n\r')) AS body_md5,
        EXISTS (
          SELECT 1 FROM aclexplode(COALESCE(function.proacl, acldefault('f', function.proowner))) acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) AS public_execute,
        has_function_privilege(${options.expectedRole}, function.oid, 'EXECUTE') AS app_execute,
        has_function_privilege(
          ${options.expectedPlatformRole}, function.oid, 'EXECUTE'
        ) AS platform_execute
      FROM pg_proc function
      JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
      JOIN pg_language language ON language.oid = function.prolang
      WHERE namespace.nspname IN ('steward_bootstrap', 'steward_rls')
        OR (
          namespace.nspname = 'public'
          AND function.oid::regprocedure::text = ANY(${boundTextArray([
            "steward_enforce_reserved_tenant_commit_state()",
            "steward_register_user_identity_subject()",
            "steward_retire_user_identity_subject()",
          ])})
        )
      ORDER BY function.oid::regprocedure::text
    `),
  );
  const expectedFunctions = EXPECTED_RLS_FUNCTION_DEFINITIONS.map((definition) => ({
    identity: definition.identity,
    result: definition.result,
    language: definition.language,
    volatility: definition.volatility,
    parallelism: definition.parallelism,
    security_definer: definition.securityDefiner,
    settings: definition.settings,
    owner:
      definition.owner === "bootstrap"
        ? options.expectedBootstrapRole
        : options.expectedMigrationRole,
    body_md5: definition.bodyMd5,
    public_execute: false,
    app_execute: definition.appExecute,
    platform_execute: definition.platformExecute,
  }));
  if (stable(functions) !== stable(expectedFunctions)) {
    throw new Error("RLS_DEPLOYMENT_FUNCTION_DEFINITION_DRIFT");
  }

  const functionAcls = rowsOf<{
    identity: string;
    grantee: string;
    privilege: string;
    grantable: boolean;
  }>(
    await db.execute(sql`
      SELECT function.oid::regprocedure::text AS identity,
        CASE privilege.grantee WHEN 0 THEN 'PUBLIC'
          ELSE pg_get_userbyid(privilege.grantee) END AS grantee,
        privilege.privilege_type::text AS privilege,
        privilege.is_grantable AS grantable
      FROM pg_proc function
      JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
      CROSS JOIN LATERAL aclexplode(
        COALESCE(function.proacl, acldefault('f', function.proowner))
      ) privilege
      WHERE namespace.nspname IN ('steward_bootstrap', 'steward_rls')
        OR (
          namespace.nspname = 'public'
          AND function.oid::regprocedure::text = ANY(${boundTextArray([
            "steward_enforce_reserved_tenant_commit_state()",
            "steward_register_user_identity_subject()",
            "steward_retire_user_identity_subject()",
          ])})
        )
      ORDER BY identity, grantee, privilege, grantable
    `),
  );
  const expectedFunctionAcls = EXPECTED_RLS_FUNCTION_DEFINITIONS.flatMap((definition) => {
    const owner =
      definition.owner === "bootstrap"
        ? options.expectedBootstrapRole
        : options.expectedMigrationRole;
    return [
      { identity: definition.identity, grantee: owner, privilege: "EXECUTE", grantable: false },
      ...(definition.appExecute
        ? [
            {
              identity: definition.identity,
              grantee: options.expectedRole,
              privilege: "EXECUTE",
              grantable: false,
            },
          ]
        : []),
      ...(definition.platformExecute
        ? [
            {
              identity: definition.identity,
              grantee: options.expectedPlatformRole,
              privilege: "EXECUTE",
              grantable: false,
            },
          ]
        : []),
    ];
  });
  functionAcls.sort(
    (left, right) =>
      left.identity.localeCompare(right.identity) ||
      left.grantee.localeCompare(right.grantee) ||
      left.privilege.localeCompare(right.privilege) ||
      Number(left.grantable) - Number(right.grantable),
  );
  expectedFunctionAcls.sort(
    (left, right) =>
      left.identity.localeCompare(right.identity) ||
      left.grantee.localeCompare(right.grantee) ||
      left.privilege.localeCompare(right.privilege) ||
      Number(left.grantable) - Number(right.grantable),
  );
  if (stable(functionAcls) !== stable(expectedFunctionAcls)) {
    throw new Error("RLS_DEPLOYMENT_FUNCTION_ACL_DRIFT");
  }

  const [personalLifecycleLock] = rowsOf<{
    identity: string;
    result: string;
    language: string;
    volatility: string;
    parallelism: string;
    security_definer: boolean;
    settings: string;
    argument_defaults: string;
    owner: string;
    body_md5: string;
  }>(
    await db.execute(sql`
      SELECT function.oid::regprocedure::text AS identity,
        pg_get_function_result(function.oid) AS result,
        language.lanname::text AS language,
        function.provolatile AS volatility,
        function.proparallel AS parallelism,
        function.prosecdef AS security_definer,
        COALESCE(array_to_string(function.proconfig, E'\n'), '') AS settings,
        COALESCE(pg_get_expr(function.proargdefaults, 0), '') AS argument_defaults,
        pg_get_userbyid(function.proowner) AS owner,
        md5(btrim(function.prosrc, E' \t\n\r')) AS body_md5
      FROM pg_proc function
      JOIN pg_language language ON language.oid = function.prolang
      WHERE function.oid =
        to_regprocedure('public.steward_lock_personal_lifecycle(uuid,text,boolean)')
    `),
  );
  if (
    !personalLifecycleLock ||
    stable(personalLifecycleLock) !==
      stable({
        identity: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.identity,
        result: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.result,
        language: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.language,
        volatility: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.volatility,
        parallelism: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.parallelism,
        security_definer: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.securityDefiner,
        settings: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.settings,
        argument_defaults: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.argumentDefaults,
        owner: options.expectedMigrationRole,
        body_md5: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.bodyMd5,
      })
  ) {
    throw new Error("RLS_DEPLOYMENT_PERSONAL_LIFECYCLE_LOCK_DEFINITION_DRIFT");
  }

  const personalLifecycleLockAcls = rowsOf<{
    grantee: string;
    privilege: string;
    grantable: boolean;
  }>(
    await db.execute(sql`
      SELECT CASE acl.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END AS grantee,
        acl.privilege_type::text AS privilege, acl.is_grantable AS grantable
      FROM pg_proc function
      CROSS JOIN LATERAL aclexplode(
        COALESCE(function.proacl, acldefault('f', function.proowner))
      ) acl
      WHERE function.oid =
        to_regprocedure('public.steward_lock_personal_lifecycle(uuid,text,boolean)')
      ORDER BY grantee, privilege
    `),
  );
  const expectedPersonalLifecycleLockAcls = [
    { grantee: options.expectedRole, privilege: "EXECUTE", grantable: false },
    { grantee: options.expectedBootstrapRole, privilege: "EXECUTE", grantable: false },
    { grantee: options.expectedMigrationRole, privilege: "EXECUTE", grantable: false },
  ].sort((left, right) => left.grantee.localeCompare(right.grantee));
  if (stable(personalLifecycleLockAcls) !== stable(expectedPersonalLifecycleLockAcls)) {
    throw new Error("RLS_DEPLOYMENT_PERSONAL_LIFECYCLE_LOCK_ACL_DRIFT");
  }

  const appNamedAcls = rowsOf<{ acl: string }>(
    await db.execute(sql`
      SELECT 'schema:' || namespace.nspname || ':' || privilege.privilege_type || ':' ||
        privilege.is_grantable AS acl
      FROM pg_namespace namespace
      CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedRole}
      UNION ALL
      SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND granted_role.rolname = ${options.expectedRole}
      UNION ALL
      SELECT 'column:' || namespace.nspname || '.' || relation.relname || '.' ||
        attribute.attname || ':' || privilege.privilege_type || ':' ||
        privilege.is_grantable AS acl
      FROM pg_attribute attribute
      JOIN pg_class relation ON relation.oid = attribute.attrelid
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL aclexplode(attribute.attacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
        AND granted_role.rolname = ${options.expectedRole}
      UNION ALL
      SELECT 'function:' || function_object.oid::regprocedure::text || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_proc function_object
      CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedRole}
      ORDER BY acl
    `),
  );
  const sequenceRows = rowsOf<{ identity: string }>(
    await db.execute(sql`
      SELECT namespace.nspname || '.' || relation.relname AS identity
      FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public' AND relation.relkind = 'S'
      ORDER BY identity
    `),
  );
  const expectedAppNamedAcls = [
    "schema:public:USAGE:false",
    "schema:steward_bootstrap:USAGE:false",
    "schema:steward_rls:USAGE:false",
    ...expectedRelations.flatMap((relation) => {
      if (
        relation.relation_name === "retained_user_provider_evidence" ||
        relation.relation_name === "user_identity_subjects"
      )
        return [];
      if (relation.relation_name === "users") return ["relation:public.users:SELECT:false"];
      return ["DELETE", "INSERT", "SELECT", "UPDATE"].map(
        (privilege) => `relation:public.${relation.relation_name}:${privilege}:false`,
      );
    }),
    ...APP_USERS_INSERT_COLUMNS.map((column) => `column:public.users.${column}:INSERT:false`),
    ...APP_USERS_UPDATE_COLUMNS.map((column) => `column:public.users.${column}:UPDATE:false`),
    ...sequenceRows.flatMap((sequence) => [
      `relation:${sequence.identity}:SELECT:false`,
      `relation:${sequence.identity}:USAGE:false`,
    ]),
    ...EXPECTED_RLS_FUNCTION_DEFINITIONS.filter((definition) => definition.appExecute).map(
      (definition) => `function:${definition.identity}:EXECUTE:false`,
    ),
    ...APP_PUBLIC_EXECUTABLE_FUNCTIONS.map((identity) => `function:${identity}:EXECUTE:false`),
  ].sort();
  if (stable(appNamedAcls.map((row) => row.acl)) !== stable(expectedAppNamedAcls)) {
    throw new Error("RLS_DEPLOYMENT_APP_ACL_DRIFT");
  }

  const unknownExecutableDefiners = rowsOf<{ identity: string }>(
    await db.execute(sql`
      SELECT function.oid::regprocedure::text AS identity
      FROM pg_proc function
      JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
      WHERE namespace.nspname = 'public' AND function.prosecdef
        AND EXISTS (
          SELECT 1
          FROM aclexplode(COALESCE(function.proacl, acldefault('f', function.proowner))) acl
          WHERE acl.privilege_type = 'EXECUTE' AND acl.grantee <> function.proowner
        )
      ORDER BY function.oid::regprocedure::text
    `),
  );
  if (unknownExecutableDefiners.length > 0) {
    throw new Error("RLS_DEPLOYMENT_UNKNOWN_EXECUTABLE_SECURITY_DEFINER");
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
          function.oid::regprocedure::text AS identity, function.prosecdef,
          function.proacl, function.proowner
        FROM pg_proc function
        JOIN pg_namespace namespace ON namespace.oid = function.pronamespace
        WHERE namespace.nspname IN ('steward_bootstrap', 'steward_rls')
      ), function_drift AS (
        SELECT format('%I.%I', nspname, proname) AS object_name
        FROM functions
        WHERE EXISTS (
          SELECT 1
          FROM aclexplode(COALESCE(proacl, acldefault('f', proowner))) privilege
          WHERE privilege.grantee = 0 AND privilege.privilege_type = 'EXECUTE'
        )
          OR has_function_privilege(${options.expectedRole}, oid, 'EXECUTE') <>
            (identity = ANY(${boundTextArray(APP_EXECUTABLE_FUNCTIONS)}))
          OR has_function_privilege(${options.expectedPlatformRole}, oid, 'EXECUTE') <>
            (identity = ANY(${boundTextArray(PLATFORM_EXECUTABLE_FUNCTIONS)}))
          OR (nspname = 'steward_bootstrap' AND prosecdef
            AND identity <> ALL(${boundTextArray([...new Set(KNOWN_BOOTSTRAP_FUNCTIONS)])}))
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

  const platformDatabaseAndDefaultAclDrift = rowsOf<{ object_name: string }>(
    await db.execute(sql`
      SELECT 'database:' || database_object.datname AS object_name
      FROM pg_database database_object
      CROSS JOIN LATERAL aclexplode(database_object.datacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedPlatformRole}
        AND (database_object.datname <> current_database()
          OR privilege.privilege_type <> 'CONNECT' OR privilege.is_grantable)
      UNION ALL
      SELECT 'default:' || owner_role.rolname || ':' || defaults.defaclobjtype::text || ':' ||
        COALESCE(namespace.nspname, '') || ':' || privilege.privilege_type::text || ':' ||
        privilege.is_grantable
      FROM pg_default_acl defaults
      JOIN pg_roles owner_role ON owner_role.oid = defaults.defaclrole
      LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedPlatformRole}
      ORDER BY object_name
    `),
  );
  if (platformDatabaseAndDefaultAclDrift.length > 0) {
    throw new Error("RLS_DEPLOYMENT_PLATFORM_ACL_DRIFT");
  }

  const platformNamedAcls = rowsOf<{ acl: string }>(
    await db.execute(sql`
      SELECT 'schema:' || namespace.nspname || ':' || privilege.privilege_type || ':' ||
        privilege.is_grantable AS acl
      FROM pg_namespace namespace
      CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedPlatformRole}
      UNION ALL
      SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND granted_role.rolname = ${options.expectedPlatformRole}
      UNION ALL
      SELECT 'function:' || function_object.oid::regprocedure::text || ':' ||
        privilege.privilege_type || ':' || privilege.is_grantable AS acl
      FROM pg_proc function_object
      JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
      CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
      JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
      WHERE granted_role.rolname = ${options.expectedPlatformRole}
      ORDER BY acl
    `),
  );
  if (stable(platformNamedAcls.map((row) => row.acl)) !== stable(EXPECTED_PLATFORM_NAMED_ACLS)) {
    throw new Error("RLS_DEPLOYMENT_PLATFORM_ACL_DRIFT");
  }
}
