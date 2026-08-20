import { createHash } from "node:crypto";
import { type SQL, sql } from "drizzle-orm";
import {
  ALL_INVENTORIED_TABLES,
  ALL_OPTIONAL_INVENTORIED_TABLES,
  BOOTSTRAP_ROOT_TABLES,
  DIRECT_TENANT_TABLES,
  INDIRECT_TENANT_TABLES,
  INTENTIONALLY_GLOBAL_TABLES,
  OPTIONAL_DIRECT_TENANT_TABLES,
  OPTIONAL_INTENTIONALLY_GLOBAL_TABLES,
} from "./rls-inventory";

type ReadinessDatabase = {
  execute(query: SQL): Promise<unknown>;
};

type RoleRow = {
  role_name: string;
  session_role_name: string;
  rolcanlogin: boolean;
  rolinherit: boolean;
  rolsuper: boolean;
  rolbypassrls: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolreplication: boolean;
  owns_database: boolean;
  can_assume_relation_owner: boolean;
  can_assume_privileged_role: boolean;
  can_assume_schema_owner: boolean;
  can_create_protected_schema: boolean;
};

type PolicyRow = {
  name: string;
  command: string;
  permissive: boolean;
  roles: Array<number | string>;
  using_expression: string | null;
  check_expression: string | null;
};

type RelationRow = {
  relation_name: string;
  relation_kind: string;
  tenant_column_type: string | null;
  owner_oid: number;
  rls_enabled: boolean;
  rls_forced: boolean;
  is_partition: boolean;
  policies: unknown;
};

type HelperRow = {
  function_name: string;
  owner_oid: number;
  relation_owner_oid: number;
  security_definer: boolean;
  volatility: string;
  parallel_safety: string;
  language_name: string;
  result_type: string;
  identity_arguments: string;
  source: string;
  settings: unknown;
  public_execute: boolean;
  app_execute: boolean;
};

type BootstrapFunctionRow = {
  function_name: string;
  identity_arguments: string;
  result_type: string;
  volatility: string;
  language_name: string;
  security_definer: boolean;
  owner_can_login: boolean;
  owner_inherit: boolean;
  owner_super: boolean;
  owner_bypass_rls: boolean;
  owner_create_db: boolean;
  owner_create_role: boolean;
  owner_replication: boolean;
  settings: unknown;
  public_execute: boolean;
  app_execute: boolean;
  source: string;
};

type BootstrapFunctionSpec = {
  result: string;
  volatility: "s" | "v";
  language: "sql" | "plpgsql";
  sha256: string;
};

export const BOOTSTRAP_FUNCTION_SPECS = new Map<string, BootstrapFunctionSpec>([
  [
    "agent_subject(p_agent_id text, p_tenant_id text, p_jti text)",
    {
      result:
        "TABLE(agent_id character varying, agent_name character varying, wallet_address character varying, signer_id uuid, signer_policy_ids jsonb, signer_expires_at timestamp with time zone, signer_revoked_at timestamp with time zone)",
      volatility: "s",
      language: "sql",
      sha256: "ec0cf0d736a63cd7f46daba69201c524230c0e01cd2ff1a7faa6db9252d63b83",
    },
  ],
  [
    "agent_tenant_subject(p_agent_id text)",
    {
      result: "TABLE(tenant_id character varying)",
      volatility: "s",
      language: "sql",
      sha256: "512d6e9385dfd70d9f26b09eab14158ecea892351a703133f38d214bd8ee2740",
    },
  ],
  [
    "app_client_subject(p_tenant_id text, p_client_id text)",
    {
      result:
        "TABLE(secret_id uuid, secret_hash text, secret_status character varying, expires_at timestamp with time zone, revoked_at timestamp with time zone, client_enabled boolean)",
      volatility: "s",
      language: "sql",
      sha256: "f9302bc90ebfe0991e0f95940c33c6c4ef9af8f2c9480dd8a4641f399966b3b6",
    },
  ],
  [
    "auth_app_clients_subject(p_tenant_id text)",
    {
      result:
        "TABLE(id character varying, allowed_redirect_urls text[], login_methods jsonb, allowed_bundle_ids text[], allowed_package_names text[])",
      volatility: "s",
      language: "sql",
      sha256: "18ce81b04f2afaba671316ef3422d897fceb8f31a572c43a218e685209c8ea08",
    },
  ],
  [
    "auth_refresh_subject(p_token_hash text)",
    {
      result:
        "TABLE(user_id uuid, tenant_id character varying, expires_at timestamp with time zone)",
      volatility: "s",
      language: "sql",
      sha256: "d9b42adcb1b23d1626e99117b42337e8aabab7ac88a8e589c66d038aed70b6c0",
    },
  ],
  [
    "auth_rotate_refresh_token(p_source_token_hash text, p_target_tenant_id text, p_successor_id text, p_successor_token_hash text, p_successor_expires_at timestamp with time zone)",
    {
      result:
        "TABLE(id text, user_id uuid, tenant_id character varying, token_hash text, expires_at timestamp with time zone, created_at timestamp with time zone)",
      volatility: "v",
      language: "plpgsql",
      sha256: "b24d7df7c7592873dfdfcf4f3c206388d67ed4b26e4ea3be9dcbd200eaa458b5",
    },
  ],
  [
    "auth_sso_discovery_subject(p_domain text)",
    {
      result: "TABLE(tenant_id character varying, domain character varying, sso_required boolean)",
      volatility: "s",
      language: "sql",
      sha256: "742888429e79955958d5209666fdf68efdb931a5ce5f99d236f61cf588ce757f",
    },
  ],
  [
    "auth_sso_domain_subject(p_tenant_id text, p_domain text)",
    {
      result: "TABLE(tenant_id character varying, sso_required boolean)",
      volatility: "s",
      language: "sql",
      sha256: "ba6452808db668fbcba842057273f17c5729e3216096bd76003b513207cca17d",
    },
  ],
  [
    "auth_tenant_config_subject(p_tenant_id text)",
    {
      result:
        "TABLE(auth_abuse_config jsonb, allowed_origins text[], email_config jsonb, oidc_providers jsonb, test_account jsonb, allowed_redirect_urls text[])",
      volatility: "s",
      language: "sql",
      sha256: "1ce60595750bc8d9317988e4f592fb0b3fde5d25846e62f230f522c90550d880",
    },
  ],
  [
    "auth_tenant_subject(p_tenant_id text, p_user_id uuid)",
    {
      result:
        "TABLE(tenant_id character varying, membership_role character varying, join_mode character varying)",
      volatility: "s",
      language: "sql",
      sha256: "ff47e35de5ac2f8ff9477d58ac6dd316b49757aba2274a59b0398905169bf8cd",
    },
  ],
  [
    "ensure_default_tenant(p_api_key_hash text)",
    {
      result: "void",
      volatility: "v",
      language: "sql",
      sha256: "34672c129177cd7c278902fa44834c84b513703d2012e58d336e5e37be8ea56a",
    },
  ],
  [
    "ensure_platform_tenant()",
    {
      result: "text",
      volatility: "v",
      language: "sql",
      sha256: "370c0503ad817caa46db3c24b535c17f60fad1ed10e97904f4188cfeba4ac24f",
    },
  ],
  [
    "ensure_system_tenant()",
    {
      result: "text",
      volatility: "v",
      language: "sql",
      sha256: "046d8671b53e43f1e901635b72d7ed2ad9672678d2f0b4246ff0d91e2ac5d1b3",
    },
  ],
  [
    "platform_delete_user(p_user_id uuid)",
    {
      result: "TABLE(user_id uuid)",
      volatility: "v",
      language: "plpgsql",
      sha256: "6de7c24426c29f6eabcb0c8258113e916a59b934e2b5770c64c288714760bc72",
    },
  ],
  [
    "platform_revoke_user_refresh_tokens(p_user_id uuid)",
    {
      result: "bigint",
      volatility: "v",
      language: "plpgsql",
      sha256: "601dbf18ac1fd541a82d580d5516db8d4c264afe3715e7948ffa1cb5107945df",
    },
  ],
  [
    "platform_set_user_deactivation(p_user_id uuid, p_deactivated boolean)",
    {
      result:
        "TABLE(user_id uuid, previous_deactivated_at timestamp with time zone, previous_updated_at timestamp with time zone, deactivated_at timestamp with time zone)",
      volatility: "v",
      language: "plpgsql",
      sha256: "7d001189039c4157136024562b91c48f5899217eb4079d70cd2d7f79007346fb",
    },
  ],
  [
    "platform_stats()",
    {
      result: "TABLE(tenant_count bigint, agent_count bigint, transaction_count bigint)",
      volatility: "s",
      language: "sql",
      sha256: "2862ce53b62f2f445b769f43018a38bb330b416162df22c7f87e34f086b085d5",
    },
  ],
  [
    "platform_tenants(p_limit integer, p_offset integer)",
    {
      result:
        "TABLE(id character varying, name character varying, owner_address character varying, created_at timestamp with time zone, updated_at timestamp with time zone)",
      volatility: "s",
      language: "sql",
      sha256: "7975811ddadfcc0130178dc196496b50f7e4b8965c56a0d78e9bb0d1b9fdc55b",
    },
  ],
  [
    "platform_user_tenant_ids(p_user_id uuid)",
    {
      result: "TABLE(tenant_id character varying)",
      volatility: "s",
      language: "sql",
      sha256: "5f7a7dc8bd229d530c593fdd0a9fb2f187190a5e3cfa922dd26d09a64ac3b56a",
    },
  ],
  [
    "retention_delete_deactivated_users(p_days integer)",
    {
      result: "bigint",
      volatility: "v",
      language: "plpgsql",
      sha256: "ec7d64bc782372e410cf4eaf4780c98d21945658f155d2bdcb60a4f82a1a11ff",
    },
  ],
  [
    "session_subject(p_user_id uuid, p_tenant_id text)",
    {
      result:
        "TABLE(deactivated_at timestamp with time zone, is_guest boolean, guest_expires_at timestamp with time zone, membership_role character varying)",
      volatility: "s",
      language: "sql",
      sha256: "89ad021a52c63f19bac33a1e4cb04db63243e0bc5a7dda2cfca5cf1e1be86777",
    },
  ],
  [
    "tenant_api_key_subject(p_tenant_id text)",
    {
      result:
        "TABLE(id character varying, name character varying, api_key_hash text, owner_address character varying, created_at timestamp with time zone, updated_at timestamp with time zone)",
      volatility: "s",
      language: "sql",
      sha256: "2efad625ca2e0b876121147e2eca842c066375bc766efc4ba3e27722422d23b8",
    },
  ],
  [
    "tenant_ids_for_internal_job()",
    {
      result: "TABLE(tenant_id character varying)",
      volatility: "s",
      language: "sql",
      sha256: "5ea8d407564411e55d8f6708f77d3039d087d6e85cf704a22c9bbeadad9178b9",
    },
  ],
]);

function resultRows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object") {
    const rows = (result as { rows?: unknown }).rows;
    if (Array.isArray(rows)) return rows as T[];
  }
  throw new Error("RLS_READINESS_QUERY_INVALID");
}

function policyRows(value: unknown): PolicyRow[] {
  if (!Array.isArray(value)) {
    throw new Error("RLS_READINESS_POLICY_RESULT_INVALID");
  }
  for (const entry of value) {
    if (
      !entry ||
      typeof entry !== "object" ||
      typeof (entry as PolicyRow).name !== "string" ||
      typeof (entry as PolicyRow).command !== "string" ||
      typeof (entry as PolicyRow).permissive !== "boolean" ||
      !Array.isArray((entry as PolicyRow).roles)
    ) {
      throw new Error("RLS_READINESS_POLICY_RESULT_INVALID");
    }
  }
  return value as PolicyRow[];
}

function canonicalSql(value: string | null): string {
  if (typeof value !== "string") return "";
  return value.toLowerCase().replace(/\s+/g, "").trim();
}

function expectedPolicyExpressions(row: RelationRow): Map<string, string> {
  const relationName = row.relation_name;
  const tenant = "steward_rls.tenant_id()";
  if (
    (DIRECT_TENANT_TABLES as readonly string[]).includes(relationName) ||
    (OPTIONAL_DIRECT_TENANT_TABLES as readonly string[]).includes(relationName)
  ) {
    const expression =
      row.tenant_column_type === "text" ? `(tenant_id=${tenant})` : `((tenant_id)::text=${tenant})`;
    return new Map([["steward_tenant_isolation", expression]]);
  }
  if (relationName in BOOTSTRAP_ROOT_TABLES) {
    return new Map([["steward_tenant_isolation", `((id)::text=${tenant})`]]);
  }
  if (relationName in INDIRECT_TENANT_TABLES) {
    const parent = relationName === "audit_archive_chunks" ? "audit_archives" : "agents";
    const localColumn = relationName === "audit_archive_chunks" ? "archive_id" : "agent_id";
    return new Map([
      [
        "steward_tenant_isolation",
        parent === "agents"
          ? `(exists(select1fromagentsparentwhere(((parent.id)::text=(${relationName}.${localColumn})::text)and((parent.tenant_id)::text=${tenant}))))`
          : `(exists(select1fromaudit_archivesparentwhere((parent.id=${relationName}.${localColumn})and((parent.tenant_id)::text=${tenant}))))`,
      ],
    ]);
  }
  if (relationName === "approval_queue") {
    return new Map([
      ["steward_tenant_direct", `((tenant_id)::text=${tenant})`],
      [
        "steward_tenant_derived",
        `((tenant_idisnull)and(exists(select1fromagentsparentwhere(((parent.id)::text=(approval_queue.agent_id)::text)and((parent.tenant_id)::text=${tenant})))))`,
      ],
    ]);
  }
  if (relationName === "user_push_subscriptions") {
    return new Map([
      ["steward_tenant_subscription", `((tenant_id)::text=${tenant})`],
      ["steward_global_user_subscription", "((tenant_idisnull)and(user_id=steward_rls.user_id()))"],
    ]);
  }
  throw new Error(`RLS_POLICY_SPEC_MISSING:${relationName}`);
}

/**
 * Prove that the live application connection cannot bypass RLS and that every
 * public relation is classified at the exact activated policy boundary.
 *
 * This is intentionally a runtime catalog check, not an environment promise:
 * a superuser URL, table-owner URL, partially applied activation, unexpected
 * plugin table, or future partition all abort startup before tenant traffic.
 */
export async function assertTenantRlsDatabaseReady(db: ReadinessDatabase): Promise<void> {
  const roles = resultRows<RoleRow>(
    await db.execute(sql`
      SELECT
        current_user::text AS role_name,
        session_user::text AS session_role_name,
        r.rolcanlogin,
        r.rolinherit,
        r.rolsuper,
        r.rolbypassrls,
        r.rolcreatedb,
        r.rolcreaterole,
        r.rolreplication,
        pg_has_role(session_user, d.datdba, 'MEMBER') AS owns_database,
        EXISTS (
          SELECT 1
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public'
            AND c.relkind IN ('r', 'p')
            AND pg_has_role(session_user, c.relowner, 'MEMBER')
        ) AS can_assume_relation_owner,
        EXISTS (
          SELECT 1 FROM pg_roles privileged
          WHERE (
              privileged.rolsuper OR privileged.rolbypassrls OR
              privileged.rolcreatedb OR privileged.rolcreaterole OR privileged.rolreplication
            ) AND pg_has_role(session_user, privileged.oid, 'MEMBER')
        ) AS can_assume_privileged_role,
        EXISTS (
          SELECT 1 FROM pg_namespace n
          WHERE n.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
            AND pg_has_role(session_user, n.nspowner, 'MEMBER')
        ) AS can_assume_schema_owner,
        EXISTS (
          SELECT 1
          FROM pg_roles candidate
          CROSS JOIN unnest(ARRAY['public','steward_rls','steward_bootstrap']) schema_name
          WHERE pg_has_role(session_user, candidate.oid, 'MEMBER')
            AND has_schema_privilege(candidate.oid, schema_name, 'CREATE')
        ) AS can_create_protected_schema
      FROM pg_roles r
      JOIN pg_database d ON d.datname = current_database()
      WHERE r.rolname = current_user
    `),
  );
  const role = roles[0];
  if (
    roles.length !== 1 ||
    !role ||
    role.role_name !== role.session_role_name ||
    !role.rolcanlogin ||
    role.rolinherit ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcreatedb ||
    role.rolcreaterole ||
    role.rolreplication ||
    role.owns_database ||
    role.can_assume_relation_owner ||
    role.can_assume_privileged_role ||
    role.can_assume_schema_owner ||
    role.can_create_protected_schema
  ) {
    throw new Error("RLS_APP_ROLE_UNSAFE");
  }

  const relations = resultRows<RelationRow>(
    await db.execute(sql`
      SELECT
        c.relname::text AS relation_name,
        c.relkind::text AS relation_kind,
        (
          SELECT format_type(a.atttypid, a.atttypmod)
          FROM pg_attribute a
          WHERE a.attrelid = c.oid
            AND a.attname = CASE WHEN c.relname = 'tenants' THEN 'id' ELSE 'tenant_id' END
            AND NOT a.attisdropped
        ) AS tenant_column_type,
        c.relowner::int AS owner_oid,
        c.relrowsecurity AS rls_enabled,
        c.relforcerowsecurity AS rls_forced,
        c.relispartition AS is_partition,
        COALESCE(
          json_agg(
            json_build_object(
              'name', p.polname,
              'command', p.polcmd,
              'permissive', p.polpermissive,
              'roles', p.polroles,
              'using_expression', pg_get_expr(p.polqual, p.polrelid),
              'check_expression', pg_get_expr(p.polwithcheck, p.polrelid)
            ) ORDER BY p.polname
          ) FILTER (WHERE p.polname IS NOT NULL),
          '[]'::json
        ) AS policies
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_policy p ON p.polrelid = c.oid
      WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      GROUP BY c.oid, c.relname, c.relowner, c.relrowsecurity, c.relforcerowsecurity, c.relispartition
      ORDER BY c.relname
    `),
  );

  const required = new Set<string>(ALL_INVENTORIED_TABLES);
  const optional = new Set<string>(ALL_OPTIONAL_INVENTORIED_TABLES);
  const global = new Set<string>([
    ...Object.keys(INTENTIONALLY_GLOBAL_TABLES),
    ...Object.keys(OPTIONAL_INTENTIONALLY_GLOBAL_TABLES),
  ]);
  const optionalTenant = new Set<string>(OPTIONAL_DIRECT_TENANT_TABLES);
  const byName = new Map(relations.map((row) => [row.relation_name, row]));

  const missing = [...required].filter((name) => !byName.has(name));
  if (missing.length > 0) {
    throw new Error(`RLS_INVENTORY_MISSING:${missing.sort().join(",")}`);
  }

  const unknown = relations
    .filter((row) => !required.has(row.relation_name) && !optional.has(row.relation_name))
    .map((row) => row.relation_name)
    .sort();
  if (unknown.length > 0) {
    throw new Error(`RLS_INVENTORY_UNCLASSIFIED:${unknown.join(",")}`);
  }

  for (const row of relations) {
    if (row.is_partition) {
      // Partitions need an explicit inventory entry and their own forced policy
      // because direct access to a child must not bypass its parent boundary.
      if (!required.has(row.relation_name) && !optionalTenant.has(row.relation_name)) {
        throw new Error(`RLS_PARTITION_UNCLASSIFIED:${row.relation_name}`);
      }
    }

    const policies = policyRows(row.policies);
    if (!["r", "p"].includes(row.relation_kind)) {
      throw new Error(`RLS_RELATION_KIND_UNSAFE:${row.relation_name}`);
    }
    if (global.has(row.relation_name)) {
      if (
        row.rls_enabled ||
        row.rls_forced ||
        policies.some((policy) => policy.name.startsWith("steward_"))
      ) {
        throw new Error(`RLS_GLOBAL_RELATION_DRIFT:${row.relation_name}`);
      }
      continue;
    }

    if (!row.rls_enabled || !row.rls_forced) {
      throw new Error(`RLS_ACTIVATION_INCOMPLETE:${row.relation_name}`);
    }
    const tenantPolicies = policies.filter(
      (policy) => policy.name !== "steward_migration_maintenance",
    );
    const expected = expectedPolicyExpressions(row);
    const maintenance = policies.find((policy) => policy.name === "steward_migration_maintenance");
    if (tenantPolicies.length !== expected.size || !maintenance) {
      throw new Error(`RLS_POLICY_DRIFT:${row.relation_name}`);
    }
    for (const policy of tenantPolicies) {
      const expectedExpression = expected.get(policy.name);
      if (
        !expectedExpression ||
        policy.command !== "*" ||
        !policy.permissive ||
        policy.roles.length !== 1 ||
        Number(policy.roles[0]) !== 0 ||
        canonicalSql(policy.using_expression) !== expectedExpression ||
        canonicalSql(policy.check_expression) !== expectedExpression
      ) {
        throw new Error(`RLS_POLICY_DRIFT:${row.relation_name}`);
      }
    }
    if (
      maintenance.command !== "*" ||
      !maintenance.permissive ||
      maintenance.roles.length !== 1 ||
      Number(maintenance.roles[0]) !== row.owner_oid ||
      canonicalSql(maintenance.using_expression) !== "true" ||
      canonicalSql(maintenance.check_expression) !== "true"
    ) {
      throw new Error(`RLS_MAINTENANCE_POLICY_UNSAFE:${row.relation_name}`);
    }
  }

  const helpers = resultRows<HelperRow>(
    await db.execute(sql`
      SELECT
        p.proname::text AS function_name,
        p.proowner::int AS owner_oid,
        relation_owner.oid::int AS relation_owner_oid,
        p.prosecdef AS security_definer,
        p.provolatile::text AS volatility,
        p.proparallel::text AS parallel_safety,
        l.lanname::text AS language_name,
        pg_get_function_result(p.oid)::text AS result_type,
        pg_get_function_identity_arguments(p.oid)::text AS identity_arguments,
        p.prosrc::text AS source,
        COALESCE(to_json(p.proconfig), '[]'::json) AS settings,
        EXISTS (
          SELECT 1
          FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) AS public_execute,
        has_function_privilege(current_user, p.oid, 'EXECUTE') AS app_execute
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_language l ON l.oid = p.prolang
      JOIN pg_class agents_relation ON agents_relation.relname = 'agents'
      JOIN pg_namespace agents_namespace
        ON agents_namespace.oid = agents_relation.relnamespace
        AND agents_namespace.nspname = 'public'
      JOIN pg_roles relation_owner ON relation_owner.oid = agents_relation.relowner
      WHERE n.nspname = 'steward_rls' AND p.proname IN ('tenant_id', 'user_id')
      ORDER BY p.proname
    `),
  );
  if (helpers.length !== 2) throw new Error("RLS_HELPER_DRIFT");
  for (const helper of helpers) {
    const settings = Array.isArray(helper.settings) ? helper.settings : [];
    const expectedSetting =
      helper.function_name === "tenant_id" ? "steward.tenant_id" : "steward.user_id";
    const expectedResult = helper.function_name === "tenant_id" ? "text" : "uuid";
    const expectedSource =
      helper.function_name === "tenant_id"
        ? "SELECT NULLIF(current_setting('steward.tenant_id', true), '')"
        : "SELECT NULLIF(current_setting('steward.user_id', true), '')::uuid";
    if (
      helper.owner_oid !== helper.relation_owner_oid ||
      helper.security_definer ||
      helper.volatility !== "s" ||
      helper.parallel_safety !== "s" ||
      helper.language_name !== "sql" ||
      helper.result_type !== expectedResult ||
      helper.identity_arguments !== "" ||
      settings.length !== 1 ||
      settings[0] !== "search_path=pg_catalog" ||
      helper.public_execute ||
      !helper.app_execute ||
      helper.source.trim() !== expectedSource ||
      !helper.source.includes(expectedSetting)
    ) {
      throw new Error(`RLS_HELPER_DRIFT:${helper.function_name}`);
    }
  }

  const bootstrapFunctions = resultRows<BootstrapFunctionRow>(
    await db.execute(sql`
      SELECT
        p.proname::text AS function_name,
        pg_get_function_identity_arguments(p.oid)::text AS identity_arguments,
        pg_get_function_result(p.oid)::text AS result_type,
        p.provolatile::text AS volatility,
        l.lanname::text AS language_name,
        p.prosecdef AS security_definer,
        owner.rolcanlogin AS owner_can_login,
        owner.rolinherit AS owner_inherit,
        owner.rolsuper AS owner_super,
        owner.rolbypassrls AS owner_bypass_rls,
        owner.rolcreatedb AS owner_create_db,
        owner.rolcreaterole AS owner_create_role,
        owner.rolreplication AS owner_replication,
        COALESCE(to_json(p.proconfig), '[]'::json) AS settings,
        EXISTS (
          SELECT 1
          FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) AS public_execute,
        has_function_privilege(current_user, p.oid, 'EXECUTE') AS app_execute,
        p.prosrc::text AS source
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_language l ON l.oid = p.prolang
      JOIN pg_roles owner ON owner.oid = p.proowner
      WHERE n.nspname = 'steward_bootstrap'
      ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)
    `),
  );
  if (bootstrapFunctions.length !== BOOTSTRAP_FUNCTION_SPECS.size) {
    throw new Error("RLS_BOOTSTRAP_FUNCTION_DRIFT");
  }
  for (const fn of bootstrapFunctions) {
    const key = `${fn.function_name}(${fn.identity_arguments})`;
    const expected = BOOTSTRAP_FUNCTION_SPECS.get(key);
    const settings = Array.isArray(fn.settings) ? fn.settings : [];
    const sourceHash = createHash("sha256").update(fn.source).digest("hex");
    if (
      !expected ||
      fn.result_type !== expected.result ||
      fn.volatility !== expected.volatility ||
      fn.language_name !== expected.language ||
      sourceHash !== expected.sha256 ||
      !fn.security_definer ||
      fn.owner_can_login ||
      fn.owner_inherit ||
      fn.owner_super ||
      !fn.owner_bypass_rls ||
      fn.owner_create_db ||
      fn.owner_create_role ||
      fn.owner_replication ||
      settings.length !== 1 ||
      settings[0] !== "search_path=pg_catalog" ||
      fn.public_execute ||
      !fn.app_execute
    ) {
      throw new Error(`RLS_BOOTSTRAP_FUNCTION_DRIFT:${key}`);
    }
  }

  const aclDrift = resultRows<{ object_name: string }>(
    await db.execute(sql`
      WITH app AS (SELECT oid FROM pg_roles WHERE rolname = current_user),
      schema_drift AS (
        SELECT n.nspname::text AS object_name
        FROM pg_namespace n, app
        WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
          AND (
            NOT EXISTS (
              SELECT 1
              FROM aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl
              WHERE acl.grantee = app.oid AND acl.privilege_type = 'USAGE'
                AND NOT acl.is_grantable
            ) OR EXISTS (
              SELECT 1
              FROM aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl
              WHERE acl.grantee <> n.nspowner
                AND (
                  acl.grantee <> app.oid OR acl.privilege_type <> 'USAGE' OR acl.is_grantable
                )
            )
          )
      ),
      function_drift AS (
        SELECT format('%I.%I(%s)', n.nspname, p.proname,
          pg_get_function_identity_arguments(p.oid)) AS object_name
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN app
        WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
          AND (
            NOT EXISTS (
              SELECT 1
              FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
              WHERE acl.grantee = app.oid AND acl.privilege_type = 'EXECUTE'
                AND NOT acl.is_grantable
            ) OR EXISTS (
              SELECT 1
              FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
              WHERE acl.grantee <> p.proowner
                AND (
                  acl.grantee <> app.oid OR acl.privilege_type <> 'EXECUTE' OR acl.is_grantable
                )
            )
          )
      )
      SELECT object_name FROM schema_drift
      UNION ALL
      SELECT object_name FROM function_drift
      ORDER BY object_name
    `),
  );
  if (aclDrift.length > 0) {
    throw new Error(`RLS_BOOTSTRAP_ACL_DRIFT:${aclDrift.map((row) => row.object_name).join(",")}`);
  }

  const unsafeDefiners = resultRows<{ function_name: string }>(
    await db.execute(sql`
      SELECT format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
        AS function_name
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname IN ('public', 'steward_rls')
        AND p.prosecdef
        AND has_function_privilege(current_user, p.oid, 'EXECUTE')
      ORDER BY 1
    `),
  );
  if (unsafeDefiners.length > 0) {
    throw new Error(
      `RLS_UNEXPECTED_SECURITY_DEFINER:${unsafeDefiners.map((row) => row.function_name).join(",")}`,
    );
  }
}
