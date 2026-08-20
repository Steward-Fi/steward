import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  ALL_INVENTORIED_TABLES,
  BOOTSTRAP_ROOT_TABLES,
  DIRECT_TENANT_TABLES,
  INDIRECT_TENANT_TABLES,
  INTENTIONALLY_GLOBAL_TABLES,
} from "../rls-inventory";
import { assertTenantRlsDatabaseReady, BOOTSTRAP_FUNCTION_SPECS } from "../rls-readiness";

type RoleOverrides = Partial<{
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
}>;

function tenantPolicies(relationName: string) {
  const tenant = "steward_rls.tenant_id()";
  const expressions = new Map<string, string>();
  if ((DIRECT_TENANT_TABLES as readonly string[]).includes(relationName)) {
    expressions.set("steward_tenant_isolation", `(tenant_id=${tenant})`);
  } else if (relationName in BOOTSTRAP_ROOT_TABLES) {
    expressions.set("steward_tenant_isolation", `((id)::text=${tenant})`);
  } else if (relationName in INDIRECT_TENANT_TABLES) {
    const parent = relationName === "audit_archive_chunks" ? "audit_archives" : "agents";
    const local = relationName === "audit_archive_chunks" ? "archive_id" : "agent_id";
    expressions.set(
      "steward_tenant_isolation",
      parent === "agents"
        ? `(exists(select1fromagentsparentwhere(((parent.id)::text=(${relationName}.${local})::text)and((parent.tenant_id)::text=${tenant}))))`
        : `(exists(select1fromaudit_archivesparentwhere((parent.id=${relationName}.${local})and((parent.tenant_id)::text=${tenant}))))`,
    );
  } else if (relationName === "approval_queue") {
    expressions.set("steward_tenant_direct", `((tenant_id)::text=${tenant})`);
    expressions.set(
      "steward_tenant_derived",
      `((tenant_idisnull)and(exists(select1fromagentsparentwhere(((parent.id)::text=(approval_queue.agent_id)::text)and((parent.tenant_id)::text=${tenant})))))`,
    );
  } else if (relationName === "user_push_subscriptions") {
    expressions.set("steward_tenant_subscription", `((tenant_id)::text=${tenant})`);
    expressions.set(
      "steward_global_user_subscription",
      "((tenant_idisnull)and(user_id=steward_rls.user_id()))",
    );
  }
  return [
    ...[...expressions].map(([name, expression]) => ({
      name,
      command: "*",
      permissive: true,
      roles: [0],
      using_expression: expression,
      check_expression: expression,
    })),
    {
      name: "steward_migration_maintenance",
      command: "*",
      permissive: true,
      roles: [42],
      using_expression: "true",
      check_expression: "true",
    },
  ];
}

function exactRelations() {
  const globals = new Set(Object.keys(INTENTIONALLY_GLOBAL_TABLES));
  return ALL_INVENTORIED_TABLES.map((relation_name) => {
    const isGlobal = globals.has(relation_name);
    return {
      relation_name,
      relation_kind: "r",
      tenant_column_type: isGlobal ? null : "text",
      owner_oid: 42,
      rls_enabled: !isGlobal,
      rls_forced: !isGlobal,
      is_partition: false,
      policies: isGlobal ? [] : tenantPolicies(relation_name),
    };
  });
}

function exactHelpers() {
  return ["tenant_id", "user_id"].map((function_name) => ({
    function_name,
    owner_oid: 42,
    relation_owner_oid: 42,
    security_definer: false,
    volatility: "s",
    parallel_safety: "s",
    language_name: "sql",
    result_type: function_name === "tenant_id" ? "text" : "uuid",
    identity_arguments: "",
    source:
      function_name === "tenant_id"
        ? "SELECT NULLIF(current_setting('steward.tenant_id', true), '')"
        : "SELECT NULLIF(current_setting('steward.user_id', true), '')::uuid",
    settings: ["search_path=pg_catalog"],
    public_execute: false,
    app_execute: true,
  }));
}

function exactBootstrapFunctions() {
  const migration = readFileSync(
    new URL("../../drizzle/0111_tenant_rls_policy_install.sql", import.meta.url),
    "utf8",
  );
  return [...BOOTSTRAP_FUNCTION_SPECS].map(([key, spec]) => {
    const function_name = key.slice(0, key.indexOf("("));
    const identity_arguments = key.slice(key.indexOf("(") + 1, -1);
    const escaped = function_name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const match = migration.match(
      new RegExp(
        `CREATE OR REPLACE FUNCTION\\s+"steward_bootstrap"\\."${escaped}"[\\s\\S]*?AS \\$\\$([\\s\\S]*?)\\$\\$;`,
      ),
    );
    if (!match?.[1]) throw new Error(`missing migration body for ${function_name}`);
    return {
      function_name,
      identity_arguments,
      result_type: spec.result,
      volatility: spec.volatility,
      language_name: spec.language,
      security_definer: true,
      owner_can_login: false,
      owner_inherit: false,
      owner_super: false,
      owner_bypass_rls: true,
      owner_create_db: false,
      owner_create_role: false,
      owner_replication: false,
      settings: ["search_path=pg_catalog"],
      public_execute: false,
      app_execute: true,
      source: match[1],
    };
  });
}

function fakeDatabase(
  options: {
    role?: RoleOverrides;
    relations?: ReturnType<typeof exactRelations>;
    helpers?: ReturnType<typeof exactHelpers>;
    bootstrapFunctions?: ReturnType<typeof exactBootstrapFunctions>;
    aclDrift?: Array<{ object_name: string }>;
    unsafeDefiners?: Array<{ function_name: string }>;
  } = {},
) {
  let calls = 0;
  return {
    async execute() {
      calls += 1;
      if (calls === 1) {
        return [
          {
            role_name: "steward_app",
            session_role_name: "steward_app",
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: false,
            rolbypassrls: false,
            rolcreatedb: false,
            rolcreaterole: false,
            rolreplication: false,
            owns_database: false,
            can_assume_relation_owner: false,
            can_assume_privileged_role: false,
            can_assume_schema_owner: false,
            can_create_protected_schema: false,
            ...options.role,
          },
        ];
      }
      if (calls === 2) return options.relations ?? exactRelations();
      if (calls === 3) return options.helpers ?? exactHelpers();
      if (calls === 4) return options.bootstrapFunctions ?? exactBootstrapFunctions();
      if (calls === 5) return options.aclDrift ?? [];
      return options.unsafeDefiners ?? [];
    },
  };
}

describe("tenant RLS runtime readiness", () => {
  test("accepts an exact activated core catalog under the restricted app role", async () => {
    await expect(assertTenantRlsDatabaseReady(fakeDatabase())).resolves.toBeUndefined();
  });

  test("rejects bypass, ownership, and schema-creation authority", async () => {
    for (const role of [
      { rolsuper: true },
      { rolbypassrls: true },
      { owns_database: true },
      { can_assume_relation_owner: true },
      { can_assume_privileged_role: true },
      { can_assume_schema_owner: true },
      { can_create_protected_schema: true },
      { session_role_name: "privileged_login" },
    ]) {
      await expect(assertTenantRlsDatabaseReady(fakeDatabase({ role }))).rejects.toThrow(
        "RLS_APP_ROLE_UNSAFE",
      );
    }
  });

  test("rejects missing, unclassified, and present-but-unforced relations", async () => {
    await expect(
      assertTenantRlsDatabaseReady(
        fakeDatabase({
          relations: exactRelations().filter((row) => row.relation_name !== "agents"),
        }),
      ),
    ).rejects.toThrow("RLS_INVENTORY_MISSING:agents");

    await expect(
      assertTenantRlsDatabaseReady(
        fakeDatabase({
          relations: [
            ...exactRelations(),
            {
              relation_name: "future_tenant_table",
              relation_kind: "r",
              tenant_column_type: "text",
              owner_oid: 42,
              rls_enabled: false,
              rls_forced: false,
              is_partition: false,
              policies: [],
            },
          ],
        }),
      ),
    ).rejects.toThrow("RLS_INVENTORY_UNCLASSIFIED:future_tenant_table");

    await expect(
      assertTenantRlsDatabaseReady(
        fakeDatabase({
          relations: [
            ...exactRelations(),
            {
              relation_name: "capabilities",
              relation_kind: "r",
              tenant_column_type: "text",
              owner_oid: 42,
              rls_enabled: false,
              rls_forced: false,
              is_partition: false,
              policies: tenantPolicies("agents"),
            },
          ],
        }),
      ),
    ).rejects.toThrow("RLS_ACTIVATION_INCOMPLETE:capabilities");
  });

  test("rejects permissive policy, maintenance-role, and helper tampering", async () => {
    const permissive = exactRelations();
    const agents = permissive.find((row) => row.relation_name === "agents")!;
    agents.policies[0] = {
      ...agents.policies[0],
      using_expression: "true",
      check_expression: "true",
    };
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ relations: permissive })),
    ).rejects.toThrow("RLS_POLICY_DRIFT:agents");

    const broadMaintenance = exactRelations();
    const tenant = broadMaintenance.find((row) => row.relation_name === "tenants")!;
    tenant.policies.at(-1)!.roles = [0];
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ relations: broadMaintenance })),
    ).rejects.toThrow("RLS_MAINTENANCE_POLICY_UNSAFE:tenants");

    const helpers = exactHelpers();
    helpers[0]!.public_execute = true;
    await expect(assertTenantRlsDatabaseReady(fakeDatabase({ helpers }))).rejects.toThrow(
      "RLS_HELPER_DRIFT:tenant_id",
    );

    const wrongBody = exactHelpers();
    wrongBody[0]!.source =
      "SELECT COALESCE(NULLIF(current_setting('steward.tenant_id', true), ''), 'other')";
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ helpers: wrongBody })),
    ).rejects.toThrow("RLS_HELPER_DRIFT:tenant_id");

    const literalWhitespace = exactHelpers();
    literalWhitespace[0]!.source = "SELECT NULLIF(current_setting('steward.tenant_id ', true), '')";
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ helpers: literalWhitespace })),
    ).rejects.toThrow("RLS_HELPER_DRIFT:tenant_id");

    const viewReplacement = exactRelations();
    viewReplacement.find((row) => row.relation_name === "users")!.relation_kind = "v";
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ relations: viewReplacement })),
    ).rejects.toThrow("RLS_RELATION_KIND_UNSAFE:users");

    const bootstrapFunctions = exactBootstrapFunctions();
    bootstrapFunctions[0]!.source += " SELECT 1";
    await expect(
      assertTenantRlsDatabaseReady(fakeDatabase({ bootstrapFunctions })),
    ).rejects.toThrow("RLS_BOOTSTRAP_FUNCTION_DRIFT");

    await expect(
      assertTenantRlsDatabaseReady(
        fakeDatabase({ aclDrift: [{ object_name: "steward_bootstrap.platform_tenants" }] }),
      ),
    ).rejects.toThrow("RLS_BOOTSTRAP_ACL_DRIFT:steward_bootstrap.platform_tenants");

    await expect(
      assertTenantRlsDatabaseReady(
        fakeDatabase({ unsafeDefiners: [{ function_name: "public.dump_agents()" }] }),
      ),
    ).rejects.toThrow("RLS_UNEXPECTED_SECURITY_DEFINER:public.dump_agents()");
  });
});
