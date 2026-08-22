import { describe, expect, test } from "bun:test";
import {
  assertRlsDeploymentSafety,
  EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION,
} from "../rls-deployment-safety";
import { EXPECTED_RLS_FUNCTION_DEFINITIONS } from "../rls-function-manifest";
import {
  EXPECTED_PUBLIC_RELATIONS,
  EXPECTED_RLS_POLICY_DEFINITIONS,
} from "../rls-policy-manifest.generated";

function database(options?: {
  unsafeRole?: boolean;
  policyDrift?: boolean;
  relationDrift?: boolean;
  capabilities?: boolean;
  partialCapabilities?: boolean;
  aclDrift?: boolean;
  functionDrift?: boolean;
  functionAclDrift?: boolean;
  appAclDrift?: boolean;
  appDatabaseAclDrift?: boolean;
  platformAclDrift?: boolean;
  publicDefiner?: boolean;
  appMembershipDrift?: boolean;
  personalLockDefinitionDrift?: boolean;
  personalLockAclDrift?: boolean;
  trading?: boolean;
  partialTrading?: boolean;
}) {
  let query = 0;
  return {
    async execute() {
      query += 1;
      if (query === 1) {
        return [
          {
            current_user: "steward_app",
            session_user: "steward_app",
            rolcanlogin: true,
            rolinherit: false,
            rolsuper: options?.unsafeRole === true,
            rolbypassrls: false,
            rolcreatedb: false,
            rolcreaterole: false,
            rolreplication: false,
            owns_database: false,
            owns_rls_relation: false,
            has_assumable_privilege: false,
            can_create_protected_schema: false,
            platform_role_safe: true,
            migration_role_safe: true,
            bootstrap_role_safe: true,
            migration_assumable_authority: false,
            app_membership_drift: options?.appMembershipDrift === true,
            bootstrap_membership_drift: false,
          },
        ];
      }
      if (query === 2) return [];
      if (query === 3) {
        const acls = [{ acl: "database:steward:CONNECT:false" }];
        if (options?.appDatabaseAclDrift) {
          acls.push({ acl: "database:steward:CREATE:false" });
        }
        return acls;
      }
      if (query === 4) return [{ database_name: "steward" }];
      if (query === 5) {
        let relations = EXPECTED_PUBLIC_RELATIONS.filter(
          (relation) =>
            relation.policy_group === "core" ||
            (relation.policy_group === "capabilities" && options?.capabilities) ||
            (relation.policy_group === "trading" && options?.trading),
        ).map(({ policy_group: _group, ...relation }) => ({
          ...relation,
          relrowsecurity: EXPECTED_RLS_POLICY_DEFINITIONS.some(
            (policy) => policy.relation_name === relation.relation_name,
          ),
          relforcerowsecurity: EXPECTED_RLS_POLICY_DEFINITIONS.some(
            (policy) => policy.relation_name === relation.relation_name,
          ),
        }));
        if (options?.partialCapabilities) {
          const capability = EXPECTED_PUBLIC_RELATIONS.find(
            (relation) => relation.policy_group === "capabilities",
          );
          if (capability) {
            const { policy_group: _group, ...relation } = capability;
            relations = [
              ...relations,
              { ...relation, relrowsecurity: true, relforcerowsecurity: true },
            ];
          }
        }
        if (options?.partialTrading) {
          const trading = EXPECTED_PUBLIC_RELATIONS.find(
            (relation) => relation.policy_group === "trading",
          );
          if (trading) {
            const { policy_group: _group, ...relation } = trading;
            relations = [
              ...relations,
              { ...relation, relrowsecurity: true, relforcerowsecurity: true },
            ];
          }
        }
        if (options?.relationDrift) {
          relations.push({
            relation_name: "unexpected_tenant_table",
            relation_kind: "r",
            partition_parents: "",
            relrowsecurity: true,
            relforcerowsecurity: true,
          });
        }
        return relations.sort((left, right) =>
          left.relation_name.localeCompare(right.relation_name),
        );
      }
      if (query === 7) {
        const definitions = EXPECTED_RLS_FUNCTION_DEFINITIONS.map((definition) => ({
          identity: definition.identity,
          result: definition.result,
          language: definition.language,
          volatility: definition.volatility,
          parallelism: definition.parallelism,
          security_definer: definition.securityDefiner,
          settings: definition.settings,
          owner: definition.owner === "bootstrap" ? "steward_bootstrap_owner" : "steward_migrator",
          body_md5: definition.bodyMd5,
          public_execute: false,
          app_execute: definition.appExecute,
          platform_execute: definition.platformExecute,
        }));
        if (options?.functionDrift)
          definitions[0] = { ...definitions[0], body_md5: "0".repeat(32) };
        return definitions;
      }
      if (query === 8) {
        const rows = EXPECTED_RLS_FUNCTION_DEFINITIONS.flatMap((definition) => {
          const owner =
            definition.owner === "bootstrap" ? "steward_bootstrap_owner" : "steward_migrator";
          return [
            {
              identity: definition.identity,
              grantee: owner,
              privilege: "EXECUTE",
              grantable: false,
            },
            ...(definition.appExecute
              ? [
                  {
                    identity: definition.identity,
                    grantee: "steward_app",
                    privilege: "EXECUTE",
                    grantable: false,
                  },
                ]
              : []),
            ...(definition.platformExecute
              ? [
                  {
                    identity: definition.identity,
                    grantee: "steward_platform",
                    privilege: "EXECUTE",
                    grantable: false,
                  },
                ]
              : []),
          ];
        });
        if (options?.functionAclDrift) {
          rows.push({
            identity: EXPECTED_RLS_FUNCTION_DEFINITIONS[0].identity,
            grantee: "hostile_role",
            privilege: "EXECUTE",
            grantable: false,
          });
        }
        return rows.sort(
          (left, right) =>
            left.identity.localeCompare(right.identity) ||
            left.grantee.localeCompare(right.grantee),
        );
      }
      if (query === 9) {
        return [
          {
            identity: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.identity,
            result: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.result,
            language: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.language,
            volatility: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.volatility,
            parallelism: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.parallelism,
            security_definer: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.securityDefiner,
            settings: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.settings,
            argument_defaults: EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.argumentDefaults,
            owner: "steward_migrator",
            body_md5: options?.personalLockDefinitionDrift
              ? "0".repeat(32)
              : EXPECTED_PERSONAL_LIFECYCLE_LOCK_DEFINITION.bodyMd5,
          },
        ];
      }
      if (query === 10) {
        const rows = [
          { grantee: "steward_app", privilege: "EXECUTE", grantable: false },
          { grantee: "steward_bootstrap_owner", privilege: "EXECUTE", grantable: false },
          { grantee: "steward_migrator", privilege: "EXECUTE", grantable: false },
        ];
        if (options?.personalLockAclDrift) {
          rows.push({ grantee: "steward_platform", privilege: "EXECUTE", grantable: false });
        }
        return rows.sort((left, right) => left.grantee.localeCompare(right.grantee));
      }
      if (query === 11) {
        const usersInsertColumns = [
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
        ];
        const usersUpdateColumns = [
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
        ];
        const appAcls = [
          "schema:public:USAGE:false",
          "schema:steward_bootstrap:USAGE:false",
          "schema:steward_rls:USAGE:false",
          "function:steward_is_authoritative_wallet_identity(text,text,text,text):EXECUTE:false",
          "function:steward_is_authoritative_wallet_tenant_owner(text,uuid):EXECUTE:false",
          "function:steward_is_reserved_tenant_id(text):EXECUTE:false",
          "function:steward_lock_tenant_deletion(text):EXECUTE:false",
          "function:steward_lock_personal_lifecycle(uuid,text,boolean):EXECUTE:false",
          "function:steward_reserved_tenant_kind(text):EXECUTE:false",
          ...EXPECTED_RLS_FUNCTION_DEFINITIONS.filter((definition) => definition.appExecute).map(
            (definition) => `function:${definition.identity}:EXECUTE:false`,
          ),
          ...EXPECTED_PUBLIC_RELATIONS.filter(
            (relation) =>
              relation.policy_group === "core" ||
              (relation.policy_group === "capabilities" && options?.capabilities) ||
              (relation.policy_group === "trading" && options?.trading),
          ).flatMap((relation) => {
            if (
              relation.relation_name === "retained_user_provider_evidence" ||
              relation.relation_name === "user_identity_subjects"
            )
              return [];
            if (relation.relation_name === "users") {
              return ["relation:public.users:SELECT:false"];
            }
            return ["DELETE", "INSERT", "SELECT", "UPDATE"].map(
              (privilege) => `relation:public.${relation.relation_name}:${privilege}:false`,
            );
          }),
          ...usersInsertColumns.map((column) => `column:public.users.${column}:INSERT:false`),
          ...usersUpdateColumns.map((column) => `column:public.users.${column}:UPDATE:false`),
        ];
        if (options?.appAclDrift) appAcls.push("relation:public.users:TRUNCATE:false");
        return appAcls.sort().map((acl) => ({ acl }));
      }
      if (query === 12) return [];
      if (query === 13) return options?.publicDefiner ? [{ identity: "public.hostile()" }] : [];
      if (query === 14) return [];
      if (query === 15) {
        return options?.aclDrift ? [{ object_name: "steward_bootstrap.unknown_authority" }] : [];
      }
      if (query === 16) return [];
      if (query === 17) {
        const acls = [
          "function:steward_bootstrap.platform_delete_user(uuid):EXECUTE:false",
          "function:steward_bootstrap.platform_personal_tenant_delete(text,boolean):EXECUTE:false",
          "function:steward_bootstrap.platform_provision_user(text,boolean,text,jsonb):EXECUTE:false",
          "function:steward_bootstrap.platform_revoke_user_refresh_tokens(uuid):EXECUTE:false",
          "function:steward_bootstrap.platform_set_user_deactivation(uuid,boolean):EXECUTE:false",
          "function:steward_bootstrap.platform_user_identity(uuid):EXECUTE:false",
          "function:steward_bootstrap.platform_user_tenant_ids(uuid):EXECUTE:false",
          "function:steward_bootstrap.platform_stats():EXECUTE:false",
          "function:steward_bootstrap.platform_tenants(integer,integer):EXECUTE:false",
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
        ];
        if (options?.platformAclDrift) acls.push("relation:public.users:DELETE:false");
        return acls.sort().map((acl) => ({ acl }));
      }
      if (query > 17) return [];
      const policies = EXPECTED_RLS_POLICY_DEFINITIONS.filter(
        (policy) =>
          policy.policy_group === "core" ||
          (policy.policy_group === "capabilities" && options?.capabilities) ||
          (policy.policy_group === "trading" && options?.trading),
      ).map(({ policy_group: _group, ...policy }) => ({ ...policy }));
      if (options?.policyDrift) policies[0] = { ...policies[0], using_expression: "true" };
      return policies;
    },
  };
}

describe("RLS deployment safety gate", () => {
  const roles = {
    expectedRole: "steward_app",
    expectedPlatformRole: "steward_platform",
    expectedBootstrapRole: "steward_bootstrap_owner",
    expectedMigrationRole: "steward_migrator",
  };

  test("accepts only the exact safe role, relation/partition shape, and policies", async () => {
    await expect(assertRlsDeploymentSafety(database(), roles)).resolves.toBeUndefined();
  });

  test("accepts an installed capabilities group even when the plugin is disabled", async () => {
    await expect(
      assertRlsDeploymentSafety(database({ capabilities: true }), {
        ...roles,
      }),
    ).resolves.toBeUndefined();
    await expect(
      assertRlsDeploymentSafety(database({ partialCapabilities: true }), {
        ...roles,
      }),
    ).rejects.toThrow("RLS_DEPLOYMENT_RELATION_INVENTORY_DRIFT");
  });

  test("accepts complete optional trading and combined plugin groups", async () => {
    await expect(
      assertRlsDeploymentSafety(database({ trading: true }), {
        ...roles,
      }),
    ).resolves.toBeUndefined();
    await expect(
      assertRlsDeploymentSafety(database({ capabilities: true, trading: true }), {
        ...roles,
      }),
    ).resolves.toBeUndefined();
  });

  test("rejects a partial optional trading group", async () => {
    await expect(
      assertRlsDeploymentSafety(database({ partialTrading: true }), {
        ...roles,
      }),
    ).rejects.toThrow("RLS_DEPLOYMENT_POLICY_DEFINITION_DRIFT");
  });

  test("rejects unsafe roles, same-count policy replacement, and extra relations", async () => {
    await expect(
      assertRlsDeploymentSafety(database({ unsafeRole: true }), {
        ...roles,
      }),
    ).rejects.toThrow("RLS_DEPLOYMENT_ROLE_UNSAFE");
    await expect(
      assertRlsDeploymentSafety(database({ policyDrift: true }), {
        ...roles,
      }),
    ).rejects.toThrow("RLS_DEPLOYMENT_POLICY_DEFINITION_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ relationDrift: true }), {
        ...roles,
      }),
    ).rejects.toThrow("RLS_DEPLOYMENT_RELATION_INVENTORY_DRIFT");
    await expect(assertRlsDeploymentSafety(database({ aclDrift: true }), roles)).rejects.toThrow(
      "RLS_DEPLOYMENT_ACL_DRIFT",
    );
    await expect(
      assertRlsDeploymentSafety(database({ functionDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_FUNCTION_DEFINITION_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ functionAclDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_FUNCTION_ACL_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ personalLockDefinitionDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_PERSONAL_LIFECYCLE_LOCK_DEFINITION_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ personalLockAclDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_PERSONAL_LIFECYCLE_LOCK_ACL_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ appDatabaseAclDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_APP_DATABASE_ACL_DRIFT");
    await expect(assertRlsDeploymentSafety(database({ appAclDrift: true }), roles)).rejects.toThrow(
      "RLS_DEPLOYMENT_APP_ACL_DRIFT",
    );
    await expect(
      assertRlsDeploymentSafety(database({ platformAclDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_PLATFORM_ACL_DRIFT");
    await expect(
      assertRlsDeploymentSafety(database({ publicDefiner: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_UNKNOWN_EXECUTABLE_SECURITY_DEFINER");
    await expect(
      assertRlsDeploymentSafety(database({ appMembershipDrift: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_ROLE_UNSAFE");
  });
});
