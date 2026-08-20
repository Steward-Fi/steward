import { describe, expect, test } from "bun:test";
import { assertRlsDeploymentSafety } from "../rls-deployment-safety";
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
  publicDefiner?: boolean;
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
            owns_rls_relation: false,
            has_assumable_privilege: false,
            can_create_protected_schema: false,
            platform_role_safe: true,
            migration_role_safe: true,
            bootstrap_role_safe: true,
          },
        ];
      }
      if (query === 2) return [];
      if (query === 3) {
        let relations = EXPECTED_PUBLIC_RELATIONS.filter(
          (relation) => relation.policy_group === "core" || options?.capabilities,
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
        if (options?.relationDrift) {
          relations.push({
            relation_name: "unexpected_tenant_table",
            relation_kind: "r",
            partition_parents: "",
            relrowsecurity: true,
            relforcerowsecurity: true,
          });
        }
        return relations;
      }
      if (query === 5) {
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
      if (query === 6) return options?.publicDefiner ? [{ identity: "public.hostile()" }] : [];
      if (query === 7) return [];
      if (query === 8) {
        return options?.aclDrift ? [{ object_name: "steward_bootstrap.unknown_authority" }] : [];
      }
      if (query > 8) return [];
      const policies = EXPECTED_RLS_POLICY_DEFINITIONS.filter(
        (policy) => policy.policy_group === "core" || options?.capabilities,
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
      assertRlsDeploymentSafety(database({ publicDefiner: true }), roles),
    ).rejects.toThrow("RLS_DEPLOYMENT_UNKNOWN_EXECUTABLE_SECURITY_DEFINER");
  });
});
