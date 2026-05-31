import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routesDir = join(import.meta.dir, "..", "routes");
const policiesSource = readFileSync(join(routesDir, "policies-standalone.ts"), "utf8");
const conditionSetsSource = readFileSync(join(routesDir, "condition-sets.ts"), "utf8");

function expectRecentMfaGate(source: string, marker: string, reason: string) {
  const start = source.indexOf(marker);
  expect(start).toBeGreaterThanOrEqual(0);
  const adminCheck = source.indexOf("requireTenantAdminSession(c)", start);
  const mfaCheck = source.indexOf(`requireRecentAdminMfa(c, "${reason}")`, start);
  expect(adminCheck).toBeGreaterThan(start);
  expect(mfaCheck).toBeGreaterThan(adminCheck);
}

describe("policy and condition-set MFA hardening", () => {
  it("requires recent MFA for policy template reads and mutations", () => {
    for (const [marker, reason] of [
      ['policiesStandaloneRoutes.get("/",', "Policy template access"],
      ['policiesStandaloneRoutes.post("/",', "Policy template creation"],
      ['policiesStandaloneRoutes.get("/:id",', "Policy template access"],
      ['policiesStandaloneRoutes.put("/:id",', "Policy template updates"],
      ['policiesStandaloneRoutes.delete("/:id",', "Policy template deletion"],
      ['policiesStandaloneRoutes.post("/:id/assign",', "Policy template assignment"],
    ] as const) {
      expectRecentMfaGate(policiesSource, marker, reason);
    }
  });

  it("requires recent MFA for simulations that use stored policy state", () => {
    const start = policiesSource.indexOf('policiesStandaloneRoutes.post("/simulate"');
    expect(start).toBeGreaterThanOrEqual(0);
    const storedStateCheck = policiesSource.indexOf("hasPolicySelector || hasAgentSelector", start);
    expect(storedStateCheck).toBeGreaterThan(start);
    expect(policiesSource.indexOf('Object.hasOwn(body, "policyId")', start)).toBeGreaterThan(start);
    expect(policiesSource.indexOf('Object.hasOwn(body, "agentId")', start)).toBeGreaterThan(start);
    expect(policiesSource.indexOf("Invalid policy template id format", start)).toBeLessThan(
      storedStateCheck,
    );
    expect(policiesSource.indexOf("Invalid agent id format", start)).toBeLessThan(storedStateCheck);
    expect(
      policiesSource.indexOf("requireTenantAdminSession(c)", storedStateCheck),
    ).toBeGreaterThan(storedStateCheck);
    expect(
      policiesSource.indexOf(
        'requireRecentAdminMfa(c, "Stored policy simulation")',
        storedStateCheck,
      ),
    ).toBeGreaterThan(storedStateCheck);
  });

  it("requires recent MFA for inline condition-set simulations", () => {
    const start = policiesSource.indexOf('policiesStandaloneRoutes.post("/simulate"');
    expect(start).toBeGreaterThanOrEqual(0);
    const inlineRulesStart = policiesSource.indexOf(
      "body.rules && Array.isArray(body.rules)",
      start,
    );
    expect(inlineRulesStart).toBeGreaterThan(start);
    const conditionSetCheck = policiesSource.indexOf(
      "hasConditionSetRule(body.rules)",
      inlineRulesStart,
    );
    expect(conditionSetCheck).toBeGreaterThan(inlineRulesStart);
    expect(
      policiesSource.indexOf("requireTenantAdminSession(c)", conditionSetCheck),
    ).toBeGreaterThan(conditionSetCheck);
    expect(
      policiesSource.indexOf(
        'requireRecentAdminMfa(c, "Inline condition-set simulation")',
        conditionSetCheck,
      ),
    ).toBeGreaterThan(conditionSetCheck);
  });

  it("requires recent MFA for condition-set reads and mutations", () => {
    for (const [marker, reason] of [
      ['conditionSetRoutes.get("/",', "Condition set access"],
      ['conditionSetRoutes.post("/",', "Condition set creation"],
      ['conditionSetRoutes.get("/:id",', "Condition set access"],
      ['conditionSetRoutes.patch("/:id",', "Condition set updates"],
      ['conditionSetRoutes.delete("/:id",', "Condition set deletion"],
      ['conditionSetRoutes.get("/:id/items",', "Condition set item access"],
      ['conditionSetRoutes.post("/:id/items",', "Condition set item updates"],
      ['conditionSetRoutes.put("/:id/items",', "Condition set item replacement"],
      ['conditionSetRoutes.delete("/:id/items/:itemId",', "Condition set item deletion"],
    ] as const) {
      expectRecentMfaGate(conditionSetsSource, marker, reason);
    }
  });
});
