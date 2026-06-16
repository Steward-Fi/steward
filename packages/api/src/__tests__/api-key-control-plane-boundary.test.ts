import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routesDir = join(import.meta.dir, "..", "routes");
const secretsSource = readFileSync(join(routesDir, "secrets.ts"), "utf8");
const policiesSource = readFileSync(join(routesDir, "policies-standalone.ts"), "utf8");
const conditionSetsSource = readFileSync(join(routesDir, "condition-sets.ts"), "utf8");
const agentsSource = readFileSync(join(routesDir, "agents.ts"), "utf8");

function routeStart(source: string, marker: string): number {
  const direct = source.indexOf(marker);
  if (direct >= 0) return direct;
  const inlineAsync = source.indexOf(marker.replace('")', '", async'));
  if (inlineAsync >= 0) return inlineAsync;
  return source.indexOf(marker.replace('")', '",'));
}

function expectAdminBeforeTenantLevel(source: string, marker: string) {
  const start = routeStart(source, marker);
  expect(start).toBeGreaterThanOrEqual(0);
  const adminCheck = source.indexOf("requireTenantAdminSession(c)", start);
  const adminOrApiKeyCheck = source.indexOf("requireTenantAdminOrApiKey(c)", start);
  const mfaAdminCheck = source.indexOf("requireRecentTenantAdminMfa(c", start);
  const boundaryCheck =
    [adminCheck, adminOrApiKeyCheck, mfaAdminCheck]
      .filter((index) => index >= 0)
      .sort((a, b) => a - b)[0] ?? -1;
  const tenantLevelCheck = source.indexOf("requireTenantLevel(c)", start);
  expect(boundaryCheck).toBeGreaterThan(start);
  expect(tenantLevelCheck === -1 || boundaryCheck < tenantLevelCheck).toBe(true);
}

describe("API key control-plane boundary", () => {
  it("requires recent MFA for secret vault and injection route reads and mutations", () => {
    expect(secretsSource).toContain("function requireRecentTenantAdminMfa");
    for (const [marker, reason] of [
      ['secretsRoutes.get("/")', "Secret management"],
      ['secretsRoutes.post("/")', "Secret management"],
      ['secretsRoutes.get("/routes")', "Route management"],
      ['secretsRoutes.post("/routes")', "Route management"],
      ['secretsRoutes.put("/routes/:id")', "Route management"],
      ['secretsRoutes.delete("/routes/:id")', "Route management"],
      ['secretsRoutes.get("/:id")', "Secret management"],
      ['secretsRoutes.put("/:id")', "Secret management"],
      ['secretsRoutes.delete("/:id")', "Secret management"],
      ['secretsRoutes.post("/:id/rotate")', "Secret management"],
    ] as const) {
      const start = routeStart(secretsSource, marker);
      expect(start).toBeGreaterThanOrEqual(0);
      expect(
        secretsSource.indexOf(`requireRecentTenantAdminMfa(c, "${reason}")`, start),
      ).toBeGreaterThan(start);
    }
  });

  it("does not allow tenant API keys to mutate secret vault or injection routes", () => {
    for (const marker of [
      'secretsRoutes.post("/")',
      'secretsRoutes.post("/routes")',
      'secretsRoutes.put("/routes/:id")',
      'secretsRoutes.delete("/routes/:id")',
      'secretsRoutes.put("/:id")',
      'secretsRoutes.delete("/:id")',
      'secretsRoutes.post("/:id/rotate")',
    ]) {
      expectAdminBeforeTenantLevel(secretsSource, marker);
    }
  });

  it("does not allow tenant API keys to enumerate secret vault metadata or injection routes", () => {
    for (const marker of [
      'secretsRoutes.get("/")',
      'secretsRoutes.get("/routes")',
      'secretsRoutes.get("/:id")',
    ]) {
      expectAdminBeforeTenantLevel(secretsSource, marker);
    }
  });

  it("does not allow tenant API keys to read or mutate policy templates or condition sets", () => {
    for (const marker of [
      'policiesStandaloneRoutes.get("/")',
      'policiesStandaloneRoutes.post("/")',
      'policiesStandaloneRoutes.get("/:id")',
      'policiesStandaloneRoutes.put("/:id")',
      'policiesStandaloneRoutes.delete("/:id")',
      'policiesStandaloneRoutes.post("/:id/assign")',
    ]) {
      expectAdminBeforeTenantLevel(policiesSource, marker);
    }

    for (const marker of [
      'conditionSetRoutes.get("/")',
      'conditionSetRoutes.post("/")',
      'conditionSetRoutes.get("/:id")',
      'conditionSetRoutes.patch("/:id")',
      'conditionSetRoutes.delete("/:id")',
      'conditionSetRoutes.get("/:id/items")',
      'conditionSetRoutes.post("/:id/items")',
      'conditionSetRoutes.put("/:id/items")',
      'conditionSetRoutes.delete("/:id/items/:itemId")',
    ]) {
      expectAdminBeforeTenantLevel(conditionSetsSource, marker);
    }
  });

  it("keeps agent admin routes behind the tenant-admin gate before tenant-level fallback", () => {
    for (const marker of [
      'agentRoutes.post("/")',
      'agentRoutes.post("/:agentId/token")',
      'agentRoutes.post("/:agentId/wallets")',
      'agentRoutes.delete("/:agentId")',
      'agentRoutes.post("/batch")',
      'agentRoutes.put("/:agentId/policies")',
    ]) {
      expectAdminBeforeTenantLevel(agentsSource, marker);
    }
  });
});
