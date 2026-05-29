import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(
  join(import.meta.dir, "..", "routes", "policies-standalone.ts"),
  "utf8",
);
const tenantConfigSource = readFileSync(
  join(import.meta.dir, "..", "routes", "tenant-config.ts"),
  "utf8",
);

describe("policy template audit rollback hardening", () => {
  it("rolls back template CRUD mutations if final audit events fail", () => {
    expect(routeSource).toContain("async function restoreTemplateSnapshot");
    expect(routeSource).toContain("DELETE FROM policy_templates WHERE id = ${snapshot.id}::uuid");
    expect(routeSource).toContain("INSERT INTO policy_templates");

    const createStart = routeSource.indexOf('policiesStandaloneRoutes.post("/")');
    const createRoute = routeSource.slice(
      createStart,
      routeSource.indexOf('policiesStandaloneRoutes.get("/:id"', createStart),
    );
    expect(createRoute).toContain('action: "policy.template.create.authorized"');
    expect(createRoute).toContain('action: "policy.template.create"');
    expect(createRoute).toContain("try {");
    expect(createRoute).toContain("deleteTemplate(tenantId, template.id)");

    const updateStart = routeSource.indexOf('policiesStandaloneRoutes.put("/:id"');
    const updateRoute = routeSource.slice(
      updateStart,
      routeSource.indexOf('policiesStandaloneRoutes.delete("/:id"', updateStart),
    );
    expect(updateRoute).toContain('action: "policy.template.update.authorized"');
    expect(updateRoute).toContain('action: "policy.template.update"');
    expect(updateRoute).toContain("const before = await getTemplate(tenantId, id)");
    expect(updateRoute).toContain("restoreTemplateSnapshot(before)");

    const deleteStart = routeSource.indexOf('policiesStandaloneRoutes.delete("/:id"');
    const deleteRoute = routeSource.slice(
      deleteStart,
      routeSource.indexOf('policiesStandaloneRoutes.post("/:id/assign"', deleteStart),
    );
    expect(deleteRoute).toContain('action: "policy.template.delete.authorized"');
    expect(deleteRoute).toContain('action: "policy.template.delete"');
    expect(deleteRoute).toContain("const existing = await getTemplate(tenantId, id)");
    expect(deleteRoute).toContain("restoreTemplateSnapshot(existing)");
  });

  it("restores prior agent policies if final template assignment audit fails", () => {
    expect(routeSource).toContain("type PolicyRow = typeof policies.$inferSelect");
    expect(routeSource).toContain("async function snapshotAgentPolicies");
    expect(routeSource).toContain("async function restoreAgentPolicies");
    expect(routeSource).toContain("inArray(policies.agentId, agentIds)");

    const assignStart = routeSource.indexOf('policiesStandaloneRoutes.post("/templates/:id/assign"');
    expect(assignStart).toBeGreaterThanOrEqual(0);
    const assignRoute = routeSource.slice(assignStart);

    expect(assignRoute).toContain('action: "policy.template.assign.authorized"');
    expect(assignRoute).toContain("const previousPolicies = await snapshotAgentPolicies(uniqueAgentIds)");
    expect(assignRoute).toContain('action: "policy.template.assign"');
    expect(assignRoute).toContain("try {");
    expect(assignRoute).toContain("restoreAgentPolicies(uniqueAgentIds, previousPolicies)");
  });

  it("restores prior agent policies if tenant config template apply final audit fails", () => {
    expect(tenantConfigSource).toContain("type AgentPolicyRow = typeof policies.$inferSelect");
    expect(tenantConfigSource).toContain("async function snapshotAgentPolicies");
    expect(tenantConfigSource).toContain("async function restoreAgentPolicies");

    const applyStart = tenantConfigSource.indexOf(
      'tenantConfigRoutes.post("/:id/config/templates/:name/apply"',
    );
    expect(applyStart).toBeGreaterThanOrEqual(0);
    const applyRoute = tenantConfigSource.slice(applyStart);
    const snapshot = applyRoute.indexOf("const previousPolicies = await snapshotAgentPolicies");
    const mutation = applyRoute.indexOf("const insertedPolicies = await db.transaction");
    const finalAudit = applyRoute.indexOf('action: "policy.template.apply"', mutation);
    const rollback = applyRoute.indexOf("restoreAgentPolicies(body.agentId, previousPolicies)");
    expect(snapshot).toBeGreaterThanOrEqual(0);
    expect(snapshot).toBeLessThan(mutation);
    expect(finalAudit).toBeGreaterThan(mutation);
    expect(rollback).toBeGreaterThan(finalAudit);
  });
});
