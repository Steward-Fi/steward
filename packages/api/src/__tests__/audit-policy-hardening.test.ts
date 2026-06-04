import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const auditSource = readFileSync(join(apiRoot, "routes", "audit.ts"), "utf8");
const auditServiceSource = readFileSync(join(apiRoot, "services", "audit.ts"), "utf8");
const policiesSource = readFileSync(join(apiRoot, "routes", "policies-standalone.ts"), "utf8");
const conditionSetsSource = readFileSync(join(apiRoot, "routes", "condition-sets.ts"), "utf8");
const tenantConfigSource = readFileSync(join(apiRoot, "routes", "tenant-config.ts"), "utf8");

describe("audit and policy route hardening", () => {
  it("exports approval actions with approval queue metadata", () => {
    const exportStart = auditSource.indexOf('auditRoutes.get("/export"');
    expect(exportStart).toBeGreaterThanOrEqual(0);
    const exportRoute = auditSource.slice(exportStart);
    expect(exportRoute).toContain(".leftJoin(approvalQueue");
    expect(exportRoute).toContain('row.aqStatus === "approved"');
    expect(exportRoute).toContain("approvalStatus=");
    expect(exportRoute).toContain("resolvedBy=");
  });

  it("marks partial audit verification as unanchored", () => {
    const verifyStart = auditSource.indexOf('auditRoutes.post("/verify"');
    expect(verifyStart).toBeGreaterThanOrEqual(0);
    const verifyRoute = auditSource.slice(verifyStart);
    expect(verifyRoute).toContain("anchored: fromSeq === 1");
    expect(verifyRoute).toContain("Partial verification is anchored");
  });

  it("uses constant-time recursive canonical audit verification", () => {
    expect(auditServiceSource).toContain("timingSafeEqual");
    expect(auditServiceSource).toContain("function canonicalJsonValue");
    expect(auditServiceSource).toContain("Object.keys(value as Record<string, unknown>).sort()");
    expect(auditServiceSource).toContain("return timingSafeEqual(a, b)");
  });

  it("bounds audit verification when toSeq is omitted", () => {
    const verifyStart = auditSource.indexOf('auditRoutes.post("/verify"');
    expect(verifyStart).toBeGreaterThanOrEqual(0);
    const verifyRoute = auditSource.slice(verifyStart);
    expect(verifyRoute).toContain("const requestedToSeq = parsedToSeq.value");
    expect(verifyRoute).toContain(
      "const toSeq = requestedToSeq ?? fromSeq + MAX_AUDIT_VERIFY_RANGE - 1",
    );
    expect(verifyRoute).toContain("toSeq - fromSeq + 1 > MAX_AUDIT_VERIFY_RANGE");
  });

  it("does not make deep combined audit log pages unreachable", () => {
    const logStart = auditSource.indexOf('auditRoutes.get("/log"');
    expect(logStart).toBeGreaterThanOrEqual(0);
    const logRoute = auditSource.slice(
      logStart,
      auditSource.indexOf('auditRoutes.get("/summary"', logStart),
    );
    expect(logRoute).toContain(
      "const combinedFetchLimit = wantTx && wantProxy ? offset + limit : limit",
    );
    expect(logRoute).toContain(".limit(wantProxy ? combinedFetchLimit : limit)");
    expect(logRoute).toContain(".limit(wantTx ? combinedFetchLimit : limit)");
    expect(logRoute).not.toContain(".limit(wantProxy ? 1000 : limit)");
    expect(logRoute).not.toContain(".limit(wantTx ? 1000 : limit)");
  });

  it("bounds expensive audit exports and all-time summaries", () => {
    expect(auditSource).toContain("const MAX_AUDIT_EXPORT_RANGE_MS");
    expect(auditSource).toContain("function validateAuditExportRange");
    expect(auditSource).toContain("audit export requires dateFrom and dateTo");
    expect(auditSource).toContain("audit export range must not exceed 31 days");
    expect(auditSource).toContain("STEWARD_ALLOW_UNBOUNDED_AUDIT_SUMMARY");
  });

  it("uses live agent counters for policy simulations with agentId", () => {
    expect(policiesSource).toContain("getTransactionStats");
    expect(policiesSource).toContain("const liveStats = hasAgentSelector");
    expect(policiesSource).toContain('source: "live"');
    expect(policiesSource).toContain('source: "synthetic-zero"');
  });

  it("writes policy template final audit events only after mutations succeed", () => {
    expect(policiesSource).toContain("function policyAuditActor");
    expect(policiesSource).toContain('action: "policy.template.create.authorized"');
    expect(policiesSource).toContain('action: "policy.template.update.authorized"');
    expect(policiesSource).toContain('action: "policy.template.delete.authorized"');
    expect(policiesSource).toContain('action: "policy.template.assign.authorized"');

    const deleteRoute = policiesSource.slice(
      policiesSource.indexOf('policiesStandaloneRoutes.delete("/:id"'),
    );
    expect(deleteRoute.indexOf('action: "policy.template.delete.authorized"')).toBeLessThan(
      deleteRoute.indexOf("const deleted = await deleteTemplate"),
    );
    expect(deleteRoute.indexOf("const deleted = await deleteTemplate")).toBeLessThan(
      deleteRoute.indexOf('action: "policy.template.delete"'),
    );
    expect(deleteRoute).toContain("const actor = policyAuditActor(c, tenantId)");

    const assignRoute = policiesSource.slice(
      policiesSource.indexOf('policiesStandaloneRoutes.post("/:id/assign"'),
    );
    expect(assignRoute.indexOf('action: "policy.template.assign.authorized"')).toBeLessThan(
      assignRoute.indexOf("await db.transaction"),
    );
    expect(assignRoute.indexOf("await db.transaction")).toBeLessThan(
      assignRoute.indexOf('action: "policy.template.assign"'),
    );
  });

  it("writes condition set final audit events only after mutations succeed", () => {
    const updateRoute = conditionSetsSource.slice(
      conditionSetsSource.indexOf('conditionSetRoutes.patch("/:id"'),
    );
    expect(updateRoute.indexOf('action: "condition_set.update.authorized"')).toBeLessThan(
      updateRoute.indexOf(".update(conditionSets)"),
    );
    expect(updateRoute.indexOf(".returning()")).toBeLessThan(
      updateRoute.indexOf("if (!row) return c.json<ApiResponse>"),
    );
    expect(updateRoute.indexOf("if (!row) return c.json<ApiResponse>")).toBeLessThan(
      updateRoute.indexOf('action: "condition_set.update"'),
    );

    const replaceRoute = conditionSetsSource.slice(
      conditionSetsSource.indexOf('conditionSetRoutes.put("/:id/items"'),
    );
    expect(replaceRoute.indexOf('action: "condition_set.items.replace.authorized"')).toBeLessThan(
      replaceRoute.indexOf("await db.transaction"),
    );
    expect(replaceRoute).toContain("const [currentSet] = await tx");
    expect(replaceRoute).toContain("if (!currentSet) return null");
    expect(replaceRoute.indexOf("if (!rows) return c.json<ApiResponse>")).toBeLessThan(
      replaceRoute.indexOf('action: "condition_set.items.replace"'),
    );
  });

  it("does not collapse tenant config update audit actors to the tenant id", () => {
    const configRoute = tenantConfigSource.slice(
      tenantConfigSource.indexOf('tenantConfigRoutes.put("/:id/config"'),
    );
    expect(configRoute).toContain('action: "tenant.config.update.authorized"');
    expect(configRoute).toContain('action: "tenant.config.update"');
    expect(configRoute).toContain('actorId: c.get("userId") ?? tenantId');
    expect(configRoute).not.toContain('actorId: tenantId,\n    action: "tenant.config.update"');
  });
});
