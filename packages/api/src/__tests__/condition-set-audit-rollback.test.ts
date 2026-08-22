import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(
  join(import.meta.dir, "..", "routes", "condition-sets.ts"),
  "utf8",
);

describe("condition set audit atomicity", () => {
  it("uses audited transactions without snapshot restoration for every mutation", () => {
    expect(routeSource).not.toContain("snapshotConditionSetItems");
    expect(routeSource).not.toContain("restoreConditionSet");
    expect(routeSource).not.toContain("restoreConditionSetItems");

    const createStart = routeSource.indexOf('conditionSetRoutes.post("/",');
    const createEnd = routeSource.indexOf("conditionSetRoutes.", createStart + 1);
    const createRoute = routeSource.slice(createStart, createEnd);
    expect(createRoute).toContain("withTenantAuditedTransaction");
    expect(createRoute).toContain("appendRequiredAudit");

    for (const marker of [
      'conditionSetRoutes.patch("/:id",',
      'conditionSetRoutes.delete("/:id",',
      'conditionSetRoutes.post("/:id/items",',
      'conditionSetRoutes.put("/:id/items",',
      'conditionSetRoutes.patch("/:id/items/:itemId",',
      'conditionSetRoutes.delete("/:id/items/:itemId",',
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      // Slice to the next route registration (or EOF) so the whole handler body
      // is captured regardless of nested `});` blocks inside the handler.
      const next = routeSource.indexOf("conditionSetRoutes.", start + marker.length);
      const route = routeSource.slice(start, next === -1 ? undefined : next);
      expect(route).toContain("withTenantAuditedTransaction");
      expect(route).toContain("appendRequiredAudit");
      expect(route).toContain("readLockedConditionSet");
    }
  });
});
