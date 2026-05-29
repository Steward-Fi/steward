import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "condition-sets.ts"), "utf8");

describe("condition set audit rollback hardening", () => {
  it("restores condition sets and items when final audit writes fail", () => {
    expect(routeSource).toContain("type ConditionSetRow = typeof conditionSets.$inferSelect");
    expect(routeSource).toContain(
      "type ConditionSetItemRow = typeof conditionSetItems.$inferSelect",
    );
    expect(routeSource).toContain("async function snapshotConditionSetItems");
    expect(routeSource).toContain("async function restoreConditionSet");
    expect(routeSource).toContain("async function restoreConditionSetItems");

    for (const [marker, rollback] of [
      ['conditionSetRoutes.post("/",', "db\n        .delete(conditionSets)"],
      ['conditionSetRoutes.patch("/:id",', "restoreConditionSet(tenantId, current"],
      ['conditionSetRoutes.delete("/:id",', "restoreConditionSet(tenantId, current, currentItems)"],
      ['conditionSetRoutes.post("/:id/items",', "restoreConditionSetItems(tenantId, set.id"],
      ['conditionSetRoutes.put("/:id/items",', "restoreConditionSetItems(tenantId, set.id"],
      [
        'conditionSetRoutes.delete("/:id/items/:itemId",',
        "restoreConditionSetItems(tenantId, set.id",
      ],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      // Slice to the next route registration (or EOF) so the whole handler body
      // is captured regardless of nested `});` blocks inside the handler.
      const next = routeSource.indexOf("conditionSetRoutes.", start + marker.length);
      const route = routeSource.slice(start, next === -1 ? undefined : next);
      expect(route).toContain("try {");
      expect(route).toContain(rollback);
    }
  });
});
