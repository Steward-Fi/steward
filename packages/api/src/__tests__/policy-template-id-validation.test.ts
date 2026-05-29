import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(
  join(import.meta.dir, "..", "routes", "policies-standalone.ts"),
  "utf8",
);

describe("policy template id validation", () => {
  it("rejects malformed UUID path params before raw SQL uuid casts", () => {
    expect(routeSource).toContain("const UUID_RE =");
    expect(routeSource).toContain("function isValidTemplateId");
    expect(routeSource).toContain("Invalid policy template id format");

    for (const marker of [
      'policiesStandaloneRoutes.get("/:id"',
      'policiesStandaloneRoutes.put("/:id"',
      'policiesStandaloneRoutes.delete("/:id"',
      'policiesStandaloneRoutes.post("/:id/assign"',
    ]) {
      const routeStart = routeSource.indexOf(marker);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const validation = routeSource.indexOf("isValidTemplateId(id)", routeStart);
      const firstTemplateRead = routeSource.indexOf("getTemplate(tenantId, id)", routeStart);
      expect(validation).toBeGreaterThan(routeStart);
      expect(firstTemplateRead === -1 || validation < firstTemplateRead).toBe(true);
    }
  });
});
