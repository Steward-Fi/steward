import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(
  join(import.meta.dir, "..", "routes", "policies-standalone.ts"),
  "utf8",
);

describe("policy template quota enforcement", () => {
  it("locks tenant template quota checks with the insert", () => {
    expect(routeSource).toContain("insertTemplateWithQuota");
    expect(routeSource).toContain("pg_advisory_xact_lock");
    expect(routeSource).toContain("policy_templates:");
    const helperStart = routeSource.indexOf("insertTemplateWithQuota");
    expect(routeSource.indexOf("SELECT count(*)::integer AS count", helperStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO policy_templates", helperStart),
    );
  });
});
