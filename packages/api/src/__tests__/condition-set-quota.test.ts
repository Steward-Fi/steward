import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(
  join(import.meta.dir, "..", "routes", "condition-sets.ts"),
  "utf8",
);

describe("condition set quota enforcement", () => {
  it("enforces item count and value-size limits on append as well as replace", () => {
    expect(routeSource).toContain("MAX_CONDITION_SETS = 100");
    expect(routeSource).toContain("tenant cannot contain more than");
    expect(routeSource).toContain("MAX_CONDITION_SET_DESCRIPTION_LENGTH = 2_000");
    expect(routeSource).toContain("MAX_CONDITION_SET_ITEM_LABEL_LENGTH = 255");
    expect(routeSource).toContain("MAX_CONDITION_SET_ITEMS = 1_000");
    expect(routeSource).toContain("MAX_CONDITION_SET_ITEM_VALUE_LENGTH");
    expect(routeSource).toContain("condition set cannot contain more than");
    expect(routeSource).toContain("pg_advisory_xact_lock");
    expect(routeSource).toContain("shouldUsePostgresAdvisoryLocks()");
  });
});
