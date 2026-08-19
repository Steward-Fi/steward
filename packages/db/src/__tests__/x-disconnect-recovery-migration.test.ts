import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const migration = readFileSync(
  join(import.meta.dir, "..", "..", "drizzle", "0107_x_disconnect_route_recovery.sql"),
  "utf8",
);

describe("X disconnect route recovery migration", () => {
  test("extends the merged lifecycle without rewriting prior recovery migrations", () => {
    expect(migration).toContain('ADD COLUMN "disabled_routes" jsonb');
    expect(migration).not.toContain("DROP CONSTRAINT");
    expect(migration).not.toContain('ADD COLUMN "kind"');
    expect(migration).not.toContain('ADD COLUMN "attempts"');
    expect(migration).not.toContain('ADD COLUMN "next_retry_at"');
  });
});
