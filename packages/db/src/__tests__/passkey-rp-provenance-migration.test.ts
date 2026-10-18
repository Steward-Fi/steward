import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

const migration = readFileSync(
  new URL("../../drizzle/0114_passkey_rp_provenance.sql", import.meta.url),
  "utf8",
);

describe("passkey RP provenance migration", () => {
  test("adds nullable provenance without guessing an RP for legacy rows", () => {
    expect(migration).toContain('ALTER TABLE "authenticators" ADD COLUMN "rp_id" varchar(253)');
    expect(migration).not.toMatch(/NOT NULL/i);
    expect(migration).not.toMatch(/UPDATE\s+"?authenticators"?/i);
    expect(migration).not.toMatch(/DEFAULT/i);
  });
});
