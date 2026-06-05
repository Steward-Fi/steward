import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "vault.ts"), "utf8");

describe("transaction id hardening", () => {
  it("rejects reusing a transaction id across agents before upsert", () => {
    const helperStart = vaultSource.indexOf("private async recordSignedTransaction");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const guard = vaultSource.indexOf(
      "Transaction id already belongs to a different agent",
      helperStart,
    );
    const upsert = vaultSource.indexOf(".onConflictDoUpdate", helperStart);
    expect(guard).toBeGreaterThan(helperStart);
    expect(upsert).toBeGreaterThan(guard);
  });
});
