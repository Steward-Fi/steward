import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const vaultSource = readFileSync(join(import.meta.dir, "..", "vault.ts"), "utf8");

describe("transaction id hardening", () => {
  it("rejects reusing a transaction id across agents before upsert", () => {
    const signStart = vaultSource.indexOf("async signTransaction");
    expect(signStart).toBeGreaterThanOrEqual(0);
    const guard = vaultSource.indexOf(
      "Transaction id already belongs to a different agent",
      signStart,
    );
    const upsert = vaultSource.indexOf(".onConflictDoUpdate", signStart);
    expect(guard).toBeGreaterThan(signStart);
    expect(upsert).toBeGreaterThan(guard);
  });
});
