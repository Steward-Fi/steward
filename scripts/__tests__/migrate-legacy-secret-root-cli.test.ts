import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { parseArgs, validateArgs } from "../migrate-legacy-secret-root";

describe("legacy-root secret migration command contract (SEC-164)", () => {
  it("requires explicit write confirmation", () => {
    expect(() => validateArgs(parseArgs([]))).toThrow("requires --confirm");
    expect(() => validateArgs(parseArgs(["--confirm"]))).not.toThrow();
    expect(() => validateArgs(parseArgs(["--dry-run"]))).not.toThrow();
  });

  it("rejects unknown flags", () => {
    expect(() => parseArgs(["--unsafe"])).toThrow("unknown flag");
  });

  it("enforces preflight before one transactional write phase and never logs plaintext", () => {
    const source = readFileSync(
      new URL("../migrate-legacy-secret-root.ts", import.meta.url),
      "utf8",
    );
    const preflight = source.indexOf("migrateLegacyRootSecrets({ dryRun: true");
    const transaction = source.indexOf("await db.transaction", preflight);
    expect(preflight).toBeGreaterThan(0);
    expect(transaction).toBeGreaterThan(preflight);
    // In-transaction drift guard: a row that fails to authenticate DURING the
    // write pass must abort the whole transaction, not commit a partial walk.
    expect(source).toContain("pg_advisory_xact_lock");
    expect(source).toContain("transaction rolled back");
    expect(source).not.toMatch(/console\.(?:log|error)\([^\n]*(?:plaintext|masterPassword)/);
  });
});
