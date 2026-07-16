import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { ALL_TABLES, parseArgs, validateArgs } from "../rotate-master-password";

describe("master-password rotation command contract", () => {
  it("requires explicit write confirmation", () => {
    expect(() => validateArgs(parseArgs([]))).toThrow("requires --confirm");
    expect(() => validateArgs(parseArgs(["--confirm"]))).not.toThrow();
  });

  it("permits table scoping only for no-write diagnostics", () => {
    expect(() => validateArgs(parseArgs(["--table", "secrets", "--confirm"]))).toThrow(
      "complete inventory rotation is mandatory",
    );
    expect(() => validateArgs(parseArgs(["--dry-run", "--table", "secrets"]))).not.toThrow();
  });

  it("rejects unknown flags and inventory names", () => {
    expect(() => parseArgs(["--unsafe"])).toThrow("unknown flag");
    expect(() => parseArgs(["--table", "not_a_table"])).toThrow("--table must be one of");
  });

  it("enforces preflight before one transactional write phase and never logs plaintext", () => {
    const source = readFileSync(new URL("../rotate-master-password.ts", import.meta.url), "utf8");
    const preflight = source.indexOf("const preflight: RotateResult[]");
    const transaction = source.indexOf("await db.transaction", preflight);
    expect(preflight).toBeGreaterThan(0);
    expect(transaction).toBeGreaterThan(preflight);
    expect(source.match(/if \(failures\.length > 0\)/g)?.length).toBe(1);
    expect(source).toContain("await db.transaction");
    expect(source).toContain("transaction rolled back");
    expect(source).not.toMatch(/console\.(?:log|error)\([^\n]*(?:plaintext|oldPw|newPw)/);
  });

  it("keeps every persistent encrypted inventory class in the mandatory set", () => {
    expect(ALL_TABLES).toEqual([
      "encrypted_keys",
      "encrypted_chain_keys",
      "secrets",
      "accounts",
      "tenant_request_signing_keys",
      "pending_proxy_requests",
      "tenant_email_configs",
      "webhook_configs",
    ]);
  });
});
