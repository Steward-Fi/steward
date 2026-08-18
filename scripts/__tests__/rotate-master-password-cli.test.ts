import { describe, expect, it } from "bun:test";
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
