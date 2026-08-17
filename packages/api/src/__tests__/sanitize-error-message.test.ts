import { describe, expect, it } from "bun:test";
import { sanitizeErrorMessage } from "../services/context";

// SEC-210: route catch-alls must never return raw internal error text (DB
// constraint names, RPC endpoint details, internal paths). Only deliberately
// client-safe messages pass through; everything else collapses to a generic
// "Internal server error".
describe("sanitizeErrorMessage (SEC-210)", () => {
  it("passes through deliberately client-safe messages", () => {
    expect(sanitizeErrorMessage(new Error("Agent already exists"))).toBe("Agent already exists");
    expect(sanitizeErrorMessage(new Error("Wallet not found"))).toBe("Wallet not found");
    expect(sanitizeErrorMessage(new Error("Unsupported chain: 999"))).toBe(
      "Unsupported chain: 999",
    );
    expect(
      sanitizeErrorMessage(
        new Error("Existing wallet is not mnemonic-recoverable; refusing unsafe restore"),
      ),
    ).toBe("Existing wallet is not mnemonic-recoverable; refusing unsafe restore");
  });

  it("collapses DB constraint/infrastructure detail to a generic message", () => {
    expect(
      sanitizeErrorMessage(
        new Error('duplicate key value violates unique constraint "agents_pkey"'),
      ),
    ).toBe("Internal server error");
    expect(sanitizeErrorMessage(new Error("connect ECONNREFUSED 10.0.0.1:8545"))).toBe(
      "Internal server error",
    );
    expect(
      sanitizeErrorMessage(new Error("Query failed: SELECT * FROM agents WHERE id = $1")),
    ).toBe("Internal server error");
  });

  it("collapses non-Error values to a generic message", () => {
    expect(sanitizeErrorMessage("string failure")).toBe("Internal server error");
    expect(sanitizeErrorMessage(undefined)).toBe("Internal server error");
    expect(sanitizeErrorMessage({ message: "object" })).toBe("Internal server error");
  });
});
