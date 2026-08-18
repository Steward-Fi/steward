import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PublicApiError, sanitizeErrorMessage } from "../services/context";

// SEC-210: route catch-alls must never return raw internal error text (DB
// constraint names, RPC endpoint details, internal paths). Only deliberately
// client-safe messages pass through; everything else collapses to a generic
// "Internal server error".
describe("sanitizeErrorMessage (SEC-210)", () => {
  it("passes through only deliberately typed client-safe messages", () => {
    expect(sanitizeErrorMessage(new PublicApiError("resource_already_exists"))).toBe(
      "Resource already exists",
    );
    expect(sanitizeErrorMessage(new PublicApiError("resource_not_found"))).toBe(
      "Resource not found",
    );
    expect(sanitizeErrorMessage(new PublicApiError("unsupported_chain"))).toBe("Unsupported chain");
    expect(sanitizeErrorMessage(new Error("secret table not found: credentials"))).toBe(
      "Internal server error",
    );
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

  it("keeps account, global-wallet, and OAuth infrastructure errors behind the sanitizer", () => {
    const routesDir = join(import.meta.dir, "..", "routes");
    const accountsSource = readFileSync(join(routesDir, "accounts.ts"), "utf8");
    const globalWalletSource = readFileSync(join(routesDir, "global-wallet.ts"), "utf8");
    const userSource = readFileSync(join(routesDir, "user.ts"), "utf8");

    expect(accountsSource).not.toContain(
      'error instanceof Error ? error.message : "Failed to create account"',
    );
    expect(accountsSource).not.toContain(
      'error instanceof Error ? error.message : "Failed to create account aggregation"',
    );
    expect(globalWalletSource).not.toContain("Global wallet signing failed");
    expect(globalWalletSource).not.toContain("Global wallet typed-data signing failed");
    expect(globalWalletSource).not.toContain("Global wallet transaction execution failed");
    expect(userSource).not.toContain(
      'err instanceof Error ? err.message : "Provider not configured"',
    );
    expect(userSource).not.toContain(
      'err instanceof Error ? err.message : "Token exchange failed"',
    );
    expect(userSource).not.toContain(
      'err instanceof Error ? err.message : "Failed to fetch user info"',
    );
  });
});
