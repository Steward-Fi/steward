import { describe, expect, it } from "bun:test";
import { PublicApiError, sanitizeErrorMessage } from "../services/context";

describe("sanitizeErrorMessage", () => {
  it("returns only deliberately typed client-safe messages", () => {
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

  it("collapses database and infrastructure detail to a generic message", () => {
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
