import { describe, expect, test } from "bun:test";
import { resolveMigrationTimeouts } from "../migrate";

describe("migration startup deadlines", () => {
  test("uses bounded defaults for connect, lock, statement, and overall execution", () => {
    expect(resolveMigrationTimeouts({})).toEqual({
      connectTimeoutSeconds: 10,
      lockTimeoutMs: 30_000,
      statementTimeoutMs: 120_000,
      overallTimeoutMs: 180_000,
    });
  });

  test("accepts explicit positive integer overrides", () => {
    expect(
      resolveMigrationTimeouts({
        STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS: "7",
        STEWARD_MIGRATION_LOCK_TIMEOUT_MS: "8000",
        STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS: "9000",
        STEWARD_MIGRATION_OVERALL_TIMEOUT_MS: "10000",
      }),
    ).toEqual({
      connectTimeoutSeconds: 7,
      lockTimeoutMs: 8_000,
      statementTimeoutMs: 9_000,
      overallTimeoutMs: 10_000,
    });
  });

  test.each(["0", "-1", "1.5", "not-a-number"])("rejects invalid deadline value %s", (value) => {
    expect(() => resolveMigrationTimeouts({ STEWARD_MIGRATION_LOCK_TIMEOUT_MS: value })).toThrow(
      "STEWARD_MIGRATION_LOCK_TIMEOUT_MS must be a positive integer",
    );
  });
});
