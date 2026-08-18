import { describe, expect, test } from "bun:test";
import { type ReadinessCheck, readinessChecksForResponse } from "../services/readiness";

const checks: Record<string, ReadinessCheck> = {
  database: { ok: false, error: "database host unavailable", detail: { host: "db.internal" } },
  redis: { ok: false, required: false, source: "memory", error: "not configured" },
  vault: { ok: true, detail: { backend: "local" } },
};

describe("readiness probe disclosure boundary", () => {
  test("unauthenticated and incorrectly authenticated probes receive booleans only", () => {
    const expected = {
      database: { ok: false },
      redis: { ok: false, required: false },
      vault: { ok: true },
    };
    expect(readinessChecksForResponse(checks, undefined, undefined)).toEqual(expected);
    expect(readinessChecksForResponse(checks, "operator-token", undefined)).toEqual(expected);
    expect(readinessChecksForResponse(checks, "operator-token", "wrong-token")).toEqual(expected);
  });

  test("the exact operator token receives diagnostic details", () => {
    expect(readinessChecksForResponse(checks, "operator-token", "operator-token")).toBe(checks);
  });
});
