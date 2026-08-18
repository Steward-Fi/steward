import { describe, expect, it } from "bun:test";
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
});
