import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const PACKAGE_DIR = join(import.meta.dir, "..", "..");
const REPOSITORY_DIR = join(PACKAGE_DIR, "..", "..");

function read(path: string): string {
  return readFileSync(path, "utf8");
}

describe("Solana signer API URL documentation", () => {
  test("active examples follow the API runtime's canonical default port", () => {
    const apiEntry = read(join(REPOSITORY_DIR, "packages", "api", "src", "index.ts"));
    const defaultPort = apiEntry.match(
      /const PORT = parseInt\(process\.env\.PORT \|\| "([0-9]+)", 10\)/,
    )?.[1];

    expect(defaultPort).toBeDefined();
    if (!defaultPort) throw new Error("API entry point no longer declares a default port");

    const activeGuidance = [
      read(join(PACKAGE_DIR, "README.md")),
      read(join(PACKAGE_DIR, "src", "steward-signer.ts")),
    ];
    for (const content of activeGuidance) {
      expect(content).toContain(`http://127.0.0.1:${defaultPort}`);
      expect(content).not.toContain("http://127.0.0.1:3000");
    }
  });
});
