import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface PackageManifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

describe("API production dependency closure", () => {
  test("declares the Bitcoin policy parser as a runtime dependency", async () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dir, "../../package.json"), "utf8"),
    ) as PackageManifest;

    expect(packageJson.dependencies?.["@scure/btc-signer"]).toBe("^2.2.0");
    expect(packageJson.devDependencies?.["@scure/btc-signer"]).toBeUndefined();

    const signer = await import("@scure/btc-signer");
    expect(typeof signer.Address).toBe("function");
  });
});
