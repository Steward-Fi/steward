import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

const PACKAGE_ROOT = join(import.meta.dirname, "../..");
const REPOSITORY_ROOT = join(PACKAGE_ROOT, "../..");
const artifactDirectory = mkdtempSync(join(tmpdir(), "steward-eliza-package-"));

let packedPackageJson: {
  dependencies?: Record<string, string>;
};
let packedEntrypoint = "";

beforeAll(() => {
  execFileSync("bunx", ["turbo", "run", "build", "--filter=@stwd/eliza-plugin"], {
    cwd: REPOSITORY_ROOT,
    stdio: "pipe",
  });

  const packOutput = execFileSync(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", artifactDirectory],
    { cwd: PACKAGE_ROOT, encoding: "utf8" },
  );
  const [{ filename }] = JSON.parse(packOutput) as Array<{ filename: string }>;
  const tarball = join(artifactDirectory, filename);
  const extracted = join(artifactDirectory, "extracted");
  mkdirSync(extracted);
  execFileSync("tar", ["-xzf", tarball, "-C", extracted]);

  packedPackageJson = JSON.parse(
    readFileSync(join(extracted, "package/package.json"), "utf8"),
  ) as typeof packedPackageJson;
  packedEntrypoint = readFileSync(join(extracted, "package/dist/index.js"), "utf8");
}, 60_000);

afterAll(() => {
  rmSync(artifactDirectory, { recursive: true, force: true });
});

describe("published package artifact", () => {
  test("contains no workspace protocol runtime dependencies", () => {
    expect(
      Object.values(packedPackageJson.dependencies ?? {}).some((value) =>
        value.startsWith("workspace:"),
      ),
    ).toBe(false);
  });

  test("bundles every @stwd/shared runtime import", () => {
    expect(packedEntrypoint).not.toContain("@stwd/shared");
    expect(packedEntrypoint).toContain("function redactedThrownDiagnostics(");
    expect(packedEntrypoint).toContain("function containsSensitiveCredentialKey(");
  });
});
