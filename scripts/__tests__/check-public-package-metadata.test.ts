import { describe, expect, test } from "bun:test";
import {
  evaluatePublicPackageMetadata,
  isFullCommitSha,
  isStrictSemverIncrease,
  parseNulDelimitedFiles,
} from "../check-public-package-metadata";

const unchangedVersions = {
  sdk: { base: "1.0.0", head: "1.0.0" },
  react: { base: "1.0.0", head: "1.0.0" },
  "eliza-plugin": { base: "1.0.0", head: "1.0.0" },
  flutter: { base: "0.1.0", head: "0.1.0" },
};

describe("public package metadata check", () => {
  test("treats newlines in filenames as data, not line delimiters", () => {
    const files = parseNulDelimitedFiles(
      new TextEncoder().encode("packages/sdk/src/hostile\npackages/sdk/CHANGELOG.md\0"),
    );
    expect(files).toEqual(["packages/sdk/src/hostile\npackages/sdk/CHANGELOG.md"]);
    expect(
      evaluatePublicPackageMetadata({ changedFiles: files, versions: unchangedVersions }),
    ).toEqual(["packages/sdk changed without a package.json version bump or changelog update"]);
  });

  test("does not accept a package.json touch without an actual version change", () => {
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/sdk/src/index.ts", "packages/sdk/package.json"],
        versions: unchangedVersions,
      }),
    ).toEqual(["packages/sdk changed without a package.json version bump or changelog update"]);
  });

  test("accepts an actual version bump or an exact changelog file", () => {
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/sdk/src/index.ts", "packages/sdk/package.json"],
        versions: { ...unchangedVersions, sdk: { base: "1.0.0", head: "1.0.1" } },
      }),
    ).toEqual([]);
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/react/src/index.ts", "packages/react/CHANGELOG.md"],
        versions: unchangedVersions,
      }),
    ).toEqual([]);
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/flutter/lib/src/client.dart", "packages/flutter/pubspec.yaml"],
        versions: { ...unchangedVersions, flutter: { base: "0.1.0", head: "0.1.1" } },
      }),
    ).toEqual([]);
  });

  test("tracks Flutter through pubspec.yaml and its own changelog", () => {
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/flutter/lib/src/client.dart"],
        versions: unchangedVersions,
      }),
    ).toEqual(["packages/flutter changed without a pubspec.yaml version bump or changelog update"]);
    expect(
      evaluatePublicPackageMetadata({
        changedFiles: ["packages/flutter/lib/src/client.dart", "packages/flutter/CHANGELOG.md"],
        versions: unchangedVersions,
      }),
    ).toEqual([]);
  });

  test("requires a strict semver increase over the immutable event base", () => {
    const changedFiles = ["packages/sdk/src/index.ts", "packages/sdk/package.json"];
    expect(
      evaluatePublicPackageMetadata({
        changedFiles,
        versions: { ...unchangedVersions, sdk: { base: "1.0.1", head: "1.0.1" } },
      }),
    ).toHaveLength(1);
    expect(
      evaluatePublicPackageMetadata({
        changedFiles,
        versions: { ...unchangedVersions, sdk: { base: "1.0.1", head: "1.0.0" } },
      }),
    ).toHaveLength(1);
    expect(isStrictSemverIncrease("1.0.0-beta.2", "1.0.0-beta.10")).toBe(true);
    expect(isStrictSemverIncrease("1.0.0", "1.0.1")).toBe(true);
    expect(isStrictSemverIncrease("1.0.0", "2.0")).toBe(false);
    expect(isStrictSemverIncrease("1.0.0-1", "1.0.0-01")).toBe(false);
    expect(isStrictSemverIncrease("1.0.0", `${"9".repeat(257)}.0.0`)).toBe(false);
  });

  test("rejects malformed or ref-like SHA inputs before invoking git", () => {
    expect(isFullCommitSha("develop")).toBe(false);
    expect(isFullCommitSha("HEAD^{commit}")).toBe(false);
    expect(isFullCommitSha("A".repeat(40))).toBe(false);
    expect(isFullCommitSha("50d4d6b2c111accb6dc2c83eb065f877af304251")).toBe(true);
  });
});
