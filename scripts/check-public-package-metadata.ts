#!/usr/bin/env bun

/**
 * Validate public-package release metadata for an immutable PR base/head pair.
 *
 * Security properties:
 * - only full SHA-1 object IDs are accepted (no attacker-controlled refspecs),
 * - fork commits are verified locally and never fetched by raw object ID,
 * - filenames are read with `-z` (newlines and other metacharacters are data),
 * - merely touching package.json is not called a version bump.
 */

const PUBLIC_PACKAGES = ["sdk", "react", "eliza-plugin"] as const;
const FULL_SHA1 = /^[0-9a-f]{40}$/;
const CHANGELOG_NAMES = new Set(["CHANGELOG.md", "CHANGELOG", "changelog.md"]);
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function isFullCommitSha(value: string | undefined): value is string {
  return typeof value === "string" && FULL_SHA1.test(value);
}

function comparePrerelease(left: string | undefined, right: string | undefined): number {
  if (left === right) return 0;
  if (left === undefined) return 1;
  if (right === undefined) return -1;
  const leftParts = left.split(".");
  const rightParts = right.split(".");
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const a = leftParts[index];
    const b = rightParts[index];
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    if (a === b) continue;
    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) return BigInt(a) < BigInt(b) ? -1 : 1;
    if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
    return a < b ? -1 : 1;
  }
  return 0;
}

export function isStrictSemverIncrease(base: string | null, head: string | null): boolean {
  if (base === null || head === null) return false;
  const before = SEMVER.exec(base);
  const after = SEMVER.exec(head);
  if (!before || !after) return false;
  for (const prerelease of [before[4], after[4]]) {
    if (prerelease?.split(".").some((part) => /^\d+$/.test(part) && part.length > 1 && part[0] === "0")) {
      return false;
    }
  }
  for (let index = 1; index <= 3; index += 1) {
    const left = BigInt(before[index]);
    const right = BigInt(after[index]);
    if (left !== right) return right > left;
  }
  return comparePrerelease(before[4], after[4]) < 0;
}

export interface PackageMetadataInput {
  changedFiles: readonly string[];
  versions: Readonly<Record<string, { base: string | null; head: string | null }>>;
}

export function evaluatePublicPackageMetadata(input: PackageMetadataInput): string[] {
  const errors: string[] = [];
  for (const pkg of PUBLIC_PACKAGES) {
    const prefix = `packages/${pkg}/`;
    const relative = input.changedFiles
      .filter((file) => file.startsWith(prefix))
      .map((file) => file.slice(prefix.length));
    if (relative.length === 0) continue;

    const changelogChanged = relative.some((file) => CHANGELOG_NAMES.has(file));
    const packageJsonChanged = relative.includes("package.json");
    const version = input.versions[pkg];
    const versionBumped =
      packageJsonChanged && isStrictSemverIncrease(version?.base ?? null, version?.head ?? null);

    if (!changelogChanged && !versionBumped) {
      errors.push(
        `${prefix.slice(0, -1)} changed without a package.json version bump or changelog update`,
      );
    }
  }
  return errors;
}

function git(args: string[]): Uint8Array {
  const result = Bun.spawnSync(["git", ...args], { stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    const detail = new TextDecoder().decode(result.stderr).trim();
    throw new Error(`git ${args[0] ?? "command"} failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout;
}

function hasCommit(sha: string): boolean {
  return (
    Bun.spawnSync(["git", "cat-file", "-e", `${sha}^{commit}`], {
      stdout: "ignore",
      stderr: "ignore",
    }).exitCode === 0
  );
}

function ensureCommit(sha: string): void {
  if (!hasCommit(sha)) {
    throw new Error(`pull request commit is not present in the checkout: ${sha}`);
  }
}

function readVersion(commit: string, pkg: string): string | null {
  const result = Bun.spawnSync(["git", "show", `${commit}:packages/${pkg}/package.json`], {
    stdout: "pipe",
    stderr: "ignore",
  });
  if (result.exitCode !== 0) return null;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(result.stdout)) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : null;
  } catch {
    return null;
  }
}

export function parseNulDelimitedFiles(bytes: Uint8Array): string[] {
  return new TextDecoder()
    .decode(bytes)
    .split("\0")
    .filter((file) => file.length > 0);
}

export function main(argv: string[]): number {
  const [baseSha, headSha] = argv;
  if (!isFullCommitSha(baseSha) || !isFullCommitSha(headSha)) {
    console.error("::error::base and head must be full lowercase 40-character commit SHAs");
    return 2;
  }

  try {
    ensureCommit(baseSha);
    ensureCommit(headSha);
    const mergeBase = new TextDecoder().decode(git(["merge-base", baseSha, headSha])).trim();
    if (!FULL_SHA1.test(mergeBase)) throw new Error("no valid merge base for PR commits");

    const changedFiles = parseNulDelimitedFiles(
      git(["diff", "--name-only", "-z", `${mergeBase}..${headSha}`]),
    );
    const versions: Record<string, { base: string | null; head: string | null }> = {};
    for (const pkg of PUBLIC_PACKAGES) {
      versions[pkg] = {
        // Changed-file attribution remains three-dot/merge-base based, but a
        // release version must advance beyond the immutable event base. If the
        // base branch independently reached the same version as the PR, the PR
        // must choose another version (or add a changelog) before merging.
        base: readVersion(baseSha, pkg),
        head: readVersion(headSha, pkg),
      };
    }
    const errors = evaluatePublicPackageMetadata({ changedFiles, versions });
    for (const error of errors) console.error(`::error::${error}`);
    return errors.length === 0 ? 0 : 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : "metadata validation failed";
    console.error(`::error::${message}`);
    return 2;
  }
}

if (import.meta.main) process.exit(main(Bun.argv.slice(2)));
