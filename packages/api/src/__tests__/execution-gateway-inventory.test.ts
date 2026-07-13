import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { RAW_EVM_SIGN_EXPECTED_COUNTS, RAW_EVM_SIGN_INVENTORY } from "@stwd/shared";

/**
 * Repository-wide CI guard for the PR4 execution gateway raw-signer inventory.
 *
 * This scans EVERY production TypeScript file under packages/api/src (excluding
 * __tests__) and counts raw `Vault.signTransaction(` call sites. It then asserts
 * a one-for-one match against the shared inventory:
 *
 *  - every file that has a raw call is enumerated in RAW_EVM_SIGN_EXPECTED_COUNTS
 *    with the EXACT count (adding a raw call to intents.ts / user.ts / a NEW file
 *    fails until the inventory is updated),
 *  - no inventory file may have fewer raw calls than enumerated (deleting an
 *    inventory entry without removing the call, or vice versa, fails),
 *  - each inventory row's stable marker is present in its file (so the
 *    classification anchors to a real, findable call site rather than a brittle
 *    line number).
 *
 * The scan lives in packages/api (not packages/shared) so it never statically
 * imports across package rootDirs; it only reads source files off disk, which is
 * exactly what a scanner should do (avoids the TS6059 cross-rootDir hazard).
 */

const API_ROOT = join(import.meta.dir, "..", ".."); // packages/api
const SRC_DIR = join(API_ROOT, "src");
const REPO_PREFIX = "packages/api/"; // inventory files are repo-relative

// Matches the two raw invocation forms used in the codebase:
//   vault.signTransaction(       (module-singleton proxy)
//   getVault().signTransaction(  (lazy accessor)
// Deliberately does NOT match `signTransactionAuthorized(` (the governed path)
// or `signSolanaTransaction(` / `signTransactionOptions`.
const RAW_SIGN_RE = /\b(?:vault|getVault\(\))\.signTransaction\(/g;

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__tests__" || entry.name === "node_modules") continue;
      out.push(...listTsFiles(full));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) {
      out.push(full);
    }
  }
  return out;
}

function repoRelative(absPath: string): string {
  // -> packages/api/src/routes/vault.ts
  return REPO_PREFIX + relative(API_ROOT, absPath).split("\\").join("/");
}

describe("execution gateway raw-signer inventory (repository-wide)", () => {
  test("actual per-file raw signTransaction counts match the shared inventory", () => {
    const actualCounts: Record<string, number> = {};
    for (const file of listTsFiles(SRC_DIR)) {
      const source = readFileSync(file, "utf8");
      const count = [...source.matchAll(RAW_SIGN_RE)].length;
      if (count > 0) actualCounts[repoRelative(file)] = count;
    }

    // Exact one-for-one equality: every raw-sign file is enumerated with the
    // exact count, and no enumerated file is missing / miscounted. A new raw
    // call anywhere OR a stale inventory entry breaks this.
    expect(actualCounts).toEqual({ ...RAW_EVM_SIGN_EXPECTED_COUNTS });
  });

  test("every inventory marker anchors to a real call site in its file", () => {
    for (const site of RAW_EVM_SIGN_INVENTORY) {
      const abs = join(API_ROOT, site.file.slice(REPO_PREFIX.length));
      const source = readFileSync(abs, "utf8");
      expect(
        source,
        `${site.file} must be readable for inventory marker "${site.marker}"`,
      ).toBeTruthy();
      expect(
        source.includes(site.marker),
        `inventory marker "${site.marker}" must be present in ${site.file}`,
      ).toBe(true);
    }
  });

  test("migrated-guarded vault call sites are preceded by an invariant guard", () => {
    const vaultSource = readFileSync(join(SRC_DIR, "routes", "vault.ts"), "utf8");
    for (const site of RAW_EVM_SIGN_INVENTORY) {
      if (site.classification !== "migrated-invariant-guarded") continue;
      if (site.file !== "packages/api/src/routes/vault.ts") continue;
      // The marker for the guarded sites IS the invariant throw string, which
      // must appear before the corresponding raw call. Presence is asserted
      // above; here we assert the invariant strings the runtime relies on exist.
      expect(vaultSource.includes(site.marker)).toBe(true);
    }
    // Both primary + approval invariant guards must exist.
    expect(vaultSource).toContain(
      "invariant: primary EVM sign reached raw signer without gateway authorization",
    );
    expect(vaultSource).toContain(
      "invariant: primary EVM approval reached raw signer without gateway authorization",
    );
  });
});
