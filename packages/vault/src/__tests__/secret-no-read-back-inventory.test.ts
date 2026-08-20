/**
 * secret-no-read-back-inventory.test.ts — repo-wide static caller inventory for
 * the SecretVault's plaintext-capable methods.
 *
 * The no-read-back property of the custody plane is only as strong as the set
 * of code paths allowed to reach plaintext. This scan proves, WITHOUT running
 * anything, that the direct-return decrypt methods (`decryptSecret` /
 * `decryptSecretRow`) are reachable from a CLOSED, classified set of files:
 *
 *   - packages/vault/src/secret-vault.ts        (the declarations themselves)
 *   - packages/proxy/src/handlers/proxy.ts      (credential injection; itself
 *     pinned module-private by the proxy's governed-decrypt-inventory test)
 *   - packages/api/src/services/provider-x-connect.ts (X OAuth refresh; the
 *     plaintext is a refresh-token payload consumed in-process)
 *
 * Adding a decrypt call anywhere else fails this test with a classification
 * instruction: prefer `SecretVault.exerciseSecret` (use-only closure, plaintext
 * never crosses the API boundary) and, if a direct return is truly required,
 * add the file here WITH a justification comment in the same commit.
 *
 * Same byte-level technique as the proxy governed-decrypt inventory and the
 * shared security-surface test.
 */

import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const PACKAGES_DIR = join(import.meta.dir, "..", "..", "..");

/** Files allowed to reference the direct-return decrypt methods. */
const ALLOWED_DECRYPT_CALLERS = new Set([
  "vault/src/secret-vault.ts",
  "proxy/src/handlers/proxy.ts",
  // Google OAuth refresh/disconnect consumes an already-locked credential row
  // in-process; plaintext stays module-private and is never returned by routes.
  "api/src/services/provider-google-connect.ts",
  "api/src/services/provider-x-connect.ts",
]);

/** Strip line + block comments so scans match real code only. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, (_m, p1) => p1);
}

function* walkTsFiles(dir: string, rel = ""): Generator<{ abs: string; rel: string }> {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === ".next") continue;
    const abs = join(dir, entry);
    const relPath = rel ? `${rel}/${entry}` : entry;
    const stats = statSync(abs);
    if (stats.isDirectory()) {
      yield* walkTsFiles(abs, relPath);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      yield { abs, rel: relPath };
    }
  }
}

describe("SecretVault no-read-back caller inventory (repo-wide)", () => {
  test("decryptSecret/decryptSecretRow callers form the pinned, classified set", () => {
    const CALL = /\bdecryptSecret(Row)?\s*\(/;
    const failures: string[] = [];

    for (const { abs, rel } of walkTsFiles(PACKAGES_DIR)) {
      // Tests may exercise the methods freely; production sources are pinned.
      if (rel.includes("__tests__") || rel.endsWith(".test.ts")) continue;
      const source = stripComments(readFileSync(abs, "utf8"));
      if (!CALL.test(source)) continue;
      if (!ALLOWED_DECRYPT_CALLERS.has(rel)) {
        failures.push(
          `${rel} calls decryptSecret/decryptSecretRow but is not in the classified caller set. ` +
            "Use SecretVault.exerciseSecret (use-only closure) instead; a direct plaintext return " +
            "requires adding this file to ALLOWED_DECRYPT_CALLERS with a written justification.",
        );
      }
    }

    expect(failures).toEqual([]);
  });

  test("every allowed caller still exists (the pin cannot go stale silently)", () => {
    for (const rel of ALLOWED_DECRYPT_CALLERS) {
      const source = readFileSync(join(PACKAGES_DIR, rel), "utf8");
      expect(source.length).toBeGreaterThan(0);
      if (rel !== "vault/src/secret-vault.ts") {
        expect(/\bdecryptSecret(Row)?\s*\(/.test(stripComments(source))).toBe(true);
      }
    }
  });

  test("the API routes layer never touches the decrypt methods", () => {
    const routesDir = join(PACKAGES_DIR, "api", "src", "routes");
    for (const { abs, rel } of walkTsFiles(routesDir)) {
      const source = stripComments(readFileSync(abs, "utf8"));
      expect(
        /\bdecryptSecret(Row)?\s*\(/.test(source),
        `packages/api/src/routes/${rel} must not decrypt secrets — routes return metadata only`,
      ).toBe(false);
    }
  });
});
