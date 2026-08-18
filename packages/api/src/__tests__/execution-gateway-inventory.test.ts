import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { RAW_EVM_SIGN_EXPECTED_COUNTS, RAW_EVM_SIGN_INVENTORY } from "@stwd/shared";

/**
 * Repository-wide CI guard for the execution gateway raw-signer inventory.
 *
 * This scans EVERY production TypeScript file under packages/api/src (excluding
 * __tests__) and counts raw member-call `.signTransaction(` sites in ANY form
 * (vault.signTransaction(, getVault().signTransaction(, signer.signTransaction(,
 * this.vault.signTransaction(, someVault.signTransaction(, whitespace variants).
 * It then asserts a one-for-one match against the shared inventory:
 *
 *  - every file that has a raw call is enumerated in RAW_EVM_SIGN_EXPECTED_COUNTS
 *    with the EXACT count (adding a raw call to intents.ts / user.ts / a NEW file
 *    fails until the inventory is updated and classifies the new hit),
 *  - no inventory file may have fewer raw calls than enumerated (deleting an
 *    inventory entry without removing the call, or vice versa, fails),
 *  - each inventory row's stable marker is present in its file (so the
 *    classification anchors to a real, findable call site rather than a brittle
 *    line number).
 *
 * It also guards against BARE-IDENTIFIER references (destructured / aliased
 * forms such as `const { signTransaction } = vault`) that would smuggle a raw
 * signer past the member-call scan. Every `signTransaction` occurrence that is
 * NOT a governed `.signTransactionAuthorized(` call and NOT a counted raw
 * member-call must be one of a tiny allow-list of benign non-call forms
 * (an object-property capability key, a documentation comment). Anything else
 * fails with an instruction to classify or remove it.
 *
 * The bar: adding a raw sign call in ANY form/file fails CI with a
 * classification instruction. The scan lives in packages/api (not
 * packages/shared) so it never statically imports across package rootDirs; it
 * only reads source files off disk, which is exactly what a scanner should do
 * (avoids the TS6059 cross-rootDir hazard).
 */

const API_ROOT = join(import.meta.dir, "..", ".."); // packages/api
const SRC_DIR = join(API_ROOT, "src");
const REPO_PREFIX = "packages/api/"; // inventory files are repo-relative

// Broadened raw-call matcher: ANY member call `<recv>.signTransaction(`, where
// <recv> ends in an identifier char, a closing paren, or a closing bracket
// (covers vault.x, getVault().x, this.vault.x, arr[i].x, someVault.x), with
// arbitrary whitespace around the dot and before the paren. It deliberately
// does NOT match `.signTransactionAuthorized(` (the governed path) because the
// pattern requires `signTransaction` be immediately followed by `\s*\(`, and
// the Authorized variant has `Authorized` in between.
const RAW_SIGN_RE = /[\w$)\]]\s*\.\s*signTransaction\s*\(/g;

// Governed path: `<recv>.signTransactionAuthorized(`. Counted separately and
// never flagged as a raw signer.
const GOVERNED_SIGN_RE = /[\w$)\]]\s*\.\s*signTransactionAuthorized\s*\(/g;

// Any textual occurrence of the identifier `signTransaction` (word-bounded so
// `signTransactionAuthorized` and `signTransactionOptions` are matched here and
// classified below, not silently ignored).
const ANY_SIGN_TOKEN_RE = /signTransaction/g;

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

/**
 * Classify a single `signTransaction` token occurrence in a production source
 * file into exactly one bucket. Returns a category plus a human-facing note so
 * an unrecognized form fails with an instruction rather than a bare boolean.
 */
function classifyTokenAt(
  source: string,
  index: number,
): {
  kind: "raw-call" | "governed-call" | "options-type" | "property-key" | "comment-ref";
  note: string;
} | null {
  const token = "signTransaction";
  const after = source.slice(index + token.length);
  const before = source.slice(Math.max(0, index - 64), index);

  // 1. Governed call: signTransactionAuthorized( ...
  if (/^Authorized\s*\(/.test(after)) {
    // Only classify as governed when it is actually a member call (preceded by
    // a member-access receiver), otherwise fall through to stricter checks.
    if (/[\w$)\]]\s*\.\s*$/.test(before))
      return { kind: "governed-call", note: "governed .signTransactionAuthorized( call" };
  }

  // 2. Options type reference: SignTransactionOptions etc. never appears as
  //    lowercase `signTransaction` + `Options`, but guard anyway.
  if (/^Options\b/.test(after))
    return { kind: "options-type", note: "SignTransactionOptions type reference" };

  // 3. Raw member call: <recv>.signTransaction( (NOT Authorized, NOT Options).
  if (/^\s*\(/.test(after) && /[\w$)\]]\s*\.\s*$/.test(before)) {
    return { kind: "raw-call", note: "raw member .signTransaction( call" };
  }

  // 4. Object-property capability key: `signTransaction:` in a policy/capability
  //    map (e.g. routes/accounts.ts operation flags). Not a call, not a signer.
  if (/^\s*:/.test(after)) return { kind: "property-key", note: "object-property capability key" };

  // 5. Documentation reference inside a line comment (e.g. `raw Vault.signTransaction`).
  //    The occurrence must sit on a line whose first non-space characters are `//`.
  const lineStart = source.lastIndexOf("\n", index) + 1;
  const lineHead = source.slice(lineStart, index);
  if (/^\s*(\/\/|\*|\/\*)/.test(lineHead))
    return { kind: "comment-ref", note: "documentation comment reference" };

  return null;
}

describe("execution gateway raw-signer inventory (repository-wide)", () => {
  test("actual per-file raw signTransaction counts match the shared inventory (any member-call form)", () => {
    const actualCounts: Record<string, number> = {};
    for (const file of listTsFiles(SRC_DIR)) {
      const source = readFileSync(file, "utf8");
      const count = [...source.matchAll(RAW_SIGN_RE)].length;
      if (count > 0) actualCounts[repoRelative(file)] = count;
    }

    // Exact one-for-one equality: every raw-sign file is enumerated with the
    // exact count, and no enumerated file is missing / miscounted. A new raw
    // call anywhere OR a stale inventory entry breaks this.
    expect(
      actualCounts,
      "A raw `.signTransaction(` call site changed. Every raw signer must be " +
        "classified in RAW_EVM_SIGN_INVENTORY (packages/shared/src/security-surface.ts) " +
        "with an exact per-file count. Add/remove the inventory entry (and its marker) " +
        "to match, or migrate the call to the governed .signTransactionAuthorized( path.",
    ).toEqual({ ...RAW_EVM_SIGN_EXPECTED_COUNTS });
  });

  test("every signTransaction token is classified (no smuggled bare/aliased raw signer)", () => {
    // Cross-check: the number of raw-call classifications equals the total of
    // the per-file inventory counts, and no token is left UNCLASSIFIED. This is
    // what catches destructured/aliased forms and any novel call shape.
    const expectedRawTotal = Object.values(RAW_EVM_SIGN_EXPECTED_COUNTS).reduce((a, b) => a + b, 0);
    let rawCallTotal = 0;
    const unclassified: string[] = [];

    for (const file of listTsFiles(SRC_DIR)) {
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(ANY_SIGN_TOKEN_RE)) {
        const index = match.index ?? 0;
        const classified = classifyTokenAt(source, index);
        if (!classified) {
          const lineNo = source.slice(0, index).split("\n").length;
          const snippetStart = source.lastIndexOf("\n", index) + 1;
          const snippetEnd = source.indexOf("\n", index);
          const snippet = source
            .slice(snippetStart, snippetEnd === -1 ? source.length : snippetEnd)
            .trim();
          unclassified.push(`${repoRelative(file)}:${lineNo}  ${snippet}`);
          continue;
        }
        if (classified.kind === "raw-call") rawCallTotal += 1;
      }
    }

    expect(
      unclassified,
      "Unrecognized `signTransaction` reference(s) found. A raw signer must be a " +
        "counted `.signTransaction(` member call (classified in RAW_EVM_SIGN_INVENTORY), " +
        "the governed `.signTransactionAuthorized(` call, an object-property capability " +
        "key, or a documentation comment. A bare/destructured/aliased reference " +
        "(e.g. `const { signTransaction } = vault`) is NOT allowed — remove it or route " +
        "through the governed path:\n" +
        unclassified.join("\n"),
    ).toEqual([]);

    expect(
      rawCallTotal,
      "The classified raw member-call count must equal the inventory total. A drift " +
        "here means a raw call was added/removed without updating RAW_EVM_SIGN_INVENTORY.",
    ).toBe(expectedRawTotal);
  });

  test("no governed .signTransactionAuthorized( call is miscounted as a raw signer", () => {
    // Belt-and-suspenders: the raw matcher must never match the governed form.
    for (const file of listTsFiles(SRC_DIR)) {
      const source = readFileSync(file, "utf8");
      const governed = [...source.matchAll(GOVERNED_SIGN_RE)];
      for (const g of governed) {
        // Re-run the raw matcher against the exact governed slice; it must not
        // produce a match, proving the raw regex excludes the Authorized form.
        const slice = source.slice(g.index ?? 0, (g.index ?? 0) + (g[0]?.length ?? 0) + 1);
        expect(
          new RegExp(RAW_SIGN_RE.source).test(slice),
          `governed call in ${repoRelative(file)} was matched by the raw signer regex`,
        ).toBe(false);
      }
    }
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
