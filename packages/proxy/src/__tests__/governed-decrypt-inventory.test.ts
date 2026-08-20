/**
 * governed-decrypt-inventory.test.ts — static governed-decrypt surface inventory
 * (spec §0.1 X1/X2, §5.3, §11.1). A source-introspection CI guard that proves,
 * WITHOUT running the flow, the two structural invariants the acceptance gate
 * (§11.1) demands:
 *
 *   1. VERIFIER-ONLY DECRYPT (X2): the governed credential decrypt/inject path
 *      (`decryptSecret` / `injectCredential` in proxy.ts) is module-private
 *      (never exported) and is reached ONLY from inside `handleProxy`, which is
 *      itself guarded by the §5.1 `authorityMode`/`governedExecutionClaim` gate.
 *      No other proxy source file calls the decrypt/inject helpers.
 *
 *   2. NON-FORGEABLE GOVERNED CONTEXT (X1, §5.3): the `governedExecutionClaim`
 *      context is SET only inside `governed-execution.ts` (dispatchGovernedExecution),
 *      and is never derived from a request header/body/query/cookie anywhere in
 *      the proxy. The §5.1 gate READS it (`c.get("governedExecutionClaim")`) but
 *      no source writes it from `c.req.*`.
 *
 * This is a byte-level scan of the on-disk source (the same technique as the
 * raw-signer inventory and the shared security-surface test). Adding a new
 * decrypt caller, exporting the helper, or wiring the governed claim from a
 * request surface fails CI with a classification instruction.
 */

import { describe, expect, test } from "bun:test";

const read = async (relPath: string): Promise<string> =>
  Bun.file(new URL(relPath, import.meta.url)).text();

/** Strip line (`//`) and block (`/* *\/`) comments so scans hit real code only. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, (_m, p1) => p1);
}

function lineOf(source: string, index: number): number {
  return source.slice(0, index).split("\n").length;
}

describe("governed decrypt sensitive-surface inventory (X1/X2, §11.1)", () => {
  test("decryptSecret + injectCredential are module-private in proxy.ts (never exported)", async () => {
    const source = await read("../handlers/proxy.ts");
    // The helpers must be declared, but NOT with an `export` modifier.
    expect(/\basync function decryptSecret\b/.test(source)).toBe(true);
    expect(/\bfunction injectCredential\b/.test(source)).toBe(true);
    expect(/export\s+(async\s+)?function decryptSecret\b/.test(source)).toBe(false);
    expect(/export\s+function injectCredential\b/.test(source)).toBe(false);
    // And they must not be re-exported by name via an export list.
    expect(/export\s*\{[^}]*\bdecryptSecret\b[^}]*\}/.test(source)).toBe(false);
    expect(/export\s*\{[^}]*\binjectCredential\b[^}]*\}/.test(source)).toBe(false);
  });

  test("the ONLY files that call decryptSecret/injectCredential are proxy.ts itself", async () => {
    // Scan every proxy source file (excluding tests + the declaration site).
    const files = [
      ...new Bun.Glob("**/*.ts").scanSync({
        cwd: new URL("../", import.meta.url).pathname,
      }),
    ].filter((f) => !f.includes("__tests__"));

    const CALL = /\b(decryptSecret|injectCredential)\s*\(/g;
    const offenders: string[] = [];
    for (const file of files) {
      const source = stripComments(await read(`../${file}`));
      for (const match of source.matchAll(CALL)) {
        // Allowed ONLY in proxy.ts (the declaration + the single gated call site).
        if (file !== "handlers/proxy.ts") {
          offenders.push(`${file}:${lineOf(source, match.index ?? 0)} calls ${match[1]}(`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  test("every decryptSecret call in proxy.ts sits AFTER the governed authority gate", async () => {
    const source = await read("../handlers/proxy.ts");
    const stripped = stripComments(source);

    // The §5.1 gate anchor (must exist exactly once) and the governed error code.
    const gateIdx = stripped.indexOf("GOVERNED_ROUTE_DIRECT_DENIED");
    expect(gateIdx).toBeGreaterThan(-1);
    // authorityMode read is the gate predicate; it must precede any decrypt.
    const authorityModeIdx = stripped.indexOf("authorityMode");
    expect(authorityModeIdx).toBeGreaterThan(-1);

    // Every decryptSecret( CALL (not the declaration) must appear at a byte
    // offset AFTER the gate, so no code decrypts before the gate is evaluated.
    const declIdx = stripped.search(/\basync function decryptSecret\b/);
    for (const match of stripped.matchAll(/\bdecryptSecret\s*\(/g)) {
      const idx = match.index ?? 0;
      if (idx === stripped.indexOf("decryptSecret", declIdx) && idx < gateIdx) {
        // This is the call INSIDE the function declaration body
        // (`return getSecretVault().decryptSecret(...)`) — allowed, it is the
        // helper's own single vault call, reached only via the gated caller.
        continue;
      }
      // Any invocation of the private helper must be after the gate.
      if (/getSecretVault\(\)\.decryptSecret/.test(stripped.slice(idx - 20, idx + 20))) continue;
      expect(idx).toBeGreaterThan(gateIdx);
    }
  });

  test("governedExecutionClaim is SET only in governed-execution.ts, never from a request surface", async () => {
    const dispatch = stripComments(await read("../handlers/governed-execution.ts"));
    // dispatchGovernedExecution builds the context object that carries the claim.
    expect(dispatch.includes("governedExecutionClaim")).toBe(true);
    expect(dispatch.includes("dispatchGovernedExecution")).toBe(true);

    // Scan ALL proxy sources: the governed claim must NEVER be written from a
    // request-derived value (header/body/query/cookie). We forbid any pattern
    // that reads a "governed" value off c.req.* and any header lookup whose name
    // contains "governed".
    const files = [
      ...new Bun.Glob("**/*.ts").scanSync({
        cwd: new URL("../", import.meta.url).pathname,
      }),
    ].filter((f) => !f.includes("__tests__"));

    const offenders: string[] = [];
    for (const file of files) {
      const source = stripComments(await read(`../${file}`));
      // Forbid: c.req.header("...governed...") / req.header('x-governed-...') etc.
      for (const m of source.matchAll(/\.header\(\s*["'`][^"'`]*governed[^"'`]*["'`]/gi)) {
        offenders.push(`${file}:${lineOf(source, m.index ?? 0)} reads a governed header`);
      }
      // Forbid: c.get("governedExecutionClaim") assigned FROM a request parse,
      // i.e. any `governedExecutionClaim` string appearing on the same line as a
      // `c.req` / `req.raw` / `parse` read. We allow c.get("governedExecutionClaim")
      // (the gate read) and the in-process context object literal.
      const lines = source.split("\n");
      lines.forEach((ln, i) => {
        if (
          /governedExecutionClaim/.test(ln) &&
          /(c\.req|req\.raw|\.json\(\)|searchParams|cookie)/i.test(ln)
        ) {
          offenders.push(`${file}:${i + 1} derives governedExecutionClaim from a request surface`);
        }
      });
    }
    expect(offenders).toEqual([]);
  });

  test("the §5.1 gate READS the claim via c.get, and requires an exact routeId match", async () => {
    const proxy = stripComments(await read("../handlers/proxy.ts"));
    // The gate must read the claim from the in-process context (never a header).
    expect(/c\.get\(\s*["'`]governedExecutionClaim["'`]/.test(proxy)).toBe(true);
    // And it must compare the claim's routeId to the selected route id (mirror of
    // the proxyApprovalRouteId guard) so a claim for a different route is rejected.
    expect(/governedClaim\.routeId\s*===\s*route\.id/.test(proxy)).toBe(true);
    // Unknown authority modes default-deny (§6.3 backstop).
    expect(proxy.includes("governed-route-unknown-authority-mode")).toBe(true);
  });
});
