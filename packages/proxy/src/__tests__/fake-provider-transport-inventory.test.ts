/**
 * PR6 fake-transport static inventory (U1 / M01 / PN01 / PN02).
 *
 * A source-introspection CI guard (same technique as the PR4
 * governed-decrypt-inventory scan) that proves, WITHOUT running the flow, that
 * the deterministic fake provider transport is UNSELECTABLE in a production
 * build:
 *
 *   M01 / PN01  `fake-provider-transport.ts` is imported ONLY by test files and
 *               the CI harness entrypoints, never by any `src/` production
 *               module (across ALL packages, not just proxy).
 *
 *   PN02        There is NO env var / request header / config row / `NODE_ENV`
 *               branch that swaps the forwarder. The ONLY setter of the terminal
 *               forwarder binding is the `__`-prefixed test seam
 *               `__setForwardProxyRequestForTests`, and the default binding
 *               resolves to `forwardWithVettedDns` (the real, DNS-vetted
 *               forwarder). No production module calls the setter.
 *
 *   U1 (no weakening)  `verifyProxyHostResolvesPublicly` and the public-HTTPS
 *               SSRF guards remain present and are still invoked on the forward
 *               path; the fake replaces ONLY the terminal I/O binding.
 *
 * Adding a production import of the fake, wiring an env/header path to select
 * it, or removing an SSRF guard fails CI here with a classification instruction.
 */

import { describe, expect, test } from "bun:test";

const read = async (relPath: string): Promise<string> =>
  Bun.file(new URL(relPath, import.meta.url)).text();

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, (_m, p1) => p1);
}

/**
 * Scan the whole monorepo `packages/` tree for TS/TSX sources (excluding the
 * fake module itself, dist, node_modules) and return the ones whose CODE (not
 * comments) imports `fake-provider-transport`.
 */
function repoSourceFiles(): { path: string; isTest: boolean; isHarness: boolean }[] {
  // import.meta.url -> .../packages/proxy/src/__tests__/this-file.ts
  const packagesRoot = new URL("../../../", import.meta.url).pathname; // .../packages/
  const glob = new Bun.Glob("**/*.{ts,tsx,mts,cts}");
  const out: { path: string; isTest: boolean; isHarness: boolean }[] = [];
  for (const rel of glob.scanSync({ cwd: packagesRoot })) {
    if (rel.includes("node_modules/") || rel.includes("/dist/")) continue;
    if (rel.endsWith("fake-provider-transport.ts")) continue; // the module itself
    const isTest =
      rel.includes("__tests__/") ||
      rel.endsWith(".test.ts") ||
      rel.endsWith(".test.tsx") ||
      rel.endsWith(".integration.test.ts");
    out.push({ path: `${packagesRoot}${rel}`, isTest, isHarness: false });
  }
  return out;
}

const FAKE_IMPORT = /\bfrom\s+["'][^"']*fake-provider-transport(?:\.js)?["']/;

describe("PR6 fake-transport static inventory (U1)", () => {
  test("M01/PN01: fake-provider-transport is imported ONLY by test files", async () => {
    const files = repoSourceFiles();
    // Sanity: the scan found a non-trivial tree.
    expect(files.length).toBeGreaterThan(50);

    const productionImporters: string[] = [];
    for (const f of files) {
      const src = stripComments(await Bun.file(f.path).text());
      if (FAKE_IMPORT.test(src) && !f.isTest && !f.isHarness) {
        productionImporters.push(f.path);
      }
    }
    // If this fails: a `src/` production module imported the test-only fake
    // transport. Move the import into a test/harness file — the fake MUST NOT be
    // reachable from any shipped code path (Gate D stop condition U1).
    expect(productionImporters).toEqual([]);
  });

  test("PN02: forwarder rebindings are limited to test seams; default is DNS-vetted", async () => {
    const proxy = stripComments(await read("../handlers/proxy.ts"));

    // The default binding is the real, DNS-vetted forwarder.
    expect(
      /let\s+forwardProxyRequestForHandler\s*:\s*ProxyForwarder\s*=\s*forwardWithVettedDns/.test(
        proxy,
      ),
    ).toBe(true);

    // The typed initializer is not a bare assignment. The only rebindings are
    // the explicit test setter and the test reset back to the vetted default.
    const assignmentValues = [
      ...proxy.matchAll(/forwardProxyRequestForHandler\s*=\s*([^;]+);/g),
    ].map((match) => match[1]?.trim());
    expect(assignmentValues).toEqual(["forwarder", "forwardWithVettedDns"]);

    const setterBody = proxy.slice(proxy.indexOf("__setForwardProxyRequestForTests"));
    expect(/forwardProxyRequestForHandler\s*=\s*forwarder\b/.test(setterBody)).toBe(true);
    const resetBody = proxy.slice(proxy.indexOf("__resetProxyHandlerTestHooksForTests"));
    expect(/forwardProxyRequestForHandler\s*=\s*forwardWithVettedDns\b/.test(resetBody)).toBe(true);

    // The setter is `__`-prefixed and test-only-named.
    expect(/export function __setForwardProxyRequestForTests\(/.test(proxy)).toBe(true);

    // No env/header/config/NODE_ENV path selects a forwarder. Assert the binding
    // is never assigned from a request/env surface.
    expect(/forwardProxyRequestForHandler\s*=\s*[^;]*process\.env/.test(proxy)).toBe(false);
    expect(/forwardProxyRequestForHandler\s*=\s*[^;]*c\.req\./.test(proxy)).toBe(false);
    expect(/forwardProxyRequestForHandler\s*=\s*[^;]*NODE_ENV/.test(proxy)).toBe(false);
  });

  test("PN02: no production proxy module calls the forwarder test hooks", async () => {
    const proxySrcRoot = new URL("../", import.meta.url).pathname;
    const glob = new Bun.Glob("**/*.ts");
    const callers: string[] = [];
    for (const rel of glob.scanSync({ cwd: proxySrcRoot })) {
      if (rel.includes("__tests__/")) continue;
      const src = stripComments(await Bun.file(`${proxySrcRoot}${rel}`).text());
      for (const hook of [
        "__setForwardProxyRequestForTests",
        "__resetProxyHandlerTestHooksForTests",
      ]) {
        if (!new RegExp(`${hook}\\s*\\(`).test(src)) continue;
        const withoutDecl = src.replace(
          new RegExp(`export function ${hook}\\s*\\([^)]*\\)\\s*:\\s*void\\s*\\{`),
          "",
        );
        if (new RegExp(`${hook}\\s*\\(`).test(withoutDecl)) callers.push(`${rel}:${hook}`);
      }
    }
    expect(callers).toEqual([]);
  });

  test("U1: SSRF/public-DNS guards remain present and on the forward path", async () => {
    const proxy = stripComments(await read("../handlers/proxy.ts"));
    // The public-DNS resolution guard exists...
    expect(/async function verifyProxyHostResolvesPublicly\(/.test(proxy)).toBe(true);
    // ...and is invoked before the terminal forward (its result feeds the
    // forwarder's `records` argument).
    expect(/await verifyProxyHostResolvesPublicly\(/.test(proxy)).toBe(true);
    expect(/forwardProxyRequestForHandler\(/.test(proxy)).toBe(true);
  });
});
