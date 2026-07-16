/**
 * client-entrypoint.test.ts: contract test for the browser/worker-safe
 * `@stwd/shared/client` entrypoint (issue #231).
 *
 * THE CONTRACT
 * ------------
 * `src/client.ts` (and its emitted `dist/client.js`) must have a transitive
 * import graph that contains:
 *   - NO `node:*` imports and no bare Node builtin imports;
 *   - NO server-only modules (`provider-execution-auth`, `provider-action`);
 *   - NO import of the top-level barrel (`index`), which would transitively
 *     drag the server-only modules back in.
 *
 * If this test fails, someone re-exported a server-only or node-dependent
 * module from the client entrypoint. That breaks `web` `cf:build` (the
 * Cloudflare Worker bundle cannot resolve `node:crypto`). Fix the entrypoint,
 * do NOT weaken this test and do NOT polyfill/stub node builtins in the
 * Worker build.
 *
 * FAIL-CLOSED: a missing dist build or an unresolvable import is a test
 * FAILURE, never a skip.
 */

import { beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, resolve } from "node:path";

const SHARED_ROOT = resolve(import.meta.dir, "..", "..");
const SRC_ENTRY = join(SHARED_ROOT, "src", "client.ts");
const DIST_ENTRY = join(SHARED_ROOT, "dist", "client.js");

/**
 * Modules that must NEVER be reachable from the client entrypoint, matched
 * against the resolved module path. `index` is the top-level barrel: reaching
 * it from client would transitively re-import every server-only module.
 */
const SERVER_ONLY_BASENAMES = new Set(["provider-execution-auth", "provider-action", "index"]);

const NODE_BUILTINS = new Set<string>([
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
]);

/** Extract every static import/export specifier from an ESM source text. */
function extractSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  // import ... from "x"; export ... from "x"; import "x";
  const fromRe = /\b(?:import|export)\b[^"'`;]*?\bfrom\s*["']([^"']+)["']/g;
  const bareImportRe = /\bimport\s*["']([^"']+)["']/g;
  const dynamicImportRe = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  const requireRe = /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;
  for (const re of [fromRe, bareImportRe, dynamicImportRe, requireRe]) {
    let m: RegExpExecArray | null = re.exec(source);
    while (m !== null) {
      specifiers.push(m[1]);
      m = re.exec(source);
    }
  }
  return specifiers;
}

interface GraphViolation {
  module: string;
  specifier: string;
  kind: "node-builtin" | "server-only" | "unresolvable" | "external";
}

/**
 * Resolve a relative specifier from `fromFile` to an on-disk module file.
 * Handles the NodeNext `.js`-suffix-in-source convention (src) and plain
 * `.js` (dist). Returns null when nothing exists (caller records a
 * violation: unresolvable imports fail closed).
 */
function resolveRelative(fromFile: string, spec: string): string | null {
  const base = resolve(dirname(fromFile), spec);
  const candidates = [
    base,
    `${base}.ts`,
    `${base}.js`,
    base.replace(/\.js$/, ".ts"),
    join(base, "index.ts"),
    join(base, "index.js"),
  ];
  for (const c of candidates) {
    try {
      if (statSync(c).isFile()) return c;
    } catch {
      // keep trying
    }
  }
  return null;
}

/**
 * Walk the static import graph from `entry`, collecting every violation of
 * the client-safety contract. Only relative imports are followed (the shared
 * package has no runtime dependencies; any bare specifier is either a node
 * builtin or an unexpected external dependency: both are violations).
 */
function walkGraph(entry: string): { visited: Set<string>; violations: GraphViolation[] } {
  const visited = new Set<string>();
  const violations: GraphViolation[] = [];
  const queue: string[] = [entry];
  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || visited.has(file)) continue;
    visited.add(file);
    const source = readFileSync(file, "utf8");
    for (const spec of extractSpecifiers(source)) {
      if (spec.startsWith(".")) {
        const target = resolveRelative(file, spec);
        if (target === null) {
          violations.push({ module: file, specifier: spec, kind: "unresolvable" });
          continue;
        }
        const basename = target
          .split("/")
          .pop()
          ?.replace(/\.(ts|js)$/, "");
        // `index` inside chains/ is the chains sub-barrel (client-safe);
        // only the TOP-LEVEL barrel is server-only.
        const isTopLevelBarrel =
          basename === "index" &&
          (dirname(target) === join(SHARED_ROOT, "src") ||
            dirname(target) === join(SHARED_ROOT, "dist"));
        if (
          (basename !== undefined && basename !== "index" && SERVER_ONLY_BASENAMES.has(basename)) ||
          isTopLevelBarrel
        ) {
          violations.push({ module: file, specifier: spec, kind: "server-only" });
          continue;
        }
        queue.push(target);
      } else if (NODE_BUILTINS.has(spec)) {
        violations.push({ module: file, specifier: spec, kind: "node-builtin" });
      } else {
        // Bare external specifier: @stwd/shared has zero runtime deps, so
        // anything here is unexpected in the client graph. Fail closed.
        violations.push({ module: file, specifier: spec, kind: "external" });
      }
    }
  }
  return { visited, violations };
}

function formatViolations(violations: GraphViolation[]): string {
  return violations
    .map((v) => `[${v.kind}] ${v.module.replace(`${SHARED_ROOT}/`, "")} -> "${v.specifier}"`)
    .join("\n");
}

describe("@stwd/shared/client entrypoint contract (issue #231)", () => {
  beforeAll(() => {
    // On a clean checkout dist/ is untracked; build it so the emitted-graph
    // assertions can run. FAIL-CLOSED: a failed build fails the suite, the
    // dist checks are never skipped.
    if (!existsSync(DIST_ENTRY)) {
      const result = spawnSync("bunx", ["tsc"], { cwd: SHARED_ROOT, stdio: "inherit" });
      if (result.status !== 0) {
        throw new Error(`building @stwd/shared dist failed (exit ${String(result.status)})`);
      }
    }
  });

  it("source graph of src/client.ts contains no node builtins or server-only modules", () => {
    const { visited, violations } = walkGraph(SRC_ENTRY);
    expect(visited.size).toBeGreaterThan(1);
    expect(formatViolations(violations)).toBe("");
  });

  it("emitted dist/client.js exists (client entrypoint must ship in the build)", () => {
    // FAIL-CLOSED: dist must be built before tests (CI builds @stwd/shared
    // first). A missing dist entry means the exports map points at nothing.
    expect(statSync(DIST_ENTRY).isFile()).toBe(true);
  });

  it("emitted dist graph of dist/client.js contains no node builtins or server-only modules", () => {
    const { visited, violations } = walkGraph(DIST_ENTRY);
    expect(visited.size).toBeGreaterThan(1);
    expect(formatViolations(violations)).toBe("");
  });

  it("package.json exports map exposes ./client with types and import conditions", () => {
    const pkg = JSON.parse(readFileSync(join(SHARED_ROOT, "package.json"), "utf8")) as {
      exports?: Record<string, { types?: string; import?: string }>;
    };
    expect(pkg.exports?.["./client"]?.import).toBe("./dist/client.js");
    expect(pkg.exports?.["./client"]?.types).toBe("./dist/client.d.ts");
  });

  it("client entrypoint still exposes the helpers web depends on", async () => {
    const client = await import("../client.js");
    expect(typeof client.getNativeDecimals).toBe("function");
    expect(typeof client.getNativeSymbol).toBe("function");
    expect(Array.isArray(client.CHAIN_PROVIDERS)).toBe(true);
    expect(typeof client.getChainProviderByNumeric).toBe("function");
    expect(typeof client.describeThrown).toBe("function");
  });

  it("web client modules do not import the top-level @stwd/shared barrel", () => {
    // Browser-bundled web code must import @stwd/shared/client, never the
    // barrel: the barrel drags node:crypto into the Cloudflare Worker bundle
    // and breaks cf:build. This scans every module under web/src.
    const webSrc = resolve(SHARED_ROOT, "..", "..", "web", "src");
    const offenders: string[] = [];
    const walkDir = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
          walkDir(full);
        } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.(test|spec)\.(ts|tsx)$/.test(entry.name)) {
          const source = readFileSync(full, "utf8");
          for (const spec of extractSpecifiers(source)) {
            if (spec === "@stwd/shared") offenders.push(`${full} -> "${spec}"`);
          }
        }
      }
    };
    walkDir(webSrc);
    expect(offenders.join("\n")).toBe("");
  });
});
