import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

export type WorkerRuntimeEnvInventoryEntry = {
  classification: "bun-entry" | "immutable-build" | "typed-bun-fallback" | "compatibility";
  reason: string;
};

/**
 * Every executable direct process.env reader in the Worker-reachable graph must
 * appear here with a narrow non-request-scoped classification. Request-scoped
 * policy belongs behind runtimeEnvironmentValue or an explicit authority.
 */
export const APPROVED_WORKER_PROCESS_ENV_READERS: Readonly<
  Record<string, WorkerRuntimeEnvInventoryEntry>
> = Object.freeze({
  "packages/api/src/services/version.ts": {
    classification: "immutable-build",
    reason: "API_VERSION is build and release metadata, never request authority",
  },
  "packages/auth/src/jwt.ts": {
    classification: "typed-bun-fallback",
    reason: "typed authority parameters and JWT AsyncLocalStorage are authoritative on Workers",
  },
  "packages/db/src/client.ts": {
    classification: "typed-bun-fallback",
    reason: "Workers pass an explicit immutable DatabaseSecurityEnv and request database handle",
  },
  "packages/shared/src/runtime-env.ts": {
    classification: "typed-bun-fallback",
    reason: "the accessor itself falls back to Bun process env outside a bound runtime snapshot",
  },
});

function executableSource(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/\/\/[^\n]*process\.env[^\n]*/g, "");
}

type WorkspacePackage = {
  directory: string;
  exports: ReadonlyMap<string, string>;
  main?: string;
};

function exportTarget(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  for (const key of ["worker", "browser", "import", "default"]) {
    const target = exportTarget((value as Record<string, unknown>)[key]);
    if (target) return target;
  }
  return null;
}

function workspacePackages(repoRoot: string): Map<string, WorkspacePackage> {
  const packages = new Map<string, WorkspacePackage>();
  const packagesRoot = join(repoRoot, "packages");
  for (const entry of readdirSync(packagesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const directory = join(packagesRoot, entry.name);
    const manifestPath = join(directory, "package.json");
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      name?: unknown;
      exports?: unknown;
      main?: unknown;
    };
    if (typeof manifest.name !== "string") continue;
    const exports = new Map<string, string>();
    if (typeof manifest.exports === "string") exports.set(".", manifest.exports);
    else if (manifest.exports && typeof manifest.exports === "object") {
      const entries = Object.entries(manifest.exports as Record<string, unknown>);
      if (entries.some(([key]) => key.startsWith("."))) {
        for (const [key, value] of entries) {
          const target = exportTarget(value);
          if (target) exports.set(key, target);
        }
      } else {
        const target = exportTarget(manifest.exports);
        if (target) exports.set(".", target);
      }
    }
    packages.set(manifest.name, {
      directory,
      exports,
      main: typeof manifest.main === "string" ? manifest.main : undefined,
    });
  }
  return packages;
}

function sourceCandidate(path: string): string | null {
  const withoutJs = path.replace(/\.(?:js|mjs|cjs)$/, "");
  for (const candidate of [
    path,
    withoutJs,
    `${withoutJs}.ts`,
    `${withoutJs}.tsx`,
    join(withoutJs, "index.ts"),
    join(withoutJs, "index.tsx"),
  ]) {
    if (existsSync(candidate) && /\.(?:ts|tsx)$/.test(candidate)) return resolve(candidate);
  }
  return null;
}

function resolveImport(
  specifier: string,
  importer: string,
  packages: ReadonlyMap<string, WorkspacePackage>,
): string | null {
  if (specifier.startsWith(".")) return sourceCandidate(resolve(dirname(importer), specifier));
  for (const [name, workspacePackage] of packages) {
    const { directory, exports, main } = workspacePackage;
    const sourceTarget = (target: string) => {
      const sourcePath = target.replace(/^\.\/dist\//, "./src/");
      return sourceCandidate(join(directory, sourcePath));
    };
    if (specifier === name) {
      const target = exports.get(".") ?? main;
      return target ? sourceTarget(target) : sourceCandidate(join(directory, "src/index.ts"));
    }
    if (specifier.startsWith(`${name}/`)) {
      const subpath = specifier.slice(name.length + 1);
      const target = exports.get(`./${subpath}`);
      return target ? sourceTarget(target) : sourceCandidate(join(directory, "src", subpath));
    }
  }
  return null;
}

function importedSpecifiers(source: string): string[] {
  const specifiers = new Set<string>();
  const runtimeSource = executableSource(source).replace(
    /\b(?:import|export)\s+type\b[\s\S]*?\bfrom\s+["'][^"']+["'];?/g,
    "",
  );
  const patterns = [
    /\b(?:import|export)\s+(?:type\s+)?(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g,
    /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of runtimeSource.matchAll(pattern)) specifiers.add(match[1]);
  }
  return [...specifiers];
}

export function workerReachableFiles(repoRoot: string): string[] {
  const absoluteRoot = resolve(repoRoot);
  const packages = workspacePackages(absoluteRoot);
  const entry = resolve(absoluteRoot, "packages/api/src/worker.ts");
  const pending = [entry];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const path = pending.pop();
    if (!path || visited.has(path)) continue;
    visited.add(path);
    const source = readFileSync(path, "utf8");
    for (const specifier of importedSpecifiers(source)) {
      const dependency = resolveImport(specifier, path, packages);
      if (dependency && !visited.has(dependency)) pending.push(dependency);
    }
  }
  return [...visited].map((path) => relative(absoluteRoot, path).replaceAll("\\", "/")).sort();
}

export function workerProcessEnvReaders(repoRoot: string): string[] {
  const absoluteRoot = resolve(repoRoot);
  return workerReachableFiles(absoluteRoot)
    .map((path) => join(absoluteRoot, path))
    .filter((path) => /\bprocess\.env\b/.test(executableSource(readFileSync(path, "utf8"))))
    .map((path) => relative(absoluteRoot, path).replaceAll("\\", "/"))
    .sort();
}

export function assertWorkerRuntimeEnvInventory(repoRoot: string): void {
  const actual = workerProcessEnvReaders(repoRoot);
  const approved = Object.keys(APPROVED_WORKER_PROCESS_ENV_READERS).sort();
  const unapproved = actual.filter((path) => !approved.includes(path));
  const stale = approved.filter((path) => !actual.includes(path));
  if (unapproved.length > 0 || stale.length > 0) {
    throw new Error(
      [
        unapproved.length > 0
          ? `unapproved Worker process.env readers: ${unapproved.join(", ")}`
          : "",
        stale.length > 0 ? `stale Worker process.env inventory: ${stale.join(", ")}` : "",
      ]
        .filter(Boolean)
        .join("; "),
    );
  }
}

if (import.meta.main) {
  const repoRoot = resolve(import.meta.dir, "..");
  assertWorkerRuntimeEnvInventory(repoRoot);
  console.log(
    `Worker runtime environment inventory verified (${workerProcessEnvReaders(repoRoot).length} classified readers)`,
  );
}
