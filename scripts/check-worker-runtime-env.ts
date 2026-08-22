import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

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
  "packages/api/src/embedded.ts": {
    classification: "bun-entry",
    reason: "embedded Bun bootstrap establishes process configuration before importing the app",
  },
  "packages/api/src/index.ts": {
    classification: "bun-entry",
    reason: "Bun server startup configuration is immutable for the process lifetime",
  },
  "packages/api/src/services/context.ts": {
    classification: "compatibility",
    reason: "one DATABASE_URL normalization write remains for Bun-only legacy consumers",
  },
  "packages/api/src/services/version.ts": {
    classification: "immutable-build",
    reason: "API_VERSION is build and release metadata, never request authority",
  },
  "packages/api/src/services/webhook-url.ts": {
    classification: "compatibility",
    reason: "request-local webhook transport policy is independently owned by issue 769",
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

const WORKER_GRAPH_ROOTS = [
  "packages/api/src",
  "packages/auth/src",
  "packages/db/src",
  "packages/plugin-capabilities/src",
  "packages/plugin-trading/src",
  "packages/plugin-wxmr/src",
  "packages/redis/src",
  "packages/shared/src",
  "packages/vault/src",
];

function productionTypeScriptFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const output: string[] = [];
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      if (name === "__tests__" || name === "dist") continue;
      output.push(...productionTypeScriptFiles(path));
    } else if (/\.(?:ts|tsx)$/.test(name) && !/\.(?:test|spec)\.(?:ts|tsx)$/.test(name)) {
      output.push(path);
    }
  }
  return output;
}

function executableSource(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/\/\/[^\n]*process\.env[^\n]*/g, "");
}

export function workerProcessEnvReaders(repoRoot: string): string[] {
  const absoluteRoot = resolve(repoRoot);
  return WORKER_GRAPH_ROOTS.flatMap((path) => productionTypeScriptFiles(join(absoluteRoot, path)))
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
