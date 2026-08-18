import { existsSync, lstatSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const PID_FILE = join(__dirname, ".e2e-pids.json");
const NEXT_BUILD_DIR = join(__dirname, "..", ".next");

function validatedPid(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) <= 1) {
    throw new Error(`Invalid ${name} PID in e2e teardown state`);
  }
  return value as number;
}

function validatedDataDir(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error("Invalid dataDir in e2e teardown state");
  const resolved = resolve(value);
  if (dirname(resolved) !== resolve(tmpdir()) || !basename(resolved).startsWith("steward-e2e-")) {
    throw new Error("Refusing to remove an unexpected e2e data directory");
  }
  return resolved;
}

function killPid(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    /* already gone */
  }
}

async function removeDirWithRetry(path: string): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      rmSync(path, { recursive: true, force: true });
      return;
    } catch (err) {
      if (attempt === 4) throw err;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    }
  }
}

/**
 * Exported for tests; Playwright calls the default export, which binds the
 * real harness paths.
 */
export async function runGlobalTeardown(pidFile: string, nextBuildDir: string): Promise<void> {
  try {
    // Setup persists state after each process spawn, but a failure before the
    // first spawn can still leave no file after producing a flag-built .next.
    // Process cleanup must therefore never gate artifact removal below.
    if (existsSync(pidFile)) {
      try {
        const stat = lstatSync(pidFile);
        if (!stat.isFile() || stat.size > 16 * 1024) {
          throw new Error("Invalid e2e teardown state file");
        }
        const raw = JSON.parse(readFileSync(pidFile, "utf8")) as Record<string, unknown>;
        const web = validatedPid(raw.web, "web");
        const api = validatedPid(raw.api, "api");
        const fakeOAuth = validatedPid(raw.fakeOAuth, "fakeOAuth");
        const dataDir = validatedDataDir(raw.dataDir);
        killPid(web);
        killPid(api);
        killPid(fakeOAuth);
        if (dataDir && existsSync(dataDir)) {
          await removeDirWithRetry(dataDir);
        }
      } finally {
        rmSync(pidFile, { force: true });
      }
    }
  } finally {
    // SEC-076: the harness builds .next with E2E_ALLOW_INSECURE_HTTP (no HSTS /
    // upgrade-insecure-requests). Never leave that artifact in the working tree
    // where it could be deployed by accident — even when setup failed before
    // writing the PID file (the early return that used to skip this).
    await removeDirWithRetry(nextBuildDir);
  }
}

export default async function globalTeardown(): Promise<void> {
  await runGlobalTeardown(PID_FILE, NEXT_BUILD_DIR);
}
