import { spawnSync } from "node:child_process";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  openSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

const PID_FILE = join(__dirname, ".e2e-pids.json");
const NEXT_BUILD_DIR = join(__dirname, "..", ".next");

type ProcessIdentity = { pid: number; startedAt: string; command: string };

function validatedProcess(value: unknown, name: string): ProcessIdentity | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid ${name} PID in e2e teardown state`);
  }
  const record = value as Record<string, unknown>;
  if (
    !Number.isSafeInteger(record.pid) ||
    (record.pid as number) <= 1 ||
    typeof record.startedAt !== "string" ||
    record.startedAt.length === 0 ||
    record.startedAt.length > 128 ||
    typeof record.command !== "string" ||
    record.command.length === 0 ||
    record.command.length > 4096
  ) {
    throw new Error(`Invalid ${name} PID in e2e teardown state`);
  }
  return record as unknown as ProcessIdentity;
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

function killProcess(processIdentity: ProcessIdentity | undefined, name: string): void {
  if (processIdentity === undefined) return;
  const { pid, startedAt, command } = processIdentity;
  const currentStartedAt = spawnSync("ps", ["-p", String(pid), "-o", "lstart="], {
    encoding: "utf8",
  }).stdout.trim();
  if (!currentStartedAt) return;
  const currentCommand = spawnSync("ps", ["-p", String(pid), "-o", "command="], {
    encoding: "utf8",
  }).stdout.trim();
  if (currentStartedAt !== startedAt || currentCommand !== command) {
    throw new Error(`Refusing to signal reused ${name} PID`);
  }
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
    let stateFd: number | undefined;
    try {
      stateFd = openSync(pidFile, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        rmSync(pidFile, { force: true });
        throw new Error("Invalid e2e teardown state file", { cause: error });
      }
    }
    if (stateFd !== undefined) {
      try {
        const stat = fstatSync(stateFd);
        if (!stat.isFile() || stat.size > 16 * 1024) {
          throw new Error("Invalid e2e teardown state file");
        }
        const raw = JSON.parse(readFileSync(stateFd, "utf8")) as Record<string, unknown>;
        const web = validatedProcess(raw.web, "web");
        const api = validatedProcess(raw.api, "api");
        const fakeOAuth = validatedProcess(raw.fakeOAuth, "fakeOAuth");
        const dataDir = validatedDataDir(raw.dataDir);
        let cleanupError: unknown;
        for (const [identity, name] of [
          [web, "web"],
          [api, "api"],
          [fakeOAuth, "fakeOAuth"],
        ] as const) {
          try {
            killProcess(identity, name);
          } catch (error) {
            cleanupError ??= error;
          }
        }
        try {
          if (dataDir && existsSync(dataDir)) {
            await removeDirWithRetry(dataDir);
          }
        } catch (error) {
          cleanupError ??= error;
        }
        if (cleanupError) {
          throw cleanupError;
        }
      } finally {
        closeSync(stateFd);
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
