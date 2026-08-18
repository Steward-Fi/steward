import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

const PID_FILE = join(__dirname, ".e2e-pids.json");
const NEXT_BUILD_DIR = join(__dirname, "..", ".next");

function killPid(pid: number | undefined): void {
  if (!pid) return;
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
    // The PID file is written LAST in global-setup, so a failed setup can
    // leave no file while still having produced a flag-built .next — process
    // cleanup is best-effort and must not gate the artifact removal below.
    if (existsSync(pidFile)) {
      const raw = JSON.parse(readFileSync(pidFile, "utf8")) as {
        fakeOAuth?: number;
        api?: number;
        web?: number;
        dataDir?: string;
      };
      killPid(raw.web);
      killPid(raw.api);
      killPid(raw.fakeOAuth);
      if (raw.dataDir && existsSync(raw.dataDir)) {
        await removeDirWithRetry(raw.dataDir);
      }
      rmSync(pidFile, { force: true });
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
