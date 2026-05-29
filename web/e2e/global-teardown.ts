import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

const PID_FILE = join(__dirname, ".e2e-pids.json");

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

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(PID_FILE)) return;
  const raw = JSON.parse(readFileSync(PID_FILE, "utf8")) as {
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
  rmSync(PID_FILE, { force: true });
}
