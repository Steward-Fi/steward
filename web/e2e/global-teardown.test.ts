import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { runGlobalTeardown } from "./global-teardown";

/**
 * SEC-076 regression tests: the e2e harness builds web/.next with
 * E2E_ALLOW_INSECURE_HTTP (no HSTS / upgrade-insecure-requests), so teardown
 * must remove that artifact even when global-setup died before writing the
 * PID file (the file is written last — a mid-setup failure previously made
 * teardown return early and leave the insecure build in the tree).
 */

let workDir: string;

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), "steward-teardown-test-"));
});

afterEach(() => {
  rmSync(workDir, { recursive: true, force: true });
});

function makeNextDir(): string {
  const nextDir = join(workDir, ".next");
  mkdirSync(nextDir, { recursive: true });
  writeFileSync(join(nextDir, "build-marker"), "e2e");
  return nextDir;
}

describe("e2e global teardown (SEC-076)", () => {
  test("removes .next even when the PID file was never written (failed setup)", async () => {
    const nextDir = makeNextDir();

    await runGlobalTeardown(join(workDir, ".e2e-pids.json"), nextDir);

    expect(existsSync(nextDir)).toBe(false);
  });

  test("removes .next, the PID file, and the data dir on a normal run", async () => {
    const nextDir = makeNextDir();
    const dataDir = join(workDir, "e2e-data");
    mkdirSync(dataDir, { recursive: true });
    const pidFile = join(workDir, ".e2e-pids.json");
    // Bogus pids: killPid swallows ESRCH for already-gone processes.
    writeFileSync(pidFile, JSON.stringify({ web: 999999, api: 999998, dataDir }));

    await runGlobalTeardown(pidFile, nextDir);

    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
    expect(existsSync(dataDir)).toBe(false);
  });

  test("still removes .next when the PID file is corrupt", async () => {
    const nextDir = makeNextDir();
    writeFileSync(join(workDir, ".e2e-pids.json"), "not json{");

    // The parse error still surfaces (teardown reports the failure), but the
    // finally-block must have removed the insecure build artifact first.
    await expect(runGlobalTeardown(join(workDir, ".e2e-pids.json"), nextDir)).rejects.toThrow();
    expect(existsSync(nextDir)).toBe(false);
  });
});
