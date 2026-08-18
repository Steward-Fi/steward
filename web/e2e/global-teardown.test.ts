import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runGlobalTeardown } from "./global-teardown";

/**
 * SEC-076 regression tests: the e2e harness builds web/.next with
 * E2E_ALLOW_INSECURE_HTTP (no HSTS / upgrade-insecure-requests), so teardown
 * must remove that artifact even when global-setup died before its first
 * process-state write.
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
  test("removes .next when setup failed before its first state write", async () => {
    const nextDir = makeNextDir();

    await runGlobalTeardown(join(workDir, ".e2e-pids.json"), nextDir);

    expect(existsSync(nextDir)).toBe(false);
  });

  test("removes .next, the PID file, and the data dir on a normal run", async () => {
    const nextDir = makeNextDir();
    const dataDir = mkdtempSync(join(tmpdir(), "steward-e2e-"));
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
    expect(existsSync(join(workDir, ".e2e-pids.json"))).toBe(false);
  });

  test("rejects dangerous process ids without signaling them", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: -1 }));
    await expect(runGlobalTeardown(pidFile, nextDir)).rejects.toThrow(/Invalid web PID/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("refuses an arbitrary data directory", async () => {
    const nextDir = makeNextDir();
    const outside = join(workDir, "must-survive");
    mkdirSync(outside);
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ dataDir: outside }));
    await expect(runGlobalTeardown(pidFile, nextDir)).rejects.toThrow(/unexpected e2e data/);
    expect(existsSync(outside)).toBe(true);
  });

  test("does not follow state-file symlinks", async () => {
    const nextDir = makeNextDir();
    const target = join(workDir, "state-target.json");
    writeFileSync(target, JSON.stringify({}));
    const pidFile = join(workDir, ".e2e-pids.json");
    symlinkSync(target, pidFile);
    await expect(runGlobalTeardown(pidFile, nextDir)).rejects.toThrow(/state file/);
    expect(existsSync(target)).toBe(true);
    expect(existsSync(pidFile)).toBe(false);
  });
});
