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
  const goneProcess = (pid: number) => ({
    pid,
    startedAt: "Mon Jan  1 00:00:00 2001",
    command: "steward-e2e-process",
  });

  const runningProcessControl = (overrides?: {
    runPs?: (args: string[]) => {
      error?: Error;
      status: number | null;
      signal: NodeJS.Signals | null;
      stdout: string;
      stderr: string;
    };
    kill?: (pid: number, signal: "SIGTERM") => void;
  }) => ({
    runPs:
      overrides?.runPs ??
      ((args: string[]) => ({
        status: 0,
        signal: null,
        stdout: args.at(-1) === "lstart=" ? "Mon Jan  1 00:00:00 2001\n" : "steward-e2e-process\n",
        stderr: "",
      })),
    kill: overrides?.kill ?? (() => {}),
  });

  test("removes .next when setup failed before its first state write", async () => {
    const nextDir = makeNextDir();

    await runGlobalTeardown(join(workDir, ".e2e-pids.json"), nextDir);

    expect(existsSync(nextDir)).toBe(false);
  });

  test("removes .next, the PID file, and the data dir on a normal run", async () => {
    const nextDir = makeNextDir();
    const dataDir = mkdtempSync(join(tmpdir(), "steward-e2e-"));
    const pidFile = join(workDir, ".e2e-pids.json");
    // Bogus pids represent processes that are already gone.
    writeFileSync(
      pidFile,
      JSON.stringify({ web: goneProcess(999999), api: goneProcess(999998), dataDir }),
    );

    await runGlobalTeardown(
      pidFile,
      nextDir,
      runningProcessControl({
        runPs: () => ({ status: 1, signal: null, stdout: "", stderr: "" }),
      }),
    );

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
    writeFileSync(pidFile, JSON.stringify({ web: { ...goneProcess(999999), pid: -1 } }));
    await expect(runGlobalTeardown(pidFile, nextDir)).rejects.toThrow(/Invalid web PID/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("refuses a reused PID whose process identity no longer matches", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(process.pid) }));
    await expect(runGlobalTeardown(pidFile, nextDir)).rejects.toThrow(/reused web PID/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("surfaces a process-inspection launch failure", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));
    const launchError = Object.assign(new Error("ps unavailable"), { code: "ENOENT" });

    await expect(
      runGlobalTeardown(
        pidFile,
        nextDir,
        runningProcessControl({
          runPs: () => ({
            error: launchError,
            status: null,
            signal: null,
            stdout: "",
            stderr: "",
          }),
        }),
      ),
    ).rejects.toThrow(/Could not inspect web process/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("surfaces an unexpected nonzero ps status", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));

    await expect(
      runGlobalTeardown(
        pidFile,
        nextDir,
        runningProcessControl({
          runPs: () => ({
            status: 2,
            signal: null,
            stdout: "",
            stderr: "synthetic ps failure",
          }),
        }),
      ),
    ).rejects.toThrow(/ps exited with status 2/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("does not mistake ps status 1 with an error message for an exited process", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));

    await expect(
      runGlobalTeardown(
        pidFile,
        nextDir,
        runningProcessControl({
          runPs: () => ({
            status: 1,
            signal: null,
            stdout: "",
            stderr: "synthetic inspection failure",
          }),
        }),
      ),
    ).rejects.toThrow(/ps exited with status 1/);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("treats ps status 1 with no output as an exited process", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));
    let signalCalls = 0;

    await runGlobalTeardown(
      pidFile,
      nextDir,
      runningProcessControl({
        runPs: () => ({ status: 1, signal: null, stdout: "", stderr: "" }),
        kill: () => {
          signalCalls += 1;
        },
      }),
    );

    expect(signalCalls).toBe(0);
    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("suppresses ESRCH when a matched process exits before signaling", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));

    await runGlobalTeardown(
      pidFile,
      nextDir,
      runningProcessControl({
        kill: () => {
          throw Object.assign(new Error("gone"), { code: "ESRCH" });
        },
      }),
    );

    expect(existsSync(nextDir)).toBe(false);
    expect(existsSync(pidFile)).toBe(false);
  });

  test("surfaces EPERM from signaling a matched process", async () => {
    const nextDir = makeNextDir();
    const pidFile = join(workDir, ".e2e-pids.json");
    writeFileSync(pidFile, JSON.stringify({ web: goneProcess(4242) }));

    await expect(
      runGlobalTeardown(
        pidFile,
        nextDir,
        runningProcessControl({
          kill: () => {
            throw Object.assign(new Error("not permitted"), { code: "EPERM" });
          },
        }),
      ),
    ).rejects.toThrow(/Could not terminate web process/);
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
