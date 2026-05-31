#!/usr/bin/env bun
/**
 * Per-file isolation test runner for @stwd/api.
 *
 * WHY THIS EXISTS
 * ---------------
 * `bun test src/__tests__/` runs all ~135 test files in ONE process, and Bun
 * shares the module registry across them. Several service modules resolve
 * env-derived state at import time and are then cached for the life of the
 * process — a db handle, the master password, feature flags, and (in some test
 * files) `globalThis.fetch`. Whichever file imports a given module first freezes
 * that state for every later file, so state leaks across files and produces
 * failures that DO NOT reproduce when the file is run on its own.
 *
 * Running each file in its own `bun test` process gives every file a pristine
 * module registry and a fresh `process.env`, which is the standard isolation
 * model (Jest workers, pytest-xdist, vitest pool=forks) and the only fully
 * robust fix for cross-file global-state contamination. It is strictly MORE
 * rigorous than the single-process suite: no leaked state from a neighbouring
 * file can ever mask a real per-file regression.
 *
 * SAFE TO PARALLELISE
 * -------------------
 * Each spawned process is independent. `test-preload.ts` bootstraps a fresh
 * in-memory PGLite per process (when no real DATABASE_URL is set) and there is
 * no shared Redis server in the test environment, so concurrent processes do
 * not collide on any shared backing store.
 *
 * USAGE
 * -----
 *   bun scripts/run-tests-isolated.ts                # default concurrency
 *   TEST_JOBS=1   bun scripts/run-tests-isolated.ts  # serial (matches solo)
 *   TEST_JOBS=12  bun scripts/run-tests-isolated.ts  # more parallelism
 *   TEST_TIMEOUT=60000 bun scripts/run-tests-isolated.ts
 *   bun scripts/run-tests-isolated.ts foo bar        # only files matching
 *                                                    # "foo" or "bar"
 *
 * Exit code is non-zero if any file fails, so it drops straight into
 * `turbo test` / `bun run verify`.
 */
import { readdirSync } from "node:fs";
import { cpus } from "node:os";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const testDir = join(apiRoot, "src", "__tests__");

function findTestFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...findTestFiles(full));
    else if (entry.name.endsWith(".test.ts")) out.push(full);
  }
  return out.sort();
}

const rel = (file: string): string => file.slice(testDir.length + 1);

const filters = process.argv.slice(2);
const allFiles = findTestFiles(testDir);
const files =
  filters.length > 0
    ? allFiles.filter((file) => filters.some((needle) => rel(file).includes(needle)))
    : allFiles;

if (files.length === 0) {
  console.error(
    `[isolated] no test files matched ${filters.length ? filters.join(", ") : testDir}`,
  );
  process.exit(1);
}

const timeout = process.env.TEST_TIMEOUT ?? "30000";
const defaultJobs = Math.max(1, Math.min(cpus().length, 8));
const jobs = Math.max(1, Number(process.env.TEST_JOBS) || defaultJobs);

interface Result {
  file: string;
  ok: boolean;
  code: number | null;
  output: string;
  ms: number;
}

async function runFile(file: string): Promise<Result> {
  const started = Date.now();
  try {
    const proc = Bun.spawn(["bun", "test", "--timeout", timeout, file], {
      cwd: apiRoot,
      stdout: "pipe",
      stderr: "pipe",
      env: process.env,
    });
    // Drain stdout/stderr concurrently to avoid the child blocking on a full
    // pipe buffer, and await the exit code at the same time.
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    return { file, ok: code === 0, code, output: `${stdout}${stderr}`, ms: Date.now() - started };
  } catch (error) {
    return {
      file,
      ok: false,
      code: null,
      output: `[isolated] failed to spawn: ${(error as Error).message}`,
      ms: Date.now() - started,
    };
  }
}

console.log(
  `[isolated] ${files.length} file(s) · concurrency ${jobs} · timeout ${timeout}ms · cwd ${apiRoot}`,
);

const results: Result[] = [];
let cursor = 0;

async function worker(): Promise<void> {
  for (let index = cursor++; index < files.length; index = cursor++) {
    const file = files[index];
    const result = await runFile(file);
    results.push(result);
    const tag = result.ok ? "PASS" : "FAIL";
    console.log(`  ${tag} ${rel(file)} (${result.ms}ms) [${results.length}/${files.length}]`);
    if (!result.ok) {
      const tail = result.output.trimEnd().split("\n").slice(-30).join("\n");
      console.log(tail.replace(/^/gm, "    │ "));
    }
  }
}

const startedAt = Date.now();
await Promise.all(Array.from({ length: Math.min(jobs, files.length) }, () => worker()));
const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);

const failed = results.filter((result) => !result.ok).sort((a, b) => a.file.localeCompare(b.file));
console.log(
  `\n[isolated] ${results.length - failed.length}/${results.length} file(s) passed in ${elapsed}s`,
);

if (failed.length > 0) {
  console.log("[isolated] FAILED file(s):");
  for (const result of failed) {
    console.log(`  - ${rel(result.file)} (exit ${result.code})`);
  }
  process.exit(1);
}

console.log("[isolated] all files passed");
