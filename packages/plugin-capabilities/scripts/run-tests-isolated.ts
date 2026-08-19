#!/usr/bin/env bun
/** Run every test file in a separate process so fixture globals cannot cross files. */
import { readdirSync } from "node:fs";
import { join } from "node:path";

const packageRoot = join(import.meta.dir, "..");
const testRoot = join(packageRoot, "src", "__tests__");
const filters = process.argv.slice(2);

function findTests(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return findTests(path);
      return entry.name.endsWith(".test.ts") ? [path] : [];
    })
    .sort();
}

const relativeName = (path: string): string => path.slice(testRoot.length + 1);
const tests = findTests(testRoot).filter(
  (path) => filters.length === 0 || filters.some((filter) => relativeName(path).includes(filter)),
);
if (tests.length === 0) {
  throw new Error(`No plugin-capabilities tests matched: ${filters.join(", ")}`);
}

const timeout = process.env.TEST_TIMEOUT ?? "30000";
const results: Array<{ path: string; exitCode: number; output: string }> = [];

for (const path of tests) {
  const child = Bun.spawn(["bun", "test", "--timeout", timeout, path], {
    cwd: packageRoot,
    env: process.env,
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  const output = `${stdout}${stderr}`;
  results.push({ path, exitCode, output });
  console.log(`[isolated] ${exitCode === 0 ? "PASS" : "FAIL"} ${relativeName(path)}`);
  if (exitCode !== 0) console.error(output.trim());
}

const failures = results.filter(({ exitCode }) => exitCode !== 0);
if (failures.length > 0) {
  throw new Error(
    `${failures.length}/${results.length} isolated test files failed: ${failures
      .map(({ path }) => relativeName(path))
      .join(", ")}`,
  );
}

console.log(`[isolated] ${results.length}/${results.length} test files passed`);
