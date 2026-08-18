#!/usr/bin/env bun

import { readdirSync } from "node:fs";
import { join } from "node:path";

const packageRoot = join(import.meta.dir, "..");
const testRoot = join(packageRoot, "src", "__tests__");

function collectTests(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...collectTests(path));
    else if (entry.name.endsWith(".test.ts")) files.push(path);
  }
  return files.sort();
}

const relativeName = (file: string): string => file.slice(testRoot.length + 1);
const filters = process.argv.slice(2);
const files = collectTests(testRoot).filter(
  (file) => filters.length === 0 || filters.some((filter) => relativeName(file).includes(filter)),
);

if (files.length === 0) {
  console.error(`[isolated] no test files matched ${filters.join(", ") || testRoot}`);
  process.exit(1);
}

const timeout = process.env.TEST_TIMEOUT ?? "30000";
let failures = 0;
const startedAt = Date.now();

console.log(`[isolated] ${files.length} file(s) · concurrency 1 · timeout ${timeout}ms`);

for (const [index, file] of files.entries()) {
  const started = Date.now();
  const child = Bun.spawn(["bun", "test", "--timeout", timeout, file], {
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
  const passed = exitCode === 0;
  if (!passed) failures += 1;
  console.log(
    `  ${passed ? "PASS" : "FAIL"} ${relativeName(file)} (${Date.now() - started}ms) [${index + 1}/${files.length}]`,
  );
  if (!passed) {
    const output = `${stdout}${stderr}`.trimEnd().split("\n").slice(-40).join("\n");
    console.log(output.replace(/^/gm, "    │ "));
  }
}

const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
console.log(
  `\n[isolated] ${files.length - failures}/${files.length} file(s) passed in ${elapsed}s`,
);
if (failures > 0) process.exit(1);
