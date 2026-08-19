#!/usr/bin/env bun
/** Run each test file in its own bounded process so fixture globals cannot cross files. */
import { readdirSync } from "node:fs";
import { join, relative } from "node:path";

const packageRoot = join(import.meta.dir, "..");
const testRoot = process.env.ISOLATED_TEST_ROOT ?? join(packageRoot, "src", "__tests__");
const filters = process.argv.slice(2);
const TEST_FILE_PATTERN = /\.(?:test|spec)\.(?:ts|tsx)$/u;
const timeout = Number(process.env.TEST_TIMEOUT ?? "30000");
const wallTimeout = Number(process.env.TEST_WALL_TIMEOUT_MS ?? "180000");
const killGrace = Number(process.env.TEST_KILL_GRACE_MS ?? "2000");
const tailBytes = Number(process.env.TEST_FAILURE_TAIL_BYTES ?? String(16 * 1024));

function findTests(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return findTests(path);
      return TEST_FILE_PATTERN.test(entry.name) ? [path] : [];
    })
    .sort();
}

const relativeName = (path: string): string => relative(testRoot, path);
const tests = findTests(testRoot).filter(
  (path) => filters.length === 0 || filters.some((filter) => relativeName(path).includes(filter)),
);
if (tests.length === 0) {
  console.error(`[isolated] no tests matched: ${filters.join(", ") || testRoot}`);
  process.exit(1);
}
if (
  !Number.isFinite(timeout) ||
  timeout <= 0 ||
  !Number.isFinite(wallTimeout) ||
  wallTimeout <= 0 ||
  !Number.isFinite(killGrace) ||
  killGrace <= 0 ||
  !Number.isFinite(tailBytes) ||
  tailBytes <= 0
) {
  throw new Error("runner timeout, kill grace, and failure tail limits must be positive numbers");
}

type Child = ReturnType<typeof Bun.spawn>;
const active = new Set<Child>();
let interruptedSignal: "SIGINT" | "SIGTERM" | undefined;

function signalTree(child: Child, signal: "SIGTERM" | "SIGKILL"): void {
  const pid = child.pid;
  if (!Number.isSafeInteger(pid) || pid <= 1) return;
  try {
    process.kill(-pid, signal);
  } catch {
    try {
      child.kill(signal);
    } catch {}
  }
}

async function terminate(child: Child): Promise<void> {
  signalTree(child, "SIGTERM");
  const killer = setTimeout(() => signalTree(child, "SIGKILL"), killGrace);
  try {
    await child.exited;
  } finally {
    clearTimeout(killer);
    active.delete(child);
  }
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    if (interruptedSignal) return;
    interruptedSignal = signal;
    void Promise.all([...active].map(terminate)).finally(() => {
      process.exit(signal === "SIGINT" ? 130 : 143);
    });
  });
}

async function drainTail(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  let retained = new Uint8Array();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const combined = new Uint8Array(retained.length + value.length);
    combined.set(retained);
    combined.set(value, retained.length);
    retained = combined.length > tailBytes ? combined.slice(combined.length - tailBytes) : combined;
  }
  return new TextDecoder().decode(retained);
}

const failures: string[] = [];
try {
  for (const path of tests) {
    const child = Bun.spawn(["bun", "test", "--timeout", String(timeout), path], {
      cwd: packageRoot,
      env: process.env,
      stdout: "pipe",
      stderr: "pipe",
      detached: true,
    });
    active.add(child);
    let timedOut = false;
    const deadline = setTimeout(() => {
      timedOut = true;
      void terminate(child);
    }, wallTimeout);
    const [stdout, stderr, exitCode] = await Promise.all([
      drainTail(child.stdout),
      drainTail(child.stderr),
      child.exited,
    ]);
    clearTimeout(deadline);
    active.delete(child);
    const ok = exitCode === 0 && !timedOut;
    console.log(`[isolated] ${ok ? "PASS" : "FAIL"} ${relativeName(path)}`);
    if (!ok) {
      failures.push(relativeName(path));
      const reason = timedOut ? `[isolated] wall timeout after ${wallTimeout}ms\n` : "";
      console.error(`${reason}${stdout}${stderr}`.trim());
    }
    if (interruptedSignal) break;
  }
} finally {
  await Promise.all([...active].map(terminate));
}

if (interruptedSignal) process.exit(interruptedSignal === "SIGINT" ? 130 : 143);
if (failures.length > 0) {
  console.error(`[isolated] ${failures.length}/${tests.length} failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`[isolated] ${tests.length}/${tests.length} test files passed`);
