import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const runner = join(import.meta.dir, "../../scripts/run-tests-isolated.ts");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })));
});

async function fixtureRoot(): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), "steward-isolated-runner-"));
  temporaryDirectories.push(path);
  return path;
}

async function run(root: string, filters: string[] = [], overrides: Record<string, string> = {}) {
  const child = Bun.spawn(["bun", runner, ...filters], {
    cwd: join(import.meta.dir, "../.."),
    env: {
      ...process.env,
      ISOLATED_TEST_ROOT: root,
      TEST_TIMEOUT: "5000",
      TEST_WALL_TIMEOUT_MS: "2000",
      TEST_KILL_GRACE_MS: "100",
      ...overrides,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { code, output: stdout + stderr };
}

async function waitForProcessExit(pid: number): Promise<boolean> {
  for (let i = 0; i < 100; i += 1) {
    try {
      process.kill(pid, 0);
      await Bun.sleep(20);
    } catch {
      return true;
    }
  }
  return false;
}

describe("isolated test runner", () => {
  test("discovers canonical test/spec TypeScript and TSX names", async () => {
    const root = await fixtureRoot();
    for (const name of ["a.test.ts", "b.spec.ts", "c.test.tsx", "d.spec.tsx"]) {
      await writeFile(
        join(root, name),
        'import { test, expect } from "bun:test"; test("ok",()=>expect(1).toBe(1));',
      );
    }
    await writeFile(join(root, "ignored.ts"), 'throw new Error("must not run")');
    const result = await run(root);
    expect(result.code).toBe(0);
    expect(result.output).toContain("4/4 test files passed");
  });

  test("bounds top-level module hangs with an external wall deadline", async () => {
    const root = await fixtureRoot();
    await writeFile(join(root, "hang.test.ts"), "await new Promise(() => {});");
    const started = Date.now();
    const result = await run(root, [], { TEST_WALL_TIMEOUT_MS: "300" });
    expect(result.code).not.toBe(0);
    expect(result.output).toContain("wall timeout after 300ms");
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  test("escalates to KILL and removes a TERM-ignoring descendant process group", async () => {
    const root = await fixtureRoot();
    const childPidFile = join(root, "child-pid");
    const descendantPidFile = join(root, "descendant-pid");
    const childTermFile = join(root, "child-term");
    const descendantTermFile = join(root, "descendant-term");
    const descendantSource = `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(descendantPidFile)},String(process.pid)); process.on("SIGTERM",()=>writeFileSync(${JSON.stringify(descendantTermFile)},"term")); await new Promise(()=>{});`;
    await writeFile(
      join(root, "kill.spec.ts"),
      `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(childPidFile)},String(process.pid)); Bun.spawn(["bun","-e",${JSON.stringify(descendantSource)}],{stdout:"ignore",stderr:"ignore"}); process.on("SIGTERM",()=>writeFileSync(${JSON.stringify(childTermFile)},"term")); await new Promise(()=>{});`,
    );

    const result = await run(root, [], {
      TEST_WALL_TIMEOUT_MS: "800",
      TEST_KILL_GRACE_MS: "200",
    });
    expect(result.code).not.toBe(0);
    expect(result.output).toContain("wall timeout after 800ms");
    expect(await readFile(childTermFile, "utf8")).toBe("term");
    expect(await readFile(descendantTermFile, "utf8")).toBe("term");

    const childPid = Number(await readFile(childPidFile, "utf8"));
    const descendantPid = Number(await readFile(descendantPidFile, "utf8"));
    expect(childPid).toBeGreaterThan(1);
    expect(descendantPid).toBeGreaterThan(1);
    expect(await waitForProcessExit(childPid)).toBe(true);
    expect(await waitForProcessExit(descendantPid)).toBe(true);
  });

  test("forwards timeout TERM to the child and reports nonzero/no-match", async () => {
    const root = await fixtureRoot();
    const marker = join(root, "term-marker");
    await writeFile(
      join(root, "signal.test.ts"),
      `import { writeFileSync } from "node:fs"; process.on("SIGTERM",()=>{writeFileSync(${JSON.stringify(marker)},"term");process.exit(143)}); await new Promise(()=>{});`,
    );
    const signaled = await run(root, [], { TEST_WALL_TIMEOUT_MS: "800" });
    expect(signaled.code).not.toBe(0);
    expect(await readFile(marker, "utf8")).toBe("term");
    expect((await run(root, ["does-not-match"])).code).not.toBe(0);

    await writeFile(
      join(root, "fail.spec.ts"),
      'import { test } from "bun:test"; test("no",()=>{throw new Error("FAIL_SENTINEL")});',
    );
    const failed = await run(root, ["fail.spec"]);
    expect(failed.code).not.toBe(0);
    expect(failed.output).toContain("FAIL_SENTINEL");
  });

  test("forwards parent SIGTERM and leaves no orphan child", async () => {
    const root = await fixtureRoot();
    const pidFile = join(root, "child-pid");
    await writeFile(
      join(root, "orphan.test.ts"),
      `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(pidFile)},String(process.pid)); await new Promise(()=>{});`,
    );
    const parent = Bun.spawn(["bun", runner], {
      cwd: join(import.meta.dir, "../.."),
      env: {
        ...process.env,
        ISOLATED_TEST_ROOT: root,
        TEST_WALL_TIMEOUT_MS: "10000",
        TEST_KILL_GRACE_MS: "100",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    let childPid = 0;
    for (let i = 0; i < 50 && childPid === 0; i += 1) {
      await Bun.sleep(20);
      childPid = Number(await readFile(pidFile, "utf8").catch(() => "0"));
    }
    expect(childPid).toBeGreaterThan(1);
    parent.kill("SIGTERM");
    expect(await parent.exited).toBe(143);
    expect(await waitForProcessExit(childPid)).toBe(true);
  });

  test("clears the wall deadline and terminates the child when stream draining rejects", async () => {
    const root = await fixtureRoot();
    const pidFile = join(root, "drain-failure-pid");
    await writeFile(
      join(root, "drain-failure.test.ts"),
      `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(pidFile)},String(process.pid)); console.log("DRAIN_FAILURE_SENTINEL"); process.on("SIGTERM",()=>{}); await new Promise(()=>{});`,
    );
    const started = Date.now();
    const result = await run(root, [], {
      ISOLATED_RUNNER_TEST_DRAIN_FAILURE_AFTER: "DRAIN_FAILURE_SENTINEL",
      TEST_WALL_TIMEOUT_MS: "5000",
      TEST_KILL_GRACE_MS: "100",
    });
    const elapsed = Date.now() - started;
    const childPid = Number(await readFile(pidFile, "utf8"));

    expect(result.code).not.toBe(0);
    expect(result.output).toContain("simulated isolated runner stream failure");
    expect(elapsed).toBeLessThan(2_000);
    expect(await waitForProcessExit(childPid)).toBe(true);
  });

  test("discards success output and retains only a bounded failure tail", async () => {
    const root = await fixtureRoot();
    await writeFile(
      join(root, "success.test.ts"),
      'import { test } from "bun:test"; test("ok",()=>console.log("SUCCESS_SECRET"));',
    );
    const success = await run(root, ["success"]);
    expect(success.code).toBe(0);
    expect(success.output).not.toContain("SUCCESS_SECRET");

    await writeFile(
      join(root, "failure.test.ts"),
      'import { test } from "bun:test"; test("bad",()=>{console.error("A".repeat(200000));throw new Error("TAIL_SENTINEL")});',
    );
    const failure = await run(root, ["failure"], { TEST_FAILURE_TAIL_BYTES: "4096" });
    expect(failure.code).not.toBe(0);
    expect(failure.output.length).toBeLessThan(10_000);
    expect(failure.output).toContain("TAIL_SENTINEL");
  });
});
