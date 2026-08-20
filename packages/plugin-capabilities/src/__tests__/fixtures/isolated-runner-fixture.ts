import { expect, test } from "bun:test";
import { existsSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";

const root = process.env.ISOLATED_FIXTURE_ROOT;
if (!root) throw new Error("ISOLATED_FIXTURE_ROOT is required");

const role = process.argv[2] ?? basename(import.meta.path).split(".")[0];
const fixturePath = (name: string) => join(root, name);

switch (role) {
  case "hang":
    await new Promise(() => {});
    break;
  case "kill": {
    process.on("SIGTERM", () => {
      writeFileSync(fixturePath("child-term"), "term");
      setTimeout(() => process.exit(0), 50);
    });
    Bun.spawn(["bun", import.meta.path, "kill-descendant"], {
      env: process.env,
      stdout: "ignore",
      stderr: "ignore",
    });
    writeFileSync(fixturePath("child-pid"), String(process.pid));
    await new Promise(() => {});
    break;
  }
  case "kill-descendant":
    process.on("SIGTERM", () => writeFileSync(fixturePath("descendant-term"), "term"));
    writeFileSync(fixturePath("descendant-pid"), String(process.pid));
    await new Promise(() => {});
    break;
  case "clean-leader":
    test("clean leader", async () => {
      const child = Bun.spawn(["bun", import.meta.path, "clean-leader-descendant"], {
        env: process.env,
        stdout: "inherit",
        stderr: "inherit",
      });
      child.unref();
      for (let i = 0; i < 400; i += 1) {
        if (
          await readFile(fixturePath("clean-leader-descendant-pid"))
            .then((value) => value.length > 0)
            .catch(() => false)
        )
          break;
        await Bun.sleep(20);
      }
      expect(await readFile(fixturePath("clean-leader-descendant-pid"), "utf8")).not.toBe("");
    });
    break;
  case "clean-leader-descendant":
    writeFileSync(fixturePath("clean-leader-descendant-pid"), String(process.pid));
    await new Promise(() => {});
    break;
  case "signal":
    process.on("SIGTERM", () => {
      writeFileSync(fixturePath("term-marker"), "term");
      process.exit(143);
    });
    writeFileSync(fixturePath("term-handler-ready"), "ready");
    await new Promise(() => {});
    break;
  case "orphan":
    writeFileSync(fixturePath("child-pid"), String(process.pid));
    await new Promise(() => {});
    break;
  case "drain-failure":
    writeFileSync(fixturePath("drain-failure-pid"), String(process.pid));
    writeFileSync(fixturePath("drain-failure-ready"), "ready");
    while (!existsSync(fixturePath("drain-failure-trigger"))) await Bun.sleep(10);
    process.stdout.write("DRAIN_FAILURE_SENTINEL\n");
    process.on("SIGTERM", () => {});
    await new Promise(() => {});
    break;
  case "failure":
    test("bad", () => {
      console.error("A".repeat(200_000));
      throw new Error("TAIL_SENTINEL");
    });
    break;
  case "explicit-failure":
    test("no", () => {
      throw new Error("FAIL_SENTINEL");
    });
    break;
  case "success":
    test("ok", () => console.log("SUCCESS_SECRET"));
    break;
  default:
    test("ok", () => expect(1).toBe(1));
}
