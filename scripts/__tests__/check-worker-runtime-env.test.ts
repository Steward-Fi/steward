import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  APPROVED_WORKER_PROCESS_ENV_READERS,
  assertWorkerRuntimeEnvInventory,
  workerProcessEnvReaders,
} from "../check-worker-runtime-env";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("Worker runtime environment inventory", () => {
  test("the repository has no unapproved Worker-reachable process.env reader", () => {
    const root = resolve(import.meta.dir, "../..");
    expect(() => assertWorkerRuntimeEnvInventory(root)).not.toThrow();
    expect(workerProcessEnvReaders(root)).toEqual(
      Object.keys(APPROVED_WORKER_PROCESS_ENV_READERS).sort(),
    );
  });

  test("a new security reader fails the guard", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-worker-env-inventory-"));
    temporaryRoots.push(root);
    const directory = join(root, "packages/api/src/routes");
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "unsafe.ts"), "export const secret = process.env.SECRET;\n");
    expect(() => assertWorkerRuntimeEnvInventory(root)).toThrow(
      "unapproved Worker process.env readers: packages/api/src/routes/unsafe.ts",
    );
  });
});
