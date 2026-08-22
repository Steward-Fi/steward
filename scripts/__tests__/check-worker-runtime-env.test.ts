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
    writeFileSync(
      join(root, "packages/api/src/worker.ts"),
      'import "./routes/unsafe";\nexport default {};\n',
    );
    writeFileSync(join(directory, "unsafe.ts"), "export const secret = process.env.SECRET;\n");
    expect(() => assertWorkerRuntimeEnvInventory(root)).toThrow(
      "unapproved Worker process.env readers: packages/api/src/routes/unsafe.ts",
    );
  });

  test("traverses runtime workspace imports but ignores unreachable source", () => {
    const root = mkdtempSync(join(tmpdir(), "steward-worker-env-graph-"));
    temporaryRoots.push(root);
    mkdirSync(join(root, "packages/api/src"), { recursive: true });
    mkdirSync(join(root, "packages/consumer/src"), { recursive: true });
    writeFileSync(join(root, "packages/api/package.json"), '{"name":"@stwd/api"}\n');
    writeFileSync(
      join(root, "packages/consumer/package.json"),
      '{"name":"@stwd/consumer","exports":{".":{"import":"./dist/runtime-entry.js"}}}\n',
    );
    writeFileSync(
      join(root, "packages/api/src/worker.ts"),
      'import { value } from "@stwd/consumer";\nexport default value;\n',
    );
    writeFileSync(
      join(root, "packages/consumer/src/runtime-entry.ts"),
      "export const value = process.env.SECRET;\n",
    );
    writeFileSync(
      join(root, "packages/api/src/unreachable.ts"),
      "export const decoy = process.env.DECOY;\n",
    );

    expect(workerProcessEnvReaders(root)).toEqual(["packages/consumer/src/runtime-entry.ts"]);
  });
});
