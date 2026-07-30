import { describe, expect, test } from "bun:test";
import { registerShutdownHook, runShutdownHooks } from "../services/shutdown-hooks";

describe("shutdown durability hooks", () => {
  test("runs registered persistence work", async () => {
    let persisted = false;
    registerShutdownHook(() => {
      persisted = true;
    });
    await runShutdownHooks();
    expect(persisted).toBe(true);
  });

  test("fails closed when persistence fails", async () => {
    registerShutdownHook(() => {
      throw new Error("seal failed");
    });
    await expect(runShutdownHooks()).rejects.toThrow("seal failed");
  });
});
