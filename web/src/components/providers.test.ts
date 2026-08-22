// @ts-nocheck
import { describe, expect, test } from "bun:test";

describe("AuthTokenSync security invariants", () => {
  test("settles wallet chunk failures so non-wallet pages can continue", async () => {
    const { resolveWalletRuntime } = await import("./providers");
    const result = await resolveWalletRuntime(async () => {
      throw new Error("wallet chunk unavailable");
    });

    expect(result).toEqual({ status: "failed" });
  });

  test("bounds a wallet chunk that never settles", async () => {
    const { resolveWalletRuntime } = await import("./providers");
    const startedAt = Date.now();
    const result = await resolveWalletRuntime(() => new Promise(() => {}), 5);

    expect(result).toEqual({ status: "failed" });
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  test("ignores a wallet chunk that resolves after the loading deadline", async () => {
    const { resolveWalletRuntime } = await import("./providers");
    let resolveLoad: ((runtime: never) => void) | undefined;
    const lateLoad = new Promise<never>((resolve) => {
      resolveLoad = resolve;
    });

    const result = await resolveWalletRuntime(() => lateLoad, 1);
    resolveLoad?.([] as never);
    await Promise.resolve();

    expect(result).toEqual({ status: "failed" });
  });
});
