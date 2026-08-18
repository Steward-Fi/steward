import { afterEach, describe, expect, test } from "bun:test";
import { closeDb, getDb, getSql, withRequestDatabase } from "../client";

const originalDriver = process.env.DATABASE_DRIVER;

afterEach(async () => {
  await closeDb();
  if (originalDriver === undefined) delete process.env.DATABASE_DRIVER;
  else process.env.DATABASE_DRIVER = originalDriver;
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("request-scoped database context", () => {
  test("routes getDb through the exact async request and clears it afterward", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    expect(
      await withRequestDatabase(requestDb, async () => {
        await Promise.resolve();
        return getDb();
      }),
    ).toBe(requestDb);

    process.env.DATABASE_DRIVER = "neon-websocket";
    expect(() => getDb()).toThrow("RLS_TRANSACTION_HANDLE_REQUIRED");
  });

  test("keeps concurrent request handles isolated across interleaving awaits", async () => {
    const dbA = { marker: "a" } as unknown as ReturnType<typeof getDb>;
    const dbB = { marker: "b" } as unknown as ReturnType<typeof getDb>;
    const aEntered = deferred();
    const releaseA = deferred();

    const a = withRequestDatabase(dbA, async () => {
      expect(getDb()).toBe(dbA);
      aEntered.resolve();
      await releaseA.promise;
      expect(getDb()).toBe(dbA);
      return "a";
    });
    await aEntered.promise;
    const b = withRequestDatabase(dbB, async () => {
      expect(getDb()).toBe(dbB);
      await Promise.resolve();
      expect(getDb()).toBe(dbB);
      return "b";
    });
    expect(await b).toBe("b");
    releaseA.resolve();
    expect(await a).toBe("a");
  });

  test("rejects nested replacement and raw SQL bypass", async () => {
    const outer = { marker: "outer" } as unknown as ReturnType<typeof getDb>;
    const inner = { marker: "inner" } as unknown as ReturnType<typeof getDb>;
    await withRequestDatabase(outer, async () => {
      await expect(withRequestDatabase(inner, async () => undefined)).rejects.toThrow(
        "REQUEST_DATABASE_CONTEXT_NESTED",
      );
      expect(() => getSql()).toThrow("REQUEST_DATABASE_RAW_SQL_UNAVAILABLE");
      expect(getDb()).toBe(outer);
    });
  });
});
