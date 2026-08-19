import { afterEach, describe, expect, test } from "bun:test";
import {
  closeDb,
  getDb,
  getSql,
  registerRequestDatabaseTask,
  withRequestDatabase,
} from "../client";

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
        expect(getDb()).not.toBe(requestDb);
        return (getDb() as unknown as { marker: string }).marker;
      }),
    ).toBe("request");

    process.env.DATABASE_DRIVER = "neon-websocket";
    expect(() => getDb()).toThrow("RLS_TRANSACTION_HANDLE_REQUIRED");
  });

  test("keeps concurrent request handles isolated across interleaving awaits", async () => {
    const dbA = { marker: "a" } as unknown as ReturnType<typeof getDb>;
    const dbB = { marker: "b" } as unknown as ReturnType<typeof getDb>;
    const aEntered = deferred();
    const releaseA = deferred();

    const a = withRequestDatabase(dbA, async () => {
      expect((getDb() as unknown as { marker: string }).marker).toBe("a");
      aEntered.resolve();
      await releaseA.promise;
      expect((getDb() as unknown as { marker: string }).marker).toBe("a");
      return "a";
    });
    await aEntered.promise;
    const b = withRequestDatabase(dbB, async () => {
      expect((getDb() as unknown as { marker: string }).marker).toBe("b");
      await Promise.resolve();
      expect((getDb() as unknown as { marker: string }).marker).toBe("b");
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
      expect((getDb() as unknown as { marker: string }).marker).toBe("outer");
    });
  });

  test("revokes the database capability inherited by detached async work", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let detached!: Promise<void>;
    await withRequestDatabase(requestDb, async () => {
      detached = (async () => {
        await release.promise;
        expect(() => getDb()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
        expect(() => getSql()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
      })();
    });
    release.resolve();
    await detached;
  });

  test("revokes a database handle and derived query captured before owner completion", async () => {
    const rawSelect = () => ({ from: () => Promise.resolve([]) });
    const requestDb = { select: rawSelect } as unknown as ReturnType<typeof getDb>;
    let capturedDb!: ReturnType<typeof getDb>;
    let capturedSelect!: ReturnType<typeof getDb>["select"];
    let capturedQuery!: ReturnType<ReturnType<typeof getDb>["select"]>;

    await withRequestDatabase(requestDb, async () => {
      capturedDb = getDb();
      capturedSelect = capturedDb.select;
      capturedQuery = capturedDb.select();
    });

    expect(capturedDb).not.toBe(requestDb);
    expect(() => capturedDb.select()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedSelect()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedQuery.from({} as never)).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
  });

  test("defers revocation until registered background database work settles", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let cleanup!: Promise<void>;
    let background!: Promise<void>;

    const result = await withRequestDatabase(
      requestDb,
      async () => {
        background = registerRequestDatabaseTask(async () => {
          await release.promise;
          expect((getDb() as unknown as { marker: string }).marker).toBe("request");
        });
        return "response";
      },
      {
        deferCleanup(promise) {
          cleanup = promise;
        },
      },
    );

    expect(result).toBe("response");
    let cleaned = false;
    void cleanup.then(() => {
      cleaned = true;
    });
    await Promise.resolve();
    expect(cleaned).toBe(false);
    release.resolve();
    await Promise.all([background, cleanup]);
    expect(cleaned).toBe(true);
  });

  test("does not let unregistered work piggyback on a registered task lifetime", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let cleanup!: Promise<void>;
    let registered!: Promise<void>;
    let detached!: Promise<void>;

    await withRequestDatabase(
      requestDb,
      async () => {
        registered = registerRequestDatabaseTask(async () => {
          await release.promise;
          expect((getDb() as unknown as { marker: string }).marker).toBe("request");
        });
        detached = (async () => {
          await release.promise;
          expect(() => getDb()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
        })();
      },
      {
        deferCleanup(promise) {
          cleanup = promise;
        },
      },
    );

    release.resolve();
    await Promise.all([registered, detached, cleanup]);
  });
});
