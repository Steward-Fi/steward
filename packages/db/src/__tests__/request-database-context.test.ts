import { afterEach, describe, expect, test } from "bun:test";
import { sql } from "drizzle-orm";
import {
  closeDb,
  getDb,
  getSql,
  waitUntilRequestDatabaseTask,
  withRequestDatabase,
} from "../client";
import { createPGLiteDb } from "../pglite";

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

  test("does not expose raw capabilities through property descriptors or prototypes", async () => {
    const rawSession = { execute: () => "mutated" };
    const requestDbSource = { session: rawSession };
    Object.defineProperty(requestDbSource, "hook", {
      configurable: true,
      set(callback: (session: typeof rawSession) => void) {
        callback(rawSession);
      },
    });
    const requestDb = requestDbSource as unknown as ReturnType<typeof getDb>;
    let capturedDb!: ReturnType<typeof getDb>;
    let capturedSession!: typeof rawSession;

    await withRequestDatabase(requestDb, async () => {
      capturedDb = getDb();
      expect(Reflect.ownKeys(capturedDb)).toContain("session");
      expect("session" in capturedDb).toBe(true);
      expect(Object.isExtensible(capturedDb)).toBe(true);
      const descriptor = Object.getOwnPropertyDescriptor(capturedDb, "session");
      const hookDescriptor = Object.getOwnPropertyDescriptor(capturedDb, "hook");
      capturedSession = descriptor?.value as typeof rawSession;
      expect(capturedSession).not.toBe(rawSession);
      expect(capturedSession.execute()).toBe("mutated");
      expect(() => hookDescriptor?.set?.(() => undefined)).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.getPrototypeOf(capturedDb)).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.defineProperty(capturedDb, "poison", { value: true })).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Reflect.set(capturedDb, "poison", true)).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Reflect.deleteProperty(capturedDb, "session")).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.setPrototypeOf(capturedDb, {})).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.preventExtensions(capturedDb)).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.defineProperty(capturedSession, "poison", { value: true })).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.setPrototypeOf(capturedSession, {})).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
      expect(() => Object.preventExtensions(capturedSession)).toThrow(
        "REQUEST_DATABASE_REFLECTION_UNAVAILABLE",
      );
    });

    expect(() => capturedSession.execute()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => "session" in capturedDb).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.isExtensible(capturedDb)).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.defineProperty(capturedDb, "poison", { value: true })).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Reflect.set(capturedDb, "poison", true)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Reflect.deleteProperty(capturedDb, "session")).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Object.setPrototypeOf(capturedDb, {})).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.preventExtensions(capturedDb)).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.defineProperty(capturedSession, "poison", { value: true })).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Reflect.deleteProperty(capturedSession, "execute")).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Object.setPrototypeOf(capturedSession, {})).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => Object.preventExtensions(capturedSession)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(rawSession).toEqual({ execute: expect.any(Function) });
    expect(Object.getPrototypeOf(rawSession)).toBe(Object.prototype);
    expect(Object.isExtensible(rawSession)).toBe(true);
    expect("poison" in (requestDb as object)).toBe(false);
  });

  test("revokes returned callables and transaction callback capabilities", async () => {
    const rawTransaction = { execute: () => "raw-transaction-executed" };
    const returnedCallable = (callback?: (tx: typeof rawTransaction) => string) =>
      callback ? callback(rawTransaction) : "raw-callable-executed";
    const requestDb = {
      makeCallable: () => returnedCallable,
      transaction: async (callback: (tx: typeof rawTransaction) => Promise<string>) =>
        callback(rawTransaction),
    } as unknown as ReturnType<typeof getDb>;
    let capturedCallable!: typeof returnedCallable;
    let capturedTransaction!: typeof rawTransaction;
    let capturedFromCallable!: typeof rawTransaction;

    const result = await withRequestDatabase(requestDb, async () => {
      const guarded = getDb() as unknown as {
        makeCallable: () => typeof returnedCallable;
        transaction: (callback: (tx: typeof rawTransaction) => Promise<string>) => Promise<string>;
      };
      capturedCallable = guarded.makeCallable();
      expect(capturedCallable()).toBe("raw-callable-executed");
      expect(
        capturedCallable((transaction) => {
          capturedFromCallable = transaction;
          expect(transaction).not.toBe(rawTransaction);
          return transaction.execute();
        }),
      ).toBe("raw-transaction-executed");
      const echoedTransaction = capturedCallable(
        (transaction) => transaction as never,
      ) as unknown as typeof rawTransaction;
      expect(echoedTransaction).not.toBe(rawTransaction);
      expect(echoedTransaction.execute()).toBe("raw-transaction-executed");
      return guarded.transaction(async (tx) => {
        capturedTransaction = tx;
        expect(tx).not.toBe(rawTransaction);
        return tx.execute();
      });
    });

    expect(result).toBe("raw-transaction-executed");
    expect(() => capturedCallable()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedFromCallable.execute()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedTransaction.execute()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
  });

  test("revokes a real PGLite transaction passed into a callback", async () => {
    const { client, db } = await createPGLiteDb("memory://");
    let capturedTransaction:
      | { execute(query: ReturnType<typeof sql>): Promise<unknown> }
      | undefined;

    try {
      await withRequestDatabase(db as ReturnType<typeof getDb>, async () => {
        await getDb().transaction(async (transaction) => {
          capturedTransaction = transaction;
          await transaction.execute(sql`select 1`);
        });
      });

      expect(capturedTransaction).toBeDefined();
      expect(() => capturedTransaction!.execute(sql`select 1`)).toThrow(
        "REQUEST_DATABASE_CONTEXT_CLOSED",
      );
    } finally {
      await client.close();
    }
  });

  test("drains registered detached work before revoking its database capability", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let detachedFinished = false;
    const owner = withRequestDatabase(requestDb, async () => {
      void waitUntilRequestDatabaseTask(async () => {
        await release.promise;
        expect(getDb()).not.toBe(requestDb);
        detachedFinished = true;
      });
      return "response";
    });

    await Promise.resolve();
    expect(detachedFinished).toBe(false);
    release.resolve();
    expect(await owner).toBe("response");
    expect(detachedFinished).toBe(true);
  });

  test("drains registered work before propagating the owner error", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let detachedFinished = false;
    const owner = withRequestDatabase(requestDb, async () => {
      void waitUntilRequestDatabaseTask(async () => {
        await release.promise;
        expect((getDb() as unknown as { marker: string }).marker).toBe("request");
        detachedFinished = true;
      });
      throw new Error("owner failed");
    });

    await Promise.resolve();
    release.resolve();
    await expect(owner).rejects.toThrow("owner failed");
    expect(detachedFinished).toBe(true);
  });

  test("does not let unregistered work piggyback on a registered task lifetime", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let registered!: Promise<void>;
    let unregistered!: Promise<void>;

    const owner = withRequestDatabase(requestDb, async () => {
      registered = waitUntilRequestDatabaseTask(async () => {
        await release.promise;
        expect((getDb() as unknown as { marker: string }).marker).toBe("request");
      });
      unregistered = (async () => {
        await release.promise;
        expect(() => getDb()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
      })();
    });

    await Promise.resolve();
    release.resolve();
    await Promise.all([owner, registered, unregistered]);
  });

  test("can defer registered cleanup while returning the owner result", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let cleanup!: Promise<void>;
    let registered!: Promise<void>;
    const owner = withRequestDatabase(
      requestDb,
      async () => {
        registered = waitUntilRequestDatabaseTask(async () => {
          await release.promise;
          expect((getDb() as unknown as { marker: string }).marker).toBe("request");
        });
        return "response";
      },
      { deferCleanup: (promise) => (cleanup = promise) },
    );

    expect(await owner).toBe("response");
    release.resolve();
    await Promise.all([registered, cleanup]);
  });
});
