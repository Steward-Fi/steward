import { afterEach, describe, expect, test } from "bun:test";
import { PGlite } from "@electric-sql/pglite";
import { live } from "@electric-sql/pglite/live";
import { eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import {
  closeDb,
  getDb,
  getSql,
  hasTenantTransactionDatabase,
  waitUntilRequestDatabaseTask,
  withRequestDatabase,
  withTenantTransactionDatabase,
  withTenantTransactionDatabaseDeadline,
} from "../client";
import { createPGLiteDb } from "../pglite";
import { tenants } from "../schema";

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
  test("tenant transaction shadows the request handle for the full downstream chain", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const transactionDb = { marker: "tenant-transaction" } as unknown as ReturnType<typeof getDb>;
    await withRequestDatabase(requestDb, async () => {
      expect((getDb() as unknown as { marker: string }).marker).toBe("request");
      await withTenantTransactionDatabase(transactionDb, { tenantId: "tenant-a" }, async () => {
        await Promise.resolve();
        expect((getDb() as unknown as { marker: string }).marker).toBe("tenant-transaction");
        expect(() => getSql()).toThrow("RLS_TENANT_RAW_SQL_UNAVAILABLE");
        await expect(
          withTenantTransactionDatabase(
            transactionDb,
            { tenantId: "tenant-a" },
            async () => undefined,
          ),
        ).rejects.toThrow("RLS_TENANT_DATABASE_CONTEXT_NESTED");
      });
      expect((getDb() as unknown as { marker: string }).marker).toBe("request");
    });
  });

  test("rejects reuse of an active tenant transaction for another tenant or user", async () => {
    const transactionDb = { marker: "tenant-transaction" } as unknown as ReturnType<typeof getDb>;
    await withTenantTransactionDatabase(
      transactionDb,
      { tenantId: "tenant-a", userId: "11111111-1111-4111-8111-111111111111" },
      async () => {
        expect(
          hasTenantTransactionDatabase({
            tenantId: "tenant-a",
            userId: "11111111-1111-4111-8111-111111111111",
          }),
        ).toBe(true);
        expect(() => hasTenantTransactionDatabase({ tenantId: "tenant-b" })).toThrow(
          "RLS_TENANT_DATABASE_CONTEXT_MISMATCH",
        );
        expect(() =>
          hasTenantTransactionDatabase({
            tenantId: "tenant-a",
            userId: "22222222-2222-4222-8222-222222222222",
          }),
        ).toThrow("RLS_TENANT_DATABASE_CONTEXT_MISMATCH");
      },
    );
  });

  test("deadline phases preserve the exact tenant transaction capability", async () => {
    const executed: unknown[] = [];
    const transactionDb = {
      marker: "tenant-transaction",
      execute: async (query: unknown) => {
        executed.push(query);
        return [];
      },
    } as unknown as ReturnType<typeof getDb>;

    await expect(
      withTenantTransactionDatabaseDeadline(Date.now() + 5_000, async () => undefined),
    ).rejects.toThrow("RLS_TENANT_DATABASE_CONTEXT_REQUIRED");

    await withTenantTransactionDatabase(
      transactionDb,
      {
        tenantId: "tenant-a",
        userId: "11111111-1111-4111-8111-111111111111",
      },
      async () => {
        await withTenantTransactionDatabaseDeadline(Date.now() + 5_000, async (deadlineDb) => {
          expect(deadlineDb).toBe(getDb());
          expect((deadlineDb as unknown as { marker: string }).marker).toBe("tenant-transaction");
          expect(
            hasTenantTransactionDatabase({
              tenantId: "tenant-a",
              userId: "11111111-1111-4111-8111-111111111111",
            }),
          ).toBe(true);
        });
      },
    );
    expect(executed).toHaveLength(3);
  });

  test("tenant transaction drains registered work and revokes retained capabilities", async () => {
    const requestDb = { marker: "request" } as unknown as ReturnType<typeof getDb>;
    const transactionDb = { marker: "tenant-transaction" } as unknown as ReturnType<typeof getDb>;
    const release = deferred();
    let retained!: ReturnType<typeof getDb>;
    let finished = false;
    await withRequestDatabase(requestDb, async () => {
      const owner = withTenantTransactionDatabase(
        transactionDb,
        { tenantId: "tenant-a" },
        async () => {
          retained = getDb();
          void waitUntilRequestDatabaseTask(async () => {
            await release.promise;
            expect((getDb() as unknown as { marker: string }).marker).toBe("tenant-transaction");
            finished = true;
          });
        },
      );
      await Promise.resolve();
      expect(finished).toBe(false);
      release.resolve();
      await owner;
      expect(finished).toBe(true);
      expect(() => (retained as unknown as { marker: string }).marker).toThrow(
        "REQUEST_DATABASE_CONTEXT_CLOSED",
      );
    });
  });

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
    let capturedPrototype!: object;
    let capturedConstructor!: ObjectConstructor;
    let constructedThroughGuard!: object;
    const rawConstructedInput = { guarded: true };

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
      capturedPrototype = Object.getPrototypeOf(capturedDb);
      expect(capturedPrototype).not.toBe(Object.prototype);
      capturedConstructor = (capturedPrototype as { constructor: ObjectConstructor }).constructor;
      expect(capturedConstructor).not.toBe(Object);
      constructedThroughGuard = capturedConstructor(rawConstructedInput);
      expect(constructedThroughGuard).not.toBe(rawConstructedInput);
      expect((constructedThroughGuard as { guarded: boolean }).guarded).toBe(true);
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
    expect(() => Object.getPrototypeOf(capturedDb)).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Reflect.ownKeys(capturedPrototype)).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedConstructor()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Reflect.ownKeys(constructedThroughGuard)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
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
    expect(() => Object.getPrototypeOf(capturedCallable)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => capturedFromCallable.execute()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.getPrototypeOf(capturedFromCallable)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
    expect(() => capturedTransaction.execute()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => Object.getPrototypeOf(capturedTransaction)).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
  });

  test("revokes Promise and thenable client capabilities without revoking result rows", async () => {
    const rawClient = {
      query: () => "raw-client-query",
      release: () => "raw-client-release",
    };
    const rawRows = [{ id: "row-1", query: "ordinary-data" }];
    const rawSubscription = { unsubscribe: () => "raw-subscription-unsubscribed" };
    type AsyncCapabilityDb = {
      rows(): Promise<typeof rawRows>;
      $client: {
        connect(): Promise<typeof rawClient>;
        connectThenable(): {
          then(resolve: (client: typeof rawClient) => void): void;
        };
        rejectedSubscription(): Promise<never>;
        subscribe(): Promise<typeof rawSubscription>;
      };
    };
    const requestDbSource: AsyncCapabilityDb = {
      rows: async () => rawRows,
      $client: {
        connect: async () => rawClient,
        connectThenable: () => ({
          // biome-ignore lint/suspicious/noThenProperty: exercises a driver PromiseLike boundary
          then(resolve: (client: typeof rawClient) => void) {
            resolve(rawClient);
          },
        }),
        rejectedSubscription: () => Promise.reject(rawSubscription),
        subscribe: async () => rawSubscription,
      },
    };
    const requestDb = requestDbSource as unknown as ReturnType<typeof getDb>;
    let rows!: typeof rawRows;
    let capturedClient!: typeof rawClient;
    let capturedThenableClient!: typeof rawClient;
    let capturedRejectedSubscription!: typeof rawSubscription;
    let capturedSubscription!: typeof rawSubscription;

    await withRequestDatabase(requestDb, async () => {
      const guardedDb = getDb() as unknown as AsyncCapabilityDb;
      const guardedClient = guardedDb.$client;
      rows = await guardedDb.rows();
      capturedClient = await guardedClient.connect();
      capturedSubscription = await guardedClient.subscribe();
      try {
        await guardedClient.rejectedSubscription();
      } catch (error) {
        capturedRejectedSubscription = error as typeof rawSubscription;
      }
      guardedClient.connectThenable().then((client) => {
        capturedThenableClient = client;
      });

      expect(rows).toBe(rawRows);
      expect(capturedClient).not.toBe(rawClient);
      expect(capturedThenableClient).not.toBe(rawClient);
      expect(capturedSubscription).not.toBe(rawSubscription);
      expect(capturedRejectedSubscription).not.toBe(rawSubscription);
      expect(capturedClient.query()).toBe("raw-client-query");
      expect(capturedThenableClient.release()).toBe("raw-client-release");
      expect(capturedSubscription.unsubscribe()).toBe("raw-subscription-unsubscribed");
      expect(capturedRejectedSubscription.unsubscribe()).toBe("raw-subscription-unsubscribed");
    });

    expect(rows).toEqual([{ id: "row-1", query: "ordinary-data" }]);
    expect(rows[0]?.id).toBe("row-1");
    expect(() => capturedClient.query()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedClient.release()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedThenableClient.query()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedThenableClient.release()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedSubscription.unsubscribe()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    expect(() => capturedRejectedSubscription.unsubscribe()).toThrow(
      "REQUEST_DATABASE_CONTEXT_CLOSED",
    );
  });

  test("preserves ordinary native driver rejection errors after request cleanup", async () => {
    const driverError = new Error("driver rejected the query");
    const requestDb = {
      execute: () => Promise.reject(driverError),
    } as unknown as ReturnType<typeof getDb>;
    let capturedError: unknown;

    await withRequestDatabase(requestDb, async () => {
      try {
        await getDb().execute(sql`select 1`);
      } catch (error) {
        capturedError = error;
      }
    });

    expect(capturedError).toBe(driverError);
    expect(capturedError).toBeInstanceOf(Error);
    expect((capturedError as Error).message).toBe("driver rejected the query");
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

  test("revokes a real PGLite listener cleanup resolved through the driver Promise", async () => {
    const { client, db } = await createPGLiteDb("memory://");
    const channel = "request_database_membrane";
    let unsubscribe!: () => Promise<void>;
    let queryResult!: { rows: Array<{ value: number }> };

    try {
      await withRequestDatabase(db as ReturnType<typeof getDb>, async () => {
        queryResult = (await getDb().execute(
          sql`select 1 as value`,
        )) as unknown as typeof queryResult;
        unsubscribe = await (
          getDb() as unknown as {
            $client: {
              listen(
                name: string,
                callback: (payload: string) => void,
              ): Promise<() => Promise<void>>;
            };
          }
        ).$client.listen(channel, () => undefined);

        expect(typeof unsubscribe).toBe("function");
      });

      expect(queryResult.rows).toEqual([{ value: 1 }]);
      expect(() => unsubscribe()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    } finally {
      await client.unlisten(channel);
      await client.close();
    }
  });

  test("revokes a real PGLite live-query subscription resolved through the driver Promise", async () => {
    const client = new PGlite("memory://", { extensions: { live } });
    const db = drizzle(client);
    let liveQuery!: Awaited<ReturnType<typeof client.live.query>>;
    let initialValue!: number;

    try {
      await client.waitReady;
      await withRequestDatabase(db as ReturnType<typeof getDb>, async () => {
        liveQuery = await (
          getDb() as unknown as {
            $client: typeof client;
          }
        ).$client.live.query<{ value: number }>("select 1 as value");
        initialValue = liveQuery.initialResults.rows[0]!.value;
        expect(initialValue).toBe(1);
      });

      expect(initialValue).toBe(1);
      expect(() => liveQuery.unsubscribe()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
      expect(() => liveQuery.refresh()).toThrow("REQUEST_DATABASE_CONTEXT_CLOSED");
    } finally {
      await client.close();
    }
  });

  test("composes real PGLite aliased subqueries without exposing their prototypes", async () => {
    const { client, db } = await createPGLiteDb("memory://");
    let capturedSubquery!: object;
    let capturedSubqueryColumn!: object;
    let capturedSubqueryPrototype!: object;
    let capturedSubqueryConstructor!: object;

    try {
      await withRequestDatabase(db as ReturnType<typeof getDb>, async () => {
        await getDb().insert(tenants).values({
          id: "request-context-subquery",
          name: "Request Context Subquery",
          apiKeyHash: "request-context-subquery-hash",
        });

        const tenantSubquery = getDb()
          .select({ id: tenants.id, name: tenants.name })
          .from(tenants)
          .as("tenant_subquery");
        capturedSubquery = tenantSubquery;
        capturedSubqueryColumn = tenantSubquery.id;
        capturedSubqueryPrototype = Object.getPrototypeOf(tenantSubquery);
        capturedSubqueryConstructor = (capturedSubqueryPrototype as { constructor: object })
          .constructor;
        expect(capturedSubqueryPrototype).not.toBe(
          Object.getPrototypeOf(
            db.select({ id: tenants.id }).from(tenants).as("raw_tenant_subquery"),
          ),
        );
        const matchesTenant = eq(tenantSubquery.id, "request-context-subquery");
        const rows = await getDb()
          .select({ id: tenantSubquery.id, name: tenantSubquery.name })
          .from(tenantSubquery)
          .where(matchesTenant);

        expect(rows).toEqual([
          {
            id: "request-context-subquery",
            name: "Request Context Subquery",
          },
        ]);
      });

      expect(() => Object.getPrototypeOf(capturedSubquery)).toThrow(
        "REQUEST_DATABASE_CONTEXT_CLOSED",
      );
      expect(() => Object.getPrototypeOf(capturedSubqueryColumn)).toThrow(
        "REQUEST_DATABASE_CONTEXT_CLOSED",
      );
      expect(() => Reflect.ownKeys(capturedSubqueryPrototype)).toThrow(
        "REQUEST_DATABASE_CONTEXT_CLOSED",
      );
      expect(() => Reflect.ownKeys(capturedSubqueryConstructor)).toThrow(
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
