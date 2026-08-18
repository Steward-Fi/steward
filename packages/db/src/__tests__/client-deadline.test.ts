import { afterEach, describe, expect, test } from "bun:test";
import { sql } from "drizzle-orm";
import { withTenantAuditQueue } from "../audit-chain";
import { DatabaseDeadlineExceededError, withDatabaseDeadline } from "../client";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("database deadlines", () => {
  test("a timed-out audit queue waiter never begins later in the background", async () => {
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const firstEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const first = withTenantAuditQueue("deadline-queue", async () => {
      entered();
      await blocked;
    });
    await firstEntered;

    let lateMutation = false;
    await expect(
      withTenantAuditQueue(
        "deadline-queue",
        async () => {
          lateMutation = true;
        },
        Date.now() + 30,
      ),
    ).rejects.toBeInstanceOf(DatabaseDeadlineExceededError);
    release();
    await first;
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(lateMutation).toBe(false);
  });

  test("neon-http aborts a stalled fetch and returns only a normalized error", async () => {
    globalThis.fetch = ((_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("fixture leaked diagnostics", "AbortError")),
          { once: true },
        );
      })) as typeof fetch;

    const startedAt = Date.now();
    const operation = withDatabaseDeadline(Date.now() + 75, (db) => db.execute(sql`select 1`), {
      driver: "neon-http",
      connectionString: "postgresql://test:test@example.invalid/steward?sslmode=require",
    });
    await expect(operation).rejects.toEqual(new DatabaseDeadlineExceededError());
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  const postgresUrl = process.env.STEWARD_TEST_POSTGRES_URL;
  test.skipIf(!postgresUrl)(
    "postgres cancels pg_sleep and rolls back before control returns",
    async () => {
      const table = `deadline_rollback_${crypto.randomUUID().replaceAll("-", "")}`;
      await withDatabaseDeadline(
        Date.now() + 5_000,
        (db) => db.execute(sql.raw(`create table ${table} (value integer not null)`)),
        { driver: "postgres-js", connectionString: postgresUrl },
      );
      try {
        await expect(
          withDatabaseDeadline(Date.now() + 100, (db) => db.execute(sql`select pg_sleep(1)`), {
            driver: "postgres-js",
            connectionString: postgresUrl,
          }),
        ).rejects.toBeInstanceOf(DatabaseDeadlineExceededError);

        const timedOut = withDatabaseDeadline(
          Date.now() + 100,
          (db) =>
            db.transaction(async (tx) => {
              await tx.execute(sql.raw(`insert into ${table} (value) values (1)`));
              await tx.execute(sql`select pg_sleep(1)`);
            }),
          { driver: "postgres-js", connectionString: postgresUrl },
        );
        await expect(timedOut).rejects.toBeInstanceOf(DatabaseDeadlineExceededError);

        const rows = await withDatabaseDeadline(
          Date.now() + 5_000,
          (db) => db.execute(sql.raw(`select count(*)::int as count from ${table}`)),
          { driver: "postgres-js", connectionString: postgresUrl },
        );
        const resultRows = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? []);
        expect((resultRows[0] as { count: number }).count).toBe(0);

        await expect(
          withDatabaseDeadline(
            Date.now() + 75,
            async (db) => {
              await new Promise((resolve) => setTimeout(resolve, 150));
              await db.execute(sql.raw(`insert into ${table} (value) values (2)`));
            },
            { driver: "postgres-js", connectionString: postgresUrl },
          ),
        ).rejects.toBeInstanceOf(DatabaseDeadlineExceededError);
        await new Promise((resolve) => setTimeout(resolve, 100));
        const afterReturn = await withDatabaseDeadline(
          Date.now() + 5_000,
          (db) => db.execute(sql.raw(`select count(*)::int as count from ${table}`)),
          { driver: "postgres-js", connectionString: postgresUrl },
        );
        const afterRows = Array.isArray(afterReturn)
          ? afterReturn
          : ((afterReturn as { rows?: unknown[] }).rows ?? []);
        expect((afterRows[0] as { count: number }).count).toBe(0);
      } finally {
        await withDatabaseDeadline(
          Date.now() + 5_000,
          (db) => db.execute(sql.raw(`drop table if exists ${table}`)),
          { driver: "postgres-js", connectionString: postgresUrl },
        );
      }
    },
  );
});
