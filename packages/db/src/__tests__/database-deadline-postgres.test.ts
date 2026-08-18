import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { createDb, DATABASE_DEADLINE_EXCEEDED_MESSAGE, withDatabaseDeadline } from "../client";

const databaseUrl = process.env.DATABASE_URL;
const describeWithPostgres = databaseUrl ? describe : describe.skip;
const tableName = `deadline_rollback_${randomUUID().replaceAll("-", "")}`;
const previousDriver = process.env.DATABASE_DRIVER;
setDefaultTimeout(30_000);

describeWithPostgres("cancel-safe deadline on real Postgres", () => {
  let admin: ReturnType<typeof createDb>;

  beforeAll(async () => {
    process.env.DATABASE_DRIVER = "postgres-js";
    admin = createDb(databaseUrl as string);
    await admin.client.unsafe(`CREATE TABLE ${tableName} (id text PRIMARY KEY)`);
  });

  afterAll(async () => {
    await admin.client.unsafe(`DROP TABLE IF EXISTS ${tableName}`);
    await admin.client.end();
    if (previousDriver === undefined) delete process.env.DATABASE_DRIVER;
    else process.env.DATABASE_DRIVER = previousDriver;
  });

  test("includes fresh connection acquisition and cancels a sleeping read", async () => {
    const startedAt = Date.now();
    await expect(
      withDatabaseDeadline(Date.now() + 1_200, (db) => db.execute(sql`select pg_sleep(5)`)),
    ).rejects.toThrow(DATABASE_DEADLINE_EXCEEDED_MESSAGE);
    expect(Date.now() - startedAt).toBeLessThan(2_500);
  });

  test("rolls back a timed-out transaction before returning control", async () => {
    const id = randomUUID();
    await expect(
      withDatabaseDeadline(Date.now() + 1_200, (db) =>
        db.transaction(async (tx) => {
          await tx.execute(sql.raw(`INSERT INTO ${tableName} (id) VALUES ('${id}')`));
          await tx.execute(sql`select pg_sleep(5)`);
        }),
      ),
    ).rejects.toThrow(DATABASE_DEADLINE_EXCEEDED_MESSAGE);

    const rows = await admin.client.unsafe(`SELECT id FROM ${tableName} WHERE id = $1`, [id]);
    expect(rows).toHaveLength(0);
  });

  test("a callback paused across the deadline cannot mutate through the closed handle", async () => {
    const id = randomUUID();
    await expect(
      withDatabaseDeadline(Date.now() + 1_200, async (db) => {
        await Bun.sleep(1_500);
        await db.execute(sql.raw(`INSERT INTO ${tableName} (id) VALUES ('${id}')`));
      }),
    ).rejects.toThrow(DATABASE_DEADLINE_EXCEEDED_MESSAGE);

    // The deadline owns and destroys the dedicated handle. A callback that was
    // idle in user code cannot resume later and enqueue a mutation on a shared
    // pool connection after the caller has already observed the timeout.
    const rows = await admin.client.unsafe(`SELECT id FROM ${tableName} WHERE id = $1`, [id]);
    expect(rows).toHaveLength(0);
  });
});
