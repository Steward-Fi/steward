import { afterAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import postgres from "postgres";

import { PostgresBackend } from "../store-backends";

const databaseUrl = process.env.DATABASE_URL;
const integration = describe.skipIf(!databaseUrl);
const sql = databaseUrl ? postgres(databaseUrl, { max: 3 }) : null;

setDefaultTimeout(30_000);

async function waitForBlockedPublisher(lockKey: string, lockerPid: number): Promise<number> {
  if (!sql) throw new Error("DATABASE_URL required");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await sql<Array<{ pid: number }>>`
      WITH target AS (
        SELECT hashtextextended(${lockKey}, 0)::bigint AS key
      )
      SELECT DISTINCT locks.pid
        FROM pg_locks AS locks
        CROSS JOIN target
       WHERE locks.locktype = 'advisory'
         AND locks.granted = false
         AND locks.pid <> ${lockerPid}
         AND locks.database = (SELECT oid FROM pg_database WHERE datname = current_database())
         AND locks.classid::bigint = ((target.key >> 32) & 4294967295)
         AND locks.objid::bigint = (target.key & 4294967295)
         AND locks.objsubid = 1
    `;
    if (rows[0]) return rows[0].pid;
    await Bun.sleep(10);
  }
  throw new Error("timed out waiting for the stale publisher to block on the guarded key");
}

async function waitForPublisherBlockedAfterGuard(
  guardedLockKey: string,
  lockerPid: number,
): Promise<number> {
  if (!sql) throw new Error("DATABASE_URL required");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await sql<Array<{ pid: number }>>`
      WITH target AS (
        SELECT hashtextextended(${guardedLockKey}, 0)::bigint AS key
      )
      SELECT DISTINCT locks.pid
        FROM pg_locks AS locks
        JOIN pg_stat_activity AS activity ON activity.pid = locks.pid
        CROSS JOIN target
       WHERE locks.locktype = 'advisory'
         AND locks.granted = true
         AND locks.pid <> ${lockerPid}
         AND locks.database = (SELECT oid FROM pg_database WHERE datname = current_database())
         AND locks.classid::bigint = ((target.key >> 32) & 4294967295)
         AND locks.objid::bigint = (target.key & 4294967295)
         AND locks.objsubid = 1
         AND activity.wait_event_type = 'Lock'
    `;
    if (rows[0]) return rows[0].pid;
    await Bun.sleep(10);
  }
  throw new Error("timed out waiting for publication after its guard read");
}

integration("Postgres email challenge publication", () => {
  afterAll(async () => {
    await sql?.end();
  });

  it("rejects a stale publisher blocked behind a newer generation", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    const namespace = `email-publish-${crypto.randomUUID()}`;
    const backend = new PostgresBackend(namespace);
    const reservationKey = "reservation";
    await backend.set(reservationKey, "generation-old", 60_000);

    const locker = await sql.reserve();
    const lockKey = `${namespace}:${reservationKey}`;
    const [{ pid: lockerPid }] = await locker<
      Array<{ pid: number }>
    >`SELECT pg_backend_pid() AS pid`;
    let locked = false;
    let stale: Promise<boolean> | undefined;
    try {
      await locker`SELECT pg_advisory_lock(hashtextextended(${lockKey}, 0))`;
      locked = true;
      stale = backend.publish([
        { key: "challenge-old", value: "active-old", ttlMs: 60_000 },
        {
          key: reservationKey,
          value: "published-old",
          ttlMs: 60_000,
          expected: "generation-old",
        },
      ]);

      const publisherPid = await waitForBlockedPublisher(lockKey, lockerPid);
      expect(publisherPid).not.toBe(lockerPid);

      await sql`
        UPDATE auth_kv_store SET value = 'generation-new'
         WHERE id = ${reservationKey} AND namespace = ${namespace}
      `;
    } finally {
      if (locked) {
        await locker`SELECT pg_advisory_unlock(hashtextextended(${lockKey}, 0))`;
      }
      locker.release();
    }

    if (!stale) throw new Error("stale publication did not start");
    expect(await stale).toBe(false);
    expect(await backend.get("challenge-old")).toBeNull();
    const current = [
      { key: "challenge-new", value: "active-new", ttlMs: 60_000 },
      { key: reservationKey, value: "published-new", ttlMs: 60_000, expected: "generation-new" },
    ] as const;
    expect(await backend.publish(current)).toBe(true);
    expect(await backend.consume("challenge-new")).toBe("active-new");
    expect(await backend.publish(current)).toBe(true);
    expect(await backend.get("challenge-new")).toBeNull();

    await expect(
      backend.publish([
        { key: "duplicate", value: "first", ttlMs: 60_000 },
        { key: "duplicate", value: "second", ttlMs: 60_000 },
      ]),
    ).rejects.toThrow("Store publication contains duplicate keys");
    expect(await backend.get("duplicate")).toBeNull();
  });

  it("never overwrites an ordinary writer that commits after the guard read", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    const namespace = `email-publish-post-guard-${crypto.randomUUID()}`;
    const backend = new PostgresBackend(namespace);
    const blockerKey = "00-blocker";
    const targetKey = "target";
    await backend.set(blockerKey, "blocker-original", 60_000);
    await backend.set(targetKey, "generation-old", 60_000);

    const locker = await sql.reserve();
    const [{ pid: lockerPid }] = await locker<
      Array<{ pid: number }>
    >`SELECT pg_backend_pid() AS pid`;
    let transactionOpen = false;
    let publication: Promise<boolean> | undefined;
    try {
      await locker`BEGIN`;
      transactionOpen = true;
      await locker`
        SELECT value FROM auth_kv_store
         WHERE id = ${blockerKey} AND namespace = ${namespace}
         FOR UPDATE
      `;
      publication = backend.publish([
        { key: blockerKey, value: "blocker-published", ttlMs: 60_000 },
        { key: "challenge", value: "active", ttlMs: 60_000 },
        {
          key: targetKey,
          value: "generation-published",
          ttlMs: 60_000,
          expected: "generation-old",
        },
      ]);

      const publisherPid = await waitForPublisherBlockedAfterGuard(
        `${namespace}:${targetKey}`,
        lockerPid,
      );
      expect(publisherPid).not.toBe(lockerPid);

      // This is the write used by a pre-#550 pod: it deliberately does not
      // participate in the new publisher's advisory-lock protocol.
      await sql`
        INSERT INTO auth_kv_store (id, namespace, value, expires_at)
        VALUES (${targetKey}, ${namespace}, 'generation-ordinary', now() + interval '1 minute')
        ON CONFLICT (id, namespace) DO UPDATE
          SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
      `;
      await locker`COMMIT`;
      transactionOpen = false;
    } finally {
      if (transactionOpen) await locker`ROLLBACK`;
      locker.release();
    }

    if (!publication) throw new Error("publication did not start");
    expect(await publication).toBe(false);
    expect(await backend.get(targetKey)).toBe("generation-ordinary");
    expect(await backend.get(blockerKey)).toBe("blocker-original");
    expect(await backend.get("challenge")).toBeNull();
  });

  it("protects absent and expired guards from an ordinary post-read insert", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    for (const initialState of ["absent", "expired"] as const) {
      const namespace = `email-publish-null-guard-${initialState}-${crypto.randomUUID()}`;
      const backend = new PostgresBackend(namespace);
      const blockerKey = "00-blocker";
      const targetKey = "target";
      await backend.set(blockerKey, "blocker-original", 60_000);
      if (initialState === "expired") {
        await sql`
          INSERT INTO auth_kv_store (id, namespace, value, expires_at)
          VALUES (${targetKey}, ${namespace}, 'generation-expired', now() - interval '1 minute')
        `;
      }

      const locker = await sql.reserve();
      const [{ pid: lockerPid }] = await locker<
        Array<{ pid: number }>
      >`SELECT pg_backend_pid() AS pid`;
      let transactionOpen = false;
      let publication: Promise<boolean> | undefined;
      try {
        await locker`BEGIN`;
        transactionOpen = true;
        await locker`
          SELECT value FROM auth_kv_store
           WHERE id = ${blockerKey} AND namespace = ${namespace}
           FOR UPDATE
        `;
        publication = backend.publish([
          { key: blockerKey, value: "blocker-published", ttlMs: 60_000 },
          { key: "challenge", value: "active", ttlMs: 60_000 },
          { key: targetKey, value: "generation-published", ttlMs: 60_000, expected: null },
        ]);

        await waitForPublisherBlockedAfterGuard(`${namespace}:${targetKey}`, lockerPid);
        await sql`
          INSERT INTO auth_kv_store (id, namespace, value, expires_at)
          VALUES (${targetKey}, ${namespace}, 'generation-ordinary', now() + interval '1 minute')
          ON CONFLICT (id, namespace) DO UPDATE
            SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at
        `;
        await locker`COMMIT`;
        transactionOpen = false;
      } finally {
        if (transactionOpen) await locker`ROLLBACK`;
        locker.release();
      }

      if (!publication) throw new Error("publication did not start");
      expect(await publication).toBe(false);
      expect(await backend.get(targetKey)).toBe("generation-ordinary");
      expect(await backend.get(blockerKey)).toBe("blocker-original");
      expect(await backend.get("challenge")).toBeNull();
    }
  });
});
