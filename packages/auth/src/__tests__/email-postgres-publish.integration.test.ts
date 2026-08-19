import { afterAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import postgres from "postgres";

import { PostgresBackend } from "../store-backends";

const databaseUrl = process.env.DATABASE_URL;
const integration = describe.skipIf(!databaseUrl);
const sql = databaseUrl ? postgres(databaseUrl, { max: 3 }) : null;

setDefaultTimeout(30_000);

type ObservedOutcome<T> = { ok: true; value: T } | { ok: false; error: unknown };

function observePromise<T>(promise: Promise<T>): Promise<ObservedOutcome<T>> {
  return promise.then(
    (value) => ({ ok: true, value }),
    (error) => ({ ok: false, error }),
  );
}

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
    let staleOutcome: Promise<ObservedOutcome<boolean>> | undefined;
    try {
      await locker`SELECT pg_advisory_lock(hashtextextended(${lockKey}, 0))`;
      locked = true;
      stale = backend.publish([
        { key: "challenge-old", value: "active-old", expiresAt: Date.now() + 60_000 },
        {
          key: reservationKey,
          value: "published-old",
          expiresAt: Date.now() + 60_000,
          expected: "generation-old",
        },
      ]);
      staleOutcome = observePromise(stale);

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
      if (staleOutcome) await staleOutcome;
    }

    if (!staleOutcome || !stale) throw new Error("stale publication did not start");
    const staleResult = await staleOutcome;
    if (!staleResult.ok) throw staleResult.error;
    expect(staleResult.value).toBe(false);
    expect(await backend.get("challenge-old")).toBeNull();
    const current = [
      { key: "challenge-new", value: "active-new", expiresAt: Date.now() + 60_000 },
      {
        key: reservationKey,
        value: "published-new",
        expiresAt: Date.now() + 60_000,
        expected: "generation-new",
      },
    ] as const;
    expect(await backend.publish(current)).toBe(true);
    expect(await backend.consume("challenge-new")).toBe("active-new");
    expect(await backend.publish(current)).toBe(true);
    expect(await backend.get("challenge-new")).toBeNull();

    await expect(
      backend.publish([
        { key: "duplicate", value: "first", expiresAt: Date.now() + 60_000 },
        { key: "duplicate", value: "second", expiresAt: Date.now() + 60_000 },
      ]),
    ).rejects.toThrow("Store publication contains duplicate keys");
    expect(await backend.get("duplicate")).toBeNull();
  });

  it("rejects a publication delayed past expiry without applying any write", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    const namespace = `email-publish-expiry-${crypto.randomUUID()}`;
    const backend = new PostgresBackend(namespace);
    const reservationKey = "reservation";
    const credentialKey = "credential";
    await backend.set(reservationKey, "reserved", 60_000);

    const locker = await sql.reserve();
    const lockKey = `${namespace}:${reservationKey}`;
    const [{ pid: lockerPid }] = await locker<
      Array<{ pid: number }>
    >`SELECT pg_backend_pid() AS pid`;
    const expiresAt = Date.now() + 250;
    let locked = false;
    let publication: Promise<boolean> | undefined;
    let publicationOutcome: Promise<ObservedOutcome<boolean>> | undefined;
    try {
      await locker`SELECT pg_advisory_lock(hashtextextended(${lockKey}, 0))`;
      locked = true;
      publication = backend.publish([
        { key: credentialKey, value: "active", expiresAt },
        {
          key: reservationKey,
          value: "published",
          expiresAt,
          expected: "reserved",
        },
      ]);
      publicationOutcome = observePromise(publication);
      await waitForBlockedPublisher(lockKey, lockerPid);
      const delayMs = expiresAt - Date.now() + 30;
      if (delayMs > 0) await Bun.sleep(delayMs);
    } finally {
      if (locked) {
        await locker`SELECT pg_advisory_unlock(hashtextextended(${lockKey}, 0))`;
      }
      locker.release();
      if (publicationOutcome) await publicationOutcome;
    }

    if (!publicationOutcome || !publication) throw new Error("publication did not start");
    const result = await publicationOutcome;
    if (!result.ok) throw result.error;
    expect(result.value).toBe(false);
    expect(await backend.get(credentialKey)).toBeNull();
    expect(await backend.get(reservationKey)).toBe("reserved");
    const rows = await sql<Array<{ expiresAt: Date }>>`
      SELECT expires_at AS "expiresAt"
        FROM auth_kv_store
       WHERE id = ${credentialKey} AND namespace = ${namespace}
    `;
    expect(rows).toHaveLength(0);
    await sql`DELETE FROM auth_kv_store WHERE namespace = ${namespace}`;
  });

  it("rolls back when a row lock delays a write past expiry", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    const namespace = `email-publish-write-expiry-${crypto.randomUUID()}`;
    const backend = new PostgresBackend(namespace);
    const reservationKey = "reservation";
    const credentialKey = "credential";
    await backend.set(reservationKey, "reserved", 60_000);
    await backend.set(credentialKey, "original", 60_000);

    const locker = await sql.reserve();
    const [{ pid: lockerPid }] = await locker<
      Array<{ pid: number }>
    >`SELECT pg_backend_pid() AS pid`;
    const expiresAt = Date.now() + 300;
    let transactionOpen = false;
    let publicationOutcome: Promise<ObservedOutcome<boolean>> | undefined;
    try {
      await locker`BEGIN`;
      transactionOpen = true;
      await locker`
        SELECT value FROM auth_kv_store
         WHERE id = ${credentialKey} AND namespace = ${namespace}
         FOR UPDATE
      `;
      publicationOutcome = observePromise(
        backend.publish([
          {
            key: reservationKey,
            value: "published",
            expiresAt,
            expected: "reserved",
          },
          { key: credentialKey, value: "active", expiresAt },
        ]),
      );
      await waitForPublisherBlockedAfterGuard(`${namespace}:${reservationKey}`, lockerPid);
      const delayMs = expiresAt - Date.now() + 30;
      if (delayMs > 0) await Bun.sleep(delayMs);
    } finally {
      if (transactionOpen) await locker`COMMIT`;
      locker.release();
    }

    if (!publicationOutcome) throw new Error("publication did not start");
    const result = await publicationOutcome;
    if (!result.ok) throw result.error;
    expect(result.value).toBe(false);
    expect(await backend.get(credentialKey)).toBe("original");
    expect(await backend.get(reservationKey)).toBe("reserved");
    await sql`DELETE FROM auth_kv_store WHERE namespace = ${namespace}`;
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
    let publicationOutcome: Promise<ObservedOutcome<boolean>> | undefined;
    try {
      await locker`BEGIN`;
      transactionOpen = true;
      await locker`
        SELECT value FROM auth_kv_store
         WHERE id = ${blockerKey} AND namespace = ${namespace}
         FOR UPDATE
      `;
      publication = backend.publish([
        { key: blockerKey, value: "blocker-published", expiresAt: Date.now() + 60_000 },
        { key: "challenge", value: "active", expiresAt: Date.now() + 60_000 },
        {
          key: targetKey,
          value: "generation-published",
          expiresAt: Date.now() + 60_000,
          expected: "generation-old",
        },
      ]);
      publicationOutcome = observePromise(publication);

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
      if (publicationOutcome) await publicationOutcome;
    }

    if (!publicationOutcome || !publication) throw new Error("publication did not start");
    const publicationResult = await publicationOutcome;
    if (!publicationResult.ok) throw publicationResult.error;
    expect(publicationResult.value).toBe(false);
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
      let publicationOutcome: Promise<ObservedOutcome<boolean>> | undefined;
      try {
        await locker`BEGIN`;
        transactionOpen = true;
        await locker`
          SELECT value FROM auth_kv_store
           WHERE id = ${blockerKey} AND namespace = ${namespace}
           FOR UPDATE
        `;
        publication = backend.publish([
          { key: blockerKey, value: "blocker-published", expiresAt: Date.now() + 60_000 },
          { key: "challenge", value: "active", expiresAt: Date.now() + 60_000 },
          {
            key: targetKey,
            value: "generation-published",
            expiresAt: Date.now() + 60_000,
            expected: null,
          },
        ]);
        publicationOutcome = observePromise(publication);

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
        if (publicationOutcome) await publicationOutcome;
      }

      if (!publicationOutcome || !publication) throw new Error("publication did not start");
      const publicationResult = await publicationOutcome;
      if (!publicationResult.ok) throw publicationResult.error;
      expect(publicationResult.value).toBe(false);
      expect(await backend.get(targetKey)).toBe("generation-ordinary");
      expect(await backend.get(blockerKey)).toBe("blocker-original");
      expect(await backend.get("challenge")).toBeNull();
    }
  });
});
