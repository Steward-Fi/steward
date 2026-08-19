import { afterAll, describe, expect, it } from "bun:test";
import postgres from "postgres";

import { PostgresBackend } from "../store-backends";

const databaseUrl = process.env.DATABASE_URL;
const integration = describe.skipIf(!databaseUrl);
const sql = databaseUrl ? postgres(databaseUrl, { max: 2 }) : null;

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
    await locker`SELECT pg_advisory_lock(hashtextextended(${`${namespace}:${reservationKey}`}, 0))`;
    const stale = backend.publish([
      { key: "challenge-old", value: "active-old", ttlMs: 60_000 },
      { key: reservationKey, value: "published-old", ttlMs: 60_000, expected: "generation-old" },
    ]);
    await Bun.sleep(50);

    await sql`
      UPDATE auth_kv_store SET value = 'generation-new'
       WHERE id = ${reservationKey} AND namespace = ${namespace}
    `;
    await locker`SELECT pg_advisory_unlock(hashtextextended(${`${namespace}:${reservationKey}`}, 0))`;
    locker.release();

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
  });
});
