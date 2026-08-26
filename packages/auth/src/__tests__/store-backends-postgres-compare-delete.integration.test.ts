import { afterAll, describe, expect, it } from "bun:test";
import postgres from "postgres";

import { PostgresBackend } from "../store-backends";

const databaseUrl = process.env.DATABASE_URL;
const integration = describe.skipIf(!databaseUrl);
const sql = databaseUrl ? postgres(databaseUrl, { max: 1 }) : null;

integration("PostgresBackend.compareDelete", () => {
  afterAll(async () => {
    await sql?.end();
  });

  it("deletes only the exact live generation", async () => {
    if (!sql) throw new Error("DATABASE_URL required");
    const namespace = `compare-delete-${crypto.randomUUID()}`;
    const backend = new PostgresBackend(namespace);
    const key = "operation-lock";

    try {
      await backend.set(key, "owner-a", 60_000);

      expect(await backend.compareDelete(key, "owner-b")).toBe(false);
      expect(await backend.get(key)).toBe("owner-a");
      expect(await backend.compareDelete(key, "owner-a")).toBe(true);
      expect(await backend.compareDelete(key, "owner-a")).toBe(false);

      await backend.set(key, "owner-new", 60_000);
      expect(await backend.compareDelete(key, "owner-a")).toBe(false);
      expect(await backend.get(key)).toBe("owner-new");

      await sql`
        UPDATE auth_kv_store
           SET expires_at = clock_timestamp() - interval '1 second'
         WHERE id = ${key} AND namespace = ${namespace}
      `;
      expect(await backend.compareDelete(key, "owner-new")).toBe(false);
    } finally {
      await sql`DELETE FROM auth_kv_store WHERE namespace = ${namespace}`;
    }
  });
});
