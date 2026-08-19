import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import postgres from "postgres";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const omittedMigration = "0073_agent_policy_builder_perps.sql";
const reconciliationMigration = "0109_agent_policy_builder_perps_reconcile.sql";

async function applyMigration(client: PGlite, file: string) {
  const migration = await readFile(join(migrations, file), "utf8");
  for (const statement of migration.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

describe("0109 agent policy builder-perps reconciliation", () => {
  test("is the contiguous journal tip after the unjournaled 0073 file", async () => {
    const journal = JSON.parse(
      await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
    ) as { entries: Array<{ idx: number; tag: string }> };

    expect(journal.entries.some(({ tag }) => tag === omittedMigration.replace(/\.sql$/, ""))).toBe(
      false,
    );
    expect(journal.entries.slice(-2).map(({ idx, tag }) => ({ idx, tag }))).toEqual([
      { idx: 108, tag: "0108_evm_nonce_tenant_ownership" },
      { idx: 109, tag: "0109_agent_policy_builder_perps_reconcile" },
    ]);
  });

  test("repairs a production-journal schema that skipped 0073 and is idempotent", async () => {
    const client = new PGlite("memory://");
    try {
      const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
      for (const file of files) {
        if (file === reconciliationMigration) break;
        if (file !== omittedMigration) await applyMigration(client, file);
      }

      const before = await client.query<{ exists: boolean }>(`
        SELECT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
        ) AS exists
      `);
      expect(before.rows[0]?.exists).toBe(false);

      await applyMigration(client, reconciliationMigration);
      await applyMigration(client, reconciliationMigration);

      const after = await client.query<{
        column_default: string;
        is_nullable: string;
      }>(`
        SELECT column_default,is_nullable FROM information_schema.columns
        WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
      `);
      expect(after.rows).toEqual([{ column_default: "false", is_nullable: "NO" }]);
    } finally {
      await client.close();
    }
  });

  const realPostgresTest = process.env.DATABASE_URL ? test : test.skip;
  realPostgresTest("is present after the journal-driven production migrator", async () => {
    const sql = postgres(process.env.DATABASE_URL!, { max: 1 });
    try {
      const column = await sql<{ column_default: string; is_nullable: string }[]>`
        SELECT column_default,is_nullable FROM information_schema.columns
        WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
      `;
      expect(column).toEqual([{ column_default: "false", is_nullable: "NO" }]);

      const applied = await sql<{ count: number; newest: number }[]>`
        SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations
      `;
      const journal = JSON.parse(
        await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
      ) as { entries: unknown[] };
      expect(applied[0]?.count).toBe(journal.entries.length);
    } finally {
      await sql.end({ timeout: 5 });
    }
  });
});
