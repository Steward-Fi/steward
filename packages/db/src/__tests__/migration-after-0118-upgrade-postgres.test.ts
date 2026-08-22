import { expect, setDefaultTimeout, test } from "bun:test";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { runMigrations } from "../migrate";

setDefaultTimeout(180_000);

const migrations = new URL("../../drizzle", import.meta.url).pathname;
const testWithPostgres = process.env.DATABASE_URL ? test : test.skip;

testWithPostgres("upgrades the exact shipped 0118 ledger without rewriting history", async () => {
  const originalDatabaseUrl = process.env.DATABASE_URL!;
  const maintenanceUrl = new URL(originalDatabaseUrl);
  maintenanceUrl.pathname = "/postgres";
  const admin = postgres(maintenanceUrl.toString(), { max: 1 });
  const databaseName = `steward_after_0118_${process.pid}_${crypto.randomUUID().replaceAll("-", "")}`;
  const targetUrl = new URL(originalDatabaseUrl);
  targetUrl.pathname = `/${databaseName}`;
  const migrationsAt0118 = await mkdtemp(join(tmpdir(), "steward-migrations-0118-"));
  let databaseCreated = false;

  try {
    const journal = JSON.parse(
      await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
    ) as { entries: Array<{ idx: number; tag: string; when: number }> };
    const shippedEntries = journal.entries.filter(({ idx }) => idx <= 118);
    await cp(migrations, migrationsAt0118, { recursive: true });
    await writeFile(
      join(migrationsAt0118, "meta", "_journal.json"),
      `${JSON.stringify({ ...journal, entries: shippedEntries }, null, 2)}\n`,
    );

    await admin`CREATE DATABASE ${admin(databaseName)}`;
    databaseCreated = true;
    const target = postgres(targetUrl.toString(), { max: 1 });
    try {
      await migrate(drizzle(target), { migrationsFolder: migrationsAt0118 });
      const shippedTail = await target<{ created_at: string }[]>`
        SELECT created_at::text
        FROM drizzle.__drizzle_migrations
        WHERE created_at = 1787306400000
        ORDER BY id
      `;
      expect(shippedTail).toHaveLength(2);
    } finally {
      await target.end({ timeout: 5 });
    }

    process.env.DATABASE_URL = targetUrl.toString();
    const first = await runMigrations();
    expect(first.applied).toEqual([
      "0119_signed_artifact_retirement",
      "0120_monero_pre_relay_lifecycle",
      "0121_trade_order_recovery",
      "0122_provider_action_audit_outbox_delivery",
    ]);
    expect((await runMigrations()).applied).toEqual([]);

    const verified = postgres(targetUrl.toString(), { max: 1 });
    try {
      const [shape] = await verified<
        {
          artifact_retired: boolean;
          monero_delete_fence: boolean;
          trade_recovery: string | null;
          outbox_claim: boolean;
        }[]
      >`
        SELECT
          EXISTS (
            SELECT 1
            FROM pg_enum value
            JOIN pg_type type ON type.oid = value.enumtypid
            WHERE type.typname = 'transaction_status' AND value.enumlabel = 'retired'
          ) AS artifact_retired,
          EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'steward_guard_approved_agent_delete' AND NOT tgisinternal
          ) AS monero_delete_fence,
          to_regclass('public.trade_order_recoveries')::text AS trade_recovery,
          EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'provider_action_audit_outbox'
              AND column_name = 'claim_token'
          ) AS outbox_claim
      `;
      expect(shape).toEqual({
        artifact_retired: true,
        monero_delete_fence: true,
        trade_recovery: "trade_order_recoveries",
        outbox_claim: true,
      });
    } finally {
      await verified.end({ timeout: 5 });
    }
  } finally {
    process.env.DATABASE_URL = originalDatabaseUrl;
    if (databaseCreated) {
      await admin.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
    }
    await admin.end({ timeout: 5 });
    await rm(migrationsAt0118, { recursive: true, force: true });
  }
});
