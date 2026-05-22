import { readFileSync } from "node:fs";
import { migrate } from "drizzle-orm/postgres-js/migrator";

import { createDb } from "./client";

declare const process: {
  argv: string[];
  exitCode?: number;
};

const MIGRATIONS_FOLDER = new URL("../drizzle", import.meta.url).pathname;
const ADVISORY_LOCK_KEY = "steward_migrations";

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

interface Journal {
  entries: JournalEntry[];
}

function readJournal(): Journal {
  const path = `${MIGRATIONS_FOLDER}/meta/_journal.json`;
  return JSON.parse(readFileSync(path, "utf-8")) as Journal;
}

function hashMigration(tag: string): string {
  // Drizzle hashes the raw .sql file contents with sha256.
  const crypto = require("node:crypto") as typeof import("node:crypto");
  const sql = readFileSync(`${MIGRATIONS_FOLDER}/${tag}.sql`, "utf-8");
  return crypto.createHash("sha256").update(sql).digest("hex");
}

/**
 * Run drizzle-kit migrations under a Postgres advisory session lock so
 * concurrent API replicas don't race on startup. Returns the tags of
 * migrations applied during this call (empty if everything was up to date).
 *
 * On first run against a DB that pre-dates this migrator (the deploy script
 * used to `psql -f` each .sql by hand), we backfill `drizzle.__drizzle_migrations`
 * from the journal so the migrator doesn't try to re-apply non-idempotent DDL.
 * Heuristic: if `__drizzle_migrations` is empty AND `tenants` exists (was
 * created by 0000), assume all journal entries are already applied.
 */
export async function runMigrations(): Promise<{ applied: string[] }> {
  const { client, db } = createDb();

  try {
    // Session-scoped advisory lock spans the whole migrator (which uses its
    // own transaction). pg_advisory_lock blocks until acquired.
    await client`SELECT pg_advisory_lock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;

    try {
      const journal = readJournal();

      // Ensure schema + table exist so we can inspect before drizzle's migrator runs.
      await client`CREATE SCHEMA IF NOT EXISTS drizzle`;
      await client`
        CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (
          id SERIAL PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `;

      const existingRows = (await client`
        SELECT created_at FROM drizzle.__drizzle_migrations
      `) as Array<{ created_at: string | number | null }>;

      const tenantsExists = (await client`
        SELECT to_regclass('public.tenants') AS r
      `) as Array<{ r: string | null }>;

      // Backfill: legacy DB previously migrated by the psql loop.
      if (existingRows.length === 0 && tenantsExists[0]?.r) {
        console.log(
          `[migrate] Legacy DB detected — seeding __drizzle_migrations with ${journal.entries.length} historical entries`,
        );
        for (const entry of journal.entries) {
          const hash = hashMigration(entry.tag);
          await client`
            INSERT INTO drizzle.__drizzle_migrations ("hash", "created_at")
            VALUES (${hash}, ${entry.when})
          `;
        }
      }

      const beforeCount = (
        (await client`SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`) as Array<{
          n: number;
        }>
      )[0].n;

      await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });

      const afterRows = (await client`
        SELECT hash, created_at
        FROM drizzle.__drizzle_migrations
        ORDER BY id ASC
      `) as Array<{ hash: string; created_at: string | number | null }>;

      const newRows = afterRows.slice(beforeCount);
      const tagByHash = new Map<string, string>();
      for (const entry of journal.entries) tagByHash.set(hashMigration(entry.tag), entry.tag);
      const applied = newRows.map((r) => tagByHash.get(r.hash) ?? r.hash);

      return { applied };
    } finally {
      await client`SELECT pg_advisory_unlock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
    }
  } finally {
    await client.end();
  }
}

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  runMigrations()
    .then(({ applied }) => {
      if (applied.length === 0) {
        console.log("[migrate] Already up to date.");
      } else {
        console.log(`[migrate] Applied ${applied.length} migration(s):`);
        for (const tag of applied) console.log(`  - ${tag}`);
      }
    })
    .catch((error) => {
      console.error("Failed to run migrations", error);
      process.exitCode = 1;
    });
}
