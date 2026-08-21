import { readFileSync } from "node:fs";
import { redactedThrownDiagnostics } from "@stwd/shared";
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

export interface CoreMigrationLedgerRow {
  id: number;
  hash: string;
  created_at: string | number | null;
}

interface CoreMigrationDatabaseShape {
  tenantsExists: boolean;
  auditEventsExists: boolean;
  publicRelationCount: number;
}

/**
 * Drizzle trusts only the greatest `created_at` in its journal. An unrelated
 * row with a future timestamp therefore makes every Steward migration appear
 * applied. Validate the entire ledger against this repository before Drizzle
 * is allowed to use that cutoff.
 */
export function assertCoreMigrationLedgerIntegrity(
  rows: readonly CoreMigrationLedgerRow[],
  journal: Journal,
  database: CoreMigrationDatabaseShape,
  options: { requireComplete?: boolean } = {},
): void {
  const expected = journal.entries.map((entry) => ({
    ...entry,
    hash: hashMigration(entry.tag),
  }));
  const expectedByIdentity = new Map(
    expected.map((entry, index) => [`${entry.when}:${entry.hash}`, { entry, index }]),
  );
  if (expectedByIdentity.size !== expected.length) {
    throw new Error("[migrate] Checked-in migration journal contains duplicate identities");
  }

  const recordedIndices: number[] = [];
  const recordedIdentities = new Set<string>();
  for (const row of rows) {
    const createdAt = Number(row.created_at);
    if (!Number.isSafeInteger(createdAt) || createdAt < 0 || !row.hash) {
      throw new Error("[migrate] Core migration journal contains a malformed row");
    }
    const identity = `${createdAt}:${row.hash}`;
    const match = expectedByIdentity.get(identity);
    if (!match) {
      throw new Error(
        "[migrate] Core migration journal contains an entry not owned by this Steward build; " +
          "refusing to trust a possibly shared or ahead database",
      );
    }
    if (recordedIdentities.has(identity)) {
      throw new Error("[migrate] Core migration journal contains a duplicate Steward entry");
    }
    recordedIdentities.add(identity);
    recordedIndices.push(match.index);
  }

  if (
    recordedIndices.some(
      (index, position) => position > 0 && index <= recordedIndices[position - 1],
    )
  ) {
    throw new Error("[migrate] Core migration journal is not in checked-in Steward order");
  }

  if (rows.length > 0 && !database.tenantsExists) {
    throw new Error(
      "[migrate] Core migration journal exists without public.tenants; refusing the wrong database",
    );
  }
  if (rows.length === 0 && !database.tenantsExists && database.publicRelationCount > 0) {
    throw new Error(
      "[migrate] Non-empty public schema has no Steward migration history; refusing a shared database",
    );
  }
  const auditMigrationIndex = journal.entries.findIndex(
    (entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG,
  );
  if (
    auditMigrationIndex !== -1 &&
    recordedIndices.some((index) => index >= auditMigrationIndex) &&
    !database.auditEventsExists
  ) {
    throw new Error(
      `[migrate] Journal claims ${LEGACY_BACKFILL_TIP_TAG} but ${LEGACY_BACKFILL_FINGERPRINT_TABLE} is missing`,
    );
  }

  if (recordedIndices.length > 0) {
    const greatestRecordedWhen = Math.max(
      ...recordedIndices.map((index) => journal.entries[index].when),
    );
    const silentlySkipped = expected.filter(
      (entry) =>
        entry.when <= greatestRecordedWhen &&
        !recordedIdentities.has(`${entry.when}:${entry.hash}`),
    );
    if (silentlySkipped.length > 0) {
      throw new Error(
        `[migrate] Core migration journal is missing ${silentlySkipped[0].tag} below its recorded cutoff`,
      );
    }
  }

  if (options.requireComplete && recordedIdentities.size !== expected.length) {
    throw new Error("[migrate] Core migrator returned with an incomplete Steward journal");
  }
}

/**
 * The legacy `psql -f` deploy loop was retired when this migrator was
 * introduced; the journal tip at that moment was 0024_audit_events. A legacy
 * DB is therefore only provably migrated through that tag — entries past it
 * must be APPLIED by the migrator, never seeded.
 */
export const LEGACY_BACKFILL_TIP_TAG = "0024_audit_events";

/**
 * Fingerprint proving a legacy DB actually reached the psql-era tip: the
 * newest table 0024 created. `public.tenants` (0000) alone says nothing about
 * how far the psql loop got before the DB was frozen.
 */
export const LEGACY_BACKFILL_FINGERPRINT_TABLE = "public.audit_events";

/**
 * Select the journal entries a legacy DB may be seeded with: everything up to
 * and including the psql-era tip. Throws if the tip is absent from the
 * journal (should never happen — it is a historical entry).
 */
export function selectLegacyBackfillEntries(journal: Journal): JournalEntry[] {
  const tipIndex = journal.entries.findIndex((entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG);
  if (tipIndex === -1) {
    throw new Error(
      `[migrate] Backfill-era tip ${LEGACY_BACKFILL_TIP_TAG} is missing from the migration journal; refusing to seed a legacy DB`,
    );
  }
  return journal.entries.slice(0, tipIndex + 1);
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
 * created by 0000), the DB came from the psql loop. We then FINGERPRINT the
 * psql-era tip (`LEGACY_BACKFILL_FINGERPRINT_TABLE`, created by 0024) and seed
 * only the entries through that tip — seeding the whole current journal would
 * silently skip every migration between the DB's true tip and now, including
 * constraint-only hardening migrations whose absence produces no runtime error.
 */
export async function runMigrations(): Promise<{ applied: string[] }> {
  const { client, db } = createDb();

  try {
    // Session-scoped advisory lock spans the whole migrator (which uses its
    // own transaction). pg_advisory_lock blocks until acquired.
    await client`SELECT pg_advisory_lock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;

    try {
      const journal = readJournal();

      // Inspect without writing first. A privileged migration URL can be
      // misconfigured to point at an unrelated/shared database; even creating
      // our bookkeeping schema there would be an unacceptable mutation before
      // the fail-closed target check runs.
      const ledgerExists = (await client`
        SELECT to_regclass('drizzle.__drizzle_migrations') AS r
      `) as Array<{ r: string | null }>;
      const tenantsExists = (await client`
        SELECT to_regclass('public.tenants') AS r
      `) as Array<{ r: string | null }>;
      const auditEventsExists = (await client`
        SELECT to_regclass(${LEGACY_BACKFILL_FINGERPRINT_TABLE}) AS r
      `) as Array<{ r: string | null }>;
      const databaseInventory = (await client`
        SELECT count(*) FILTER (
          WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p')
        )::int AS public_relation_count
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      `) as Array<{ public_relation_count: number }>;
      const databaseShape: CoreMigrationDatabaseShape = {
        tenantsExists: Boolean(tenantsExists[0]?.r),
        auditEventsExists: Boolean(auditEventsExists[0]?.r),
        publicRelationCount: databaseInventory[0]?.public_relation_count ?? 0,
      };
      let existingRows: CoreMigrationLedgerRow[] = [];
      if (ledgerExists[0]?.r) {
        existingRows = (await client`
          SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC
        `) as CoreMigrationLedgerRow[];
      }
      assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape);

      // Only a verified empty/legacy Steward target may receive the ledger.
      await client`CREATE SCHEMA IF NOT EXISTS drizzle`;
      await client`
        CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (
          id SERIAL PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `;

      // Backfill: legacy DB previously migrated by the psql loop.
      if (existingRows.length === 0 && tenantsExists[0]?.r) {
        // Fingerprint the psql-era tip before trusting the heuristic: a DB
        // frozen at an older tip must fail loudly here, not be seeded with
        // migrations it never applied.
        if (!databaseShape.auditEventsExists) {
          throw new Error(
            `[migrate] Legacy DB detected (public.tenants exists) but fingerprint table ` +
              `${LEGACY_BACKFILL_FINGERPRINT_TABLE} is missing — the DB predates migration ` +
              `${LEGACY_BACKFILL_TIP_TAG}. Refusing to seed __drizzle_migrations: entries past ` +
              `the DB's true tip would be silently skipped (including security-hardening ` +
              `migrations). Reconcile the schema manually, then re-run migrations.`,
          );
        }
        const backfillEntries = selectLegacyBackfillEntries(journal);
        console.log(
          `[migrate] Legacy DB detected — seeding __drizzle_migrations with ${backfillEntries.length} ` +
            `entries through ${LEGACY_BACKFILL_TIP_TAG}; the migrator will apply the remaining ` +
            `${journal.entries.length - backfillEntries.length} journal entrie(s) normally`,
        );
        for (const entry of backfillEntries) {
          const hash = hashMigration(entry.tag);
          await client`
            INSERT INTO drizzle.__drizzle_migrations ("hash", "created_at")
            VALUES (${hash}, ${entry.when})
          `;
        }
        existingRows = (await client`
          SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC
        `) as CoreMigrationLedgerRow[];
        assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape);
      }

      const beforeCount = (
        (await client`SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`) as Array<{
          n: number;
        }>
      )[0].n;

      await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });

      const afterRows = (await client`
        SELECT id, hash, created_at
        FROM drizzle.__drizzle_migrations
        ORDER BY id ASC
      `) as CoreMigrationLedgerRow[];
      const [postMigrationShape] = (await client`
        SELECT
          to_regclass('public.tenants') IS NOT NULL AS tenants_exists,
          to_regclass(${LEGACY_BACKFILL_FINGERPRINT_TABLE}) IS NOT NULL AS audit_events_exists,
          count(*) FILTER (
            WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p')
          )::int AS public_relation_count
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      `) as Array<{
        tenants_exists: boolean;
        audit_events_exists: boolean;
        public_relation_count: number;
      }>;
      assertCoreMigrationLedgerIntegrity(
        afterRows,
        journal,
        {
          tenantsExists: postMigrationShape?.tenants_exists ?? false,
          auditEventsExists: postMigrationShape?.audit_events_exists ?? false,
          publicRelationCount: postMigrationShape?.public_relation_count ?? 0,
        },
        {
          requireComplete: true,
        },
      );

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
      console.error("Failed to run migrations", redactedThrownDiagnostics(error));
      process.exitCode = 1;
    });
}
