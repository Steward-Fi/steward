import { readFileSync } from "node:fs";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { migrate } from "drizzle-orm/postgres-js/migrator";

import { createDb } from "./client";

declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
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
  legacyFingerprintMatches: boolean;
  userObjectCount: number;
}

export interface MigrationTimeouts {
  connectSeconds: number;
  advisoryLockMs: number;
  statementMs: number;
  overallMs: number;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`[migrate] ${name} must be a positive integer`);
  }
  return parsed;
}

export function resolveMigrationTimeouts(
  env: Record<string, string | undefined> = process.env,
): MigrationTimeouts {
  const connectSeconds = positiveInteger(
    env.STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS,
    15,
    "STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS",
  );
  const advisoryLockMs = positiveInteger(
    env.STEWARD_MIGRATION_LOCK_TIMEOUT_MS,
    60_000,
    "STEWARD_MIGRATION_LOCK_TIMEOUT_MS",
  );
  const statementMs = positiveInteger(
    env.STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS,
    300_000,
    "STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS",
  );
  const overallMs = positiveInteger(
    env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS,
    600_000,
    "STEWARD_MIGRATION_OVERALL_TIMEOUT_MS",
  );
  if (advisoryLockMs > overallMs || statementMs > overallMs) {
    throw new Error(
      "[migrate] migration lock/statement timeouts must not exceed the overall timeout",
    );
  }
  return { connectSeconds, advisoryLockMs, statementMs, overallMs };
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
  if (rows.length === 0 && database.tenantsExists && !database.legacyFingerprintMatches) {
    throw new Error(
      "[migrate] Non-empty database resembles Steward but does not match the complete legacy schema fingerprint; refusing to create migration bookkeeping",
    );
  }
  if (rows.length === 0 && !database.tenantsExists && database.userObjectCount > 0) {
    throw new Error(
      "[migrate] Non-empty user schema has no Steward migration history; refusing a shared database",
    );
  }
  const auditMigrationIndex = journal.entries.findIndex(
    (entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG,
  );
  if (
    auditMigrationIndex !== -1 &&
    recordedIndices.some((index) => index >= auditMigrationIndex) &&
    (!database.auditEventsExists || !database.legacyFingerprintMatches)
  ) {
    throw new Error(
      `[migrate] Journal claims ${LEGACY_BACKFILL_TIP_TAG} but the complete legacy schema fingerprint does not match`,
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
 * The newest table created by the legacy psql-era tip. Before backfilling its
 * ledger, runMigrations additionally verifies the complete 0000-0024 relation,
 * migration-specific column, and critical-index fingerprint; this sentinel is
 * retained for the explicit tip lookup and diagnostics.
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
 * created by 0000), the DB may have come from the psql loop. Before accepting
 * it, verify the complete 0000-0024 relation, migration-specific column, and
 * critical-index fingerprint. Then seed only entries through that tip —
 * seeding the whole current journal would silently skip every migration
 * between the DB's true tip and now, including constraint-only hardening
 * migrations whose absence produces no runtime error.
 */
export async function runMigrations(): Promise<{ applied: string[] }> {
  const timeouts = resolveMigrationTimeouts();
  const { client, db } = createDb(undefined, {
    max: 1,
    connectTimeoutSeconds: timeouts.connectSeconds,
    statementTimeoutMs: timeouts.statementMs,
    lockTimeoutMs: timeouts.advisoryLockMs,
    idleInTransactionTimeoutMs: timeouts.statementMs,
  });
  let overallTimedOut = false;
  let deadlineClose: Promise<void> | undefined;
  const overallTimer = setTimeout(() => {
    overallTimedOut = true;
    deadlineClose = client.end({ timeout: 0 });
    void deadlineClose.catch(() => undefined);
  }, timeouts.overallMs);
  let advisoryLockHeld = false;

  try {
    // Session-scoped advisory lock spans the whole migrator (which uses its
    // own transaction). Give this wait its own shorter server-side bound.
    await client`SELECT set_config('statement_timeout', ${`${timeouts.advisoryLockMs}ms`}, false)`;
    await client`SELECT pg_advisory_lock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
    advisoryLockHeld = true;
    await client`SELECT set_config('statement_timeout', ${`${timeouts.statementMs}ms`}, false)`;

    try {
      const journal = readJournal();

      // Inspect without writing first. A privileged migration URL can be
      // misconfigured to point at an unrelated/shared database; even creating
      // our bookkeeping schema there would be an unacceptable mutation before
      // the fail-closed target check runs.
      const ledgerExists = (await client`
        SELECT to_regclass('drizzle.__drizzle_migrations') AS r
      `) as Array<{ r: string | null }>;
      const drizzleSchemaExists = (await client`
        SELECT to_regnamespace('drizzle') AS r
      `) as Array<{ r: string | null }>;
      const tenantsExists = (await client`
        SELECT to_regclass('public.tenants') AS r
      `) as Array<{ r: string | null }>;
      const auditEventsExists = (await client`
        SELECT to_regclass(${LEGACY_BACKFILL_FINGERPRINT_TABLE}) AS r
      `) as Array<{ r: string | null }>;
      const databaseInventory = (await client`
        SELECT
          (
            SELECT count(*) FROM pg_namespace candidate
            WHERE candidate.nspname NOT IN (
              'public', 'drizzle', 'steward_rls', 'steward_bootstrap',
              'pg_catalog', 'information_schema'
            )
              AND candidate.nspname !~ '^pg_(toast|temp|toast_temp)'
          ) + (
            SELECT count(*) FROM pg_class object
            JOIN pg_namespace candidate ON candidate.oid = object.relnamespace
            WHERE candidate.nspname IN ('public', 'drizzle', 'steward_rls', 'steward_bootstrap')
          ) + (
            SELECT count(*) FROM pg_proc object
            JOIN pg_namespace candidate ON candidate.oid = object.pronamespace
            WHERE candidate.nspname IN ('public', 'drizzle', 'steward_rls', 'steward_bootstrap')
          ) + (
            SELECT count(*) FROM pg_type object
            JOIN pg_namespace candidate ON candidate.oid = object.typnamespace
            WHERE candidate.nspname IN ('public', 'drizzle', 'steward_rls', 'steward_bootstrap')
              AND object.typtype IN ('c', 'd', 'e', 'm', 'r')
          ) AS user_object_count,
          (
            SELECT count(*) = 28
            FROM (VALUES
              ('agents'), ('approval_queue'), ('encrypted_keys'), ('policies'),
              ('tenants'), ('transactions'), ('accounts'), ('authenticators'), ('sessions'),
              ('user_tenants'), ('users'), ('agent_wallets'), ('encrypted_chain_keys'),
              ('webhook_deliveries'), ('secrets'), ('secret_routes'), ('proxy_audit_log'),
              ('tenant_configs'), ('webhook_configs'), ('auto_approval_rules'),
              ('auth_kv_store'), ('refresh_tokens'), ('policy_templates'),
              ('agent_registrations'), ('reputation_cache'), ('registry_index'),
              ('trade_sessions'), ('audit_events')
            ) AS required(relation_name)
            WHERE to_regclass('public.' || required.relation_name) IS NOT NULL
          ) AND (
            SELECT count(*) = 21
            FROM (VALUES
              ('agents', 'owner_user_id'), ('agents', 'wallet_type'),
              ('tenant_configs', 'allowed_origins'), ('tenant_configs', 'join_mode'),
              ('tenant_configs', 'email_config'), ('users', 'wallet_chain'),
              ('proxy_audit_log', 'reason'),
              ('accounts', 'access_token_iv'), ('accounts', 'access_token_tag'),
              ('accounts', 'access_token_salt'), ('accounts', 'refresh_token_iv'),
              ('accounts', 'refresh_token_tag'), ('accounts', 'refresh_token_salt'),
              ('encrypted_chain_keys', 'venue'), ('encrypted_chain_keys', 'purpose'),
              ('agent_wallets', 'venue'),
              ('audit_events', 'tenant_id'), ('audit_events', 'seq'),
              ('audit_events', 'prev_hash'), ('audit_events', 'hmac'),
              ('audit_events', 'action')
            ) AS required(relation_name, column_name)
            WHERE EXISTS (
              SELECT 1
              FROM information_schema.columns column_inventory
              WHERE column_inventory.table_schema = 'public'
                AND column_inventory.table_name = required.relation_name
                AND column_inventory.column_name = required.column_name
            )
          ) AND (
            SELECT count(*) = 6
            FROM (VALUES
              ('auth_kv_store_expires_idx'), ('refresh_tokens_token_hash_idx'),
              ('agent_registrations_tenant_agent_chain_idx'),
              ('encrypted_chain_keys_agent_chain_venue_idx'),
              ('trade_sessions_agent_venue_status_idx'), ('audit_events_tenant_seq_idx')
            ) AS required(index_name)
            WHERE to_regclass('public.' || required.index_name) IS NOT NULL
          ) AS legacy_fingerprint_matches
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      `) as Array<{ user_object_count: number; legacy_fingerprint_matches: boolean }>;
      const databaseShape: CoreMigrationDatabaseShape = {
        tenantsExists: Boolean(tenantsExists[0]?.r),
        auditEventsExists: Boolean(auditEventsExists[0]?.r),
        legacyFingerprintMatches: databaseInventory[0]?.legacy_fingerprint_matches === true,
        userObjectCount: databaseInventory[0]?.user_object_count ?? 0,
      };
      let existingRows: CoreMigrationLedgerRow[] = [];
      if (ledgerExists[0]?.r) {
        existingRows = (await client`
          SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC
        `) as CoreMigrationLedgerRow[];
      }
      assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape);
      if (existingRows.length === journal.entries.length) {
        assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape, {
          requireComplete: true,
        });
        return { applied: [] };
      }

      // Only a verified empty/legacy Steward target may receive the ledger.
      // Avoid even idempotent CREATE statements once admin topology/the ledger
      // exists: PostgreSQL requires database/schema CREATE before checking IF
      // NOT EXISTS, which would make an already-complete runtime migration
      // probe depend on a release-only privilege.
      if (!drizzleSchemaExists[0]?.r) {
        await client`CREATE SCHEMA drizzle`;
      }
      if (!ledgerExists[0]?.r) {
        await client`
          CREATE TABLE drizzle.__drizzle_migrations (
            id SERIAL PRIMARY KEY,
            hash text NOT NULL,
            created_at bigint
          )
        `;
      }

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
          (
            SELECT count(*) = 28
            FROM (VALUES
              ('agents'), ('approval_queue'), ('encrypted_keys'), ('policies'),
              ('tenants'), ('transactions'), ('accounts'), ('authenticators'), ('sessions'),
              ('user_tenants'), ('users'), ('agent_wallets'), ('encrypted_chain_keys'),
              ('webhook_deliveries'), ('secrets'), ('secret_routes'), ('proxy_audit_log'),
              ('tenant_configs'), ('webhook_configs'), ('auto_approval_rules'),
              ('auth_kv_store'), ('refresh_tokens'), ('policy_templates'),
              ('agent_registrations'), ('reputation_cache'), ('registry_index'),
              ('trade_sessions'), ('audit_events')
            ) AS required(relation_name)
            WHERE to_regclass('public.' || required.relation_name) IS NOT NULL
          ) AND (
            SELECT count(*) = 21
            FROM (VALUES
              ('agents', 'owner_user_id'), ('agents', 'wallet_type'),
              ('tenant_configs', 'allowed_origins'), ('tenant_configs', 'join_mode'),
              ('tenant_configs', 'email_config'), ('users', 'wallet_chain'),
              ('proxy_audit_log', 'reason'),
              ('accounts', 'access_token_iv'), ('accounts', 'access_token_tag'),
              ('accounts', 'access_token_salt'), ('accounts', 'refresh_token_iv'),
              ('accounts', 'refresh_token_tag'), ('accounts', 'refresh_token_salt'),
              ('encrypted_chain_keys', 'venue'), ('encrypted_chain_keys', 'purpose'),
              ('agent_wallets', 'venue'),
              ('audit_events', 'tenant_id'), ('audit_events', 'seq'),
              ('audit_events', 'prev_hash'), ('audit_events', 'hmac'),
              ('audit_events', 'action')
            ) AS required(relation_name, column_name)
            WHERE EXISTS (
              SELECT 1
              FROM information_schema.columns column_inventory
              WHERE column_inventory.table_schema = 'public'
                AND column_inventory.table_name = required.relation_name
                AND column_inventory.column_name = required.column_name
            )
          ) AND (
            SELECT count(*) = 6
            FROM (VALUES
              ('auth_kv_store_expires_idx'), ('refresh_tokens_token_hash_idx'),
              ('agent_registrations_tenant_agent_chain_idx'),
              ('encrypted_chain_keys_agent_chain_venue_idx'),
              ('trade_sessions_agent_venue_status_idx'), ('audit_events_tenant_seq_idx')
            ) AS required(index_name)
            WHERE to_regclass('public.' || required.index_name) IS NOT NULL
          ) AS legacy_fingerprint_matches,
          0::int AS user_object_count
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      `) as Array<{
        tenants_exists: boolean;
        audit_events_exists: boolean;
        legacy_fingerprint_matches: boolean;
        user_object_count: number;
      }>;
      assertCoreMigrationLedgerIntegrity(
        afterRows,
        journal,
        {
          tenantsExists: postMigrationShape?.tenants_exists ?? false,
          auditEventsExists: postMigrationShape?.audit_events_exists ?? false,
          legacyFingerprintMatches: postMigrationShape?.legacy_fingerprint_matches ?? false,
          userObjectCount: postMigrationShape?.user_object_count ?? 0,
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
      if (advisoryLockHeld && !overallTimedOut) {
        await client`SELECT pg_advisory_unlock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
      }
    }
  } catch (error) {
    if (overallTimedOut) {
      throw new Error(`[migrate] Migration exceeded the ${timeouts.overallMs}ms overall timeout`, {
        cause: error,
      });
    }
    throw error;
  } finally {
    clearTimeout(overallTimer);
    if (deadlineClose) await deadlineClose.catch(() => undefined);
    else await client.end({ timeout: 0 });
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
