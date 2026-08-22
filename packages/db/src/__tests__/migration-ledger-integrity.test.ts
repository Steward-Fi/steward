import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  assertCoreMigrationLedgerIntegrity,
  type CoreMigrationLedgerRow,
  LEGACY_BACKFILL_TIP_TAG,
} from "../migrate";

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

const migrations = new URL("../../drizzle/", import.meta.url);
const journal = JSON.parse(readFileSync(new URL("meta/_journal.json", migrations), "utf8")) as {
  entries: JournalEntry[];
};

function row(entry: JournalEntry, id: number): CoreMigrationLedgerRow {
  const sql = readFileSync(new URL(`${entry.tag}.sql`, migrations));
  return {
    id,
    hash: createHash("sha256").update(sql).digest("hex"),
    created_at: entry.when,
  };
}

function rows(entries: JournalEntry[]): CoreMigrationLedgerRow[] {
  return entries.map((entry, index) => row(entry, index + 1));
}

const migratedDatabase = {
  tenantsExists: true,
  auditEventsExists: true,
  legacyFingerprintMatches: true,
  publicRelationCount: 250,
};

describe("core migration ledger integrity", () => {
  test("inspects and rejects the target before creating migration bookkeeping", () => {
    const source = readFileSync(new URL("../migrate.ts", import.meta.url), "utf8");
    const inspect = source.indexOf("to_regclass('drizzle.__drizzle_migrations')");
    const validate = source.indexOf(
      "assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape)",
    );
    const mutate = source.indexOf("CREATE SCHEMA IF NOT EXISTS drizzle");
    expect(inspect).toBeGreaterThan(0);
    expect(validate).toBeGreaterThan(inspect);
    expect(mutate).toBeGreaterThan(validate);
  });

  test("accepts a genuinely empty database before the first migration", () => {
    expect(() =>
      assertCoreMigrationLedgerIntegrity([], journal, {
        tenantsExists: false,
        auditEventsExists: false,
        legacyFingerprintMatches: false,
        publicRelationCount: 0,
      }),
    ).not.toThrow();
  });

  test("accepts a complete Steward journal and the bounded legacy backfill prefix", () => {
    expect(() =>
      assertCoreMigrationLedgerIntegrity(rows(journal.entries), journal, migratedDatabase, {
        requireComplete: true,
      }),
    ).not.toThrow();

    const legacyTip = journal.entries.findIndex((entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG);
    expect(legacyTip).toBeGreaterThan(0);
    expect(() =>
      assertCoreMigrationLedgerIntegrity(
        rows(journal.entries.slice(0, legacyTip + 1)),
        journal,
        migratedDatabase,
      ),
    ).not.toThrow();
  });

  test("rejects unrelated and ahead rows before Drizzle can trust their timestamp", () => {
    const poisoned = [
      ...rows(journal.entries.slice(0, 3)),
      { id: 999, hash: "f".repeat(64), created_at: journal.entries.at(-1)!.when + 1 },
    ];
    expect(() => assertCoreMigrationLedgerIntegrity(poisoned, journal, migratedDatabase)).toThrow(
      /not owned by this Steward build/,
    );
  });

  test("rejects a missing migration below the recorded cutoff", () => {
    const missing = rows(
      journal.entries.filter((entry) => entry.tag !== "0111_tenant_rls_policy_install"),
    );
    expect(() => assertCoreMigrationLedgerIntegrity(missing, journal, migratedDatabase)).toThrow(
      /missing 0111_tenant_rls_policy_install below its recorded cutoff/,
    );
  });

  test("rejects wrong, shared, and ambiguous legacy database shapes", () => {
    expect(() =>
      assertCoreMigrationLedgerIntegrity(rows(journal.entries), journal, {
        ...migratedDatabase,
        tenantsExists: false,
      }),
    ).toThrow(/wrong database/);
    expect(() =>
      assertCoreMigrationLedgerIntegrity([], journal, {
        tenantsExists: false,
        auditEventsExists: false,
        legacyFingerprintMatches: false,
        publicRelationCount: 1,
      }),
    ).toThrow(/shared database/);

    // The namespaced core ledger is authoritative. A stale public Drizzle
    // journal is just another legacy public relation when Steward's own root
    // and fingerprint prove the bounded psql-era backfill path.
    expect(() =>
      assertCoreMigrationLedgerIntegrity([], journal, {
        tenantsExists: true,
        auditEventsExists: true,
        legacyFingerprintMatches: true,
        publicRelationCount: 251,
      }),
    ).not.toThrow();
  });

  test("rejects claimed legacy-tip state without its complete schema fingerprint", () => {
    expect(() =>
      assertCoreMigrationLedgerIntegrity(rows(journal.entries), journal, {
        ...migratedDatabase,
        auditEventsExists: false,
      }),
    ).toThrow(/complete legacy schema fingerprint does not match/);
    expect(() =>
      assertCoreMigrationLedgerIntegrity([], journal, {
        tenantsExists: true,
        auditEventsExists: true,
        legacyFingerprintMatches: false,
        publicRelationCount: 2,
      }),
    ).toThrow(/does not match the complete legacy schema fingerprint/);
  });

  test("validates explicit positive migration timeout bounds", async () => {
    const { resolveMigrationTimeouts } = await import("../migrate");
    expect(
      resolveMigrationTimeouts({
        STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS: "3",
        STEWARD_MIGRATION_LOCK_TIMEOUT_MS: "4000",
        STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS: "5000",
        STEWARD_MIGRATION_OVERALL_TIMEOUT_MS: "6000",
      }),
    ).toEqual({ connectSeconds: 3, advisoryLockMs: 4000, statementMs: 5000, overallMs: 6000 });
    expect(() =>
      resolveMigrationTimeouts({ STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS: "0" }),
    ).toThrow(/positive integer/);
    expect(() =>
      resolveMigrationTimeouts({
        STEWARD_MIGRATION_LOCK_TIMEOUT_MS: "7000",
        STEWARD_MIGRATION_OVERALL_TIMEOUT_MS: "6000",
      }),
    ).toThrow(/must not exceed/);
  });

  test("requires the full checked-in journal after the migrator returns", () => {
    const legacyTip = journal.entries.findIndex((entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG);
    expect(() =>
      assertCoreMigrationLedgerIntegrity(
        rows(journal.entries.slice(0, legacyTip + 1)),
        journal,
        migratedDatabase,
        { requireComplete: true },
      ),
    ).toThrow(/returned with an incomplete Steward journal/);
  });
});
