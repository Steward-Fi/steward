import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { readMigrationFiles } from "drizzle-orm/migrator";

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

interface Journal {
  entries: JournalEntry[];
}

const migrationsFolder = join(import.meta.dir, "..", "..", "drizzle");

describe("merged migration gap backfill", () => {
  test("applies every merged gap migration after an existing 0118 ledger tip", () => {
    const journal = JSON.parse(
      readFileSync(join(migrationsFolder, "meta", "_journal.json"), "utf8"),
    ) as Journal;
    const existingTip = journal.entries.find(
      (entry) => entry.tag === "0118_generic_intent_execution_delete_fence",
    );
    if (!existingTip) throw new Error("merged 0118 migration is missing from the journal");

    // Drizzle chooses pending PostgreSQL migrations by comparing every journal
    // timestamp with the greatest already-recorded created_at value. Because
    // 0118 shipped before 0114 and the carrier filled 0115-0117. Every gap
    // migration must therefore have a timestamp newer than 0118 even though
    // its tag sorts before it. The wallet migration is safe to replay because
    // its DDL is idempotent; this also repairs deployments where 0114 was
    // skipped when it originally shared 0118's timestamp.
    const pending = readMigrationFiles({ migrationsFolder })
      .filter((migration) => existingTip.when < migration.folderMillis)
      .map(
        (migration) => journal.entries.find((entry) => entry.when === migration.folderMillis)?.tag,
      );

    expect(pending).toEqual([
      "0114_durable_wallet_claim_account_audit",
      "0115_signed_artifact_retirement",
      "0116_monero_pre_relay_lifecycle",
      "0117_trade_order_recovery",
      "0119_provider_action_audit_outbox_delivery",
    ]);
  });
});
