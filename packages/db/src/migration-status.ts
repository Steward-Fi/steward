import { readFileSync } from "node:fs";

export type MigrationExpectation = {
  tag: string;
  createdAt: number;
  count: number;
};

type Journal = { entries?: Array<{ tag?: unknown; when?: unknown }> };

/**
 * Return the checked-in migration tip. Reading the journal keeps operational
 * diagnostics aligned with the migrator instead of duplicating a tag that
 * becomes stale whenever a migration is added.
 */
export function getMigrationExpectation(): MigrationExpectation {
  const path = new URL("../drizzle/meta/_journal.json", import.meta.url);
  const journal = JSON.parse(readFileSync(path, "utf8")) as Journal;
  const entries = journal.entries ?? [];
  const last = entries.at(-1);
  if (!last || typeof last.tag !== "string" || typeof last.when !== "number") {
    throw new Error("migration journal has no valid tip");
  }
  return { tag: last.tag, createdAt: last.when, count: entries.length };
}
