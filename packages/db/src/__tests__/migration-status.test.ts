import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  assessMigrationLedger,
  getMigrationExpectation,
  getMigrationLedgerExpectation,
  type MigrationLedgerEntry,
} from "../migration-status";

function ledgerEntry(createdAt: number, seed: string): MigrationLedgerEntry {
  return { createdAt, hash: createHash("sha256").update(seed).digest("hex") };
}

describe("migration expectation", () => {
  test("is derived from the checked-in journal tip", () => {
    const journal = JSON.parse(
      readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
    ) as { entries: Array<{ tag: string; when: number }> };
    const tip = journal.entries.at(-1);
    expect(tip).toBeDefined();
    expect(getMigrationExpectation()).toEqual({
      tag: tip?.tag,
      createdAt: tip?.when,
      count: journal.entries.length,
    });
  });

  test("journals the operator transfer reservation migration for production", () => {
    const journal = JSON.parse(
      readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
    ) as { entries: Array<{ tag: string }> };
    expect(
      journal.entries.some((entry) => entry.tag === "0094_operator_transfer_reservations"),
    ).toBe(true);
  });

  test("derives exact hashes and timestamps for the complete checked-in ledger", () => {
    const journal = JSON.parse(
      readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
    ) as { entries: Array<{ tag: string; when: number }> };
    const expectation = getMigrationLedgerExpectation();
    expect(expectation.entries).toHaveLength(journal.entries.length);
    for (const [index, entry] of journal.entries.entries()) {
      expect(expectation.entries[index]).toEqual({
        createdAt: entry.when,
        hash: createHash("sha256")
          .update(readFileSync(new URL(`../../drizzle/${entry.tag}.sql`, import.meta.url)))
          .digest("hex"),
      });
    }
  });
});

describe("migration ledger readiness", () => {
  const first = ledgerEntry(1000, "first");
  const required = ledgerEntry(2000, "required");
  const knownForward = ledgerEntry(3000, "known-forward");
  const unknownForward = ledgerEntry(4000, "unknown-forward");

  test("accepts the exact required ledger", () => {
    expect(assessMigrationLedger([first, required], [first, required])).toEqual({
      ok: true,
      state: "exact",
      requiredCount: 2,
      actualCount: 2,
      forwardCount: 0,
    });
  });

  test("fails closed when the ledger is behind the required migration", () => {
    expect(assessMigrationLedger([first], [first, required])).toEqual({
      ok: false,
      state: "behind",
      requiredCount: 2,
      actualCount: 1,
      forwardCount: 0,
    });
  });

  test("accepts a valid forward ledger whose suffix is known", () => {
    expect(
      assessMigrationLedger(
        [first, required, knownForward],
        [first, required],
        [first, required, knownForward],
      ),
    ).toEqual({
      ok: true,
      state: "ahead-known",
      requiredCount: 2,
      actualCount: 3,
      forwardCount: 1,
    });
  });

  test("accepts a valid forward ledger whose suffix is unknown to this release", () => {
    expect(assessMigrationLedger([first, required, unknownForward], [first, required])).toEqual({
      ok: true,
      state: "ahead-unknown",
      requiredCount: 2,
      actualCount: 3,
      forwardCount: 1,
    });
  });

  test("fails closed for missing, altered, malformed, duplicate, and non-forward entries", () => {
    const alteredRequired = ledgerEntry(required.createdAt, "altered");
    const malformedHash = { createdAt: 3000, hash: "not-a-sha256" };
    const duplicateTimestamp = ledgerEntry(required.createdAt, "duplicate");
    const nonForwardUnknown = ledgerEntry(1500, "non-forward-unknown");
    for (const applied of [
      [first, unknownForward],
      [first, alteredRequired, unknownForward],
      [first, required, malformedHash],
      [first, required, duplicateTimestamp],
      [first, nonForwardUnknown, required],
      [required, first],
      [first, required, unknownForward, knownForward],
    ]) {
      expect(assessMigrationLedger(applied, [first, required]).ok).toBe(false);
      expect(assessMigrationLedger(applied, [first, required]).state).toBe("corrupt");
    }
  });
});
