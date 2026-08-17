/**
 * SEC-030 regression tests. The legacy-DB backfill must seed only the journal
 * entries the psql-era deploy loop provably applied (through 0024), not the
 * entire current journal — otherwise constraint-only hardening migrations
 * (e.g. 0046/0047 cross-tenant FKs and CHECK constraints) are silently skipped
 * on legacy DBs while the app appears healthy.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import {
  LEGACY_BACKFILL_FINGERPRINT_TABLE,
  LEGACY_BACKFILL_TIP_TAG,
  selectLegacyBackfillEntries,
} from "../migrate";

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

function readJournal(): { entries: JournalEntry[] } {
  return JSON.parse(
    readFileSync(new URL("../../drizzle/meta/_journal.json", import.meta.url), "utf8"),
  ) as { entries: JournalEntry[] };
}

describe("legacy DB backfill (SEC-030)", () => {
  test("seeds only entries through the psql-era tip, never the whole journal", () => {
    const journal = readJournal();
    const seeded = selectLegacyBackfillEntries(journal);

    // The backfill must stop at the psql-era tip...
    expect(seeded.at(-1)?.tag).toBe(LEGACY_BACKFILL_TIP_TAG);
    expect(seeded.length).toBeLessThan(journal.entries.length);

    // ...and must never seed hardening migrations that landed after the psql
    // loop was retired — those must be APPLIED by the migrator so their
    // constraints actually exist.
    const seededTags = new Set(seeded.map((entry) => entry.tag));
    expect(seededTags.has("0046_pr79_cross_tenant_fks")).toBe(false);
    expect(seededTags.has("0047_pr79_security_invariants")).toBe(false);
    for (const entry of journal.entries) {
      if (entry.tag > LEGACY_BACKFILL_TIP_TAG) {
        expect(seededTags.has(entry.tag)).toBe(false);
      }
    }
  });

  test("fingerprints the psql-era tip table, not the 0000-era tenants table", () => {
    // `tenants` exists on every legacy DB regardless of how far the psql loop
    // got; the fingerprint must name the newest backfill-era object instead.
    expect(LEGACY_BACKFILL_FINGERPRINT_TABLE).toBe("public.audit_events");
    expect(LEGACY_BACKFILL_FINGERPRINT_TABLE).not.toBe("public.tenants");
  });

  test("refuses to seed when the backfill-era tip is missing from the journal", () => {
    const truncated = {
      entries: [
        { idx: 0, tag: "0000_black_klaw", when: 1 },
        { idx: 1, tag: "0001_multi_wallet", when: 2 },
      ],
    };
    expect(() => selectLegacyBackfillEntries(truncated)).toThrow(/backfill-era tip/i);
  });
});
