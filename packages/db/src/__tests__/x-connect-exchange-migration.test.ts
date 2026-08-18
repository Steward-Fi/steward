import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const migration = readFileSync(
  join(import.meta.dir, "..", "..", "drizzle", "0105_x_connect_exchange_recovery.sql"),
  "utf8",
);

describe("X connect exchange recovery migration", () => {
  test("backfills legacy retryable rows before enforcing next_retry_at", () => {
    const pendingBackfill = migration.indexOf(
      `SET "next_retry_at" = now()\nWHERE "state" = 'revocation_pending'`,
    );
    const attentionBackfill = migration.indexOf(
      `SET "state" = 'revocation_pending', "next_retry_at" = now()`,
    );
    const retryConstraint = migration.indexOf(`ADD CONSTRAINT "provider_x_lifecycle_retry_check"`);
    expect(pendingBackfill).toBeGreaterThan(-1);
    expect(attentionBackfill).toBeGreaterThan(pendingBackfill);
    expect(retryConstraint).toBeGreaterThan(attentionBackfill);
  });
});
