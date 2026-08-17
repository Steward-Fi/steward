/**
 * SEC-166: pin the Workers (neon-http) audit-append posture.
 *
 * CLOUDFLARE.md previously claimed advisory locks are unused; in reality the
 * audit chain acquires `pg_advisory_xact_lock` on every non-PGLite append
 * (`appendAuditEvent`, `withTenantAuditedTransaction`). On Workers the point
 * is moot today: drizzle's neon-http driver throws
 * "No transactions support in neon-http driver" from `db.transaction()`, so
 * an audited write rejects BEFORE any statement — lock or INSERT — runs.
 * Audited actions on Workers therefore FAIL CLOSED (the action is denied);
 * the chain is never silently skipped.
 *
 * These tests pin that contract. A future drizzle upgrade that adds neon-http
 * transaction support will break them — that is intentional: it forces an
 * explicit re-review of whether `pg_advisory_xact_lock` over the HTTP
 * transport provides the per-tenant serialization the chain requires.
 */
import { describe, expect, test } from "bun:test";
import { createNeonHttpDb } from "../client";

// Constructing the client is lazy — no network is touched, and
// transaction() throws before any HTTP round-trip.
const { db } = createNeonHttpDb(
  "postgres://user:pass@db.example.invalid/steward?sslmode=verify-full",
);

describe("audit chain on neon-http (Workers) — SEC-166", () => {
  test("db.transaction rejects, so audited writes fail closed on Workers", async () => {
    await expect(db.transaction(async () => {})).rejects.toThrow(
      /No transactions support in neon-http driver/,
    );
  });

  test("the transaction body never runs — neither the advisory lock nor the append", async () => {
    let bodyRan = false;
    await expect(
      db.transaction(async () => {
        // Mirrors appendAuditEvent's first step on non-PGLite runtimes
        // (pg_advisory_xact_lock, then the head read + INSERT).
        bodyRan = true;
      }),
    ).rejects.toThrow(/No transactions support in neon-http driver/);
    expect(bodyRan).toBe(false);
  });
});
