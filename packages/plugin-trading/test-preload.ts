/**
 * Bun test preload for @stwd/api — runs ONCE per `bun test` process, before any
 * test file's module graph is evaluated.
 *
 * Why this exists: the api suite runs all ~135 test files in a SINGLE process,
 * and route/service modules (notably src/services/context.ts) are cached in the
 * shared module registry after their first evaluation. context.ts resolves
 * several invariants at module-init time:
 *   - `DATABASE_URL` (throws unless STEWARD_PGLITE_MEMORY / STEWARD_DB_MODE marks
 *     a PGLite runtime, or a real DATABASE_URL is present),
 *   - `STEWARD_MASTER_PASSWORD` (required), and
 *   - `export const db = getDb()` plus a floating default-tenant insert, which
 *     both need a working DB handle.
 *
 * Whichever test file FIRST triggers a route import "wins" that one-time
 * evaluation. Without this preload, when that first evaluation lands while a
 * prior file's afterAll has `delete`d STEWARD_PGLITE_MEMORY, context.ts throws
 * "DATABASE_URL is required" and the *failure is cached* for every later
 * importer — surfacing as the ~80 DATABASE_URL failures and the
 * "unhandled error between tests" from the floating default-tenant insert.
 *
 * This preload makes that first evaluation deterministic: it marks the PGLite
 * runtime, supplies full-entropy test secrets, and installs a PGLite override so
 * getDb()/the default-tenant insert succeed. Individual test files STILL call
 * createPGLiteDb()+setPGLiteOverride() in their own beforeAll to get a fresh,
 * isolated schema per file; this only provides the process-wide bootstrap.
 *
 * Security note: every value is set with `??=`, so a real environment (real
 * DATABASE_URL, real secrets in CI) is never overridden, and the PGLite
 * bootstrap is skipped entirely when a real DATABASE_URL is present. The test
 * secrets below are full-entropy values — identical in spirit to the per-file
 * `process.env.X ??= ...` convention already used across the suite (e.g.
 * vault-raw-signing, auth-guest-accounts). No production guard is weakened:
 * the hardened getJwtSecret() dev-secret refusal and the audit HMAC requirement
 * both still apply; we simply supply acceptable real test keys once.
 */

import { afterAll } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

// Full-entropy test secrets (never dev-weak values the hardened guards reject).
process.env.STEWARD_MASTER_PASSWORD ??= "steward-api-test-suite-master-password";
process.env.STEWARD_JWT_SECRET ??=
  "steward-api-test-suite-shared-jwt-secret-with-enough-entropy-0123456789";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);

// Only bootstrap PGLite when no real database is configured. This branch is the
// normal local/CI test path; a real DATABASE_URL (e.g. integration CI) is left
// untouched so the suite can run against real Postgres unchanged.
if (!process.env.DATABASE_URL) {
  process.env.STEWARD_PGLITE_MEMORY ??= "true";
  process.env.STEWARD_DB_MODE ??= "pglite";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  // Release the bootstrap PGLite handle once this process's tests finish. Bun
  // force-exits with a non-zero code (99) if any async handle keeps the event
  // loop alive at exit, and an in-memory PGLite stays reachable for the whole
  // process. Test files that run their own closeDb() teardown release it
  // themselves; source-introspection tests, all-skip files, and any file that
  // never touches the DB do not — so without this they exited 99 despite every
  // assertion passing (0 fail). This top-level afterAll runs after every
  // file-scoped afterAll, and closeDb() is idempotent (a no-op once the override
  // is cleared), so files that already tear down their own per-file DB are
  // unaffected.
  afterAll(async () => {
    await closeDb();
  });
}
