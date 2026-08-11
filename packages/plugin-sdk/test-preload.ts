/**
 * bun test preload for @stwd/plugin-sdk - runs ONCE per `bun test` process,
 * before any test file's module graph is evaluated.
 *
 * the sdk re-exports the plugin host runtime from @stwd/api/plugin. that module
 * graph eagerly evaluates @stwd/api's `services/context`, which resolves
 * env-dependent invariants at module-init (DATABASE_URL, STEWARD_MASTER_PASSWORD,
 * a db handle). without a deterministic bootstrap, importing the facade throws
 * "DATABASE_URL is required". this preload supplies a pglite runtime + full-
 * entropy test secrets, mirroring @stwd/api's own test preload.
 *
 * every value is set with `??=` so a real environment (real DATABASE_URL / real
 * secrets in CI) is never overridden, and the pglite bootstrap is skipped when a
 * real DATABASE_URL is present. no production guard is weakened.
 */

import { afterAll } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

process.env.STEWARD_MASTER_PASSWORD ??= "steward-plugin-sdk-test-master-password";
process.env.STEWARD_JWT_SECRET ??=
  "steward-plugin-sdk-test-shared-jwt-secret-with-enough-entropy-0123456789";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);

if (!process.env.DATABASE_URL) {
  process.env.STEWARD_PGLITE_MEMORY ??= "true";
  process.env.STEWARD_DB_MODE ??= "pglite";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  afterAll(async () => {
    await closeDb();
  });
}
