/**
 * bun test preload for @stwd/plugin-capabilities — runs ONCE per `bun test`
 * process, before any test file's module graph is evaluated.
 *
 * every value is set with `??=` so a real environment is never overridden, and
 * the PGLite runtime is only marked when there is no real DATABASE_URL. no
 * production guard is weakened; these are acceptable full-entropy test values.
 */

process.env.STEWARD_MASTER_PASSWORD ??= "steward-plugin-capabilities-test-master-password";
process.env.STEWARD_JWT_SECRET ??=
  "steward-plugin-capabilities-test-shared-jwt-secret-with-enough-entropy-0123456789";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "a".repeat(64);

if (!process.env.DATABASE_URL) {
  process.env.STEWARD_PGLITE_MEMORY ??= "true";
  process.env.STEWARD_DB_MODE ??= "pglite";
}
