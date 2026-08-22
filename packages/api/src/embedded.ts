/**
 * Steward Embedded — local/desktop mode entry point.
 *
 * Starts the Steward API with PGLite (Postgres-in-WASM) so no external
 * database is required. Data is persisted to ~/.steward/data/ by default.
 *
 * Usage:
 *   bun run packages/api/src/embedded.ts
 *
 * Environment variables (all optional):
 *   STEWARD_PGLITE_PATH   — custom data directory (default ~/.steward/data)
 *   STEWARD_PGLITE_MEMORY — "true" for in-memory (no persistence)
 *   PORT                  — API port (default 3200)
 *   STEWARD_BIND_HOST     — bind host (default 127.0.0.1)
 */

import { createPGLiteDb, getDataDir, setPGLiteOverride } from "@stwd/db/pglite";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { loadOrCreateEmbeddedMasterPassword } from "./services/embedded-master-password";

// Force PGLite/embedded mode
process.env.STEWARD_DB_MODE = "pglite";
process.env.STEWARD_EMBEDDED = "true";

// Set a sentinel DATABASE_URL so context.ts's requireEnv doesn't throw.
// PGLite overrides getDb() before any SQL runs, so this URL is never used.
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "pglite://embedded";
}

// Ensure the Bun runtime custody authority has a durable master password.
// Auto-generate one if not provided — the sidecar also generates one and passes
// it via env, but standalone `bun run start:local` needs a fallback.
// SEC-147: a fresh random password per boot silently makes everything sealed
// under it undecryptable after restart, so the generated password is persisted
// to the data dir (mode 0600) and reused on subsequent boots.
if (!process.env.STEWARD_MASTER_PASSWORD) {
  process.env.STEWARD_MASTER_PASSWORD = loadOrCreateEmbeddedMasterPassword(getDataDir());
  console.log(
    "[embedded] Using the protected embedded master-password file (mode 0600).\n" +
      "[embedded] Set STEWARD_MASTER_PASSWORD explicitly to manage it yourself.",
  );
}

async function main() {
  const dataDir = getDataDir();
  console.log("╔══════════════════════════════════════════╗");
  console.log("║     Steward — Local / Desktop Mode       ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log(`Data directory: ${dataDir}`);
  console.log();

  // Initialize PGLite + run migrations BEFORE the API boots
  console.log("[embedded] Initializing PGLite database...");
  const { db, client } = await createPGLiteDb();
  console.log("[embedded] Database ready.");

  // Register PGLite as the backing database for getDb()/closeDb()
  setPGLiteOverride(db, () => client.close());

  // Now boot the API
  console.log("[embedded] Starting API server...");
  await import("./index");
}

main().catch((err) => {
  console.error("[embedded] Fatal error", redactedThrownDiagnostics(err));
  process.exit(1);
});
