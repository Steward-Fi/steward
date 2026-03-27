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

import { createPGLiteDb, getDataDir } from "@stwd/db";
import { setPGLiteOverride } from "@stwd/db/src/client";

// Force PGLite mode
process.env.STEWARD_DB_MODE = "pglite";

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
  setPGLiteOverride(db as any, () => client.close());

  // Now boot the API
  console.log("[embedded] Starting API server...");
  await import("./index");
}

main().catch((err) => {
  console.error("[embedded] Fatal error:", err);
  process.exit(1);
});
