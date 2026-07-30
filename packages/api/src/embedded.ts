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

import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createPGLiteDb, getDataDir, setPGLiteOverride } from "@stwd/db/pglite";
import {
  DevMeasurementKeyProvider,
  DstackSealedStateKeyProvider,
  SealedState,
  type SealedStateEnvelope,
} from "@stwd/sealed-state";
import { registerShutdownHook } from "./services/shutdown-hooks";

// Force PGLite/embedded mode
process.env.STEWARD_DB_MODE = "pglite";
process.env.STEWARD_EMBEDDED = "true";

// Set a sentinel DATABASE_URL so context.ts's requireEnv doesn't throw.
// PGLite overrides getDb() before any SQL runs, so this URL is never used.
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = "pglite://embedded";
}

// Ensure STEWARD_MASTER_PASSWORD is set (context.ts requires it at module level).
// Auto-generate a random one if not provided — the sidecar also generates one
// and passes it via env, but standalone `bun run start:local` needs a fallback.
if (!process.env.STEWARD_MASTER_PASSWORD) {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  process.env.STEWARD_MASTER_PASSWORD = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  const dataDir = getDataDir();
  console.log("╔══════════════════════════════════════════╗");
  console.log("║     Steward — Local / Desktop Mode       ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log(`Data directory: ${dataDir}`);
  console.log();

  // Initialize PGLite + run migrations BEFORE the API boots. When configured,
  // the production entry path keeps PGLite in memory and persists only an
  // attestation-bound encrypted snapshot, never a plaintext data directory.
  console.log("[embedded] Initializing PGLite database...");
  const sealedPath = process.env.STEWARD_SEALED_PGLITE_PATH;
  let snapshot: Blob | undefined;
  let sealedState: SealedState | undefined;
  let measurement: { imageDigest: string; configHash: string } | undefined;
  if (sealedPath) {
    // First boot has no snapshot yet, so force memory explicitly as well as on restore.
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const backend = process.env.STEWARD_SEALED_STATE_BACKEND ?? "dstack-tdx";
    if (backend === "dstack-tdx") {
      const keys = new DstackSealedStateKeyProvider();
      measurement = await keys.currentMeasurement();
      sealedState = new SealedState(keys);
    } else if (backend === "noop-dev") {
      const secret = process.env.STEWARD_SEALED_STATE_DEV_SECRET;
      if (!secret)
        throw new Error("noop-dev sealed state requires STEWARD_SEALED_STATE_DEV_SECRET");
      measurement = {
        imageDigest: process.env.STEWARD_DEV_MEASUREMENT_IMAGE ?? "noop-dev",
        configHash: process.env.STEWARD_DEV_MEASUREMENT_CONFIG ?? "noop-dev",
      };
      sealedState = new SealedState(new DevMeasurementKeyProvider(secret));
      console.warn(
        "[embedded] INSECURE noop-dev sealed-state backend enabled; never use outside development",
      );
    } else {
      throw new Error(`unknown sealed-state backend: ${backend}`);
    }
    if (existsSync(sealedPath)) {
      const envelope = JSON.parse(readFileSync(sealedPath, "utf8")) as SealedStateEnvelope;
      const bytes = await sealedState.unseal(envelope, measurement);
      snapshot = new Blob([
        bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
      ]);
    }
  }
  const { db, client } = await createPGLiteDb(undefined, snapshot);
  if (sealedPath && sealedState && measurement) {
    registerShutdownHook(async () => {
      const dump = await client.dumpDataDir("gzip");
      const bytes = new Uint8Array(await dump.arrayBuffer());
      const envelope = await sealedState.seal(bytes, measurement, "embedded-agent-state");
      const temporary = `${sealedPath}.tmp`;
      writeFileSync(temporary, JSON.stringify(envelope), { mode: 0o600 });
      renameSync(temporary, sealedPath);
    });
  }
  console.log("[embedded] Database ready.");

  // Register PGLite as the backing database for getDb()/closeDb()
  setPGLiteOverride(db, () => client.close());

  // Now boot the API
  console.log("[embedded] Starting API server...");
  await import("./index");
}

main().catch((err) => {
  console.error("[embedded] Fatal error:", err);
  process.exit(1);
});
