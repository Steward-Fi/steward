/**
 * Steward API Proxy Gateway
 *
 * Sits between agent containers and external APIs.
 * Agents send requests here; the proxy authenticates via JWT,
 * looks up credential routes, decrypts + injects credentials,
 * and forwards the request to the real API.
 *
 * Runs as a separate process from the main Steward API.
 *
 * Usage:
 *   STEWARD_MASTER_PASSWORD=xxx STEWARD_PROXY_PORT=8080 bun run src/index.ts
 */

import { validateJwtSecretEnv } from "@stwd/auth";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { PROXY_PORT } from "./config";
import { getAliasNames } from "./handlers/alias";
import { initProxyRedis, shutdownProxyRedis } from "./middleware/redis-enforcement";

// ─── Ensure DB is initialised ────────────────────────────────────────────────

import { createDb, getDatabaseUrl, getDb } from "@stwd/db";
import { assertProxyRlsReady } from "./startup-rls";

validateJwtSecretEnv();

const dbUrl = getDatabaseUrl();
if (!dbUrl) {
  console.error("⛔ DATABASE_URL is required");
  process.exit(1);
}
createDb(dbUrl);
try {
  await assertProxyRlsReady(getDb());
} catch (error) {
  console.error("⛔ Tenant RLS readiness failed", redactedThrownDiagnostics(error));
  process.exit(1);
}

// Import the route graph only after the database role/catalog gate succeeds.
// Keeping this dynamic also prevents test-order cycles from observing the
// server's default export before its top-level startup has completed.
const { default: app } = await import("./app");

// ─── Start ───────────────────────────────────────────────────────────────────

// ─── Redis initialization (non-blocking) ─────────────────────────────────────

initProxyRedis().catch((err) => {
  console.warn(
    "[proxy] Redis initialization failed, continuing without Redis",
    redactedThrownDiagnostics(err),
  );
});

// ─── Graceful shutdown ────────────────────────────────────────────────────────

const shutdownProxy = async (signal: string) => {
  console.log(`[proxy] Received ${signal}, shutting down...`);
  await shutdownProxyRedis();
  process.exit(0);
};

process.on("SIGINT", () => void shutdownProxy("SIGINT"));
process.on("SIGTERM", () => void shutdownProxy("SIGTERM"));

console.log(`🔀 Steward Proxy Gateway starting on :${PROXY_PORT}`);
console.log(`   Aliases: ${getAliasNames().join(", ")}`);
console.log(`   Health:  http://localhost:${PROXY_PORT}/health`);

export default {
  port: PROXY_PORT,
  fetch: app.fetch,
};
