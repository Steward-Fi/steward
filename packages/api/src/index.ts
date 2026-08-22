/**
 * Steward API — Bun entry point.
 *
 * The Hono application itself lives in `./app.ts` so the same routes can be
 * served by other runtimes (Cloudflare Workers, Electrobun embedded). This
 * file only contains code that needs a long-lived Node/Bun process:
 *
 *   - The in-memory IP rate-limit log (only safe in single-process mode)
 *   - `setInterval` GC for expired entries
 *   - The blocking `runMigrations()` call at boot
 *   - The /ready readiness probe (depends on migration state + DB ping)
 *   - `Bun.serve` plus SIGINT/SIGTERM graceful shutdown
 */

import { validateJwtSecretEnv } from "@stwd/auth";
import {
  assertRlsDeploymentSafety,
  closeDb,
  getDb,
  getMigrationExpectation,
  runMigrations,
} from "@stwd/db";
import { shouldUsePGLite } from "@stwd/db/pglite";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { composeApp } from "./compose";
import { globalRateLimitRequiresRedis } from "./middleware/global-rate-limit";
import {
  getRedisClient,
  initRedis,
  isRedisConfigured,
  redisEnforcementRequiresDurability,
  shutdownRedis,
} from "./middleware/redis";
import { resolveEnabledPlugins } from "./plugin-config";
import { createReadinessHandler, type ReadinessCheck } from "./readiness";
import { assertAuthStoresAreSafe, getAuthStoreSources, initAuthStores } from "./routes/auth";
import { startAccountWalletLifecycleRecoveryScheduler } from "./services/account-wallet-lifecycle";
import { checkCapabilityRateLimitReadiness } from "./services/capability-rate-limit-readiness";
import { API_VERSION, type ApiResponse } from "./services/context";
import { startGoogleCredentialLifecycleScheduler } from "./services/provider-google-lifecycle-scheduler";
import { startProviderReservationReconciliationScheduler } from "./services/provider-reservation-reconciliation-scheduler";
import { startXCredentialLifecycleScheduler } from "./services/provider-x-lifecycle-scheduler";
import { startRetentionScheduler } from "./services/retention";
import { SOCKET_PEER_ENV_KEY } from "./services/runtime-gate";
import { startTransactionReceiptPollingScheduler } from "./services/transaction-receipt-poller";
import {
  getUpstreamCredentialLeaseSchedulerHealth,
  startUpstreamCredentialLeaseScheduler,
} from "./services/upstream-credential-lease-scheduler";
import { configuredVaultStartupLogLine, getConfiguredVault } from "./services/vault-factory";
import { startWebhookRetryScheduler } from "./services/webhook-retry-scheduler";

// ─── Constants ────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3200", 10);
const startTime = Date.now();
let migrationsRan = false;

if (!Number.isInteger(PORT) || PORT <= 0) {
  throw new Error("PORT must be a positive integer");
}
validateJwtSecretEnv();

// Compose the deployable app: lean core + this repo's opt-in plugins (trading).
// composeApp() is async because plugin registration may be async + the trading
// plugin is dynamically imported so the lean core graph never statically pulls
// in the trading stack. top-level await is supported by the Bun entry.
const app = await composeApp();
const capabilitiesEnabled = resolveEnabledPlugins().has("capabilities");

// ─── Shutdown guard ──────────────────────────────────────────────────────────
let isShuttingDown = false;
let cancelRetention: (() => void) | undefined;
let cancelProviderReservationReconciliation: (() => void) | undefined;
let cancelTransactionReceiptPolling: (() => void) | undefined;
let cancelWebhookRetryScheduler: (() => void) | undefined;
let cancelUpstreamCredentialLeaseScheduler: (() => Promise<void>) | undefined;
let cancelGoogleCredentialLifecycleScheduler: (() => Promise<void>) | undefined;
let cancelXCredentialLifecycleScheduler: (() => Promise<void>) | undefined;
let cancelAccountWalletLifecycleRecoveryScheduler: (() => Promise<void>) | undefined;

function runtimeGate(): Response | null {
  if (isShuttingDown) {
    return Response.json({ ok: false, error: "Server is shutting down" } satisfies ApiResponse, {
      status: 503,
    });
  }

  return null;
}

// ─── /ready — deep readiness probe ───────────────────────────────────────────
//
// Only mounted on the Bun entry. Workers expose `/health` (in app.ts) and rely
// on the Cloudflare control plane for instance health.
//
// SEC-071: the full check payload discloses deployment fingerprint details
// (migration tags, auth-store/Redis backend identity, whether
// STEWARD_MASTER_PASSWORD is set, DB/proxy clock skew, error strings).
// Unauthenticated callers get the same 200/503 status plus per-check ok flags
// only; operators can set STEWARD_READY_PROBE_TOKEN and send it as
// X-Steward-Probe-Token to receive the full diagnostic detail. The handler
// policy lives in readiness.ts; this entrypoint supplies the production I/O.

app.get(
  "/ready",
  createReadinessHandler({
    apiVersion: API_VERSION,
    startedAt: startTime,
    environment: () => ({
      allowMemoryAuthStores: process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES === "true",
      probeToken: process.env.STEWARD_READY_PROBE_TOKEN,
      requiresDurableAuthStores:
        process.env.NODE_ENV === "production" || process.env.STEWARD_RUNTIME === "workers",
    }),
    checkDatabase: async () => {
      const checks: Record<string, ReadinessCheck> = {};
      const expectedMigration = getMigrationExpectation();
      checks.migrations = { ok: false, detail: { expected: expectedMigration.tag } };
      try {
        const db = getDb();
        const pglite = shouldUsePGLite();
        const result = pglite
          ? await db.execute(sql`
          SELECT
            EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000 AS database_time_ms,
            EXISTS(
              SELECT 1 FROM __steward_migrations WHERE tag = ${expectedMigration.tag}
            ) AS expected_migration_applied
        `)
          : await db.execute(sql`
          SELECT
            EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS database_time_ms,
            (SELECT MAX(created_at) FROM drizzle.__drizzle_migrations) AS migration_created_at
        `);
        const rows = Array.isArray(result)
          ? result
          : ((result as unknown as { rows?: unknown[] }).rows ?? []);
        const row = rows[0] as
          | { database_time_ms?: string | number; migration_created_at?: string | number | null }
          | undefined;
        const databaseTimeMs = Number(row?.database_time_ms);
        const migrationCreatedAt = Number(row?.migration_created_at);
        const expectedMigrationApplied =
          (row as { expected_migration_applied?: unknown } | undefined)
            ?.expected_migration_applied === true;
        const databaseSkewMs = Math.abs(Date.now() - databaseTimeMs);
        checks.database = {
          ok: Number.isFinite(databaseTimeMs) && databaseSkewMs <= 30_000,
          detail: { clockSkewMs: Math.round(databaseSkewMs), serverTime: new Date().toISOString() },
        };
        checks.migrations = {
          ok:
            migrationsRan &&
            (pglite
              ? expectedMigrationApplied
              : migrationCreatedAt === expectedMigration.createdAt),
          detail: {
            expected: expectedMigration.tag,
            expectedCreatedAt: expectedMigration.createdAt,
            ...(pglite
              ? { expectedMigrationApplied }
              : {
                  actualCreatedAt: Number.isFinite(migrationCreatedAt) ? migrationCreatedAt : null,
                }),
          },
        };
        if (process.env.NODE_ENV === "production") {
          const expectedRole = process.env.STEWARD_APP_DATABASE_ROLE;
          if (!expectedRole) throw new Error("STEWARD_APP_DATABASE_ROLE is required in production");
          await assertRlsDeploymentSafety(db, { expectedRole });
          checks.rlsDeployment = { ok: true };
        }
      } catch {
        checks.database = { ok: false, error: "Database health check failed" };
      }
      return checks;
    },
    checkRedis: async () => {
      const redisRequired = globalRateLimitRequiresRedis() || redisEnforcementRequiresDurability();
      try {
        const redis = getRedisClient();
        return redis
          ? { ok: (await redis.ping()).toUpperCase() === "PONG" }
          : isRedisConfigured()
            ? redisRequired
              ? { ok: false, error: "Redis is configured but not connected" }
              : {
                  ok: false,
                  required: false,
                  error: "Redis is configured but not connected (memory acknowledged)",
                }
            : redisRequired
              ? { ok: false, error: "Redis is required for durable production rate limiting" }
              : { ok: false, required: false, error: "Redis is not configured (optional mode)" };
      } catch {
        return redisRequired
          ? { ok: false, error: "Redis health check failed" }
          : { ok: false, required: false, error: "Redis health check failed (optional mode)" };
      }
    },
    checkProxyClock: async () => {
      const proxyUrl = process.env.STEWARD_PROXY_URL?.replace(/\/+$/, "");
      if (!proxyUrl) {
        return {
          ok: false,
          required: false,
          error: "STEWARD_PROXY_URL not configured",
        };
      }
      const startedAt = Date.now();
      const response = await fetch(`${proxyUrl}/health`, { signal: AbortSignal.timeout(3_000) });
      const body = (await response.json()) as { serverTime?: unknown };
      const endedAt = Date.now();
      const proxyTime = Date.parse(String(body.serverTime ?? ""));
      const midpoint = startedAt + (endedAt - startedAt) / 2;
      const skewMs = Math.abs(proxyTime - midpoint);
      return {
        ok: response.ok && Number.isFinite(proxyTime) && skewMs <= 30_000,
        detail: { clockSkewMs: Math.round(skewMs) },
      };
    },
    getAuthStoreSources,
    isVaultConfigured: () => Boolean(process.env.STEWARD_MASTER_PASSWORD),
    getAdditionalChecks: capabilitiesEnabled
      ? async () => {
          const health = getUpstreamCredentialLeaseSchedulerHealth();
          return {
            capabilityRateLimit: await checkCapabilityRateLimitReadiness(),
            upstreamCredentialLeases: {
              ok: health.ok,
              detail: {
                enabled: health.enabled,
                inFlight: health.inFlight,
                lastStartedAt: health.lastStartedAt,
                lastSucceededAt: health.lastSucceededAt,
                lastFailedAt: health.lastFailedAt,
              },
              ...(health.lastError ? { error: health.lastError } : {}),
            },
          };
        }
      : undefined,
  }),
);

// ─── Database migrations (blocking — must complete before serving traffic) ───

if (shouldUsePGLite()) {
  migrationsRan = true;
  console.log("[steward] PGLite mode detected — skipping Postgres migrator.");
} else if (process.env.SKIP_MIGRATIONS === "true" || process.env.SKIP_MIGRATIONS === "1") {
  migrationsRan = true;
  console.log("[steward] SKIP_MIGRATIONS set — skipping auto-migration. Run migrations manually.");
} else {
  try {
    console.log("[steward] Running database migrations...");
    const { applied } = await runMigrations();
    migrationsRan = true;
    if (applied.length > 0) {
      console.log(`[steward] Applied ${applied.length} migration(s): ${applied.join(", ")}`);
      const { writeAuditEvent } = await import("./services/audit");
      try {
        await writeAuditEvent({
          tenantId: "system",
          actorType: "system",
          action: "system.migration.applied",
          metadata: { count: applied.length, names: applied },
        });
      } catch (auditErr) {
        console.error(
          "[steward] Failed to record migration audit event",
          redactedThrownDiagnostics(auditErr),
        );
      }
    } else {
      console.log("[steward] Migrations already up to date.");
    }

    // Plugin-owned migrations are applied AFTER the core migrator so a
    // plugin migration may reference core tables via FK. Each plugin's migrations
    // land in its OWN namespaced bookkeeping table
    // (drizzle.__drizzle_migrations_plugin_<id>), totally isolated from the core's
    // drizzle.__drizzle_migrations journal. Fail-closed: a plugin migration error
    // aborts boot (we never half-boot with a partially-migrated plugin schema).
    const { runComposedPluginMigrations } = await import("./compose");
    const pluginResults = await runComposedPluginMigrations();
    if (pluginResults.length > 0) {
      console.log(
        `[steward] Applied plugin migrations: ${pluginResults
          .map((r) => `${r.pluginName}\u2192${r.migrationsTable}`)
          .join(", ")}`,
      );
    }
  } catch (err) {
    console.error("[steward] Migration failed — cannot start", redactedThrownDiagnostics(err));
    process.exit(1);
  }
}

if (process.env.NODE_ENV === "production" && !shouldUsePGLite()) {
  const expectedRole = process.env.STEWARD_APP_DATABASE_ROLE;
  if (!expectedRole) throw new Error("STEWARD_APP_DATABASE_ROLE is required in production");
  try {
    await assertRlsDeploymentSafety(getDb(), { expectedRole });
  } catch (error) {
    console.error(
      "[steward] RLS deployment safety assertion failed — cannot start",
      redactedThrownDiagnostics(error),
    );
    process.exit(1);
  }
}

// ─── Redis + auth stores (blocking — must complete before serving traffic) ──

let redisOk = false;
try {
  redisOk = await initRedis();
} catch (err) {
  console.warn(
    "[steward] Redis initialization failed; trying Postgres auth storage",
    redactedThrownDiagnostics(err),
  );
}

// Postgres is the durable fallback for the long-lived server when Redis is not
// available. buildBackend probes every namespace; the assertion below turns
// any production fallback to process-local memory into a startup failure.
await initAuthStores(migrationsRan && !redisOk);
assertAuthStoresAreSafe();

// ─── Data retention scheduler (SOC2 CC2) ────────────────────────────────────

if (migrationsRan) {
  cancelAccountWalletLifecycleRecoveryScheduler = startAccountWalletLifecycleRecoveryScheduler();
  if (process.env.GOOGLE_PROVIDER_CLIENT_ID && process.env.GOOGLE_PROVIDER_CLIENT_SECRET) {
    cancelGoogleCredentialLifecycleScheduler = startGoogleCredentialLifecycleScheduler();
  }
  if (process.env.X_CLIENT_ID && process.env.X_CLIENT_SECRET) {
    cancelXCredentialLifecycleScheduler = startXCredentialLifecycleScheduler();
  }
  cancelRetention = startRetentionScheduler();
  if (redisOk) {
    cancelProviderReservationReconciliation = startProviderReservationReconciliationScheduler();
  }
  cancelTransactionReceiptPolling = startTransactionReceiptPollingScheduler();
  cancelWebhookRetryScheduler = startWebhookRetryScheduler();
  if (capabilitiesEnabled) {
    cancelUpstreamCredentialLeaseScheduler = await startUpstreamCredentialLeaseScheduler();
  }
}

// Resolve custody before accepting traffic. A configured backend that cannot
// initialize throws here, so production never falls back to local AES.
getConfiguredVault();
console.log(configuredVaultStartupLogLine());

// ─── Server ───────────────────────────────────────────────────────────────────

const BIND_HOST = process.env.STEWARD_BIND_HOST || "127.0.0.1";

const serverOptions = {
  hostname: BIND_HOST,
  port: PORT,
  fetch: (request: Request, server: { requestIP(req: Request): { address: string } | null }) => {
    const peerAddress = server.requestIP(request)?.address ?? null;
    // Hand the runtime-observed socket peer to the app via Hono's env bag so
    // per-route limiters (auth) can key on it when no trusted forwarding
    // config exists — it cannot be client-influenced, unlike any header.
    return runtimeGate() ?? app.fetch(request, { [SOCKET_PEER_ENV_KEY]: peerAddress });
  },
  idleTimeout: 30,
} as Parameters<typeof Bun.serve>[0] & { hostname?: string };

const server = Bun.serve(serverOptions);

const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  if (cancelRetention) cancelRetention();
  if (cancelProviderReservationReconciliation) cancelProviderReservationReconciliation();
  if (cancelTransactionReceiptPolling) cancelTransactionReceiptPolling();
  if (cancelWebhookRetryScheduler) cancelWebhookRetryScheduler();
  if (cancelUpstreamCredentialLeaseScheduler) await cancelUpstreamCredentialLeaseScheduler();
  if (cancelGoogleCredentialLifecycleScheduler) await cancelGoogleCredentialLifecycleScheduler();
  if (cancelXCredentialLifecycleScheduler) await cancelXCredentialLifecycleScheduler();
  if (cancelAccountWalletLifecycleRecoveryScheduler) {
    await cancelAccountWalletLifecycleRecoveryScheduler();
  }

  try {
    await Promise.all([closeDb(), shutdownRedis()]);
  } catch (error) {
    console.error("Failed to close connections cleanly", redactedThrownDiagnostics(error));
  }

  process.exit(0);
};

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

console.log(`Steward API running on ${BIND_HOST}:${server.port}`);
