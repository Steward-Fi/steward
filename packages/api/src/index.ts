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

import { createHash, timingSafeEqual } from "node:crypto";
import { validateJwtSecretEnv } from "@stwd/auth";
import {
  assessMigrationLedger,
  closeDb,
  getDb,
  getMigrationExpectation,
  getMigrationLedgerExpectation,
  runMigrations,
} from "@stwd/db";
import { shouldUsePGLite } from "@stwd/db/pglite";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { composeApp } from "./compose";
import { getRedisClient, initRedis, isRedisConfigured, shutdownRedis } from "./middleware/redis";
import { resolveEnabledPlugins } from "./plugin-config";
import { assertAuthStoresAreSafe, getAuthStoreSources, initAuthStores } from "./routes/auth";
import {
  API_VERSION,
  type ApiResponse,
  nonceCleanupTimer,
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
} from "./services/context";
import { startGoogleCredentialLifecycleScheduler } from "./services/provider-google-lifecycle-scheduler";
import { startProviderReservationReconciliationScheduler } from "./services/provider-reservation-reconciliation-scheduler";
import { startXCredentialLifecycleScheduler } from "./services/provider-x-lifecycle-scheduler";
import { startRetentionScheduler } from "./services/retention";
import {
  InMemoryRateLimiter,
  parseNonNegativeInt,
  parsePositiveInt,
  resolveClientIp,
  SOCKET_PEER_ENV_KEY,
} from "./services/runtime-gate";
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
const migrationExpectation = getMigrationExpectation();
const migrationLedgerExpectation = getMigrationLedgerExpectation();
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

// ─── In-memory rate-limit log + shutdown guard ───────────────────────────────
//
// NOT used by the Workers entry — the Workers runtime mounts the shared
// Redis-backed sliding-window limiter across all routes instead (SEC-068,
// see middleware/global-rate-limit.ts, gated on isWorkersRuntime in app.ts).
//
// SEC-014: the limiter keys on the socket peer unless the operator declares
// STEWARD_TRUSTED_PROXY_HOPS > 0, in which case the client IP is derived from
// the rightmost trusted XFF entries (client-supplied XFF prefixes are never
// trusted). The key space is capped and fails closed when full.

const trustedProxyHops = parseNonNegativeInt(process.env.STEWARD_TRUSTED_PROXY_HOPS, 0);
const rateLimiter = new InMemoryRateLimiter(
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
  parsePositiveInt(process.env.STEWARD_RATE_LIMIT_MAX_KEYS, 10_000),
);
let isShuttingDown = false;
let cancelRetention: (() => void) | undefined;
let cancelProviderReservationReconciliation: (() => void) | undefined;
let cancelTransactionReceiptPolling: (() => void) | undefined;
let cancelWebhookRetryScheduler: (() => void) | undefined;
let cancelUpstreamCredentialLeaseScheduler: (() => Promise<void>) | undefined;
let cancelGoogleCredentialLifecycleScheduler: (() => Promise<void>) | undefined;
let cancelXCredentialLifecycleScheduler: (() => Promise<void>) | undefined;

function runtimeGate(request: Request, peerAddress: string | null): Response | null {
  const url = new URL(request.url);
  if (url.pathname === "/health" || url.pathname === "/ready") return null;

  if (isShuttingDown) {
    return Response.json({ ok: false, error: "Server is shutting down" } satisfies ApiResponse, {
      status: 503,
    });
  }

  const ip = resolveClientIp(request.headers, peerAddress, trustedProxyHops);
  const verdict = rateLimiter.check(ip);
  if (verdict.limited) {
    return Response.json({ ok: false, error: "Rate limit exceeded" } satisfies ApiResponse, {
      status: 429,
      headers: { "Retry-After": verdict.retryAfterSeconds.toString() },
    });
  }
  return null;
}

const requestLogCleanupTimer = setInterval(() => {
  rateLimiter.sweep();
}, RATE_LIMIT_WINDOW_MS);

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
// X-Steward-Probe-Token to receive the full diagnostic detail.

function readyProbeAuthorized(presented: string | undefined): boolean {
  const expected = process.env.STEWARD_READY_PROBE_TOKEN;
  if (!expected || !presented) return false;
  const a = createHash("sha256").update(expected).digest();
  const b = createHash("sha256").update(presented).digest();
  return timingSafeEqual(a, b);
}

app.get("/ready", async (c) => {
  const checks: Record<
    string,
    { ok: boolean; required?: boolean; error?: string; source?: string; detail?: unknown }
  > = {};

  checks.migrations = { ok: false, detail: { expected: migrationExpectation.tag } };

  try {
    const db = getDb();
    const pglite = shouldUsePGLite();
    const result = pglite
      ? await db.execute(sql`
          SELECT
            EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000 AS database_time_ms,
            EXISTS(
              SELECT 1 FROM __steward_migrations WHERE tag = ${migrationExpectation.tag}
            ) AS expected_migration_applied
        `)
      : await db.execute(sql`
          SELECT
            EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS database_time_ms,
            migrations.hash AS migration_hash,
            migrations.created_at AS migration_created_at
          FROM (SELECT 1) AS singleton
          LEFT JOIN LATERAL (
            SELECT hash, created_at
            FROM drizzle.__drizzle_migrations
            ORDER BY id ASC
          ) AS migrations ON TRUE
        `);
    const rows = Array.isArray(result)
      ? result
      : ((result as unknown as { rows?: unknown[] }).rows ?? []);
    const row = rows[0] as
      | {
          database_time_ms?: string | number;
          migration_hash?: unknown;
          migration_created_at?: string | number | null;
        }
      | undefined;
    const databaseTimeMs = Number(row?.database_time_ms);
    const expectedMigrationApplied =
      (row as { expected_migration_applied?: unknown } | undefined)?.expected_migration_applied ===
      true;
    const migrationLedger = pglite
      ? []
      : rows
          .map((resultRow) => resultRow as Record<string, unknown>)
          .filter(
            (resultRow) =>
              (resultRow.migration_hash !== null && resultRow.migration_hash !== undefined) ||
              (resultRow.migration_created_at !== null &&
                resultRow.migration_created_at !== undefined),
          )
          .map((resultRow) => ({
            hash: resultRow.migration_hash,
            createdAt: resultRow.migration_created_at,
          }));
    const migrationReadiness = pglite
      ? undefined
      : assessMigrationLedger(migrationLedger, migrationLedgerExpectation.entries);
    const databaseSkewMs = Math.abs(Date.now() - databaseTimeMs);
    checks.database = {
      ok: Number.isFinite(databaseTimeMs) && databaseSkewMs <= 30_000,
      detail: { clockSkewMs: Math.round(databaseSkewMs), serverTime: new Date().toISOString() },
    };
    checks.migrations = {
      ok: migrationsRan && (pglite ? expectedMigrationApplied : migrationReadiness?.ok === true),
      detail: {
        expected: migrationExpectation.tag,
        expectedCreatedAt: migrationExpectation.createdAt,
        ...(pglite
          ? { expectedMigrationApplied }
          : {
              actualCreatedAt:
                migrationLedger.length > 0
                  ? Math.max(...migrationLedger.map((entry) => Number(entry.createdAt))) || null
                  : null,
              ledgerState: migrationReadiness?.state ?? "corrupt",
              actualCount: migrationReadiness?.actualCount ?? 0,
              forwardCount: migrationReadiness?.forwardCount ?? 0,
            }),
      },
    };
  } catch {
    checks.database = { ok: false, error: "Database health check failed" };
  }

  try {
    const redis = getRedisClient();
    checks.redis = redis
      ? { ok: (await redis.ping()).toUpperCase() === "PONG" }
      : isRedisConfigured()
        ? { ok: false, error: "Redis is configured but not connected" }
        : { ok: false, required: false, error: "Redis is not configured (optional mode)" };
  } catch {
    checks.redis = { ok: false, error: "Redis health check failed" };
  }

  const proxyUrl = process.env.STEWARD_PROXY_URL?.replace(/\/+$/, "");
  if (!proxyUrl) {
    checks.proxyClock = {
      ok: false,
      required: false,
      error: "STEWARD_PROXY_URL not configured",
    };
  } else {
    try {
      const startedAt = Date.now();
      const response = await fetch(`${proxyUrl}/health`, { signal: AbortSignal.timeout(3_000) });
      const body = (await response.json()) as { serverTime?: unknown };
      const endedAt = Date.now();
      const proxyTime = Date.parse(String(body.serverTime ?? ""));
      const midpoint = startedAt + (endedAt - startedAt) / 2;
      const skewMs = Math.abs(proxyTime - midpoint);
      checks.proxyClock = {
        ok: response.ok && Number.isFinite(proxyTime) && skewMs <= 30_000,
        detail: { clockSkewMs: Math.round(skewMs) },
      };
    } catch {
      checks.proxyClock = { ok: false, error: "Proxy health check failed" };
    }
  }

  if (!process.env.STEWARD_MASTER_PASSWORD) {
    checks.vault = { ok: false, error: "STEWARD_MASTER_PASSWORD not set" };
  } else {
    checks.vault = { ok: true };
  }

  const storeSources = getAuthStoreSources();
  const memoryAuthStores = Object.entries(storeSources)
    .filter(([, source]) => source === "memory")
    .map(([name]) => name);
  const memoryAuthStoresAllowed =
    process.env.STEWARD_ALLOW_MEMORY_AUTH_STORES === "true" ||
    process.env.NODE_ENV !== "production";
  checks.authStores = {
    ok: memoryAuthStores.length === 0 || memoryAuthStoresAllowed,
    source: Object.entries(storeSources)
      .map(([name, source]) => `${name}:${source}`)
      .join(","),
    ...(memoryAuthStores.length > 0 && !memoryAuthStoresAllowed
      ? { error: `Production auth stores using memory: ${memoryAuthStores.join(", ")}` }
      : {}),
  };

  if (capabilitiesEnabled) {
    const health = getUpstreamCredentialLeaseSchedulerHealth();
    checks.upstreamCredentialLeases = {
      ok: health.ok,
      detail: {
        enabled: health.enabled,
        inFlight: health.inFlight,
        lastStartedAt: health.lastStartedAt,
        lastSucceededAt: health.lastSucceededAt,
        lastFailedAt: health.lastFailedAt,
      },
      ...(health.lastError ? { error: health.lastError } : {}),
    };
  }

  const allOk = Object.values(checks).every((check) => check.ok || check.required === false);
  const verbose = readyProbeAuthorized(c.req.header("x-steward-probe-token"));
  const publicChecks = Object.fromEntries(
    Object.entries(checks).map(([name, check]) => [
      name,
      { ok: check.ok, ...(check.required === false ? { required: false } : {}) },
    ]),
  );
  return c.json(
    {
      status: allOk ? "ready" : "not_ready",
      version: API_VERSION,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      checks: verbose ? checks : publicChecks,
    },
    allOk ? 200 : 503,
  );
});

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

    // Plugin-owned migrations (Phase 2c): applied AFTER the core migrator so a
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
    return (
      runtimeGate(request, peerAddress) ??
      app.fetch(request, { [SOCKET_PEER_ENV_KEY]: peerAddress })
    );
  },
  idleTimeout: 30,
} as Parameters<typeof Bun.serve>[0] & { hostname?: string };

const server = Bun.serve(serverOptions);

const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  clearInterval(requestLogCleanupTimer);
  if (nonceCleanupTimer) clearInterval(nonceCleanupTimer);
  if (cancelRetention) cancelRetention();
  if (cancelProviderReservationReconciliation) cancelProviderReservationReconciliation();
  if (cancelTransactionReceiptPolling) cancelTransactionReceiptPolling();
  if (cancelWebhookRetryScheduler) cancelWebhookRetryScheduler();
  if (cancelUpstreamCredentialLeaseScheduler) await cancelUpstreamCredentialLeaseScheduler();
  if (cancelGoogleCredentialLifecycleScheduler) await cancelGoogleCredentialLifecycleScheduler();
  if (cancelXCredentialLifecycleScheduler) await cancelXCredentialLifecycleScheduler();
  rateLimiter.clear();

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
