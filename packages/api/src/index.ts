/**
 * Steward API — main entry point.
 *
 * Sets up global middleware, mounts route modules, and starts the server.
 * All route logic lives in `./routes/*`; shared state lives in `./services/context`.
 */

import { closeDb, getDb, runMigrations, shouldUsePGLite } from "@stwd/db";
import { sql } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { logger } from "hono/logger";
import { correlationId } from "./middleware/correlation";
import { initRedis, shutdownRedis } from "./middleware/redis";
import { tenantCors } from "./middleware/tenant-cors";
import { agentRoutes } from "./routes/agents";
import { approvalRoutes } from "./routes/approvals";
import { auditRoutes } from "./routes/audit";
import { authRoutes, initAuthStores } from "./routes/auth";
import { dashboardRoutes } from "./routes/dashboard";
import { discoveryRoutes, erc8004Routes } from "./routes/erc8004";
import { platformRoutes } from "./routes/platform";
import { policiesStandaloneRoutes } from "./routes/policies-standalone";
import { secretsRoutes } from "./routes/secrets";
import { tenantConfigRoutes } from "./routes/tenant-config";
import { tenantRoutes } from "./routes/tenants";
import { userRoutes } from "./routes/user";
import { vaultRoutes } from "./routes/vault";
import { webhookRoutes } from "./routes/webhooks";
import {
  API_VERSION,
  type ApiResponse,
  type AppVariables,
  dashboardAuthMiddleware,
  nonceCleanupTimer,
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
  tenantAuth,
} from "./services/context";

// ─── App setup ────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3200", 10);
const startTime = Date.now();
let migrationsRan = false;

if (!Number.isInteger(PORT) || PORT <= 0) {
  throw new Error("PORT must be a positive integer");
}

const app = new Hono<{ Variables: AppVariables }>();
const requestLog = new Map<string, { count: number; resetAt: number }>();
let isShuttingDown = false;

// ─── Global error handler ─────────────────────────────────────────────────────

app.onError((err, c) => {
  const requestId = c.get("requestId") || "unknown";

  if (err instanceof SyntaxError || err.message?.includes("JSON")) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid JSON in request body" },
      400,
    );
  }

  console.error(`[${requestId}] Unhandled API error:`, err);
  return c.json<ApiResponse>(
    { ok: false, error: "Internal server error" },
    500,
  );
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────

app.notFound((c) =>
  c.json<ApiResponse>(
    { ok: false, error: `Not found: ${c.req.method} ${c.req.path}` },
    404,
  ),
);

// ─── Global middleware ────────────────────────────────────────────────────────

app.use("*", tenantCors);
app.use("*", logger());
app.use("*", correlationId);

app.use(
  "*",
  bodyLimit({
    maxSize: 1024 * 1024,
    onError: (c) =>
      c.json<ApiResponse>(
        { ok: false, error: "Request body too large (max 1MB)" },
        413,
      ),
  }),
);

// ─── Rate limiting + shutdown guard ───────────────────────────────────────────

app.use("*", async (c, next) => {
  if (c.req.path === "/health" || c.req.path === "/ready") return next();

  if (isShuttingDown) {
    return c.json<ApiResponse>(
      { ok: false, error: "Server is shutting down" },
      503,
    );
  }

  const forwardedFor = c.req.header("x-forwarded-for");
  const ip =
    forwardedFor?.split(",")[0]?.trim() ||
    c.req.header("x-real-ip") ||
    "unknown";
  const now = Date.now();
  const current = requestLog.get(ip);

  if (!current || current.resetAt <= now) {
    requestLog.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    c.header(
      "Retry-After",
      Math.ceil((current.resetAt - now) / 1000).toString(),
    );
    return c.json<ApiResponse>(
      { ok: false, error: "Rate limit exceeded" },
      429,
    );
  }

  current.count += 1;
  requestLog.set(ip, current);
  return next();
});

const requestLogCleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of requestLog.entries()) {
    if (entry.resetAt <= now) requestLog.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS);

// ─── Auth middleware per route group ──────────────────────────────────────────

app.use("/agents", (c, next) => tenantAuth(c, next));
app.use("/agents/*", (c, next) => tenantAuth(c, next));
app.use("/vault/*", (c, next) => tenantAuth(c, next));
app.use("/secrets", (c, next) => tenantAuth(c, next));
app.use("/secrets/*", (c, next) => tenantAuth(c, next));
app.use("/tenants/:id", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
);
app.use("/tenants/:id/webhook", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
);
app.use("/tenants/:id/config", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
);
app.use("/tenants/:id/config/*", (c, next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") }),
);
app.use("/dashboard/*", (c, next) => dashboardAuthMiddleware(c, next));
app.use("/webhooks", (c, next) => tenantAuth(c, next));
app.use("/webhooks/*", (c, next) => tenantAuth(c, next));
app.use("/approvals", (c, next) => tenantAuth(c, next));
app.use("/approvals/*", (c, next) => tenantAuth(c, next));
app.use("/audit", (c, next) => tenantAuth(c, next));
app.use("/audit/*", (c, next) => tenantAuth(c, next));
app.use("/policies", (c, next) => tenantAuth(c, next));
app.use("/policies/*", (c, next) => tenantAuth(c, next));

// ─── Health & root ────────────────────────────────────────────────────────────

app.get("/", (c) =>
  c.json({ name: "steward", version: API_VERSION, status: "running" }),
);
app.get("/health", (c) =>
  c.json({
    status: "ok",
    version: API_VERSION,
    uptime: Math.floor((Date.now() - startTime) / 1000),
  }),
);

// /ready — deep readiness check for container orchestration (k8s, ECS, etc.)
// Returns 200 only when: database is reachable, migrations have run, vault is initialized.
// Use /health for liveness probes, /ready for readiness probes.
app.get("/ready", async (c) => {
  const checks: Record<string, { ok: boolean; error?: string }> = {};

  // 1. Migrations ran at startup
  checks.migrations = { ok: migrationsRan };

  // 2. Database connectivity
  try {
    const db = getDb();
    // A cheap query that exercises the connection without touching app tables
    await db.execute(sql`SELECT 1`);
    checks.database = { ok: true };
  } catch (err: any) {
    checks.database = { ok: false, error: err?.message ?? "unknown" };
  }

  // 3. Vault initialized (master password present and usable)
  try {
    if (!process.env.STEWARD_MASTER_PASSWORD) {
      checks.vault = { ok: false, error: "STEWARD_MASTER_PASSWORD not set" };
    } else {
      checks.vault = { ok: true };
    }
  } catch (err: any) {
    checks.vault = { ok: false, error: err?.message ?? "unknown" };
  }

  const allOk = Object.values(checks).every((c) => c.ok);
  return c.json(
    {
      status: allOk ? "ready" : "not_ready",
      version: API_VERSION,
      uptime: Math.floor((Date.now() - startTime) / 1000),
      checks,
    },
    allOk ? 200 : 503,
  );
});

// ─── Route modules ────────────────────────────────────────────────────────────

app.route("/auth", authRoutes);
app.route("/platform", platformRoutes);
app.route("/user", userRoutes);
app.route("/agents", agentRoutes);
app.route("/vault", vaultRoutes);
app.route("/secrets", secretsRoutes);
app.route("/tenants", tenantRoutes);
app.route("/tenants", tenantConfigRoutes);
app.route("/dashboard", dashboardRoutes);
app.route("/webhooks", webhookRoutes);
app.route("/approvals", approvalRoutes);
app.route("/audit", auditRoutes);
app.route("/policies", policiesStandaloneRoutes);
app.route("/agents", erc8004Routes);
app.route("/discovery", discoveryRoutes);

// ─── Database migrations (blocking — must complete before serving traffic) ───

if (shouldUsePGLite()) {
  migrationsRan = true;
  console.log("[steward] PGLite mode detected — skipping Postgres migrator.");
} else if (
  process.env.SKIP_MIGRATIONS === "true" ||
  process.env.SKIP_MIGRATIONS === "1"
) {
  migrationsRan = true;
  console.log(
    "[steward] SKIP_MIGRATIONS set — skipping auto-migration. Run migrations manually.",
  );
} else {
  try {
    console.log("[steward] Running database migrations...");
    await runMigrations();
    migrationsRan = true;
    console.log("[steward] Migrations complete.");
  } catch (err) {
    console.error("[steward] Migration failed — cannot start:", err);
    process.exit(1);
  }
}

// ─── Redis + auth store initialization (non-blocking) ───────────────────────

initRedis()
  .then((redisOk) => {
    // Initialize auth stores after Redis availability is known.
    // usePostgres=true when migrations have run, so auth_kv_store table exists.
    const usePostgres = migrationsRan && !redisOk;
    return initAuthStores(usePostgres);
  })
  .catch((err) => {
    console.warn(
      "[steward] Redis/auth store initialization failed, using in-memory stores:",
      err,
    );
    initAuthStores(false).catch(() => {});
  });

// ─── Server ───────────────────────────────────────────────────────────────────

const BIND_HOST = process.env.STEWARD_BIND_HOST || "127.0.0.1";

const serverOptions = {
  hostname: BIND_HOST,
  port: PORT,
  fetch: (request) => app.fetch(request),
  idleTimeout: 30,
} as Parameters<typeof Bun.serve>[0] & { hostname?: string };

const server = Bun.serve(serverOptions);

const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  clearInterval(requestLogCleanupTimer);
  clearInterval(nonceCleanupTimer);
  requestLog.clear();

  try {
    await Promise.all([closeDb(), shutdownRedis()]);
  } catch (error) {
    console.error("Failed to close connections cleanly", error);
  }

  process.exit(0);
};

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

console.log(`Steward API running on ${BIND_HOST}:${server.port}`);
