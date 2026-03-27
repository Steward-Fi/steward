/**
 * Steward API — main entry point.
 *
 * Sets up global middleware, mounts route modules, and starts the server.
 * All route logic lives in `./routes/*`; shared state lives in `./services/context`.
 */

import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { logger } from "hono/logger";

import { correlationId } from "./middleware/correlation";
import { authRoutes } from "./routes/auth";
import { agentRoutes } from "./routes/agents";
import { platformRoutes } from "./routes/platform";
import { tenantRoutes } from "./routes/tenants";
import { userRoutes } from "./routes/user";
import { secretsRoutes } from "./routes/secrets";
import { vaultRoutes } from "./routes/vault";

import {
  API_VERSION,
  RATE_LIMIT_MAX_REQUESTS,
  RATE_LIMIT_WINDOW_MS,
  nonceCleanupTimer,
  tenantAuth,
  type AppVariables,
  type ApiResponse,
} from "./services/context";
import { closeDb } from "@stwd/db";
import { initRedis, shutdownRedis } from "./middleware/redis";

// ─── App setup ────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3200", 10);
const startTime = Date.now();

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
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  console.error(`[${requestId}] Unhandled API error:`, err);
  return c.json<ApiResponse>({ ok: false, error: "Internal server error" }, 500);
});

// ─── 404 fallback ─────────────────────────────────────────────────────────────

app.notFound((c) =>
  c.json<ApiResponse>({ ok: false, error: `Not found: ${c.req.method} ${c.req.path}` }, 404),
);

// ─── Global middleware ────────────────────────────────────────────────────────

app.use("*", cors({
  origin: "*",
  allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowHeaders: ["Content-Type", "X-Steward-Tenant", "X-Steward-Key", "X-Steward-Platform-Key", "Authorization"],
  exposeHeaders: ["Content-Length", "X-Request-Id"],
  maxAge: 86400,
}));
app.use("*", logger());
app.use("*", correlationId);

app.use("*", bodyLimit({
  maxSize: 1024 * 1024,
  onError: (c) => c.json<ApiResponse>({ ok: false, error: "Request body too large (max 1MB)" }, 413),
}));

// ─── Rate limiting + shutdown guard ───────────────────────────────────────────

app.use("*", async (c, next) => {
  if (c.req.path === "/health") return next();

  if (isShuttingDown) {
    return c.json<ApiResponse>({ ok: false, error: "Server is shutting down" }, 503);
  }

  const forwardedFor = c.req.header("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || c.req.header("x-real-ip") || "unknown";
  const now = Date.now();
  const current = requestLog.get(ip);

  if (!current || current.resetAt <= now) {
    requestLog.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (current.count >= RATE_LIMIT_MAX_REQUESTS) {
    c.header("Retry-After", Math.ceil((current.resetAt - now) / 1000).toString());
    return c.json<ApiResponse>({ ok: false, error: "Rate limit exceeded" }, 429);
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

// ─── Health & root ────────────────────────────────────────────────────────────

app.get("/", (c) => c.json({ name: "steward", version: API_VERSION, status: "running" }));
app.get("/health", (c) =>
  c.json({
    status: "ok",
    version: API_VERSION,
    uptime: Math.floor((Date.now() - startTime) / 1000),
  }),
);

// ─── Route modules ────────────────────────────────────────────────────────────

app.route("/auth", authRoutes);
app.route("/platform", platformRoutes);
app.route("/user", userRoutes);
app.route("/agents", agentRoutes);
app.route("/vault", vaultRoutes);
app.route("/secrets", secretsRoutes);
app.route("/tenants", tenantRoutes);

// ─── Server ───────────────────────────────────────────────────────────────────

// ─── Redis initialization (non-blocking) ─────────────────────────────────────

initRedis().catch((err) => {
  console.warn("[steward] Redis initialization failed, continuing without Redis:", err);
});

// ─── Server ───────────────────────────────────────────────────────────────────

const BIND_HOST = process.env.STEWARD_BIND_HOST || "127.0.0.1";

const server = Bun.serve({
  hostname: BIND_HOST,
  port: PORT,
  fetch: (request) => app.fetch(request),
  idleTimeout: 30,
});

const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}, shutting down Steward API`);

  server.stop(true);
  clearInterval(requestLogCleanupTimer);
  clearInterval(nonceCleanupTimer);
  requestLog.clear();

  try {
    await Promise.all([
      closeDb(),
      shutdownRedis(),
    ]);
  } catch (error) {
    console.error("Failed to close connections cleanly", error);
  }

  process.exit(0);
};

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

console.log(`Steward API running on ${server.hostname}:${server.port}`);
