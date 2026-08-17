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
import { metricsTokenIsValid, renderSecurityMetrics, securityMetricsEnabled } from "@stwd/shared";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { PROXY_PORT } from "./config";
import { getAliasNames } from "./handlers/alias";
import { handleProxy } from "./handlers/proxy";
import { handlePendingProxyRequest, listPendingProxyRequests } from "./handlers/release";
import { authMiddleware } from "./middleware/auth";
import { initProxyRedis, shutdownProxyRedis } from "./middleware/redis-enforcement";

// ─── Ensure DB is initialised ────────────────────────────────────────────────

import { createDb, getDatabaseUrl } from "@stwd/db";

validateJwtSecretEnv();

const dbUrl = getDatabaseUrl();
if (!dbUrl) {
  console.error("⛔ DATABASE_URL is required");
  process.exit(1);
}
createDb(dbUrl);

// ─── App ─────────────────────────────────────────────────────────────────────

const app = new Hono();

// SEC-174: agents are server-side callers, so CORS is OFF by default — a
// wildcard origin lets any website drive unauthenticated probes (and use a
// leaked token cross-origin from browser JS). Set STEWARD_PROXY_CORS_ORIGINS
// (comma-separated) only if a browser client genuinely needs cross-origin
// access.
const corsOrigins = (process.env.STEWARD_PROXY_CORS_ORIGINS ?? "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
if (corsOrigins.length > 0) {
  app.use("*", cors({ origin: corsOrigins }));
}

// ─── Health check (unauthenticated) ──────────────────────────────────────────

// SEC-174: keep the unauthenticated response minimal — no service version or
// alias list (recon details). The API readiness probe only reads serverTime.
app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "steward-proxy",
    serverTime: new Date().toISOString(),
  }),
);

// ─── Opt-in operator metrics (separate token, disabled by default) ────────────

app.get("/metrics", (c, next) => {
  // Disabled is the default. Fall THROUGH to the normal auth + proxy pipeline
  // (return next()) rather than emitting a distinctive 404 here, so a disabled
  // /metrics is byte-identical to any other unrouted path (the proxy's catch-all
  // runs authMiddleware first, so an unauthenticated probe of /metrics gets the
  // exact same 401 as an unauthenticated probe of any random path). Emitting a
  // 404 only from here would fingerprint the endpoint's existence to an
  // unauthenticated attacker, since every other path returns 401. This mirrors
  // the API side, where the disabled 404 is identical to the generic notFound.
  if (!securityMetricsEnabled()) return next();
  const authorization = c.req.header("Authorization");
  const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
  if (!metricsTokenIsValid(token)) {
    return c.json({ ok: false, error: "Metrics authentication required" }, 401);
  }
  try {
    return c.text(renderSecurityMetrics(), 200, {
      "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
      "Cache-Control": "no-store",
    });
  } catch {
    return c.json({ ok: false, error: "Metrics unavailable" }, 503);
  }
});

// ─── All other routes go through auth + proxy ────────────────────────────────

app.use("*", authMiddleware);
app.get("/approvals/proxy", listPendingProxyRequests);
app.get("/approvals/proxy/:id", handlePendingProxyRequest);
app.all("*", handleProxy);

// ─── Start ───────────────────────────────────────────────────────────────────

// ─── Redis initialization (non-blocking) ─────────────────────────────────────

initProxyRedis().catch((err) => {
  console.warn("[proxy] Redis initialization failed, continuing without Redis:", err);
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
