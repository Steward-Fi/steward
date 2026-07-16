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

// CORS — allow all origins for now (agents call from Docker network)
app.use("*", cors());

// ─── Health check (unauthenticated) ──────────────────────────────────────────

app.get("/health", (c) =>
  c.json({
    ok: true,
    service: "steward-proxy",
    version: "0.3.0",
    aliases: getAliasNames(),
  }),
);

// ─── Opt-in operator metrics (separate token, disabled by default) ────────────

app.get("/metrics", (c) => {
  if (!securityMetricsEnabled()) return c.json({ ok: false, error: "Not found" }, 404);
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
