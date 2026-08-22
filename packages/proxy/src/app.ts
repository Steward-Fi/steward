import { metricsTokenIsValid, renderSecurityMetrics, securityMetricsEnabled } from "@stwd/shared";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { configuredProxyCorsOrigins } from "./config";
import { handleProxy } from "./handlers/proxy";
import { handlePendingProxyRequest, listPendingProxyRequests } from "./handlers/release";
import { authMiddleware } from "./middleware/auth";

export function createProxyApp() {
  const app = new Hono();
  const corsOrigins = configuredProxyCorsOrigins();
  if (corsOrigins.length > 0) app.use("*", cors({ origin: corsOrigins }));

  app.get("/health", (c) =>
    c.json({ ok: true, service: "steward-proxy", serverTime: new Date().toISOString() }),
  );
  app.get("/metrics", (c, next) => {
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

  app.use("*", authMiddleware);
  app.get("/approvals/proxy", listPendingProxyRequests);
  app.get("/approvals/proxy/:id", handlePendingProxyRequest);
  app.all("*", handleProxy);
  return app;
}

export default createProxyApp();
