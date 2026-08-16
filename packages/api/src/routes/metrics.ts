import { metricsTokenIsValid, renderSecurityMetrics, securityMetricsEnabled } from "@stwd/shared";
import { Hono } from "hono";

export const metricsRoutes = new Hono();

metricsRoutes.get("/", (c) => {
  // Deliberately indistinguishable from an absent route unless explicitly
  // enabled. This guard is the primary endpoint exposure boundary.
  if (!securityMetricsEnabled()) {
    return c.json({ ok: false, error: "Not found: GET /metrics" }, 404);
  }

  const authorization = c.req.header("Authorization");
  const candidate = authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
  if (!metricsTokenIsValid(candidate)) {
    return c.json({ ok: false, error: "Metrics authentication required" }, 401, {
      "WWW-Authenticate": 'Bearer realm="steward-metrics"',
    });
  }

  try {
    return c.text(renderSecurityMetrics(), 200, {
      "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
      "Cache-Control": "no-store",
    });
  } catch {
    // Export failure is isolated from all governed action paths.
    return c.json({ ok: false, error: "Metrics unavailable" }, 503);
  }
});
