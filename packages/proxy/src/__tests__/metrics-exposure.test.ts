/**
 * Proxy /metrics exposure guard.
 *
 * The opt-in operator metrics endpoint must be disabled by default AND, while
 * disabled, be INDISTINGUISHABLE from any other unrouted path. The proxy runs
 * authMiddleware as its catch-all, so every unauthenticated request to an
 * unknown path returns a 401. If disabled /metrics emitted its own 404 instead,
 * an unauthenticated attacker could fingerprint the endpoint's existence by the
 * anomalous status/body. This test locks the no-fingerprint property (the
 * disabled handler falls through via next()), and that a valid operator token
 * still scrapes metrics once enabled.
 */
import { beforeEach, describe, expect, test } from "bun:test";

const TOKEN = "operator-metrics-token-32-characters-minimum";

beforeEach(() => {
  delete process.env.STEWARD_METRICS_ENABLED;
  delete process.env.STEWARD_METRICS_TOKEN;
});

describe("proxy /metrics exposure guard", () => {
  test("disabled /metrics is byte-identical to an unknown path (no fingerprint)", async () => {
    const mod = await import("../app.ts");
    const app = mod.default as { fetch: (r: Request) => Promise<Response> };

    const metrics = await app.fetch(new Request("http://proxy.local/metrics"));
    const unknown = await app.fetch(new Request("http://proxy.local/definitely-not-a-route"));

    const metricsBody = await metrics.text();
    const unknownBody = await unknown.text();

    // Same status AND same body: the disabled endpoint reveals nothing.
    expect(metrics.status).toBe(unknown.status);
    expect(metricsBody).toBe(unknownBody);
    // Sanity: the shared behavior is the auth catch-all (401), never a 404 that
    // would betray the route's existence.
    expect(metrics.status).toBe(401);
  });

  test("enabled + valid operator token renders metrics; missing token is rejected", async () => {
    process.env.STEWARD_METRICS_ENABLED = "true";
    process.env.STEWARD_METRICS_TOKEN = TOKEN;
    const mod = await import("../app.ts");
    const app = mod.default as { fetch: (r: Request) => Promise<Response> };

    const authed = await app.fetch(
      new Request("http://proxy.local/metrics", {
        headers: { Authorization: `Bearer ${TOKEN}` },
      }),
    );
    expect(authed.status).toBe(200);
    expect(authed.headers.get("content-type")).toContain("text/plain");
    const body = await authed.text();
    expect(body).toContain("steward_governed_executions_total");

    const noToken = await app.fetch(new Request("http://proxy.local/metrics"));
    expect(noToken.status).toBe(401);

    const wrongToken = await app.fetch(
      new Request("http://proxy.local/metrics", {
        headers: { Authorization: "Bearer wrong" },
      }),
    );
    expect(wrongToken.status).toBe(401);
  });
});
