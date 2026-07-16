import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { __resetSecurityMetricsForTests, observeSecurityAuditEvent } from "@stwd/shared";
import app from "../app";

const savedEnabled = process.env.STEWARD_METRICS_ENABLED;
const savedToken = process.env.STEWARD_METRICS_TOKEN;
const token = "operator-metrics-token-32-characters-minimum";

afterEach(() => {
  if (savedEnabled === undefined) delete process.env.STEWARD_METRICS_ENABLED;
  else process.env.STEWARD_METRICS_ENABLED = savedEnabled;
  if (savedToken === undefined) delete process.env.STEWARD_METRICS_TOKEN;
  else process.env.STEWARD_METRICS_TOKEN = savedToken;
  __resetSecurityMetricsForTests();
});

beforeEach(() => {
  delete process.env.STEWARD_METRICS_ENABLED;
  delete process.env.STEWARD_METRICS_TOKEN;
});

describe("GET /metrics exposure guard", () => {
  test("is a 404 while disabled", async () => {
    const response = await app.request("/metrics");
    expect(response.status).toBe(404);
  });

  test("rejects missing and wrong operator tokens", async () => {
    process.env.STEWARD_METRICS_ENABLED = "true";
    process.env.STEWARD_METRICS_TOKEN = token;
    expect((await app.request("/metrics")).status).toBe(401);
    expect(
      (await app.request("/metrics", { headers: { Authorization: "Bearer wrong" } })).status,
    ).toBe(401);
  });

  test("returns Prometheus text without audit metadata", async () => {
    process.env.STEWARD_METRICS_ENABLED = "true";
    process.env.STEWARD_METRICS_TOKEN = token;
    observeSecurityAuditEvent("provider.execution.outcome_unknown", {
      token: "sk_live_NEVER_RENDER",
      email: "private@example.com",
    });
    const response = await app.request("/metrics", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    const body = await response.text();
    expect(body).toContain('outcome="outcome_unknown"} 1');
    expect(body).not.toContain("sk_live_NEVER_RENDER");
    expect(body).not.toContain("private@example.com");
  });
});
