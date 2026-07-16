import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __resetSecurityMetricsForTests,
  metricsTokenIsValid,
  observeSecurityAuditEvent,
  renderSecurityMetrics,
  securityMetricsEnabled,
} from "../security-metrics";

describe("bounded security metrics", () => {
  beforeEach(() => __resetSecurityMetricsForTests());
  afterEach(() => __resetSecurityMetricsForTests());

  test("real typed audit events increment only bounded labels", () => {
    observeSecurityAuditEvent("provider.execution.succeeded", {});
    observeSecurityAuditEvent("provider.execution.outcome_unknown", {});
    observeSecurityAuditEvent("provider.action.denied", { reasonCode: "POLICY_HARD_DENY" });
    observeSecurityAuditEvent("provider.approval.decided", { decision: "denied" });
    const rendered = renderSecurityMetrics(1000);
    expect(rendered).toContain('outcome="succeeded"} 1');
    expect(rendered).toContain('outcome="outcome_unknown"} 1');
    expect(rendered).toContain('reason_class="policy"} 1');
    expect(rendered).toContain('decision="denied"} 1');
  });

  test("rejects arbitrary labels and never renders secret or PII canaries", () => {
    const canaries = ["sk_live_SUPERSECRET", "person@example.com", "tenant-123", "raw-custom-reason"];
    observeSecurityAuditEvent("provider.action.denied", {
      reasonCode: canaries[3],
      token: canaries[0],
      email: canaries[1],
      tenantId: canaries[2],
    });
    observeSecurityAuditEvent("provider.execution.attacker_label", { outcome: canaries[0] });
    const rendered = renderSecurityMetrics();
    for (const canary of canaries) expect(rendered).not.toContain(canary);
    expect(rendered).toContain('reason_class="other"} 1');
  });

  test("enablement is exact and token requires 32 characters", () => {
    expect(securityMetricsEnabled({ STEWARD_METRICS_ENABLED: "TRUE" })).toBe(false);
    expect(securityMetricsEnabled({ STEWARD_METRICS_ENABLED: "true" })).toBe(true);
    expect(metricsTokenIsValid("short", { STEWARD_METRICS_TOKEN: "short" })).toBe(false);
    const token = "a".repeat(32);
    expect(metricsTokenIsValid(token, { STEWARD_METRICS_TOKEN: token })).toBe(true);
    expect(metricsTokenIsValid(`${token}x`, { STEWARD_METRICS_TOKEN: token })).toBe(false);
  });
});
