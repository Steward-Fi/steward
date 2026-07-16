import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __resetSecurityMetricsForTests,
  __setSecurityMetricsObserverFailureForTests,
  classifyDenialReason,
  DENIAL_REASON_CLASSES,
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
    observeSecurityAuditEvent("provider.approval.decided", { toStatus: "approval_denied" });
    const rendered = renderSecurityMetrics(1000);
    expect(rendered).toContain('outcome="succeeded"} 1');
    expect(rendered).toContain('outcome="outcome_unknown"} 1');
    expect(rendered).toContain('reason_class="policy"} 1');
    expect(rendered).toContain('decision="denied"} 1');
  });

  test("rejects arbitrary labels and never renders secret or PII canaries", () => {
    const canaries = [
      "sk_live_SUPERSECRET",
      "person@example.com",
      "tenant-123",
      "raw-custom-reason",
    ];
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

  test("hostile values in reasons, provider names, and error strings never mint a label", () => {
    // Canaries injected through EVERY field the denial classifier reads, plus a
    // wholly-unknown reason code, must all collapse to the bounded "other" class
    // and never surface verbatim in the scrape output.
    const canaries = [
      "DROP TABLE audit_events",
      "sk_live_LEAK",
      "attacker.example.com",
      'reason_class="injected"} 999',
      "\n# HELP forged_metric injected\nforged_metric 1",
    ];
    observeSecurityAuditEvent("provider.action.denied", {
      reasonCode: canaries[0],
      accessReasonCode: canaries[1],
      policyReasonCodes: [canaries[2]],
      provider: canaries[3],
    });
    observeSecurityAuditEvent("provider.execution.denied_at_boundary", {
      reasonCode: canaries[4],
      error: canaries[1],
    });
    // A hostile approval decision string must not mint a decision label either.
    observeSecurityAuditEvent("provider.approval.decided", { decision: canaries[3] });
    const rendered = renderSecurityMetrics();
    for (const canary of canaries) expect(rendered).not.toContain(canary);
    // No injected metric line, no forged label — the render is a fixed catalog.
    expect(rendered).not.toContain("forged_metric");
    expect(rendered).not.toContain('reason_class="injected"');
    // Every rendered reason_class label is a member of the compile-time set.
    const reasonLabels = [...rendered.matchAll(/reason_class="([^"]*)"/g)].map((m) => m[1]);
    for (const label of reasonLabels)
      expect((DENIAL_REASON_CLASSES as readonly string[]).includes(label)).toBe(true);
  });

  test("classifyDenialReason always returns a bounded class for any input", () => {
    const inputs: unknown[] = [
      undefined,
      null,
      42,
      {},
      [],
      "",
      "totally-unknown-reason",
      "POLICY_HARD_DENY",
      "SCOPE_MISSING",
      "EXEC_AUTH_STALE_ROUTE",
    ];
    for (const input of inputs)
      expect(
        (DENIAL_REASON_CLASSES as readonly string[]).includes(classifyDenialReason(input)),
      ).toBe(true);
  });

  test("a throwing observer never propagates through the isolated call site", () => {
    // The db/proxy post-commit hooks wrap observeSecurityAuditEvent in try/catch.
    // Prove the throw is real (so the isolation wrap is load-bearing) and that a
    // caller who wraps it, like the real hook sites do, is unaffected.
    __setSecurityMetricsObserverFailureForTests(true);
    expect(() => observeSecurityAuditEvent("provider.execution.succeeded", {})).toThrow();
    let survived = false;
    try {
      observeSecurityAuditEvent("provider.execution.succeeded", {});
    } catch {
      survived = true;
    }
    expect(survived).toBe(true);
    __setSecurityMetricsObserverFailureForTests(false);
    // After clearing the fault, the counter path works again and stays bounded.
    observeSecurityAuditEvent("provider.execution.succeeded", {});
    expect(renderSecurityMetrics()).toContain('outcome="succeeded"} 1');
  });

  test("enablement is exact and token requires 32 characters", () => {
    expect(securityMetricsEnabled({ STEWARD_METRICS_ENABLED: "TRUE" })).toBe(false);
    expect(securityMetricsEnabled({ STEWARD_METRICS_ENABLED: "true" })).toBe(true);
    expect(metricsTokenIsValid("short", { STEWARD_METRICS_TOKEN: "short" })).toBe(false);
    const token = "a".repeat(32);
    expect(metricsTokenIsValid(token, { STEWARD_METRICS_TOKEN: token })).toBe(true);
    expect(metricsTokenIsValid(`${token}x`, { STEWARD_METRICS_TOKEN: token })).toBe(false);
    // Configured-but-short token fails closed even when the candidate matches it.
    expect(metricsTokenIsValid("a".repeat(31), { STEWARD_METRICS_TOKEN: "a".repeat(31) })).toBe(
      false,
    );
    // No configured token => always closed.
    expect(metricsTokenIsValid(token, {})).toBe(false);
  });
});
