# Self-hosted security metrics and alerting

Steward does not send telemetry or alerts to Steward-Fi. Operators may opt in to a process-local Prometheus endpoint and route durable typed audit events through their own infrastructure.

## Enable the metrics endpoint

The endpoint is disabled by default and returns `404` until explicitly enabled. Set both:

```text
STEWARD_METRICS_ENABLED=true
STEWARD_METRICS_TOKEN=<random value of at least 32 characters>
```

Scrape `GET /metrics` with `Authorization: Bearer <token>`. Missing, short, or incorrect tokens are rejected. Generate a token with a cryptographically secure generator, store it outside source control, and rotate it like any operator credential.

The API and proxy are separate processes and each exposes its own process-local `/metrics` view. Scrape both when deployed separately. Bind their listeners to localhost or a private service network, terminate TLS at the operator-controlled ingress, and do not expose either endpoint directly to the public Internet. The bearer token is defense in depth, not a substitute for network isolation and TLS.

No tenant, user, agent, action, route, provider, resource, error message, raw denial reason, or other unbounded value appears in labels. The only labels are compile-time bounded outcome, reason class, and approval decision enums.

## Metric catalog

- `steward_governed_executions_total{outcome="succeeded|failed|outcome_unknown"}`: terminal governed execution audit events.
- `steward_security_denials_total{reason_class="..."}`: denials collapsed into a fixed reason class. Investigate durable audit records for exact typed details.
- `steward_approval_decisions_total{decision="approved|denied"}`: provider approval decisions.
- `steward_governed_boundary_denials_total`: typed `provider.execution.denied_at_boundary` events. This is a provider-boundary denial signal, not proof that every legacy or bypass path in the product was attempted.
- `steward_nonce_claim_contentions_total`: execution authorization claims that returned the typed `EXEC_AUTH_CLAIM_LOST` result.
- `steward_audit_checkpoint_age_seconds`: age of the most recent checkpoint created by the current API process. `-1` means none has been observed since process start.

Counters and the checkpoint-age observation are in memory and reset on process restart. Prometheus can retain scraped samples, but a reset is not durable evidence. The tamper-evident audit chain and signed checkpoint records are the durable investigation source. Metrics are operational hints only and do not establish compliance, completeness, exactly-once processing, or operator-proof execution.

Collection is post-decision or best-effort. Metrics failures cannot authorize, deny, roll back, or otherwise change a governed action.

## Typed audit event alert catalog

Suggested starting points must be tuned to baseline volume and maintenance windows:

- `provider.execution.outcome_unknown`, **critical**: page immediately on any event. Freeze automated retries for that execution until an operator reconciles its upstream state.
- `provider.execution.denied_at_boundary`, **high**: page on any event outside planned credential, route, or account rotation. Otherwise alert on 3 events in 5 minutes. Review the typed `reasonCode` in the audit record.
- `provider.execution.failed`, **medium**: alert when 5 events occur in 10 minutes or the failure ratio exceeds the operator's baseline. An upstream failure is not automatically a security incident.
- `provider.action.denied`, **medium**: alert on a sharp rise over baseline, for example 10 events in 5 minutes. Use the durable audit event to distinguish access and policy causes.
- `provider.approval.decided` with decision `denied`, **low to medium**: notify or ticket on each denial for high-risk workflows; otherwise alert on 5 in 15 minutes.
- `provider.approval.expired` or `provider.approval.staled`, **medium**: alert on 3 in 15 minutes. Check approver latency and dependency or policy changes.
- `provider.execution.claimed`, **informational**: useful for correlation, not normally alert-worthy alone.
- `provider.execution.succeeded`, **informational**: use as denominator and investigation context.

`EXEC_AUTH_CLAIM_LOST` is currently a typed execution result counted directly by the proxy, not a durable audit event. Treat a rise in `steward_nonce_claim_contentions_total` as **high** at 3 in 5 minutes and correlate with request logs and nearby `provider.execution.claimed` events. A process restart can hide the prior counter value, so absence after restart is not evidence that contention did not occur.

There is no fabricated generic "bypass attempted" audit event. The catalog uses the existing typed `provider.execution.denied_at_boundary` event and states its narrower meaning. Add alert semantics only when a corresponding typed event exists.

## Example Prometheus rules

```yaml
groups:
  - name: steward-security
    rules:
      - alert: StewardExecutionOutcomeUnknown
        expr: increase(steward_governed_executions_total{outcome="outcome_unknown"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: Steward governed execution has an unknown outcome
      - alert: StewardBoundaryDenials
        expr: increase(steward_governed_boundary_denials_total[5m]) >= 3
        for: 0m
        labels:
          severity: high
      - alert: StewardNonceClaimContention
        expr: increase(steward_nonce_claim_contentions_total[5m]) >= 3
        for: 0m
        labels:
          severity: high
      - alert: StewardCheckpointNotObserved
        expr: steward_audit_checkpoint_age_seconds < 0 or steward_audit_checkpoint_age_seconds > 86400
        for: 15m
        labels:
          severity: medium
```

After any alert, preserve and inspect the audit bundle rather than relying on metric labels. Metric labels are deliberately too coarse for forensic conclusions.
