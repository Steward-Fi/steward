# Webhook Red-Team Notes

Date: 2026-06-03
Scope: webhook SSRF/DNS rebinding, secret redaction, replay/retry controls, delivery exports, and MFA-gated webhook control-plane routes.

This file is intentionally narrow. It records current security evidence and open gaps without changing the product implementation while other agents are editing the webhook stack.

## Current Evidence

| Area | Evidence | Result |
| --- | --- | --- |
| DNS rebinding at delivery time | `packages/webhooks/src/dispatcher.ts` installs a public-address `lookup` guard unless `allowPrivateNetwork` is explicitly enabled. `packages/webhooks/src/__tests__/queue.test.ts` covers private IPv4, IPv4-mapped IPv6, NAT64/6to4, IPv6 link-local, and IPv6 site-local rebinding. | Passing |
| Special-use literal IP filtering | `packages/api/src/services/webhook-url.ts` and `packages/webhooks/src/dispatcher.ts` reject configuration-time and delivery-time special-use literal IPs, including documentation ranges, benchmarking ranges, 6to4/NAT64 embeddings, multicast/reserved space, and broadcast. | Passing |
| Payload secret redaction | `packages/api/src/services/webhook-dispatch.ts` exports and applies `redactWebhookSecrets` before configured and legacy webhook fanout. `packages/api/src/__tests__/webhook-payload-redaction.test.ts` covers nested mnemonic, private-key, OAuth-token, refresh-token, and pregenerated claim-token redaction. | Passing |
| Signed delivery | `packages/webhooks/src/__tests__/dispatcher-security.test.ts` and `packages/api/src/__tests__/webhook-signed-delivery.test.ts` exercise real HMAC v2 delivery, tamper rejection, stable retry signatures, and 4xx no-retry behavior. | Passing |
| Retry/replay control plane | `packages/api/src/__tests__/webhook-retry-hardening.test.ts` and `packages/api/src/__tests__/webhook-audit-order.test.ts` source-check current URL/event revalidation, terminal-status checks, retry-budget preservation, and redacted delivery history/retry responses. | Passing |
| Webhook admin MFA | `packages/api/src/__tests__/webhook-audit-order.test.ts` confirms create/list/update/delete/history/manual-retry routes require owner/admin session and recent MFA. | Passing |
| Unsafe signing/export gates | `packages/api/src/__tests__/vault-unsafe-signing-hardening.test.ts` passes for unsafe signing MFA, tenant MFA policy, wildcard-signing limits, key import/export freshness, no-store export responses, and direct native-signing guards. `packages/api/src/__tests__/key-export-guards.test.ts` is currently skipped in this worktree. | Partial |

## Open Findings

## 2026-06-04 Follow-Up

Additional red-team checks found and patched two SSRF parity mismatches between configuration-time validation and delivery-time DNS enforcement:

- Configuration-time URL validation now blocks the full IPv6 link-local `fe80::/10` range, not just `fe80:` literals.
- Delivery-time DNS validation now blocks Teredo `2001::/32` and documentation `2001:db8::/32` answers through parsed IPv6 words, matching the API URL validator.

Webhook payload redaction was also broadened for common auth/provider variants (`access_token`, `idToken`, `id_token`, `jwt`, `authorization`, `bearer_token`, `sessionToken`, `apiKey`, `api_key`, `clientSecret`, `client_secret`, `private_key`, `recovery_phrase`, `seed_phrase`). The redaction helper now lives in a pure module so the regression test runs without booting database context.

### 1. Special-use literal IP filtering now covers configuration and delivery

`packages/api/src/services/webhook-url.ts` and `packages/webhooks/src/dispatcher.ts` reject special-use literal IPs at both webhook configuration time and delivery time. Regression tests cover representative documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), benchmarking ranges (`198.18.0.0/15`), 6to4/NAT64/IPv4-mapped embeddings, multicast/reserved space, and broadcast.

Residual risk: hostname-based callbacks still rely on delivery-time DNS lookup enforcement, so keep the dispatcher lookup guard enabled in production and avoid `allowPrivateNetwork` except for explicit local test sinks.

### 2. API webhook payload redaction now runs before dispatch persistence

`packages/api/src/services/webhook-dispatch.ts` now redacts nested secret-bearing fields before both configured-webhook delivery persistence and legacy tenant-config fanout. `packages/api/src/__tests__/webhook-payload-redaction.test.ts` provides the focused regression for mnemonic, private key, OAuth token, refresh token, and pregenerated claim token fields.

Residual risk: redaction is key-name based. New webhook payload schemas that introduce differently named secret fields should add those names to `SENSITIVE_WEBHOOK_KEYS` and extend the regression fixture before shipping.

### 3. Key export E2E guard suite is skipped in this worktree

`packages/api/src/__tests__/vault-unsafe-signing-hardening.test.ts` passes source-level gates for unsafe signing and export no-store behavior. `packages/api/src/__tests__/key-export-guards.test.ts` reports 6 skipped tests in this worktree, so the live route coverage for recent-MFA export allow/deny behavior was not revalidated here.

Impact: source-level invariants are useful but weaker than route execution. Keep this on the release gate until the PGLite/test harness state is stable.

## Commands Run

```bash
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/webhook-url-validation.test.ts packages/api/src/__tests__/webhook-payload-redaction.test.ts packages/api/src/__tests__/webhook-retry-hardening.test.ts packages/webhooks/src/__tests__/queue.test.ts
```

Result: 29 pass, 1 fail. Failure was `webhook payload secrecy > redacts nested mnemonic and private key material before delivery persistence`, blocked before the assertion by `DATABASE_URL is required`.

```bash
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/vault-unsafe-signing-hardening.test.ts packages/api/src/__tests__/key-export-guards.test.ts
```

Result: 8 pass, 6 skip, 0 fail.

```bash
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/webhooks/src/__tests__/dispatcher-security.test.ts packages/api/src/__tests__/webhook-audit-order.test.ts packages/api/src/__tests__/webhook-signed-delivery.test.ts
```

Result: 18 pass, 0 fail.
