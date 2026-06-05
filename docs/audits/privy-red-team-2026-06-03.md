# Privy-Competitor Red-Team Review

Date: 2026-06-03
Scope: Steward API, SDK contracts, webhook dispatcher, user wallet custody, linked accounts, tenant control plane, and dashboard-sensitive controls under concurrent development.

This review is adversarial rather than feature-marketing oriented. It focuses on ways a hostile user, malicious tenant, compromised app, or confused integration could steal keys, bind the wrong identity, cross tenant boundaries, or exfiltrate secrets while Steward grows into a Privy competitor.

## Executive Findings

- No direct tenant-boundary bypass was confirmed in the reviewed wallet, recovery, account-linking, OAuth/SIWE, webhook, and tenant-admin routes. The high-value routes consistently bind user or tenant context and require MFA for custody-sensitive actions.
- One bounded SSRF hardening gap was patched: webhook URL validation now rejects additional IPv4 special-use ranges, including documentation, benchmark, multicast, reserved, and broadcast addresses.
- DNS-based SSRF for webhooks is mitigated at delivery time by the webhook transport's public-address DNS lookup guard, including private IPv4, mapped/embedded private IPv6, NAT64/6to4, link-local, site-local, and special-use ranges. Where a runtime cannot pin the selected address through the outbound socket, keep dispatch-time lookup tests in CI and fail closed on any non-public answer.
- Custody protections are still process-bound. An API-process compromise defeats policy enforcement, private key export controls, webhook redaction, and recovery-phrase hygiene because secrets are decrypted in-process.
- Pregenerated wallet claims are improving, but the complete security story still needs inventory, rotation, claim expiration enforcement validation, and operator workflows that make leaked or stale claim tokens easy to revoke.

## Attack Path Matrix

| Surface | Adversarial path | Existing control observed | Gap or failure mode | Risk |
| --- | --- | --- | --- | --- |
| Embedded user wallets | Stolen user JWT attempts key export or wallet restore | `/user/me/wallet/export`, recovery setup, restore, and pregenerated claim require personal user session and recent MFA | If MFA session is stolen within freshness window, the API trusts it; no per-action confirmation phrase or WebAuthn transaction binding yet | High |
| Private key export | Tenant/user enables export flags and attacker triggers break-glass export | Export is disabled unless explicit env flags are set; user export requires recent MFA; response uses `no-store`; audit occurs before export | API-process compromise or env misconfiguration still exposes plaintext keys | Critical if host compromised |
| Recovery phrase setup | Browser/plugin steals one-time BIP-39 phrase from response | Setup requires MFA, returns phrase once, no-store headers, no mnemonic in webhooks/audit metadata | Client-side malware and screenshots remain out of scope; phrase cannot be reliably zeroed in JS memory | High |
| Recovery phrase restore | Attacker brute-forces or submits guessed mnemonic | BIP-39 validation; MFA required; restore response does not echo mnemonic | No route-specific brute-force throttle beyond global request controls was confirmed in this pass | Medium |
| Pregenerated wallet claims | Leaked claim token claims wallet before intended user | MFA required; token is hashed server-side; claim uses compare-and-swap before key export; raw token is redacted from webhooks | Need completed expiry/rotation UX and validation; token bearer semantics still make distribution channel security critical | High |
| Pregenerated wallet claims | Double-spend/race claims same token twice | Claim route updates the source agent platform marker before vault export and rolls back on export/import failure | Distributed DB isolation and vault import rollback should remain covered by integration tests | Medium |
| Linked EVM/Solana wallets | User signs a message for one account and attacker binds it elsewhere | Challenge key is user and chain scoped; message includes user id and nonce; optional address/public-key binding; link requires MFA; nonce consumed once | Message does not include tenant/domain, but linked accounts are global per user and route requires personal session | Low |
| Linked OAuth accounts | OAuth state or code replay binds provider account to attacker | OAuth link challenge is user/state scoped; token route checks provider, redirect URI, tenant, and MFA; state consumed once | Provider account uniqueness is global, but provider token refresh handling and revocation UX need ongoing review | Medium |
| OAuth/SIWE login | Tenant hint confusion signs user into wrong tenant | Auth routes validate explicit tenants, tenant membership, redirect allowlists, login-method policy, and SIWE nonce tenant/domain policy | Multiple tenant hint channels (`X-Steward-Tenant`, body, query) increase integration mistakes; tests must keep precedence explicit | Medium |
| SIWE/SIWS nonce | Nonce generated for one tenant/domain replayed against another | Nonce record includes domain and optional tenant; verify evaluates SIWE policy and tenant resolution | Allowed-domain config errors can still let malicious app origins request legitimate login | Medium |
| Webhooks | Configure webhook to internal service or metadata endpoint | URL validator rejects credentials, non-HTTPS by default, localhost, `.local`/`.internal`, private IPv4, private/special IPv6, NAT64/6to4 private embeddings; dispatcher resolves immediately before connection and rejects non-public DNS answers | True IP pinning remains runtime-dependent, so transport tests must stay in CI and production must fail closed when lookup enforcement is unavailable | Medium |
| Webhook payloads | Secrets leaked in payload snapshots or replay | Dispatcher recursively redacts sensitive keys, stores encrypted secrets, and list/history redacts delivery error details | Redaction is key-name based; a newly introduced unusual secret field can bypass until added | Medium |
| Webhook delivery | Replay endpoint resends stale sensitive payload | Replay re-redacts original data and signs delivery; admin/MFA gates on config routes | Replay should continue enforcing tenant-admin MFA and delivery ownership in integration tests | Medium |
| Tenant boundary | User supplies another tenant id to platform/user routes | Reviewed handlers use tenant-scoped query filters and session tenant/membership checks; linked global accounts are intentionally excluded from tenant-admin user reads | Route-by-route discipline is still required; no DB row-level security was observed | High |
| Rate limits | Auth endpoints brute-forced or spammed | Redis-backed auth throttles, MFA failed-attempt counters, captcha hooks, idempotency conflict controls | Production safety depends on Redis availability and strict soft-fail env settings | Medium |
| Dashboard controls | Stolen admin session changes webhooks, origins, MFA, or app clients | Tenant-admin routes require owner/admin session and many require recent MFA; settings exposes hardening checklist | Dashboard-specific CSRF/Clickjacking review should remain part of browser E2E; CSP is only as strong as deployment headers | Medium |

## Exploit Scenario Patched

Webhook SSRF via IPv4 special-use addresses:

1. A tenant admin registers a webhook using a URL such as `https://198.18.0.1/hook`, `https://224.0.0.1/hook`, or `https://255.255.255.255/hook`.
2. The previous literal-IP validator rejected RFC1918, loopback, link-local, carrier-grade NAT, and some IPv6 private encodings, but it did not reject several non-public IPv4 special-use ranges.
3. A deployment that can route any of these ranges could send signed webhook traffic to infrastructure that should never receive tenant-controlled callbacks.

Patch:

- `packages/api/src/services/webhook-url.ts` now rejects IPv4 `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, and `240.0.0.0/4` including broadcast.
- `packages/api/src/__tests__/webhook-url-validation.test.ts` covers representative URLs for those ranges.

## Exploit Scenarios Tested Or Reviewed

- Wallet link nonce replay: reviewed EVM/Solana link handlers for user-scoped challenge keys, optional address binding, signature verification, single-use nonce consume, and MFA gate.
- OAuth account link replay: reviewed user/state-scoped challenge storage, provider binding, redirect URI binding, tenant binding, state consume before token exchange, global provider-account uniqueness checks, and MFA gate.
- Pregenerated claim race: reviewed claim path for existing wallet precheck, recent MFA, hashed claim lookup, compare-and-swap marker before vault export, rollback on import/export failure, and no-store response.
- Recovery phrase exfiltration: reviewed setup/restore for recent MFA, BIP-39 validation, no-store headers, non-echoing restore responses, and webhook metadata that does not include mnemonic.
- Webhook payload leakage: reviewed recursive key-name redaction and delivery snapshot handling; raw `claimToken`, private keys, mnemonic-like field names, access tokens, refresh tokens, and id tokens should be redacted.
- Tenant-admin webhook controls: reviewed admin session + recent MFA gate, URL validation, event allowlist validation, encrypted webhook secret storage, one-time secret return, and secret omission from list responses.
- Tenant-scoped read/write queries: reviewed representative routes for `tenantId` filters and session tenant/membership checks; no global linked-account leak from tenant-admin user reads was identified in this pass.

## Unresolved High-Risk Items

1. Runtime proof for webhook DNS pinning. Dispatch-time DNS resolution now rejects private, special-use, and link-local answers immediately before the outbound request; continue proving this in `@stwd/webhooks` tests and pin the selected IP through the outbound request layer wherever the runtime supports it.
2. API-process compromise remains catastrophic for custody. Move signing and key export into a separate signer service or HSM/KMS boundary where the API can request policy-bound signatures but cannot directly decrypt keys.
3. Route-specific brute-force throttles for recovery restore and pregenerated claim tokens should be explicit and covered by tests, independent of global request-expiry/signature/idempotency controls.
4. Pregenerated wallet operations need a complete revocation and rotation control plane: list unclaimed wallets, expire claim tokens, rotate claim tokens, bulk revoke, and audit each distribution event without storing raw tokens.
5. Webhook redaction is key-name based. Add schema-level tests for every event type and fail closed for unknown secret-bearing fields before dispatch.
6. Database isolation is enforced in application code, not database row-level security. Hosted multi-tenant mode should add RLS or equivalent query policy tests for tenant-owned tables.
7. Dashboard control-plane CSRF/clickjacking review needs browser E2E coverage against real session cookies, CSP, frame ancestors, and mutation endpoints.
8. MFA freshness is session-wide. Add per-action confirmation or transaction-bound WebAuthn prompts for private key export, wallet recovery restore, webhook secret rotation, app-client secret creation, and high-value global-wallet write confirmations.

## Follow-Up Validation Commands

Run these focused checks while the product worktree is concurrently dirty:

```bash
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/webhook-url-validation.test.ts packages/webhooks/src/__tests__/dispatcher-security.test.ts packages/webhooks/src/__tests__/queue.test.ts
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/webhook-payload-redaction.test.ts packages/api/src/__tests__/webhook-retry-hardening.test.ts packages/api/src/__tests__/webhook-events.test.ts
/Users/shawwalters/.bun/bin/bun test --timeout 30000 packages/api/src/__tests__/user-linked-accounts.test.ts packages/api/src/__tests__/user-wallet-recovery-setup.test.ts packages/api/src/__tests__/pregenerated-user-wallets.test.ts
```
