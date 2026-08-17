# Capability Provider Modes

When an agent requests a manifest capability, Steward answers in one of two
**modes**. This table is the human-readable projection of the single source of
truth in [`src/provider-modes.ts`](./src/provider-modes.ts) (`PROVIDER_MODES`).

- **token** — Steward returns a **short-lived, scoped token** the agent uses
  directly. Only honest when the provider's credentials can actually be
  down-scoped and made short-lived.
- **broker** — Steward performs the upstream call **on behalf of** the agent; the
  credential never leaves the enclave. This is the **honest default** whenever a
  provider's secret cannot be down-scoped.

Anything **not listed** defaults to **broker** (fail-safe: never hand out a token
for a provider we have not deliberately classified as token-safe).

| Provider | Mode   | Rationale |
|----------|--------|-----------|
| `discord` | **broker** | Discord bot tokens cannot be down-scoped or short-lived by Discord; handing the raw token to an agent would leak a long-lived credential. Steward brokers the call so the token never leaves the enclave. **This is the canonical broker-mode case.** |
| `github` | **token** | GitHub App installation tokens are natively short-lived (≈1h) and scopable per installation/permission; Steward can mint a scoped installation token. (A raw PAT-backed github provider would instead be broker mode.) |
| `llm` | **broker** | A shared LLM pool seat is a long-lived provider API key that cannot be down-scoped per agent; Steward brokers completions through the credential-injection proxy so the key stays in the enclave (spend/rate policy enforced server-side). |
| `wallet` | **broker** | Signing authority must never leave custody. The agent requests a signature; Steward (vault / future threshold signer, Pillar D) performs it and returns only the signature. There is no "scoped short-lived private key" to hand out. |
| `openai` | **broker** | OpenAI API keys are long-lived and not per-call scopable; brokered through the existing OpenAI-compatible capability adapter so the key stays server-side. |
| `stripe` | **broker** | Stripe secret keys are long-lived and highly sensitive; restricted keys still cannot be minted short-lived per-agent on demand, so Steward brokers the call. |
| *(unlisted)* | **broker** | Fail-safe default. |

## How modes are exercised

### token mode
```
POST /capabilities/manifest/github:app:org/issue
Idempotency-Key: random-unguessable-value
{ "workspaceId": "...", "ttlSeconds": 3600,
  "resource": { "repositories": ["steward"],
                "permissions": { "issues": "write" } } }
→ { "mode": "token", "issuer": "github-app-installation",
    "leaseId": "...", "token": "<GitHub installation token>",
    "acknowledgementRequired": true, "acknowledgementDeadlineSeconds": 30,
    "expiresAt": "...", "resource": { ... } }
```
This is an actual GitHub App installation token, not a Steward JWT and not a
stored PAT. The configured allowlist and live capability grant constrain the
requested repositories and permissions. Steward returns the token once with
`Cache-Control: no-store`; its SHA-256 digest and an AAD-bound encrypted
revocation handle are retained with the immutable tenant/workspace/agent/grant/
capability/resource binding. The holder must then prove receipt:

```
POST /capabilities/manifest/leases/:leaseId/ack
{ "token": "<the delivered GitHub installation token>" }
```

Until that proof commits, the lease stays `delivery_pending`; bounded recovery
revokes stale unacknowledged delivery using the encrypted handle. Reusing the
idempotency key returns `409` and never replays the credential. GitHub does not
accept a caller-selected installation-token TTL, so this endpoint accepts
exactly `ttlSeconds: 3600`; shorter values are rejected rather than presented as
an upstream lifetime Steward cannot enforce. Issuance also fails closed when
the live grant expires before GitHub's fixed one-hour token expiry; a provider
token is never delivered with a lifetime beyond its authority.

The long-lived API starts an immediate, periodic, cursor-bounded recovery sweep
for every tenant with durable lease state. It revokes abandoned deliveries and
stale encrypted handles without waiting for another issuance request, and
graceful shutdown waits for an in-flight sweep before closing the database.
Every terminal or `needs_attention` transition and its core audit record commit
atomically; an audit failure leaves the prior recoverable state for a later
exact-CAS retry rather than creating an unaudited terminal outcome.

### broker mode
```
POST /capabilities/manifest/discord:bot-token:soliza/issue
→ { "mode": "broker",
    "delegation": { "capabilityName": "discord-send", "method": "POST", "note": "..." } }
```
No token is returned. The agent exercises the capability through the existing,
already-defended broker path:
```
POST /capabilities/discord-send/invoke   { "body": { ... } }
```
The credential-injection proxy injects the secret outbound and the agent receives
only the scrubbed upstream response.

## Expiry, renewal & revocation

- GitHub chooses installation-token expiry (currently one hour). Steward sends
  no fictitious TTL field to GitHub and accepts only the one-hour API contract.
  It rejects and revokes a response whose expiry is not shaped like a newly
  issued one-hour token; it does not pretend a shorter local timestamp shortens
  an upstream token.
- Renewal is a fresh issuance with a new idempotency key and a complete live
  grant/scope check. A token is never replayed.
- Capability disable/delete, relevant capability changes, and grant revocation
  tombstone authority before sweeping every bound lease with its exact encrypted
  token. An issuer finishing concurrently observes the changed authority and
  self-revokes instead of delivering.
- `POST /capabilities/manifest/leases/:leaseId/revoke` requires the token as
  proof of possession. Steward compares its digest, calls GitHub's token revoke
  endpoint, and marks the lease revoked only after GitHub proves invalidation.
  Plaintext is exercised only inside the escrow callback. An ambiguous revoker
  failure returns `503` and persists `needs_attention` with the sealed handle;
  it never reasserts that the provider credential is active.
- If interruption happens after an upstream issue call but before a sealed
  handle is durable, the provider outcome is honestly recorded as unknown. If a
  handle is durable, stale delivery/revocation recovery claims the exact scanned
  status and `updated_at` snapshot before exercising that exact token, so it
  cannot revoke a lease that was acknowledged concurrently.
- A success response or GitHub's documented invalid-token response proves that
  the credential is unusable. An undocumented `404` is not treated as proof.
- Lease lifecycle events and lease identities are append-only at the database
  boundary; parent agent/workspace deletion is restricted so evidence cannot be
  removed by cascade.

These tests use a deterministic fake upstream boundary. They do not constitute
live GitHub, Railway, or deployment proof.
