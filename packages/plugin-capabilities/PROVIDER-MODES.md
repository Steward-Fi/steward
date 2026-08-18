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
| `github` | **broker** | GitHub App installation tokens can be short-lived and scoped, but Steward does not yet perform the provider-native installation-token exchange. GitHub remains brokered until it does; an internal Steward JWT is not a GitHub credential. |
| `llm` | **broker** | A shared LLM pool seat is a long-lived provider API key that cannot be down-scoped per agent; Steward brokers completions through the credential-injection proxy so the key stays in the enclave (spend/rate policy enforced server-side). |
| `wallet` | **broker** | Signing authority must never leave custody. The agent requests a signature; Steward (vault / future threshold signer, Pillar D) performs it and returns only the signature. There is no "scoped short-lived private key" to hand out. |
| `openai` | **broker** | OpenAI API keys are long-lived and not per-call scopable; brokered through the existing OpenAI-compatible capability adapter so the key stays server-side. |
| `stripe` | **broker** | Stripe secret keys are long-lived and highly sensitive; restricted keys still cannot be minted short-lived per-agent on demand, so Steward brokers the call. |
| *(unlisted)* | **broker** | Fail-safe default. |

## How modes are exercised

### token mode (no provider currently enabled)

When a provider-native scoped-token minter is implemented and enabled, issuance
may return that provider's short-lived credential. Steward must not substitute
one of its own session JWTs for a provider credential.

GitHub is deliberately broker mode today. Its credential stays in Steward and
the agent invokes the granted capability through the defended broker path.

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

## Renewal & revocation

- For a future token-mode provider, **TTL** is minute-scale (`DEFAULT_ISSUE_TTL_SECONDS = 120`, hard ceiling
  `MAX_ISSUE_TTL_SECONDS = 300`). Agents auto-renew.
- **Revocation** is an operator act: disable the capability or revoke the grant
  via the existing capability CRUD. The change takes effect at the agent's **next
  renewal** — bounded by the TTL, satisfying the Pillar-A green criterion
  (<5 min). Every renewal is a fresh, fully-checked issuance.
- For an immediate token-mode kill, the minted `jti` is surfaced so it can be revoked via the
  existing JWT revocation store.
