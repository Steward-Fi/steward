# Steward Specification — Overview

> **Version:** 0.1.0  
> **Status:** Draft  
> **Date:** 2026-03-23

## What is Steward?

Steward is a server-side wallet infrastructure service for AI agents. It sits between an agent and its wallet, encrypting private keys at rest, enforcing configurable policies before signing, and providing audit trails for every transaction.

## Scope

This specification defines:

1. **Storage Format** — How private keys are encrypted, stored, and retrieved
2. **Signing Interface** — Request format, chain routing, response shape, and error semantics
3. **Policy Engine** — Policy types, evaluation logic, hard vs. soft gates, and approval queues
4. **Agent Access Layer** — Authentication, authorization, tenant isolation, and agent scoping
5. **Supported Chains** — Chain families, identifiers, key derivation, and signing methods

## Design Principles

### Keys never leave the vault
Private keys are encrypted at rest with AES-256-GCM. Decryption happens only during a signing operation, in-process. The raw key is never returned via API, never logged, never sent to the agent.

### Policy before signing
Every agent transaction passes through the policy engine before the key is decrypted. Hard policy failures reject immediately. Soft policy failures (auto-approve threshold) queue for human review. No policy bypass exists in the agent access path.

### Multi-tenant by design
Steward serves multiple tenants (platforms, organizations) from a single deployment. Each tenant has isolated agents, policies, and API keys. Cross-tenant access is not possible through the agent API.

### Backwards-compatible evolution
New features add fields and endpoints. Existing fields and endpoints don't change meaning. Clients built against an older version continue working against a newer deployment.

## Architecture

```
Agent / Platform Client
  │
  │  HTTP (SDK or direct)
  ▼
┌────────────────────────────────────┐
│         Steward API (Hono)         │
│  ┌──────────┐  ┌────────────────┐  │
│  │   Auth   │  │  Rate Limiter  │  │
│  └────┬─────┘  └───────┬────────┘  │
│       │                │           │
│  ┌────▼────────────────▼────────┐  │
│  │       Policy Engine          │  │
│  │  spending-limit              │  │
│  │  approved-addresses          │  │
│  │  rate-limit                  │  │
│  │  time-window                 │  │
│  │  auto-approve-threshold      │  │
│  └────┬──────────────┬──────────┘  │
│       │ pass         │ soft fail   │
│  ┌────▼──────┐  ┌────▼──────────┐  │
│  │   Vault   │  │ Approval Queue│  │
│  │ (sign)    │  │ (webhook)     │  │
│  └────┬──────┘  └───────────────┘  │
│       │                            │
│  ┌────▼──────────────────────────┐ │
│  │    Encrypted Keystore (DB)    │ │
│  │    AES-256-GCM + scrypt       │ │
│  └───────────────────────────────┘ │
└────────────────────────────────────┘
```

## Document Conventions

- **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are interpreted per [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).
- Code examples are informative unless explicitly marked as normative.
- Field names use `camelCase` in JSON payloads.

## Conformance

An implementation is conforming if it correctly implements:

1. The storage format (§01)
2. The signing interface (§02)
3. The policy engine (§03)
4. At least one supported chain family (§05)

Partial conformance is acceptable if documented. An implementation MUST NOT claim "Steward-compatible" without implementing at least §01 through §03.
