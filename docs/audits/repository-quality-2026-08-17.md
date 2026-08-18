# Repository quality audit — 2026-08-17

## Scope

This audit covered the tracked monorepo, package manifests, migrations, generated API contracts,
tests, workflows, deployment assets, examples, and current documentation. It used repeated passes
for inventory/dead code, production comments and historical residue, security and failure modes,
test quality and missing coverage, documentation/runtime agreement, and live pull-request overlap.

The audit does not treat a source-text assertion as behavioral evidence. Tests which only searched
implementation files for names, ordering, or strings were removed or replaced with calls through
public routes/services and assertions against responses, database state, audits, and rollback
behavior. File readers that remain are limited to generated artifacts, executable migrations,
deployment/configuration contracts, and explicit security-inventory boundaries.

## Findings resolved

### Financial execution and custody

- Added durable, atomic wallet-operation idempotency for broadcast-capable EVM and Solana paths.
  Claims are tenant/agent/operation scoped, bind a canonical request digest, reject conflicting or
  concurrent reuse, and retain terminal or ambiguous outcomes.
- Integrated external-custody `outcome_unknown` recovery with the idempotency ledger. A receipt can
  advance the bound transaction to broadcast, confirmed, or failed, and a later retry replays the
  reconciled result without signing or broadcasting again.
- Made transaction identifiers immutable across agents and request bodies. State transitions retain
  custody backend identity and require exact hash agreement for ambiguous-outcome reconciliation.
- Replaced fail-open Redis-only spend bookkeeping with authoritative database transaction data for
  cumulative policy enforcement, including conservative accounting for unresolved broadcasts.
- Hardened EVM nonce allocation so ambiguous broadcasts block reuse until chain evidence resolves
  the nonce.
- Added durable Redis idempotency to Hyperliquid and Polymarket order submission. In-flight claims
  use short leases; complete and submission-unknown records do not expire; production has no implicit
  in-memory fallback; audit failure cannot reopen a venue submission.
- Polymarket order policy now verifies token-to-market identity through the venue API instead of
  trusting caller-supplied condition metadata.

### Authentication, authorization, and failure semantics

- Moved user wallet/social/OAuth link challenges onto the configured durable challenge backend and
  awaited challenge deletion failures.
- Centralized recent-MFA validation with a bounded clock-skew check, rejecting non-finite and
  far-future timestamps across sensitive routes.
- Normalized condition-set persistence/audit failures to generic server errors while retaining
  transaction rollback and preventing internal error disclosure.
- Preserved fail-closed provider authority, approval quorum, budget, count-cap, and execution-binding
  behavior while integrating the quality changes with the latest `develop` security waves.
- Removed raw forwarded-header diagnostics and other temporary, merge-era, phase, sprint, and PR
  commentary from production paths. Remaining comments describe the current invariant or trust
  boundary.

### Tests and continuous integration

- Removed pure implementation-source scans and replaced the highest-risk families with behavioral
  route, database, audit-failure, rollback, concurrency, and public-API tests.
- Added behavioral coverage for wallet idempotency, cross-caller claims, request conflicts,
  post-broadcast failures, ambiguous custody outcomes, receipt reconciliation, transaction-ID reuse,
  recent MFA, auth refresh/revoke races, condition-set audit rollback, and rendered policy editing.
- Added required generated-SDK drift checking, real PostgreSQL security suites, Java SDK behavior,
  the Waifu example tests, and a non-wallet Chromium browser suite to CI.
- Kept credentialed wallet-extension and live-provider suites explicitly opt-in because they require
  external identities or secrets; they are not represented as covered by ordinary CI.

### Repository and documentation hygiene

- Deleted unreferenced work products, unsafe legacy deployment scripts, committed test residue,
  superseded components/helpers, and verified-unused dependencies; regenerated the lockfile.
- Renamed still-useful mutation proofs around the invariant they exercise and kept them executable.
- Added or corrected `AGENTS.md`, `CLAUDE.md`, package READMEs, deployment guides, security posture,
  ADRs, Mintlify navigation, OpenAPI instructions, Eliza configuration, ERC-8004 limitations, and
  the Waifu webhook example.
- Standardized the canonical JWT secret name and development-chain default, removed personal paths
  and live inventory, and made production deployment examples use the shipped hardened service
  units.
- Regenerated both OpenAPI documents and SDK types from the runtime contract. Database migrations
  are sequential and immutable: external-custody reconciliation is `0091`; wallet idempotency is
  `0107`.

## Dead-code result

The pinned production Knip scan reports nine dependency rows and three duplicate-export groups.
Every row is a verified static-analysis false positive caused by root integration scripts or runnable
private-package entrypoints; every duplicate is an intentional semantic/public alias. The detailed
evidence and exact command are in `docs/audits/deadcode.md`.

## Validation contract

The following checks are required on the final integrated head before merge:

```bash
bun install --frozen-lockfile
bun run lint
bun run typecheck
bun run test
bun run --cwd packages/api openapi:check
bun run test:e2e:browser:chromium
```

API/proxy E2E is run separately against the explicitly provisioned embedded or Compose services used
by CI; deterministic root tests never attach to an arbitrary localhost daemon. Workflow YAML is also
checked with `actionlint`, migrations with behavioral database tests, and the live pull-request queue
is refreshed after the quality branch lands. A local pass is reported separately from GitHub checks
and merge state.

## Live pull-request disposition

PRs already merged into the audited base are retained and integrated, including external-custody
outcome reconciliation and the wave-2b infrastructure/script hardening. The remaining queue is not
rubber-stamped: SDK, auth, vault, credential-lease, Slack, and Google provider branches each receive
an exact-head restack, focused design review, and fresh CI. Credential delivery must be recoverable
across post-commit response loss; Google access tokens must refresh before governed dispatch; and
concurrency/security limits must be claimed atomically before the protected operation.
