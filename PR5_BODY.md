## PR5 — Correlated Case Evidence & Existing Bundle Extension

Implements the PR5 contract (`PR5-CASE-EVIDENCE-SPEC.md`) on top of the landed PR1–PR4 stack (base `develop` tip `85ccc7c`, after PR4 #199). Makes the complete governed-provider case — action intent through terminal dispatch outcome — provable to an offline auditor using the EXISTING tamper-evident audit-chain + Ed25519 checkpoint cryptography. No second ledger, no second signing key, no new HMAC key, no migration.

### What landed (spec-mapped)

- **Shared types (§2.1, §4.4)** — `packages/shared/src/provider-case.ts`: crypto-free `ProviderCaseManifestV1` / `ProviderCaseEvidenceV1`, `ProviderCaseEventRole` / `ProviderCaseTerminalState`, the mechanical `requiredRoles()` completeness function, `roleForAction()` taxonomy mapper, and stable reason codes.
- **Correlator / manifest assembler (§1.3, §3, §4)** — `packages/api/src/services/provider-case.ts`: pure-read `getProviderCase` / `getProviderCaseEvidence`. Correlates by indexed `resource_id=caseId` + asserts `metadata.intentId` agreement (N23 event-theft guard). Resolves terminal state from the authoritative binding/nonce columns, computes mechanical completeness, hashes the provider idempotency key (§3.4 — raw key never enters the manifest), re-validates the safe summary redaction (§3.3), enforces per-event + whole-manifest size caps (§3.6). Runs all reads inside ONE read-only snapshot (REPEATABLE READ READ ONLY on Postgres; PGLite serialized) so `verifyAuditChain` + `readAuditBundleData` share the snapshot (§4.1/§4.3, KC06).
- **Signing factor-out (§6.2)** — `packages/api/src/services/audit.ts`: extracted `signAuditBundle` (+ `BUNDLE_CANONICALIZATION_SPEC`) so `/audit/bundle` and `/evidence` produce byte-identical envelopes from one signing path. Added an optional snapshot `executor` param to `verifyAuditChain` / `readAuditBundleData` (defaults to `getDb()`, existing callers unchanged).
- **Routes (§5)** — `packages/api/src/routes/provider-case.ts`: `GET /v2/provider-actions/:id/{case,evidence}` behind the SAME owner/admin + recent-MFA gate as `/audit/*` (extracted to `middleware/audit-gate.ts`; `/audit/*` now reuses it, never a weaker gate). Strict case-id validation, `/evidence` signing-key 503, uniform `CASE_NOT_FOUND` for foreign tenant/workspace/nonexistent (§5.4, D2 non-enumerating).
- **Offline verifier (§6.6, §7)** — `scripts/verify-evidence-bundle.mjs`: accepts BOTH a raw `/audit/bundle` (unchanged, no regression) and a `/evidence` envelope. Adds `--expected-key-fingerprint` / `STEWARD_EXPECTED_AUDIT_KEY_FP` trust-root binding (C6, E7; rotation set supported), and the manifest cross-check (§7.4): every manifest event matches the signed bundle event by hmac+action+role, every manifest fact is backed by the owning signed event's metadata, and the forged-completeness guard (a manifest claiming `complete` while a required role is absent from the SIGNED events FAILS). Zero project imports preserved.

### Anchor re-verification (CRITICAL FIRST STEP) — drift REPORTED, not silently reinterpreted

The spec was written pre-PR4/pre-X-provider. I re-verified every anchor against the landed code. Findings:

- **C-DRIFT-1 (taxonomy folding, ACCOMMODATED):** PR2 emits a SINGLE folded genesis event `provider.action.{allowed,denied,approval_required}` carrying BOTH the access and policy decision hashes, rather than the spec §1.4 separate `provider.access.decided` + `provider.policy.decided` events. `roleForAction` maps the folded event to the `genesis` role and `requiredRoles` treats `genesis` as satisfying the pre-approval decision requirement. This keeps completeness mechanical against code AS LANDED. C1/C2 are fully satisfied (every persisted intent gets exactly one correlated genesis event with `resource_type='provider_action'`, `resource_id=intents.id`, `metadata.intentId`, via the required-audit outbox + crash-recovery sweeper). Forward-compat names for the split taxonomy are retained in `roleForAction` in case PR2 ever splits them.
- **C1/C3 CONFIRMED landed:** every PR3 approval event (`provider.approval.{decided,expired,staled}`, `provider.resume.ready`) and every PR4 execution event (`provider.execution.{authorized,claimed,denied_at_boundary,dispatched,succeeded,failed,outcome_unknown}`) sets `resource_type='provider_action'` + `resource_id=intents.id` + `metadata.intentId`. PR4 dispatched/terminal + PR4 authorized events carry `providerIdempotencyKeyHash` (sha256), NEVER the raw key (C3). The manifest's fallback `0083` functional index is therefore NOT needed (default: zero migration, as the C1-ratified plan intended).
- **C-DRIFT-2 (route mount, DESIGN NOTE):** the spec §6.3 says "add the two routes under the existing `auditRoutes` Hono app," but that app is mounted at `/audit`, while §5.1 mandates the paths `/v2/provider-actions/:id/{case,evidence}`. Resolution: the gate middleware was EXTRACTED (`middleware/audit-gate.ts`) and the case routes registered on a dedicated `/v2` sub-app using the IDENTICAL gate (never weaker), registered concretely BEFORE the `/v2` authority wildcard (same collision-avoidance pattern as `registerProviderActionRoutes`). This honors the §5.1 path contract AND the §6.3 "no weaker gate" constraint.
- **C-DRIFT-3 (workspace-scoped session access, DEFERRED per spec):** the shared gate admits tenant `owner`/`admin` sessions (carrying a tenant role), and those callers may read ANY workspace in their tenant (the §5.2 tenant-admin arm). Workspace-scoped `workspace_admin` / `workspace_auditor` SESSION access is deferred — the spec §5.2 itself lists workspace-auditor as "if later added," and the session gate carries a tenant role, not a workspace role. Reported here rather than silently narrowing.

### Test counts (all green)

- `provider-case-service.test.ts` — 9 (terminal-state mapping, mechanical completeness, foreign-tenant/workspace/nonexistent → null (D2), no raw idempotency key leak §3.4, N23 event-theft drop).
- `provider-case-evidence.integration.test.ts` — 15 (route + offline round-trip: N01/N02/N03, N04, N05, N06, N07, N08, N09, N11, N12, N17/N35, N24, N37/N38/N39, clean PASS w/wo fingerprint, access-denied honest complete).
- `provider-case-verifier.test.ts` — 10 (synthetic no-DB: N18, N19, N20, N22, N40, N43, N44, N45, clean, plain-bundle no-regression).
- `provider-case-purity.test.ts` — 2 (static pure-read assertion, deterministic manifest).
- `provider-case-honesty.test.ts` — 5 (chain_segment_broken → unknown KC07; genesis-never-drained → never complete KC14; concurrent reads identical KC04/KC06; row-absence honesty; effect surfacing).
- **PR5 total: 41/41.**
- **Regression (all pass):** `/audit/bundle` 12 (signAuditBundle factor-out, incl. offline verifier round-trip — no behavior change); PR3 approval lifecycle/negative/boundary + provider-action-service 56; PR3 approval route/concurrency + provider-x-governed-e2e 34; PR4 governed-execution 35.

### Mutation receipts (§9) — `packages/api/scripts/pr5-mutation-proofs.sh`

10 guards, each weakens ONE evidence predicate and must flip a passing test to failing. **Result: 10 killed, 0 survived.**

- M1 manifest hmac==bundle (N43), M2 forged-completeness (N09), M3 fingerprint trust-root (N17), M4 fact-backing (N08), M5 unknown-schema fail-closed (N44), M6 tenant cross-check (N22), M7 events-content digest (N19), M8 seq-bracket (N20), M9 metadata.intentId agreement (N23), M10 workspace scoping (D2 enumeration).

### Invariants held

- **E1/E2:** case id IS `intents.id`; no second identifier, no second ledger. Manifest is a derived index over already-committed audit rows + binding/nonce columns.
- **E3:** authenticity is transitive through the existing Ed25519 checkpoint; no new signature/key.
- **E4/E8:** completeness is mechanical; `outcome_unknown`-unreconciled / awaiting-terminal / broken-chain are honestly `incomplete`/`unknown`, never `complete`; unknown versions fail closed.
- **E5:** data-minimized — hashes/IDs/enums/integer status only; raw provider idempotency key hashed; safe summary re-redacted; denylist scanned.
- **E6/E7:** offline, no network, no Steward secret; operator-holds-both-keys limit stated in verifier output + docs.

### Honest gaps

1. **Governed-execution terminal states (`executing`/`succeeded`/`failed`/`outcome_unknown` via the PROXY path) are not seeded in PR5 unit tests.** The `succeeded`/`failed`/`outcome_unknown` binding states and the v2 execution nonce are produced by PR4's proxy `dispatchGovernedExecution`, which PR5 does not exercise (it's PR4's tested territory + needs the fake transport arriving in PR6). PR5 tests cover: the ALLOWED-stub path (`allowed_stub`→`succeeded`/`failed`), access-denied, pending, approved/execution_ready, plus the manifest's execution-fact plumbing via the verifier synthetic bundles and the terminal-state resolver unit-level. A full governed→executed→evidence e2e lands naturally in PR6 (golden path) which consumes `/evidence` + the verifier. The N25 (raw provider idempotency key) guard is enforced at the SOURCE (PR4 emits only the hash; asserted by the C3-confirmed anchor + the manifest's own hashing), and the leak-scan asserts absence in exported evidence.
2. **REPEATABLE READ isolation is best-effort on non-PGLite:** `SET TRANSACTION ISOLATION LEVEL` inside the tx is wrapped in try/catch (some drivers only honor isolation at BEGIN). The append-only monotonic chain makes a re-read safe regardless, and the manifest's seq+hmac index pins the case events; the evidence bundle read+sign runs just after the snapshot (immutable range) to avoid a write-inside-read-only-tx deadlock on PGLite's single connection. A true real-Postgres REPEATABLE-READ coherence CI assertion (KC01/KC06 on real PG) is deferred to the PR7 real-Postgres harness (the spec routes KC-on-real-PG there).
3. **Verifier `roleForAction`/`requiredRoles` are replicated** (the verifier has ZERO project imports by design). They mirror `@stwd/shared/provider-case.ts`; a drift would be caught by the round-trip integration tests (the API-produced manifest is verified by the script), but there is no compile-time link. A golden-vector cross-check test asserts the API canonicalizer and the verifier agree byte-for-byte on the checkpoint/events digest (via the existing audit-bundle offline round-trip).

DO NOT MERGE — opened for review.

— [sol-orch]
