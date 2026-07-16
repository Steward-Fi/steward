# PR6 anchor re-verification (against develop d2bf7ce, 2026-07-16)

Spec was written at PR2-era develop (a1dcd75) and requires re-verification post
PR3/PR4/PR5 (§10). Verified against actual develop tip `d2bf7ce`.

## Confirmed anchors (spec § / line drift)

- **Migrations:** 0081 = `exact_approval_binding` (PR3), 0082 =
  `execution_authorization_v2` (PR4). PR5 (case/evidence) landed with **NO
  migration** (spec's `0083`-if-needed fallback was NOT taken). **PR6 adds NO
  migration.** Next free number would be 0083.
- **Proxy test seam:** `__setForwardProxyRequestForTests` at `proxy.ts:1052`
  (spec said :1039), `let forwardProxyRequestForHandler: ProxyForwarder =
  forwardWithVettedDns` at :1050, `type ProxyForwarder = typeof
  forwardWithVettedDns` at :1049. Signature (url, method, headers, body,
  records) matches spec §2.3 exactly. `verifyProxyHostResolvesPublicly` at :846
  and invoked before the forward. **U1 seam intact.**
- **PR4 dispatch:** `packages/proxy/src/handlers/governed-execution.ts`
  `dispatchGovernedExecution(intentId, tenantId)` present; fails closed on absent
  `STEWARD_EXECUTION_AUTH_SECRET` (`EXEC_AUTH_KEY_UNAVAILABLE` 503, P48/F06);
  terminal/outcome_unknown replay guards present.
- **PR4 mint:** `packages/api/src/services/provider-execution.ts`
  `mintProviderExecutionAuthorizationWithinTx`, `hashProviderIdempotencyKey`
  (hash-only, D3 confirmed).
- **PR3 routes:** `provider-approvals.ts` mounts GET/POST
  `/v2/provider-actions/:id/approval` + POST `/execute`. `providerApprovalService.resume()`
  mints the v2 nonce idempotently for `execution_ready` bindings.
- **PR5 routes:** `provider-case.ts` mounts GET `/v2/provider-actions/:id/{case,evidence}`
  with `tenantAuth` + `auditOwnerAdminMfaGate`. Manifest carries
  `completeness`/`incompletenessReasons`/`terminalState`/`missingRequiredRoles`
  verbatim. Folded genesis event confirmed (single
  `provider.action.{allowed,denied,approval_required}` event).
- **Verifier fingerprint flag:** `scripts/verify-evidence-bundle.mjs` supports
  `--expected-key-fingerprint`/`--fp` (G3 resolved by PR5).
- **G2 (env wiring) RESOLVED by PR4:** `STEWARD_EXECUTION_AUTH_SECRET` is already
  in `packages/cli/src/init.ts:71`, `packages/cli/src/doctor.ts:40`, and
  `deploy/enterprise-reference/docker-compose.yml:44,90`. **PR6 verifies only,
  does NOT double-add.**
- **D1/D2/D3:** revision-binding chain, resource_id retrofit, and
  providerIdempotencyKeyHash all landed; no blocking drift.

## Contradictions reported (follow CODE as landed)

- **C1 (read op terminates at in-process stub, NOT the governed forwarder).**
  On develop, an ALLOWED read op (`github.issue.list`) runs
  `executeProviderActionStub` (an in-process echo of operationId/actionDigest)
  and NEVER reaches `dispatchGovernedExecution`/`forwardProxyRequestForHandler`.
  Only the **write/approval** path (`github.pr.comment.create` → approve →
  resume → dispatch) traverses the governed forwarder. The spec (§2.2 M02)
  assumed reads dispatch through the forwarder too. PR6 therefore rides the fake
  forwarder proof on the **write** operation (M04/M14). The read leg still proves
  the full access→policy→allow authority path (its terminal transport is the
  stub, which is transport-independent from the forwarder-vetting concern). This
  is not a defect; it is the landed dispatch topology.

- **C2 (X provider is live; spec is github-only).** `x.provider-action.v1` is in
  the profile CHECK with full-chain E2Es on develop
  (`packages/shared/src/x-provider-action.ts`). Spec predates this. PR6 ADDS an X
  leg to the fake-transport matrix where cheap (X write via the same governed
  path) and documents the abstraction generalizes beyond GitHub.

- **C3 (PR5 shipped no migration).** Spec's `0083`-if-needed correlation index
  was not needed; PR3 retrofitted `resource_id` onto the genesis events (D2
  resolved the honest way), so PR5 needed no fallback index. PR6 accounts for
  migrations ending at 0082.

## Codex review round 1 (resolved)

Codex flagged 3 contract mismatches in the added CLI/dashboard surfaces (fixed):
- **[P1]** dashboard approve/deny omitted the route-required `idempotencyKey`
  (`APPROVAL_FIELD_INVALID`). Now derives a stable per-decision key matching the
  route's `IDEM_KEY_RE` (`/^[\x21-\x7e]{8,255}$/`).
- **[P2]** CLI `create` sent `{action, idempotencyKeyHash}`; the route's strict
  top-level schema accepts `{workspaceId, providerAccountId, operationKey,
  arguments, idempotencyKey}`. Fixed.
- **[P2]** CLI `approve/deny` omitted `idempotencyKey`. Fixed (flag or derived).
All three verified against the exact route validation code (not just the review).
