# Workstream C working notes (#195) — governed wiring + E2E proof for X

Scratch notes for the implementer. Not shipped copy; kept in-tree so the design
decisions are reviewable alongside the code. The polished runbook lives in
`RUNBOOK-real-x-proof.md`.

## Two planes (confirmed by reading the github wiring end to end)

1. **Provider-action authority pipeline** (`packages/api`): propose
   (`POST /v2/provider-actions`) -> access -> policy
   (`composeProviderActionPolicyDecision`) -> approval arm (`provider-approval.ts`
   `buildApprovalArm`) -> human decide/resume (`provider-approvals.ts` +
   `ProviderApprovalService`) -> in-process **stub** executor
   (`executeProviderActionStub`). This is the LEGACY (pre-PR4) execution path on
   `develop`. It NEVER decrypts a credential or hits the wire. It records the
   binding, the commitment, and the audit chain.

2. **Proxy credential-route injection** (`packages/proxy`): the actual Bearer
   injection happens here via `secret_routes` (created with
   `SecretVault.createRoute`). Proven for github by
   `packages/proxy/src/__tests__/github-credential-route.test.ts` over the
   `__setForwardProxyRequestForTests` fake-transport seam: the proxy resolves the
   route -> secret id -> decrypts the CURRENT version -> injects
   `Authorization: Bearer <token>` upstream, and the agent's own JWT never leaks.

X is wired through BOTH planes exactly as github is: authority pipeline for
propose/policy/approval, proxy secret-route for the real byte-level injection.

## Drift decision (secret version bump between approval and execution)

**Decision: version drift STALES the action fail-closed. It does NOT silently
use the new token.** This is already MANDATED and IMPLEMENTED by PR3 — X inherits
it for free; I only prove it for X and cite it here.

- The approval commitment (`ProviderApprovalCommitmentV1.executionDependencies`)
  binds `{ routeId, routeRevision, secretId, secretVersion }`. `buildApprovalArm`
  sets `secretVersion = account.credentialVersion` at propose time
  (`provider-approval.ts`, service copy).
- At BOTH approve and safe-resume, `revalidateDependencies` checks:
  `account.credentialSecretId !== c.executionDependencies.secretId ||
   account.credentialVersion !== c.executionDependencies.secretVersion`
  -> returns `APPROVAL_CREDENTIAL_STALE` and `staleTransition(...)` moves the
  action to `approval_stale` (intent canceled), fail-closed.
- #197's refresh rotation bumps `provider_accounts.credential_version` (and
  repoints the secret_route to the new secret row via
  `rotateSecretWithinTx`). So a refresh landing between approval and execution
  is exactly a `credential_version` bump on the account row -> surfaces as
  `APPROVAL_CREDENTIAL_STALE`. The stale token is never used; the human must
  re-approve against the new version.
- This matches the task's rule verbatim: "if the commitment binds secretVersion,
  version drift must surface as the existing drift/stale error, NOT silently use
  the new version." No new policy invented; existing PR3 binding reused.

Spec citation: PR3 approval spec §5.1 (commitment executionDependencies) + §5.2
(dependency revalidation, credential staleness) — implemented at
`packages/api/src/services/provider-approval.ts` `revalidateDependencies`
(`APPROVAL_CREDENTIAL_STALE`).

## Minimal-touch wiring changes

- `@stwd/shared` `provider-approval.ts`: widen commitment
  `operation.canonicalProfile` from the github literal to a string union that
  also admits `x.provider-action.v1`. Pure type widening; JCS hashes whatever
  string is present, so no digest behavior change for github.
- `provider-authority-store.ts`: add `x` to `PROVIDER_OPERATION_ALLOWLIST`
  (`x.tweet.create`=POST, `x.tweet.delete`=DELETE, `x.user.me.read`=GET; widen
  the method union to include DELETE) + `PROVIDER_HOST_ALLOWLIST` (`x` ->
  `api.x.com`).
- `@stwd/vault` `secret-route-validator.ts`: add `api.x.com` to
  `DEFAULT_SECRET_ROUTE_HOSTS` and a `STRICT_HOSTS` entry (minPathSegments 2,
  requireExplicitMethod true, disallowPathWildcards true). All three X paths
  (`/2/tweets`, `/2/tweets/{id}`, `/2/users/me`) have >=2 segments.
- `proxy/config.ts`: add `x -> api.x.com` alias.
- `provider-action-service.ts`: accept `GithubActionBuild | XActionBuild`; derive
  the policy-context `host` from the action origin instead of hardcoding
  `api.github.com`. `canonicalProfile` on the commitment already flows from the
  operation profile via the approval arm change.
- `provider-actions.ts` route: dispatch X operation keys to `buildXAction`.

## NOT touched (PR4 in-flight on feat/execution-authorization-v2)

- No changes to proxy governed-execution v2 files, no migration 0082/0083.
- X rides the legacy stub authority path + the existing proxy secret-route
  injection, exactly like github today. `governed_v2` cutover for X happens
  with/after PR4 (noted in the PR body).

## Dashboard

Checked `apps/` + packages for an existing provider-accounts UI surface to
extend. If none exists that cheaply admits an X connect button + status + scopes,
this is filed as a follow-up in the PR rather than built here (avoids a UI
redesign in a wiring/proof PR).
