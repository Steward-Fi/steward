# PR4 Worklog — execution authorization v2 + governed proxy cutover

Branch: feat/execution-authorization-v2 off develop 95dd2a4 (PR2 #191, PR3 #192 merged)
Journal max = 0081 → my migration = 0082

## Verified preconditions
- [x] develop tip = 95dd2a4 (#192 PR3)
- [x] 0081 landed authority_revision + bump trigger (G1 option a) — DO NOT re-add
- [x] 0080 created provider_action_bindings + provider_action_audit_outbox
- [x] journal max = 0081 → 0082 is mine
- [x] verify execution_authorization_nonces v1 columns (schema) — v2 columns landed in commit 128e054
- [x] verify audit-chain.ts withTenantAuditedTransaction primitive (audit-chain.ts:431, AppendRequiredAudit:407, AuditEventInput:184)
- [x] verify provider-action.ts JCS helper (PR2) — jcsStringify:520, computeActionDigest:719, computeProviderExecutionCommitmentHash, providerExecutionSignatureInput all present
- [x] verify PR3 provider-approval.ts resume path (execution_ready entry) — resume() at :1333, mint hook point = right before `provider.resume.ready` append at ~:1450
- [x] SOURCE OF TRUTH for v2 commitment = queue.approvalCommitment (jsonb ProviderApprovalCommitmentV1) persisted on approval_queue: carries executionDependencies{routeId,routeRevision,secretId,secretVersion}, accessDecision{id,hash,matchedGrants[],matchedBindings[]}, policyDecision{policyRevisionHash,hash}, operation{id,revision}, requestHash, actionDigest, approvalCommitmentHash(=binding.approvalCommitmentHash). binding.requestEnvelope(jsonb) = PR2 ProviderRequestEnvelopeV1 for target/normalizedPath/method/host + orderedQueryPairs + selectedHeaders.
- [x] baseline green on resume: 8 crypto (api) + 11 migration (db) tests pass; @stwd/shared + @stwd/redis tsc clean; bun install no-op.

## RESUME POINT (fresh session 2026-07-14 20:40)
Prior attempt DID commit 3 units (128e054 schema+migration, 123c42a v2 signing, 1d49fdb move crypto to shared). Continue from commit plan step 4.
NEXT: provider-execution.ts (mint-within-tx + commitment builder from approvalCommitment + dispatch orchestration) → proxy governed gate → plugin gate → compose wiring → negative/concurrency/mutation suites.

## Spec deltas from brief
- 0082 carries: nonce v2 extension + secret_routes {authority_mode, provider_operation_id} + secret_route_authority_mode enum + governed CHECK. NOT authority_revision (in 0081).
- 0082 bump trigger: EXTEND 0081's steward_bump_secret_route_authority_revision() predicate to include authority_mode + provider_operation_id.
- audit metadata: providerIdempotencyKeyHash (sha256), NEVER raw key.
- lifecycle events: resource_type='provider_action', resource_id=intents.id (PR5 C1).

## Commit plan (small logical commits, Author Sol <sol@shad0w.xyz>)
1. 0082 migration + schema.ts extensions + drizzle journal + migration CI test
2. execution-contract.ts v2 type + provider-action.ts v2 commitment JCS helper + golden vectors
3. execution-authorization.ts v2 mint/verify (HKDF, keyId rotation, fail-closed)
4. provider-execution.ts (mint + dispatchGovernedExecution + claim SQL + revalidation + reconcile)
5. proxy.ts governed gate + matching + auth context + query-forwarding governed path
6. plugin-capabilities invoke.ts governed block + OpenAI adapter block
7. compose/env.example/deploy STEWARD_EXECUTION_AUTH_SECRET wiring
8. static inventory test + negative matrix (§8, 54) + concurrency (§9, 22) + mutation proofs script

## Design decisions (integration seams)
- MINT: inside PR3 resume() tx (spec §2.3 preferred, removes crash window). provider-execution.ts exposes `mintProviderExecutionAuthorizationWithinTx(tx, appendRequiredAudit, {intentId, binding, queue, commitment})` called at the END of PR3 resume() right after execution_ready is set + before its provider.resume.ready append (so authorized event + resume.ready both in one tx). Guarded by exec_auth_nonces_intent_uniq (F01/K22 idempotency).
  - All the bound facts come from the PR3 approval commitment (route/routeRevision, secret/secretVersion, operation/opRevision, account, access/policy hashes, approvalCommitmentHash) + binding columns. grantDependencyHash = sha256(JCS(sorted matched binding+grant ids/revisions from commitment.accessDecision)). providerIdempotencyKey minted server-side (uuid) at mint.
- CLAIM: dispatchGovernedExecution(intentId) in provider-execution.ts — loads execution_ready binding+v2 nonce by intent_id, runs §2.3 atomic claim UPDATE (raw SQL, all bound facts), on win builds in-process proxy context w/ governedExecutionClaim ctx key, calls handleProxy.
- PROXY GATE: proxy.ts after findMatchingRoute (line ~1090, before injectAs==='query' check at 1110): if route.authorityMode==='governed_v2' AND no governedExecutionClaim ctx (or routeId mismatch) => 403 GOVERNED_ROUTE_DIRECT_DENIED. Unknown authority_mode => default-deny. governedExecutionClaim NEVER from header (mirror proxyApprovalRelease).
- QUERY: governed path rebuilds outbound query from PR2 orderedQueryPairs (canonical serialization) not extractRawQuery. Recompute actionDigest, require == claimed before dispatch.
- forwarder stub: reuse existing forwardProxyRequestForHandler seam (setForwarder) — PR6 owns real sandbox.

## Open contradictions to report (do not silently resolve)
- **C2 (RESOLVED by package placement, reported):** The PROXY runs as a SEPARATE PROCESS from the API (`packages/proxy/src/index.ts` header: "Runs as a separate process from the main Steward API"). Proxy deps = @stwd/{auth,db,redis,vault,shared}; it does NOT depend on @stwd/api. But spec §0.2/§5.3 place `dispatchGovernedExecution` in `packages/api/src/services/provider-execution.ts` AND require it to "call handleProxy" (handleProxy lives in @stwd/proxy). That is impossible in-process across the api->(no proxy dep) boundary.
  - RESOLUTION: split along the real dependency graph. (1) v2 signing crypto MOVED from api into @stwd/shared (pure crypto, no DB; proxy already deps shared) so the proxy claim can verify. (2) MINT stays in api `provider-execution.ts`, invoked inside PR3 resume() tx (mint-within-tx). (3) `dispatchGovernedExecution` + the atomic claim + governed handleProxy call live in `packages/proxy/src/handlers/governed-execution.ts` (proxy owns handleProxy + the in-process context injection pattern from release.ts). Shared claim-predicate builder + commitment builder live in a module both can import (@stwd/db for the SQL, @stwd/shared for crypto/commitment). This preserves X1-X4 (claim is one atomic DB UPDATE regardless of process) and the verifier-only decrypt boundary. Reported, not silently resolved.
- **C1 (RESOLVED in-migration, faithful to spec intent):** spec §1.2 & §1.1 require composite FKs `secret_routes_provider_operation_fk (tenant_id, provider_operation_id) -> provider_operations (tenant_id, id)` and `exec_auth_nonces_operation_fk` references `provider_operations (tenant_id, workspace_id, provider_account_id, id)` (that 4-col key EXISTS). But the 2-col target `provider_operations (tenant_id, id)` does NOT exist on develop — PR1's 0079 only created `(tenant_id, workspace_id, provider_account_id, id)` UNIQUE + single-col PK `id`. The spec's stated FK target `(tenant_id, id)` is unsatisfiable as written.
  - RESOLUTION: 0082 adds `provider_operations_tenant_id_id_uniq UNIQUE (tenant_id, id)` (mirrors exactly how PR2's 0080 added `intents_tenant_id_id_uniq` for the same reason). This preserves the spec's tenant-scoped composite-FK guarantee for the route->operation FK. The nonce->operation FK keeps the 4-col target as spec'd (exists). Reported, not silently resolved.
