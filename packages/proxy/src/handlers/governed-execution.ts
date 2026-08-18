/**
 * governed-execution.ts — PR4 governed dispatch entry (spec §2.3, §4.1, §5.3,
 * §6). This is the ONLY caller allowed to reach a governed route's decrypt.
 *
 * WHY THIS LIVES IN @stwd/proxy (contradiction C2, resolved & reported): the
 * proxy runs as a SEPARATE PROCESS from the API and does NOT depend on @stwd/api,
 * yet §5.3 requires dispatchGovernedExecution to call handleProxy (which lives
 * here). So the claim + the governed handleProxy invocation live in the proxy;
 * the MINT stays in the API inside the PR3 resume tx. The v2 signing crypto is in
 * @stwd/shared so both sides agree. The claim is one atomic DB UPDATE regardless
 * of process, preserving X1-X4.
 *
 * FLOW (single writer, spec §2.3 / §4.1):
 *   1. load the execution_ready binding + its v2 nonce by intent_id;
 *   2. atomic single-winner claim UPDATE (every bound fact re-checked at DB time,
 *      X3/X4) + append provider.execution.claimed in the SAME audited tx (I14);
 *   3. signing-boundary revalidation (exact equality on route/operation/account/
 *      secret + verify the v2 signature, X5) — defense in depth beyond the claim;
 *   4. build the non-forgeable in-process governedExecutionClaim context and call
 *      handleProxy (which permits the already-selected governed route, §5.1);
 *   5. record the terminal dispatch outcome (succeeded / failed /
 *      outcome_unknown), NEVER a blind retry (X8).
 *
 * The governedExecutionClaim context is set ONLY here (never from a request
 * header/body/query/cookie), mirroring executePendingProxyRequest's
 * proxyApprovalRelease. No decrypt happens until AFTER the claim commits.
 */

import { createHash } from "node:crypto";
import {
  approvalQueue,
  executionAuthorizationNonces,
  getDb,
  intents,
  providerAccounts,
  providerActionBindings,
  providerOperations,
  secretRoutes,
  secrets,
  withTenantAuditedTransaction,
  workspaces,
} from "@stwd/db";
import {
  assertRegisteredProfile,
  buildProviderExecutionCommitmentV2,
  CanonError,
  computeActionDigest,
  computeApprovalCommitmentHash,
  computeProviderExecutionCommitmentHash,
  type GithubCanonicalActionV1,
  getProfileDescriptor,
  isExecutionAuthV2SecretConfigured,
  isGenericDescriptorError,
  isUnregisteredProfileError,
  jcsStringify,
  observeNonceClaimContention,
  type ProviderApprovalCommitmentV1,
  parseCanonicalProviderActionBytes,
  serializeCanonicalOutboundQuery,
  validateGenericHttpDescriptor,
  verifyProviderExecutionCommitmentV2,
  verifyProviderExecutionPolicyEvidence,
  verifyXSummonAttestation,
} from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";
import type { Context } from "hono";
import { handleProxy } from "./proxy";

// ─── Error codes (spec §6.1) ───────────────────────────────────────────────────

export type GovernedDispatchCode =
  | "EXEC_AUTH_NOT_READY"
  | "EXEC_AUTH_CLAIM_LOST"
  | "EXEC_AUTH_EXPIRED"
  | "EXEC_AUTH_STALE_ROUTE"
  | "EXEC_AUTH_STALE_SECRET"
  | "EXEC_AUTH_STALE_DEPENDENCY"
  | "EXEC_AUTH_ACCOUNT_DISABLED"
  | "EXEC_AUTH_KEY_UNAVAILABLE"
  | "EXEC_AUTH_SIGNATURE_INVALID"
  | "EXEC_AUTH_POLICY_EVIDENCE_MISSING"
  | "EXEC_AUTH_SUMMON_ATTESTATION_INVALID"
  | "EXEC_DISPATCH_OUTCOME_UNKNOWN"
  | "EXEC_DISPATCH_UPSTREAM_ERROR"
  | "EXEC_AUDIT_UNAVAILABLE"
  | "EXEC_TERMINAL_STATE";

export interface GovernedDispatchResult {
  ok: boolean;
  code: GovernedDispatchCode | "EXEC_DISPATCH_SUCCEEDED";
  httpStatus: number;
  intentId: string;
  executionId?: string;
  dispatchState?: string;
  upstreamStatusCode?: number;
}

// Test-only fault-injection hooks (production no-ops; not settable from runtime
// input). Named per spec §9 fault barriers.
export interface GovernedDispatchHooks {
  afterLoad?: () => void | Promise<void>;
  afterClaim?: () => void | Promise<void>;
  afterRevalidate?: () => void | Promise<void>;
  beforeForward?: () => void | Promise<void>;
  afterDispatchedAt?: () => void | Promise<void>;
  afterUpstream?: () => void | Promise<void>;
  beforeTerminal?: () => void | Promise<void>;
}

let dispatchHooks: GovernedDispatchHooks = {};
export function __setGovernedDispatchHooksForTests(hooks: GovernedDispatchHooks): void {
  dispatchHooks = hooks;
}
export function __resetGovernedDispatchHooksForTests(): void {
  dispatchHooks = {};
}
async function hook(name: keyof GovernedDispatchHooks): Promise<void> {
  const h = dispatchHooks[name];
  if (h) await h();
}

class AuditUnavailableError extends Error {}
// Thrown inside the claim tx when the binding was not execution_ready at claim
// time (codex P1a): rolls the whole claim back so the nonce is never consumed
// against a non-ready binding. Classified as a lost claim by the caller.
class BindingNotReadyError extends Error {}

interface LoadedGovernedExecution {
  intentId: string;
  tenantId: string;
  workspaceId: string;
  actorAgentId: string;
  authorizationId: string;
  nonce: string;
  executionId: string;
  providerAccountId: string;
  operationId: string;
  operationRevision: number;
  routeId: string;
  routeRevision: number;
  secretId: string;
  secretVersion: number;
  requestHash: string;
  actionDigest: string;
  commitmentHash: string;
  grantDependencyHash: string;
  providerIdempotencyKey: string;
  keyId: string;
  signature: string;
  approvalId: string;
  approvalCommitmentHash: string;
  approvalCommitment: ProviderApprovalCommitmentV1;
  canonicalAction: GithubCanonicalActionV1;
  requestId: string;
  dispatchState: string;
  authStatus: string;
  bindingStatus: string;
  executionPolicyDecisionId: string | null;
  executionPolicyRevisionHash: string | null;
  executionPolicyDecision: Record<string, unknown> | null;
  executionPolicyDecisionHash: string | null;
  executionPolicyEvaluatedAt: string | null;
  requestEnvelope: Record<string, unknown>;
  safeSummary: Record<string, unknown>;
  idempotencyKeyHash: string;
  issuedAt: string;
  expiresAt: string;
}

/** Pure final-boundary verifier used by dispatch and hostile tests. Absence is
 * valid for actions whose policy did not require summon provenance; a one-sided
 * or invalid persisted record is always a deny. */
export function verifyDispatchXSummonProvenance(input: {
  audience: string;
  tenantId: string;
  workspaceId: string;
  actorAgentId: string;
  providerAccountId: string;
  idempotencyKeyHash: string;
  requestHash: string;
  requestEnvelope: Record<string, unknown>;
  safeSummary: Record<string, unknown>;
  canonicalAction: GithubCanonicalActionV1;
  keysJson: string | undefined;
  now?: Date;
}): "absent" | "valid" | "invalid" {
  if (sha256Hex(jcsStringify(input.requestEnvelope)) !== input.requestHash) return "invalid";
  const summonDigest = input.requestEnvelope.xSummonAttestationDigest;
  const persistedAttestation = input.safeSummary.xSummonAttestation;
  if (summonDigest === undefined && persistedAttestation === undefined) return "absent";
  const body = input.canonicalAction.canonicalBody;
  const reply =
    body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>).reply
      : undefined;
  const sourcePostId =
    reply && typeof reply === "object" && !Array.isArray(reply)
      ? (reply as Record<string, unknown>).in_reply_to_tweet_id
      : undefined;
  if (typeof summonDigest !== "string" || typeof sourcePostId !== "string") return "invalid";
  const verification = verifyXSummonAttestation(
    persistedAttestation,
    {
      audience: input.audience,
      tenantId: input.tenantId,
      workspaceId: input.workspaceId,
      actorAgentId: input.actorAgentId,
      providerAccountId: input.providerAccountId,
      sourcePostId,
      idempotencyKeyHash: input.idempotencyKeyHash,
    },
    input.keysJson,
    input.now,
  );
  return verification.ok && verification.digest === summonDigest ? "valid" : "invalid";
}

/**
 * Load the execution_ready binding + its active v2 authorization by intent_id.
 * Returns null when the intent is not execution_ready or has no active v2 nonce.
 */
async function loadGovernedExecution(
  tenantId: string,
  intentId: string,
): Promise<LoadedGovernedExecution | null> {
  const db = getDb();
  const rows = await db
    .select({
      binding: providerActionBindings,
      nonce: executionAuthorizationNonces,
    })
    .from(providerActionBindings)
    .innerJoin(
      executionAuthorizationNonces,
      and(
        eq(executionAuthorizationNonces.intentId, providerActionBindings.intentId),
        eq(executionAuthorizationNonces.version, 2),
      ),
    )
    .where(
      and(
        eq(providerActionBindings.tenantId, tenantId),
        eq(providerActionBindings.intentId, intentId),
      ),
    )
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  const { binding, nonce } = row;

  // The persisted PR3 approval commitment lives on the approval_queue row; the
  // binding carries approval_queue_id. Reload it (jsonb) by that id.
  if (!binding.approvalQueueId) return null;
  const queueRows = await db
    .select({
      id: approvalQueue.id,
      approvalCommitment: approvalQueue.approvalCommitment,
      approvalCommitmentHash: approvalQueue.approvalCommitmentHash,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.tenantId, tenantId), eq(approvalQueue.id, binding.approvalQueueId)))
    .limit(1);
  const q = queueRows[0];
  if (!q || !q.approvalCommitment) return null;

  // Origin policy is independent of the action bytes. Fixed adapters use their
  // compile-time registry allowlist; config-driven operations use the validated
  // descriptor from the exact operation revision bound to this execution.
  const operationRows = await db
    .select({
      operationKey: providerOperations.operationKey,
      requestProfile: providerOperations.requestProfile,
      revision: providerOperations.revision,
    })
    .from(providerOperations)
    .where(
      and(
        eq(providerOperations.tenantId, tenantId),
        eq(providerOperations.workspaceId, binding.workspaceId),
        eq(providerOperations.providerAccountId, binding.providerAccountId),
        eq(providerOperations.id, binding.operationId),
      ),
    )
    .limit(1);
  const operation = operationRows[0];
  if (!operation) return null;
  if (operation.revision !== binding.operationRevision) {
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "operation revision does not match binding");
  }
  const profile = assertRegisteredProfile(binding.canonicalProfile);
  const profileDescriptor = getProfileDescriptor(profile);
  if (!profileDescriptor) return null;
  let allowedOrigins: readonly string[];
  if (profileDescriptor.kind === "adapter-fixed") {
    allowedOrigins = profileDescriptor.allowedOrigins;
  } else {
    if (operation.requestProfile.profile !== profile) {
      throw new CanonError("CANON_JSON_SHAPE_INVALID", "operation profile does not match binding");
    }
    allowedOrigins = [
      validateGenericHttpDescriptor(operation.requestProfile.operationDescriptor).origin,
    ];
  }

  const canonicalAction = parseGovernedCanonicalActionForDispatch(
    new Uint8Array(binding.canonicalActionBytes as Uint8Array),
    profile,
    allowedOrigins,
    operation,
  );

  return {
    intentId: binding.intentId,
    tenantId: binding.tenantId,
    workspaceId: binding.workspaceId,
    actorAgentId: binding.actorAgentId,
    authorizationId: nonce.authorizationId,
    nonce: nonce.nonce,
    executionId: nonce.executionId as string,
    providerAccountId: binding.providerAccountId,
    operationId: binding.operationId,
    operationRevision: binding.operationRevision,
    routeId: nonce.routeId as string,
    routeRevision: nonce.routeRevision as number,
    secretId: nonce.secretId as string,
    secretVersion: nonce.secretVersion as number,
    requestHash: nonce.requestHash as string,
    actionDigest: nonce.actionDigest as string,
    commitmentHash: nonce.commitmentHash as string,
    grantDependencyHash: nonce.grantDependencyHash as string,
    providerIdempotencyKey: nonce.providerIdempotencyKey as string,
    keyId: nonce.keyId as string,
    signature: nonce.signature,
    approvalId: q.id,
    approvalCommitmentHash: q.approvalCommitmentHash ?? "",
    approvalCommitment: q.approvalCommitment as unknown as ProviderApprovalCommitmentV1,
    canonicalAction,
    requestId: nonce.requestId,
    dispatchState: (nonce.dispatchState as string) ?? "none",
    authStatus: nonce.status,
    bindingStatus: binding.status,
    executionPolicyDecisionId: binding.executionPolicyDecisionId,
    executionPolicyRevisionHash: binding.executionPolicyRevisionHash,
    executionPolicyDecision: binding.executionPolicyDecision,
    executionPolicyDecisionHash: binding.executionPolicyDecisionHash,
    executionPolicyEvaluatedAt: binding.executionPolicyEvaluatedAt?.toISOString() ?? null,
    requestEnvelope: binding.requestEnvelope,
    safeSummary: binding.safeSummary,
    idempotencyKeyHash: binding.idempotencyKeyHash,
    issuedAt: (nonce.issuedAt as Date).toISOString(),
    expiresAt: (nonce.expiresAt as Date).toISOString(),
  };
}

export function parseGovernedCanonicalActionForDispatch(
  bytes: Uint8Array,
  expectedProfile: string,
  allowedOrigins: readonly string[],
  operation: { operationKey: string; requestProfile: Record<string, unknown> },
): GithubCanonicalActionV1 {
  return parseCanonicalProviderActionBytes(
    bytes,
    expectedProfile,
    allowedOrigins,
    operation,
  ) as GithubCanonicalActionV1;
}

function deny(
  code: GovernedDispatchCode,
  httpStatus: number,
  intentId: string,
  extra?: Partial<GovernedDispatchResult>,
): GovernedDispatchResult {
  if (code === "EXEC_AUTH_CLAIM_LOST") {
    try {
      observeNonceClaimContention();
    } catch {
      // Metrics are never allowed to affect the claim decision.
    }
  }
  return { ok: false, code, httpStatus, intentId, ...extra };
}

/**
 * Dispatch a governed, approved (execution_ready) provider action exactly once.
 *
 * @param intentId the PR3 intent (lifecycle root).
 * @param tenantId owning tenant.
 */
export async function dispatchGovernedExecution(
  intentId: string,
  tenantId: string,
): Promise<GovernedDispatchResult> {
  // Fail closed if the v2 secret is absent (X7, P48/F06). No decrypt, no claim.
  if (!isExecutionAuthV2SecretConfigured()) {
    return deny("EXEC_AUTH_KEY_UNAVAILABLE", 503, intentId);
  }

  let loaded: LoadedGovernedExecution | null;
  try {
    loaded = await loadGovernedExecution(tenantId, intentId);
  } catch (error) {
    // Corrupt/noncanonical persisted bytes are an authority dependency failure,
    // never an uncaught 500 and never a reason to claim/decrypt/forward.
    if (
      error instanceof CanonError ||
      isGenericDescriptorError(error) ||
      isUnregisteredProfileError(error)
    ) {
      return deny("EXEC_AUTH_STALE_DEPENDENCY", 409, intentId);
    }
    throw error;
  }
  await hook("afterLoad");
  if (!loaded) return deny("EXEC_AUTH_NOT_READY", 409, intentId);

  // Revalidate authenticated X summon provenance at the final dispatch
  // boundary. The request hash makes the attestation digest load-bearing; the
  // proxy independently verifies the adapter signature, exact scope/source and
  // current expiry before any claim or credential decrypt.
  const summonProvenance = verifyDispatchXSummonProvenance({
    ...loaded,
    audience: process.env.STEWARD_X_SUMMON_ATTESTATION_AUDIENCE ?? "",
    keysJson: process.env.STEWARD_X_SUMMON_ATTESTATION_PUBLIC_KEYS,
  });
  if (summonProvenance === "invalid") {
    return deny("EXEC_AUTH_SUMMON_ATTESTATION_INVALID", 409, intentId);
  }

  // Terminal / already-dispatched: never re-dispatch (X8, P26). A consumed nonce
  // with a terminal dispatch_state returns its current state without dispatching.
  // This is checked BEFORE the binding-ready guard so a re-read of an already
  // dispatched/outcome_unknown execution returns its true state (its binding is
  // no longer execution_ready by then).
  if (loaded.authStatus !== "active" || loaded.dispatchState !== "none") {
    if (loaded.dispatchState === "outcome_unknown")
      return deny("EXEC_DISPATCH_OUTCOME_UNKNOWN", 202, intentId, {
        executionId: loaded.executionId,
        dispatchState: loaded.dispatchState,
      });
    return deny("EXEC_TERMINAL_STATE", 409, intentId, {
      executionId: loaded.executionId,
      dispatchState: loaded.dispatchState,
    });
  }

  // #239 rollout boundary: a pre-0084 execution_ready row may carry a validly
  // signed legacy nonce but never have reserved the current cumulative cap.
  // Require and verify the execute-time decision before the claim/decrypt edge.
  const executionPolicy = loaded.executionPolicyDecision;
  if (
    !loaded.executionPolicyDecisionId ||
    !loaded.executionPolicyRevisionHash ||
    !executionPolicy ||
    !loaded.executionPolicyDecisionHash ||
    !loaded.executionPolicyEvaluatedAt ||
    !verifyProviderExecutionPolicyEvidence(executionPolicy, loaded.executionPolicyDecisionHash, {
      decisionId: loaded.executionPolicyDecisionId,
      intentId: loaded.intentId,
      requestHash: loaded.requestHash,
      actionDigest: loaded.actionDigest,
      operationId: loaded.operationId,
      operationKey: loaded.approvalCommitment.operation.key,
      policyRevisionHash: loaded.executionPolicyRevisionHash,
      decidedAt: loaded.executionPolicyEvaluatedAt,
    })
  ) {
    return deny("EXEC_AUTH_POLICY_EVIDENCE_MISSING", 409, intentId, {
      executionId: loaded.executionId,
    });
  }

  // For a FRESH (active nonce, dispatch_state='none') execution, the ONLY
  // dispatchable binding state is execution_ready (codex P1a, §2.2). A binding
  // that has advanced past execution_ready via another path (while its nonce
  // somehow lingers active/none) must never reach the claim. This is the early
  // read-side guard; the claim tx ALSO gates the execution_ready -> executing
  // transition atomically so a race cannot slip a non-ready binding through.
  if (loaded.bindingStatus !== "execution_ready") {
    return deny("EXEC_AUTH_NOT_READY", 409, intentId, { executionId: loaded.executionId });
  }

  // ── Signing-boundary revalidation (X5, §4.1 step 3) ────────────────────────
  // First recompute actionDigest from the persisted canonical action itself. The
  // commitment carries the approved digest, so merely rebuilding the commitment
  // without this equality would NOT detect a DB-level body/query mutation whose
  // target and header-name set stayed unchanged. This check makes the exact
  // outbound action bytes load-bearing at the final boundary.
  if (computeActionDigest(loaded.canonicalAction) !== loaded.actionDigest) {
    return deny("EXEC_AUTH_STALE_DEPENDENCY", 409, intentId, {
      executionId: loaded.executionId,
    });
  }

  // #201 fail-closed consumption site (proxy dispatch): the persisted canonical
  // action's profile MUST be a registered profile before we dispatch it
  // outbound. This is the last authority boundary; an unregistered profile in a
  // stored binding (corruption / a de-registered profile) is refused rather than
  // dispatched. github/x/generic-http all pass; anything else denies.
  try {
    assertRegisteredProfile(loaded.canonicalAction.profile);
  } catch (e) {
    if (isUnregisteredProfileError(e))
      return deny("EXEC_AUTH_STALE_DEPENDENCY", 409, intentId, {
        executionId: loaded.executionId,
      });
    throw e;
  }

  // Recompute the v2 commitment from the persisted approval + canonical action +
  // the mint's exact issuedAt/expiresAt/keyId (read from the nonce row), require
  // it equals the stored commitment_hash, and verify the HMAC signature over it.
  // This is exact-equality on route/operation/account/secret/approval commitment
  // + a domain-separated signature check BEFORE any decrypt (defense in depth
  // beyond the claim predicate; a tampered stored commitment_hash / signature is
  // caught here even if the claim's varchar equality somehow passed).
  if (computeApprovalCommitmentHash(loaded.approvalCommitment) !== loaded.approvalCommitmentHash) {
    return deny("EXEC_AUTH_STALE_DEPENDENCY", 409, intentId, {
      executionId: loaded.executionId,
    });
  }

  const rebuilt = buildProviderExecutionCommitmentV2({
    approval: loaded.approvalCommitment,
    action: loaded.canonicalAction,
    approvalCommitmentHash: loaded.approvalCommitmentHash,
    approvalId: loaded.approvalId,
    authorizationId: loaded.authorizationId,
    executionId: loaded.executionId,
    requestId: loaded.requestId,
    providerIdempotencyKey: loaded.providerIdempotencyKey,
    nonce: loaded.nonce,
    issuedAt: loaded.issuedAt,
    expiresAt: loaded.expiresAt,
    keyId: loaded.keyId,
  });
  if (
    computeProviderExecutionCommitmentHash(rebuilt) !== loaded.commitmentHash ||
    rebuilt.tenantId !== loaded.tenantId ||
    rebuilt.workspaceId !== loaded.workspaceId ||
    rebuilt.actorAgentId !== loaded.actorAgentId ||
    rebuilt.providerAccountId !== loaded.providerAccountId ||
    rebuilt.operationId !== loaded.operationId ||
    rebuilt.operationRevision !== loaded.operationRevision ||
    rebuilt.requestHash !== loaded.requestHash ||
    rebuilt.actionDigest !== loaded.actionDigest ||
    rebuilt.grantDependencyHash !== loaded.grantDependencyHash ||
    rebuilt.routeId !== loaded.routeId ||
    rebuilt.routeRevision !== loaded.routeRevision ||
    rebuilt.secretId !== loaded.secretId ||
    rebuilt.secretVersion !== loaded.secretVersion
  ) {
    // A bound fact drifted, a denormalized nonce/binding column was substituted,
    // or the stored hash was tampered. Fail before claim/decrypt.
    return deny("EXEC_AUTH_STALE_DEPENDENCY", 409, intentId, {
      executionId: loaded.executionId,
    });
  }
  let signatureValid: boolean;
  try {
    signatureValid = verifyProviderExecutionCommitmentV2(rebuilt, loaded.signature);
  } catch {
    // Secret unavailable at the verify boundary => fail closed (X7, P48).
    return deny("EXEC_AUTH_KEY_UNAVAILABLE", 503, intentId, {
      executionId: loaded.executionId,
    });
  }
  if (!signatureValid) {
    return deny("EXEC_AUTH_SIGNATURE_INVALID", 403, intentId, {
      executionId: loaded.executionId,
    });
  }

  // Pre-claim live-revision drift check (X5, P13/P14): the nonce bound the
  // route/secret revision at MINT time. If either rotated AFTER mint, the bound
  // value is stale vs live. Detect this BEFORE claiming so a rotated route/secret
  // fails closed with zero decrypt and the nonce is NOT consumed (it can only
  // expire). The claim predicate compares the nonce to itself, so live drift must
  // be caught here (and again in the boundary check, defense in depth).
  {
    const db = getDb();
    const [liveRoute] = await db
      .select({
        authorityRevision: secretRoutes.authorityRevision,
        mode: secretRoutes.authorityMode,
        providerOperationId: secretRoutes.providerOperationId,
        secretId: secretRoutes.secretId,
      })
      .from(secretRoutes)
      .where(and(eq(secretRoutes.tenantId, tenantId), eq(secretRoutes.id, loaded.routeId)))
      .limit(1);
    if (
      !liveRoute ||
      liveRoute.mode !== "governed_v2" ||
      liveRoute.authorityRevision !== loaded.routeRevision ||
      liveRoute.secretId !== loaded.secretId
    ) {
      return deny("EXEC_AUTH_STALE_ROUTE", 409, intentId, { executionId: loaded.executionId });
    }
    // Route↔operation binding (codex P2): the nonce binds routeId and operationId
    // independently, and provider_operations.secret_route_id is NOT unique, so a
    // governed route configured for operation A must not be usable to inject a
    // credential for a DIFFERENT operation B. The authority_revision bump (0082
    // trigger) catches a RECONFIGURATION of THIS route, but not the case where a
    // nonce for operation B references a route whose provider_operation_id points
    // at operation A. Assert the live route is still bound to exactly the minted
    // operation before any decrypt — fail closed on mismatch.
    if (liveRoute.providerOperationId !== loaded.operationId) {
      return deny("EXEC_AUTH_STALE_ROUTE", 409, intentId, { executionId: loaded.executionId });
    }
    const [liveSecret] = await db
      .select({ version: secrets.version })
      .from(secrets)
      .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, loaded.secretId)))
      .limit(1);
    if (!liveSecret || liveSecret.version !== loaded.secretVersion) {
      return deny("EXEC_AUTH_STALE_SECRET", 409, intentId, { executionId: loaded.executionId });
    }
  }
  await hook("afterRevalidate");

  // ── Atomic single-winner claim (spec §2.3, X3/X4) ──────────────────────────
  // Every bound fact is re-checked at DB time in the SAME statement. Zero rows =>
  // claim lost (expired / already consumed / any bound fact drifted). The claim +
  // its audit commit atomically via withTenantAuditedTransaction (I14/G3).
  let claimed = false;
  let claimReason: GovernedDispatchCode | null = null;
  try {
    await withTenantAuditedTransaction(tenantId, async (tx, appendRequiredAudit) => {
      const dbTx = tx as ReturnType<typeof getDb>;
      const updated = await dbTx
        .update(executionAuthorizationNonces)
        .set({
          status: "consumed",
          consumedAt: new Date(),
          dispatchState: "claimed",
        })
        .where(
          and(
            eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId),
            eq(executionAuthorizationNonces.nonce, loaded.nonce),
            eq(executionAuthorizationNonces.version, 2),
            eq(executionAuthorizationNonces.status, "active"),
            sql`${executionAuthorizationNonces.expiresAt} > now()`,
            eq(executionAuthorizationNonces.tenantId, tenantId),
            eq(executionAuthorizationNonces.workspaceId, loaded.workspaceId),
            eq(executionAuthorizationNonces.agentId, loaded.actorAgentId),
            eq(executionAuthorizationNonces.executionId, loaded.executionId),
            eq(executionAuthorizationNonces.intentId, loaded.intentId),
            eq(executionAuthorizationNonces.providerAccountId, loaded.providerAccountId),
            eq(executionAuthorizationNonces.operationId, loaded.operationId),
            eq(executionAuthorizationNonces.operationRevision, loaded.operationRevision),
            eq(executionAuthorizationNonces.routeId, loaded.routeId),
            eq(executionAuthorizationNonces.routeRevision, loaded.routeRevision),
            eq(executionAuthorizationNonces.secretId, loaded.secretId),
            eq(executionAuthorizationNonces.secretVersion, loaded.secretVersion),
            eq(executionAuthorizationNonces.requestHash, loaded.requestHash),
            eq(executionAuthorizationNonces.actionDigest, loaded.actionDigest),
            eq(executionAuthorizationNonces.commitmentHash, loaded.commitmentHash),
          ),
        )
        .returning({ id: executionAuthorizationNonces.id });

      if (updated.length === 0) {
        // Losers of a concurrent race (or drift) do NOT dispatch. We still need
        // to classify why so callers get the exact §6.1 code; do a lightweight
        // re-read AFTER the failed claim.
        return;
      }

      // Advance the binding execution_ready -> executing (§2.2) in the SAME tx and
      // make that transition part of the claim success condition (codex P1a): the
      // nonce claim and the binding lifecycle are one atomic step, so a nonce can
      // NEVER be consumed while the binding is not execution_ready (e.g. already
      // terminal from another path). The PR3 transition trigger requires
      // binding_revision to increment by exactly 1. If the scoped update affects
      // ZERO rows, the binding was not in execution_ready → roll the whole claim
      // back (no consumed nonce, no dispatch, fail closed).
      const bindingAdvanced = await dbTx
        .update(providerActionBindings)
        .set({
          status: "executing",
          bindingRevision: sql`${providerActionBindings.bindingRevision} + 1`,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(providerActionBindings.tenantId, tenantId),
            eq(providerActionBindings.intentId, loaded.intentId),
            eq(providerActionBindings.status, "execution_ready"),
            eq(
              providerActionBindings.executionPolicyDecisionHash,
              loaded.executionPolicyDecisionHash as string,
            ),
          ),
        )
        .returning({ intentId: providerActionBindings.intentId });
      if (bindingAdvanced.length === 0) {
        // The binding was NOT execution_ready (terminal / rolled back / raced).
        // Undo the nonce claim by throwing to roll back the whole tx, then
        // classify as a lost claim (no dispatch, X4/§2.2).
        throw new BindingNotReadyError();
      }

      try {
        await appendRequiredAudit({
          tenantId,
          actorType: "system",
          actorId: "steward-system",
          action: "provider.execution.claimed",
          resourceType: "provider_action",
          resourceId: loaded.intentId,
          metadata: {
            schemaVersion: "steward.provider-execution-audit.v1",
            intentId: loaded.intentId,
            executionId: loaded.executionId,
            authorizationId: loaded.authorizationId,
            dispatchState: "claimed",
            routeId: loaded.routeId,
            routeRevision: loaded.routeRevision,
            secretVersion: loaded.secretVersion,
            commitmentHash: loaded.commitmentHash,
            providerIdempotencyKeyHash: sha256Hex(loaded.providerIdempotencyKey),
          },
        });
      } catch (e) {
        throw new AuditUnavailableError((e as Error).message);
      }
      claimed = true;
    });
  } catch (e) {
    if (e instanceof AuditUnavailableError) {
      // The whole claim tx rolled back (F07/P50/K11): nonce stays active, no
      // decrypt. Fail closed.
      return deny("EXEC_AUDIT_UNAVAILABLE", 503, intentId);
    }
    if (e instanceof BindingNotReadyError) {
      // The nonce claim rolled back because the binding was not execution_ready
      // (codex P1a): the nonce is NOT consumed, nothing dispatched. Classify as a
      // lost claim (the binding lifecycle, not the nonce, is the blocker).
      return deny("EXEC_AUTH_CLAIM_LOST", 409, intentId, { executionId: loaded.executionId });
    }
    throw e;
  }
  await hook("afterClaim");

  if (!claimed) {
    claimReason = await classifyClaimFailure(tenantId, loaded);
    return deny(claimReason, claimReason === "EXEC_AUTH_EXPIRED" ? 410 : 409, intentId, {
      executionId: loaded.executionId,
    });
  }

  // ── Post-claim boundary account/workspace status check (§4.1 step 3) ───────
  // The claim SQL cannot express account/workspace disabled as an equality, so
  // re-check here BEFORE decrypt. A disabled-but-same-revision account fails.
  const boundary = await revalidateAccountBoundary(tenantId, loaded);
  await hook("afterRevalidate");
  if (!boundary.ok) {
    await recordPreDispatchDenial(tenantId, loaded, boundary.code);
    return deny(boundary.code, 409, intentId, { executionId: loaded.executionId });
  }

  // ── Dispatch exactly once via handleProxy with the governed context ────────
  await hook("beforeForward");
  return dispatchOnce(tenantId, loaded);
}

// sha256 hex-prefixed (audit records the HASH of the provider idempotency key,
// NEVER the raw key — PR5 C3 data minimization).
function sha256Hex(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

/**
 * Classify why a claim returned zero rows by re-reading the current nonce/route/
 * secret state. Non-enumerating: any foreign/absent yields a generic lost code.
 */
async function classifyClaimFailure(
  tenantId: string,
  loaded: LoadedGovernedExecution,
): Promise<GovernedDispatchCode> {
  const db = getDb();
  const rows = await db
    .select({ nonce: executionAuthorizationNonces })
    .from(executionAuthorizationNonces)
    .where(
      and(
        eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId),
        eq(executionAuthorizationNonces.version, 2),
      ),
    )
    .limit(1);
  const n = rows[0]?.nonce;
  if (!n) return "EXEC_AUTH_CLAIM_LOST";
  if (n.status === "revoked") return "EXEC_AUTH_STALE_ROUTE";
  if (n.status === "expired") return "EXEC_AUTH_EXPIRED";
  if (n.status === "consumed") return "EXEC_AUTH_CLAIM_LOST"; // another winner (K01/P43)
  // DB-time expiry FIRST (X4): an active nonce past its deadline is expired, not
  // stale. Classify it as expired before checking route/secret drift.
  if (n.expiresAt && (n.expiresAt as Date).getTime() <= Date.now()) return "EXEC_AUTH_EXPIRED";
  // Still active, unexpired, but claim lost => a bound fact drifted. Distinguish.
  const routeRows = await db
    .select({ authorityRevision: secretRoutes.authorityRevision })
    .from(secretRoutes)
    .where(and(eq(secretRoutes.tenantId, tenantId), eq(secretRoutes.id, loaded.routeId)))
    .limit(1);
  const currentRouteRev = routeRows[0]?.authorityRevision;
  if (currentRouteRev !== undefined && currentRouteRev !== loaded.routeRevision)
    return "EXEC_AUTH_STALE_ROUTE";
  const secretRows = await db
    .select({ version: secrets.version })
    .from(secrets)
    .where(and(eq(secrets.tenantId, tenantId), eq(secrets.id, loaded.secretId)))
    .limit(1);
  const currentSecretVer = secretRows[0]?.version;
  if (currentSecretVer !== undefined && currentSecretVer !== loaded.secretVersion)
    return "EXEC_AUTH_STALE_SECRET";
  // Expiry at DB time.
  const expRows = await db
    .select({ expiresAt: executionAuthorizationNonces.expiresAt })
    .from(executionAuthorizationNonces)
    .where(eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId))
    .limit(1);
  if (expRows[0]?.expiresAt && expRows[0].expiresAt.getTime() <= Date.now())
    return "EXEC_AUTH_EXPIRED";
  return "EXEC_AUTH_STALE_DEPENDENCY";
}

async function revalidateAccountBoundary(
  tenantId: string,
  loaded: LoadedGovernedExecution,
): Promise<{ ok: true } | { ok: false; code: GovernedDispatchCode }> {
  const db = getDb();
  // Workspace status: a disabled/revoked workspace must fail closed before any
  // decrypt (codex P1b). The claim SQL cannot express the workspace status.
  const wsRows = await db
    .select({ status: workspaces.status })
    .from(workspaces)
    .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, loaded.workspaceId)))
    .limit(1);
  const ws = wsRows[0];
  if (!ws || ws.status !== "active") return { ok: false, code: "EXEC_AUTH_ACCOUNT_DISABLED" };

  // Provider account: must exist, be active, AND live in the bound workspace
  // (scope the lookup by workspace so a same-id account moved/rebound elsewhere
  // cannot pass, mirroring the approval boundary).
  const accRows = await db
    .select({ status: providerAccounts.status, revision: providerAccounts.revision })
    .from(providerAccounts)
    .where(
      and(
        eq(providerAccounts.tenantId, tenantId),
        eq(providerAccounts.workspaceId, loaded.workspaceId),
        eq(providerAccounts.id, loaded.providerAccountId),
      ),
    )
    .limit(1);
  const acc = accRows[0];
  if (!acc || acc.status !== "active") return { ok: false, code: "EXEC_AUTH_ACCOUNT_DISABLED" };
  if (acc.revision !== loaded.approvalCommitment.providerAccount.revision)
    return { ok: false, code: "EXEC_AUTH_STALE_DEPENDENCY" };

  // Provider operation: must exist, be active, live in the bound workspace +
  // account, AND its revision must still equal the committed one (codex P1b: the
  // operation STATUS and scope were not checked before). A disabled operation or
  // a revision drift fails closed.
  const opRows = await db
    .select({ status: providerOperations.status, revision: providerOperations.revision })
    .from(providerOperations)
    .where(
      and(
        eq(providerOperations.tenantId, tenantId),
        eq(providerOperations.workspaceId, loaded.workspaceId),
        eq(providerOperations.providerAccountId, loaded.providerAccountId),
        eq(providerOperations.id, loaded.operationId),
      ),
    )
    .limit(1);
  const op = opRows[0];
  if (!op || op.status !== "active") return { ok: false, code: "EXEC_AUTH_ACCOUNT_DISABLED" };
  if (op.revision !== loaded.operationRevision)
    return { ok: false, code: "EXEC_AUTH_STALE_DEPENDENCY" };
  return { ok: true };
}

async function recordPreDispatchDenial(
  tenantId: string,
  loaded: LoadedGovernedExecution,
  code: GovernedDispatchCode,
): Promise<void> {
  // Pre-dispatch post-claim denial: dispatch_state 'failed', binding 'failed'
  // (§2.2, §4.1 step 3). Never re-open the claim.
  await withTenantAuditedTransaction(tenantId, async (tx, appendRequiredAudit) => {
    const dbTx = tx as ReturnType<typeof getDb>;
    await dbTx
      .update(executionAuthorizationNonces)
      .set({ dispatchState: "failed", dispatchedAt: new Date(), outcomeRecordedAt: new Date() })
      .where(eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId));
    // Pre-dispatch denial happens AFTER the claim already transitioned the
    // binding execution_ready -> executing (the claim tx set status='executing',
    // dispatch_state='claimed'). The boundary account/dependency check then fails
    // BEFORE any decrypt/forward, so the legal binding transition here is
    // executing -> failed (both execution_ready->failed and executing->failed are
    // admitted by the 0082 transition trigger; the live precursor is executing).
    await dbTx
      .update(providerActionBindings)
      .set({
        status: "failed",
        bindingRevision: sql`${providerActionBindings.bindingRevision} + 1`,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerActionBindings.tenantId, tenantId),
          eq(providerActionBindings.intentId, loaded.intentId),
          eq(providerActionBindings.status, "executing"),
        ),
      );
    await dbTx
      .update(intents)
      .set({ status: "failed", failedBy: "steward-system", failedAt: new Date() })
      .where(eq(intents.id, loaded.intentId));
    await appendRequiredAudit({
      tenantId,
      actorType: "system",
      actorId: "steward-system",
      action: "provider.execution.denied_at_boundary",
      resourceType: "provider_action",
      resourceId: loaded.intentId,
      metadata: {
        schemaVersion: "steward.provider-execution-audit.v1",
        intentId: loaded.intentId,
        executionId: loaded.executionId,
        authorizationId: loaded.authorizationId,
        dispatchState: "failed",
        reasonCode: code,
      },
    });
  });
}

/**
 * Build the non-forgeable in-process governedExecutionClaim context and call
 * handleProxy exactly once, then record the terminal outcome (§4.1 steps 4-6).
 */
async function dispatchOnce(
  tenantId: string,
  loaded: LoadedGovernedExecution,
): Promise<GovernedDispatchResult> {
  // Rebuild the outbound query from the CANONICAL orderedQueryPairs (spec §5.4),
  // never from a raw stored string.
  const outboundQuery = serializeCanonicalOutboundQuery(loaded.canonicalAction.orderedQueryPairs);
  const host = new URL(loaded.canonicalAction.origin).host;
  const path = `/proxy/${host}${loaded.canonicalAction.normalizedPath}`;
  const search = outboundQuery === "" ? "" : `?${outboundQuery}`;
  const url = `https://steward-proxy.local${path}${search}`;

  const method = loaded.canonicalAction.method;
  const headers = new Headers();
  for (const [name, value] of loaded.canonicalAction.selectedHeaders) headers.set(name, value);
  // Serialize the outbound body with the SAME JCS serializer that computed the
  // canonical action digest + v2 signature (codex P2). JSON.stringify does NOT
  // guarantee JCS key ordering (e.g. integer-like keys sort differently), so it
  // could send bytes that were never authorized. jcsStringify(canonicalBody) is
  // byte-identical to what canonicalActionBytes committed.
  const bodyBytes =
    loaded.canonicalAction.canonicalBody === null
      ? undefined
      : new TextEncoder().encode(jcsStringify(loaded.canonicalAction.canonicalBody));
  const request = new Request(url, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : bodyBytes,
  });

  const responseHeaders = new Headers();
  const context = {
    req: {
      method,
      path,
      raw: request,
      header: (name: string) => request.headers.get(name) ?? undefined,
    },
    get: (key: string) => {
      if (key === "agentId") return loaded.actorAgentId;
      if (key === "tenantId") return tenantId;
      if (key === "governedExecutionClaim")
        return {
          authorizationId: loaded.authorizationId,
          executionId: loaded.executionId,
          routeId: loaded.routeId,
          // Carry the CLAIMED route revision + secret binding so the proxy gate can
          // fail closed if the route/secret was rotated between the claim and the
          // decrypt (codex P1 stale-credential race): a matching routeId alone is
          // not sufficient because the current route.secretId/version drives the
          // decrypt. The proxy gate re-verifies these against the live route.
          routeRevision: loaded.routeRevision,
          secretId: loaded.secretId,
          secretVersion: loaded.secretVersion,
          workspaceId: loaded.workspaceId,
          providerAccountId: loaded.providerAccountId,
          operationId: loaded.operationId,
          operationRevision: loaded.operationRevision,
          providerAccountRevision: loaded.approvalCommitment.providerAccount.revision,
        };
      return undefined;
    },
    header: (name: string, value: string) => responseHeaders.set(name, value),
    json: (payload: unknown, status?: number) =>
      new Response(JSON.stringify(payload), {
        status: status ?? 200,
        headers: {
          "content-type": "application/json",
          ...Object.fromEntries(responseHeaders.entries()),
        },
      }),
  } as unknown as Context;

  // Mark dispatched BEFORE awaiting the upstream body so a crash mid-flight
  // leaves an evidenced `dispatched` (→ reconciler treats as outcome_unknown,
  // F03/K08). Never blind retry (X8).
  const dispatchMarked = await setDispatched(tenantId, loaded);
  if (!dispatchMarked) {
    // Another state transition won after claim. Never forward unless this caller
    // atomically owns claimed -> dispatched and its required audit committed.
    return deny("EXEC_TERMINAL_STATE", 409, loaded.intentId, {
      executionId: loaded.executionId,
      dispatchState: "claimed",
    });
  }
  await hook("afterDispatchedAt");

  let response: Response;
  try {
    response = await handleProxy(context);
  } catch {
    // Timeout / connection reset / abort AFTER dispatch => outcome_unknown,
    // NEVER auto-retry (X8, K13/K14).
    await hook("afterUpstream");
    await recordTerminal(tenantId, loaded, "outcome_unknown", undefined);
    return deny("EXEC_DISPATCH_OUTCOME_UNKNOWN", 202, loaded.intentId, {
      executionId: loaded.executionId,
      dispatchState: "outcome_unknown",
    });
  }
  await hook("afterUpstream");

  const upstreamStatus = response.status;
  // Drain/cancel the proxy response body on EVERY governed path (codex P2). The
  // dispatcher records only the OUTCOME; it never streams the body back to a
  // client. handleProxy releases its in-flight proxy slot via
  // releaseWhenBodyCloses, so an unconsumed streaming body would leak that slot
  // and eventually reject later requests for this agent/tenant with a 429. We
  // cancel after reading status (and, for the 502 case, after cloning to inspect
  // the forward-failure envelope). cancel() on an already-consumed/absent body is
  // a safe no-op.
  // Fire-and-forget: cancel() releases the proxy slot when the underlying body
  // acknowledges, but we must NOT await it on the outcome path — a slow/parked
  // upstream body could otherwise block the terminal recording indefinitely. The
  // slot release happens asynchronously via releaseWhenBodyCloses' cancel().
  const drainBody = (r: Response): void => {
    void Promise.resolve()
      .then(() => r.body?.cancel())
      .catch(() => {
        // Best-effort: a body that already errored/closed cannot leak the slot.
      });
  };
  // Classification (spec §4.1 step 5, X8). handleProxy collapses a FORWARD-level
  // failure (connection reset / timeout / DNS / abort AFTER we set dispatched_at)
  // into its own 502 JSON envelope `{ ok:false, error:"Upstream request failed" }`.
  // That case is genuinely AMBIGUOUS — we sent the request but never got a clean
  // upstream response, so we CANNOT prove the provider had no effect → it MUST be
  // outcome_unknown (never a blind retry, X8), NOT a definitive `failed`. A status
  // that actually came FROM the upstream (a received 2xx/3xx/4xx/5xx) is
  // unambiguous. We detect the proxy's own forward-failure envelope by its exact
  // shape so a genuine upstream 502 is still classified as a definitive failure.
  const isSuccess = upstreamStatus >= 200 && upstreamStatus < 400;
  await hook("beforeTerminal");
  if (isSuccess) {
    drainBody(response);
    await recordTerminal(tenantId, loaded, "succeeded", upstreamStatus);
    return {
      ok: true,
      code: "EXEC_DISPATCH_SUCCEEDED",
      httpStatus: upstreamStatus,
      intentId: loaded.intentId,
      executionId: loaded.executionId,
      dispatchState: "succeeded",
      upstreamStatusCode: upstreamStatus,
    };
  }

  // Distinguish proxy-generated pre-forward boundary denials from actual
  // upstream responses. These exact envelopes are produced only by the governed
  // decrypt boundary and must preserve their authority code, not be mislabeled as
  // provider failures. Also distinguish the proxy's ambiguous forward-failure
  // envelope from a genuine upstream 502.
  let proxyError: string | undefined;
  if (upstreamStatus === 409 || upstreamStatus === 502 || upstreamStatus === 503) {
    try {
      const parsed = (await response.clone().json()) as { ok?: boolean; error?: string };
      if (parsed?.ok === false) proxyError = parsed.error;
    } catch {
      proxyError = undefined;
    }
  }
  const forwardLevelFailure = upstreamStatus === 502 && proxyError === "Upstream request failed";
  // Cancel the original body (the 502 branch cloned it; every other error status
  // never touched it) so the proxy in-flight slot is released (codex P2).
  drainBody(response);
  if (forwardLevelFailure) {
    // Sent-but-no-clean-response → outcome_unknown, NEVER auto-retry (X8, K13/K14).
    await recordTerminal(tenantId, loaded, "outcome_unknown", undefined);
    return deny("EXEC_DISPATCH_OUTCOME_UNKNOWN", 202, loaded.intentId, {
      executionId: loaded.executionId,
      dispatchState: "outcome_unknown",
    });
  }

  const governedBoundaryCodes: Partial<Record<string, GovernedDispatchCode>> = {
    EXEC_AUTH_ACCOUNT_DISABLED: "EXEC_AUTH_ACCOUNT_DISABLED",
    EXEC_AUTH_STALE_DEPENDENCY: "EXEC_AUTH_STALE_DEPENDENCY",
    EXEC_AUTH_STALE_SECRET: "EXEC_AUTH_STALE_SECRET",
  };
  const governedBoundaryCode = proxyError ? governedBoundaryCodes[proxyError] : undefined;
  if (governedBoundaryCode) {
    await recordTerminal(tenantId, loaded, "failed", undefined);
    return deny(governedBoundaryCode, upstreamStatus, loaded.intentId, {
      executionId: loaded.executionId,
      dispatchState: "failed",
    });
  }
  if (proxyError === "EXEC_AUDIT_UNAVAILABLE") {
    // The proxy already released all resources. Required terminal audit is also
    // unavailable, so retain dispatched for reconciliation rather than inventing
    // a terminal record with no evidence.
    return deny("EXEC_AUDIT_UNAVAILABLE", 503, loaded.intentId, {
      executionId: loaded.executionId,
      dispatchState: "dispatched",
    });
  }

  await recordTerminal(tenantId, loaded, "failed", upstreamStatus);
  return deny("EXEC_DISPATCH_UPSTREAM_ERROR", 502, loaded.intentId, {
    executionId: loaded.executionId,
    dispatchState: "failed",
    upstreamStatusCode: upstreamStatus,
  });
}

async function setDispatched(tenantId: string, loaded: LoadedGovernedExecution): Promise<boolean> {
  let marked = false;
  await withTenantAuditedTransaction(tenantId, async (tx, appendRequiredAudit) => {
    const dbTx = tx as ReturnType<typeof getDb>;
    const updated = await dbTx
      .update(executionAuthorizationNonces)
      .set({ dispatchState: "dispatched", dispatchedAt: new Date() })
      .where(
        and(
          eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId),
          eq(executionAuthorizationNonces.tenantId, tenantId),
          eq(executionAuthorizationNonces.status, "consumed"),
          eq(executionAuthorizationNonces.dispatchState, "claimed"),
        ),
      )
      .returning({ id: executionAuthorizationNonces.id });
    if (updated.length !== 1) return;
    await appendRequiredAudit({
      tenantId,
      actorType: "system",
      actorId: "steward-system",
      action: "provider.execution.dispatched",
      resourceType: "provider_action",
      resourceId: loaded.intentId,
      metadata: {
        schemaVersion: "steward.provider-execution-audit.v1",
        intentId: loaded.intentId,
        executionId: loaded.executionId,
        authorizationId: loaded.authorizationId,
        dispatchState: "dispatched",
        providerIdempotencyKeyHash: sha256Hex(loaded.providerIdempotencyKey),
      },
    });
    marked = true;
  });
  return marked;
}

async function recordTerminal(
  tenantId: string,
  loaded: LoadedGovernedExecution,
  state: "succeeded" | "failed" | "outcome_unknown",
  upstreamStatusCode: number | undefined,
): Promise<void> {
  const bindingStatus =
    state === "succeeded" ? "succeeded" : state === "failed" ? "failed" : "outcome_unknown";
  await withTenantAuditedTransaction(tenantId, async (tx, appendRequiredAudit) => {
    const dbTx = tx as ReturnType<typeof getDb>;
    await dbTx
      .update(executionAuthorizationNonces)
      .set({ dispatchState: state, outcomeRecordedAt: new Date() })
      .where(eq(executionAuthorizationNonces.authorizationId, loaded.authorizationId));
    // executing -> succeeded|failed|outcome_unknown (§2.2). Bump binding_revision
    // by exactly 1 (PR3 trigger convention) and scope by the executing precursor.
    await dbTx
      .update(providerActionBindings)
      .set({
        status: bindingStatus,
        bindingRevision: sql`${providerActionBindings.bindingRevision} + 1`,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerActionBindings.tenantId, tenantId),
          eq(providerActionBindings.intentId, loaded.intentId),
          eq(providerActionBindings.status, "executing"),
        ),
      );
    // intents mapping (§2.2): succeeded -> executed; failed -> failed;
    // outcome_unknown -> stays authorized (no confirmed effect).
    if (state === "succeeded") {
      await dbTx
        .update(intents)
        .set({ status: "executed", executedBy: "steward-system", executedAt: new Date() })
        .where(eq(intents.id, loaded.intentId));
    } else if (state === "failed") {
      await dbTx
        .update(intents)
        .set({ status: "failed", failedBy: "steward-system", failedAt: new Date() })
        .where(eq(intents.id, loaded.intentId));
    }
    const action =
      state === "succeeded"
        ? "provider.execution.succeeded"
        : state === "failed"
          ? "provider.execution.failed"
          : "provider.execution.outcome_unknown";
    await appendRequiredAudit({
      tenantId,
      actorType: "system",
      actorId: "steward-system",
      action,
      resourceType: "provider_action",
      resourceId: loaded.intentId,
      metadata: {
        schemaVersion: "steward.provider-execution-audit.v1",
        intentId: loaded.intentId,
        executionId: loaded.executionId,
        authorizationId: loaded.authorizationId,
        dispatchState: state,
        ...(upstreamStatusCode !== undefined ? { upstreamStatusCode } : {}),
        providerIdempotencyKeyHash: sha256Hex(loaded.providerIdempotencyKey),
      },
    });
  });
}
