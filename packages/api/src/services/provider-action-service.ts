/**
 * provider-action-service.ts — the PR2 provider-action authority pipeline.
 *
 * Given a verified provider principal + a validated GitHub action build, this
 * service runs the transactional authority pipeline (spec §6.4):
 *
 *   1. Resolve the scoped workspace/account/operation. An unresolved or foreign
 *      tuple writes REQUIRED denial audit and returns SCOPE_RESOURCE_NOT_FOUND
 *      (404) WITHOUT creating an intent (spec §1.8).
 *   2. In ONE transaction: insert the intents root; evaluate access against
 *      stable revisions; evaluate exact-action policy ONLY if access allows;
 *      insert one complete provider_action_bindings row; enqueue the REQUIRED
 *      audit event into the transactional outbox; commit.
 *   3. Drain the outbox into the tamper-evident audit chain. A drain failure
 *      denies (EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE, 503) with the stub count
 *      still zero.
 *   4. Only on a committed allow/allow decision, call the in-process executor
 *      stub (never a real credential/network). Its result maps status
 *      allowed_stub -> stub_succeeded | stub_failed.
 *
 * Idempotent replay with the SAME complete binding returns the existing state;
 * a reused key with any different binding is REPLAY_IDEMPOTENCY_CONFLICT (409).
 *
 * The service NEVER decrypts a credential, calls the proxy, mints execution
 * authorization, or performs network I/O. That is PR4.
 */

import { randomUUID } from "node:crypto";
import {
  agents,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  workspaces,
} from "@stwd/db";
import {
  composeProviderActionPolicyDecision,
  cumulativeSpendBucketKey,
  MAX_AGGREGATE_WINDOW_SECONDS,
  type ProviderPolicyContext,
  type ProviderPolicyEvaluationV1,
  type ProviderPolicyRule,
  windowedInvokeBucketKey,
} from "@stwd/policy-engine";
import type { GithubActionBuild } from "@stwd/provider-github";
import type { XActionBuild } from "@stwd/provider-x";
import {
  assertRegisteredProfile,
  buildGenericHttpAction,
  CanonError,
  computeProviderPolicyInputDigest,
  type GenericHttpActionBuild,
  type GenericHttpCanonicalActionV1,
  GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  type GithubCanonicalActionV1,
  isConfigDrivenProfile,
  isGenericDescriptorError,
  jcsStringify,
  type ProviderRequestEnvelopeV1,
  sha256HexPrefixed,
  UnregisteredProfileError,
  validateGenericHttpDescriptor,
  type XCanonicalActionV1,
} from "@stwd/shared";

/**
 * The provider-action pipeline is adapter-agnostic: it reads only the generic
 * canonical-action fields (profile/method/origin/normalizedPath/query/headers/
 * body), the validated `policyArgs`, and the `safeSummary`. github and X builds
 * are structurally compatible on all of those, so the pipeline accepts either.
 * Adding a new adapter is a matter of extending this union, never forking the
 * pipeline.
 */
/**
 * A build produced by an adapter-fixed profile (github/x) or the config-driven
 * generic-http profile. All three are structurally compatible on the fields the
 * pipeline reads (action.profile/method/origin/path/query/headers/body,
 * policyArgs, safeSummary), so the pipeline consumes them uniformly.
 */
export type ConcreteProviderActionBuild =
  | GithubActionBuild
  | XActionBuild
  | GenericHttpActionBuild;

/**
 * #201: a DEFERRED build for a config-driven (generic-http) operation. The route
 * cannot canonicalize it because the operator-authored descriptor lives on the
 * resolved provider_operations row. The service finalizes it (loads + validates
 * the descriptor, then `buildGenericHttpAction`) immediately after scope
 * resolution, BEFORE any digest is computed.
 */
export interface DeferredGenericBuild {
  kind: "deferred-generic";
  operationKey: string;
  method: string | undefined;
  args: unknown;
}

export type ProviderActionBuild = ConcreteProviderActionBuild | DeferredGenericBuild;
/** The structurally-shared canonical action shape every adapter emits. */
type AnyCanonicalActionV1 =
  | GithubCanonicalActionV1
  | XCanonicalActionV1
  | GenericHttpCanonicalActionV1;

function isDeferredGenericBuild(b: ProviderActionBuild): b is DeferredGenericBuild {
  return (b as DeferredGenericBuild).kind === "deferred-generic";
}

import {
  type CumulativeSpendScope,
  releaseCumulativeSpend,
  releaseWindowedInvoke,
  reserveCumulativeSpend,
  reserveWindowedInvoke,
  settleCumulativeSpend,
} from "@stwd/redis";
import { and, eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { appendAuditEvent, withTenantAuditQueue, writeAuditEvent } from "./audit";
import { ApprovalArmError, buildApprovalArm } from "./provider-approval";

const EVALUATOR_VERSION = "provider-action.v1";
const POLICY_TYPE = "capability-intent" as const;

/**
 * A handle to an atomic cumulative-spend reservation (#206) so the pipeline can
 * SETTLE it (known-success) or RELEASE it (known-failure/deny). On
 * outcome_unknown the pipeline deliberately does NEITHER - the reservation ages
 * out at the window edge (fail closed for a money cap: never free budget that
 * may have really spent).
 */
export interface CumulativeSpendReservationHandle {
  /** the spend-STREAM identity (scope+scopeKey+currency); NOT the cap threshold
   *  (cap edits must not orphan a reservation). */
  stream: {
    agentId: string;
    scope: CumulativeSpendScope;
    scopeKey: string;
    currency: string;
  };
  reservationId: string;
  amount: number;
}

/** A handle to an atomic windowed-invoke (maxCalls) reservation (#206). */
export interface WindowedInvokeReservationHandle {
  agentId: string;
  operationKey: string;
  reservationId: string;
}

// ─── Public result envelope ───────────────────────────────────────────────────

export type ProviderActionOutcome =
  | { kind: "scope_not_found"; code: "SCOPE_RESOURCE_NOT_FOUND"; httpStatus: 404 }
  | {
      kind: "access_denied";
      code: string;
      httpStatus: 403;
      intentId: string;
      requestHash: string;
      actionDigest: string;
    }
  | {
      kind: "policy_denied";
      code: string;
      httpStatus: 403 | 503;
      intentId: string;
      requestHash: string;
      actionDigest: string;
    }
  | {
      kind: "approval_required";
      code: "APPROVAL_REQUIRED";
      httpStatus: 202;
      intentId: string;
      requestHash: string;
      actionDigest: string;
    }
  | {
      kind: "allowed";
      code: "POLICY_ALLOW";
      httpStatus: 200;
      intentId: string;
      requestHash: string;
      actionDigest: string;
      stub: ProviderActionStubResult;
    }
  | {
      kind: "replay_conflict";
      code: "REPLAY_IDEMPOTENCY_CONFLICT";
      httpStatus: 409;
    }
  | {
      kind: "evidence_failure";
      code:
        | "EVIDENCE_DECISION_PERSIST_FAILED"
        | "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE"
        | "APPROVAL_QUORUM_CONFIG_INVALID";
      httpStatus: 503 | 422;
      intentId?: string;
    }
  | {
      kind: "backend_unavailable";
      code: "BACKEND_STUB_UNAVAILABLE";
      httpStatus: 503;
      intentId: string;
      requestHash: string;
      actionDigest: string;
    };

export interface ProviderActionStubResult {
  ok: boolean;
  status: "stub_succeeded" | "stub_failed";
  echo: { operationId: string; actionDigest: string };
}

export interface CreateProviderActionInput {
  principal: ProviderPrincipalV1;
  workspaceId: string;
  providerAccountId: string;
  operationKey: string;
  build: ProviderActionBuild;
  idempotencyKeyHash: string;
  requestedAt: string;
  expiresAt: string;
  nonce: string;
  /** Audit provenance (never authority). */
  requestId?: string | null;
}

// ─── The in-process executor stub (PR2 only — NEVER real dispatch) ─────────────

/**
 * The PR2 executor stub. It accepts ONLY a persisted intent id and reloads the
 * immutable facts; it accepts no replacement action or identity. It performs no
 * credential decrypt and no network I/O. A successful stub call is NOT proof of
 * credential-bound enforcement (that is PR4).
 */
export async function executeProviderActionStub(
  intentId: string,
): Promise<ProviderActionStubResult> {
  const db = getDb();
  const [binding] = await db
    .select({
      operationId: providerActionBindings.operationId,
      actionDigest: providerActionBindings.actionDigest,
      status: providerActionBindings.status,
    })
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId))
    .limit(1);
  if (!binding || binding.status !== "allowed_stub") {
    // Only an allow-committed binding may be executed. Anything else is a bug or
    // a race; treat as a failed stub without side effects.
    return {
      ok: false,
      status: "stub_failed",
      echo: { operationId: binding?.operationId ?? "", actionDigest: binding?.actionDigest ?? "" },
    };
  }
  return {
    ok: true,
    status: "stub_succeeded",
    echo: { operationId: binding.operationId, actionDigest: binding.actionDigest },
  };
}

// ─── Decision documents (spec §6.1 / §6.2) ────────────────────────────────────

interface DependencyRevisions {
  actor: number;
  workspace: number;
  providerAccount: number;
  operation: number;
  bindings: Array<{ id: string; revision: number }>;
  grants: Array<{ id: string; revision: number }>;
}

interface PersistedAccessDecisionV1 {
  schemaVersion: "steward.provider-access-decision.v1";
  decisionId: string;
  intentId: string;
  tenantId: string;
  workspaceId: string;
  actor: { type: "agent"; id: string };
  providerAccountId: string;
  operationId: string;
  operationKey: string;
  environment: "development" | "staging" | "production";
  effect: "allow" | "deny";
  reasonCode: string;
  matchedBindingIds: string[];
  matchedGrantIds: string[];
  dependencyRevisions: DependencyRevisions;
  decidedAt: string;
}

interface PersistedPolicyDecisionV1 {
  schemaVersion: "steward.provider-policy-decision.v1";
  decisionId: string;
  intentId: string;
  requestHash: string;
  actionDigest: string;
  operationId: string;
  operationKey: string;
  effect: "hard_deny" | "approval_required" | "allow";
  reasonCodes: string[];
  policyResults: Array<{
    policyId: string;
    policyType: "capability-intent";
    applicable: true;
    configuredEffect: "allow" | "deny" | "require-approval";
    outcome: "pass" | "hard_deny" | "approval_required";
    reasonCode: string;
    ruleRevisionHash: string;
  }>;
  policyRevisionHash: string;
  evaluatorVersion: string;
  decidedAt: string;
}

function byUuidBytes(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function ruleRevisionHash(rule: {
  id: string;
  type: string;
  enabled: boolean;
  config: Record<string, unknown>;
}): string {
  return sha256HexPrefixed(
    jcsStringify({ id: rule.id, type: rule.type, enabled: rule.enabled, config: rule.config }),
  );
}

// ─── Deny mapping ─────────────────────────────────────────────────────────────

// Access denials on resolved resources are always 403 (spec §8: GRANT_*). Policy
// denials split 403/503 by code, so only the policy map needs code-specific status.
const POLICY_DENY_HTTP: Record<string, number> = {
  POLICY_NO_GOVERNING_ALLOW: 403,
  POLICY_HARD_DENY: 403,
  POLICY_CONFIGURATION_INVALID: 403,
  POLICY_INPUT_UNAVAILABLE: 503,
  POLICY_EVALUATOR_ERROR: 503,
};

// ─── Service ──────────────────────────────────────────────────────────────────

/**
 * The subset of the drizzle db handle the evaluators use. Both the top-level db
 * and a `db.transaction(tx => ...)` executor satisfy it, so access + policy can
 * be evaluated INSIDE the persisting transaction against the SAME committed
 * snapshot as the binding insert (closes the eval->commit TOCTOU window; the FK
 * constraints then guarantee the referenced rows still exist at commit).
 */
type DbBase = ReturnType<typeof getDb>;
/** The db handle OR a transaction executor — both support the queries the
 *  evaluators run, so access/policy can be evaluated inside the tx. */
type DbExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];

/** The non-null policy evaluation result shape (access=allow path). */
type PolicyResult = {
  doc: PersistedPolicyDecisionV1;
  evaluation: ProviderPolicyEvaluationV1;
  decisionId: string;
  cumulativeSpendReservations: CumulativeSpendReservationHandle[];
  windowedInvokeReservation?: WindowedInvokeReservationHandle;
};

class ProviderActionService {
  private db() {
    return getDb();
  }

  /**
   * The provider-action pipeline entry point. See file header for the ordered
   * transactional contract.
   */
  async createProviderAction(input: CreateProviderActionInput): Promise<ProviderActionOutcome> {
    const { principal } = input;
    const inputBuild = input.build;
    const tenantId = principal.tenantId;
    const actorAgentId = principal.agentId;

    // ── Step 1: resolve scope (pre-intent). Unresolved/foreign => 404 + audit. ──
    // Idempotent replay is checked AFTER scope resolution (we key on the resolved
    // operation id). The idempotency composite unique index + request-hash unique
    // index additionally enforce this at the storage layer.
    const resolved = await this.resolveScope(
      tenantId,
      input.workspaceId,
      input.providerAccountId,
      input.operationKey,
    );
    if (!resolved) {
      // For a deferred generic build the descriptor lives on the (missing)
      // operation row, so there is no canonical action to digest yet; use a
      // stable per-request placeholder digest for the denial audit. A concrete
      // build digests its already-canonicalized action.
      const scopeDenyDigest = isDeferredGenericBuild(inputBuild)
        ? sha256HexPrefixed(
            jcsStringify({
              profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
              scope: "unresolved",
            }),
          )
        : sha256HexPrefixed(jcsStringify(this.canonicalActionObject(inputBuild.action)));
      await this.writeRequiredDenialAudit(tenantId, {
        action: "provider.action.denied",
        resourceType: "provider-action",
        resourceId: `${input.workspaceId}:${input.providerAccountId}:${input.operationKey}`,
        metadata: {
          reasonCode: "SCOPE_RESOURCE_NOT_FOUND",
          actorAgentId,
          actionDigest: scopeDenyDigest,
          requestId: input.requestId ?? null,
        },
      });
      return { kind: "scope_not_found", code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
    }

    const { workspace, account, operation } = resolved;
    const environment = workspace.environment as PersistedAccessDecisionV1["environment"];

    // ── #201: finalize a deferred generic-http build now that the operation
    // (and its operator-authored descriptor) is resolved. Fail closed on an
    // unregistered profile or an invalid descriptor with a stable CANON_* code
    // (mapped to a 400 deny by the route). The descriptor is loaded from the
    // resolved operation's requestProfile; the tx snapshot re-reads the same
    // row, and the operation is immutable-except-status, so this pre-tx read is
    // consistent with the tx build.
    let build: ConcreteProviderActionBuild;
    try {
      build = isDeferredGenericBuild(inputBuild)
        ? this.finalizeGenericBuild(inputBuild, operation.requestProfile)
        : inputBuild;
    } catch (e) {
      if (e instanceof UnregisteredProfileError) throw new CanonError(e.code);
      if (isGenericDescriptorError(e)) throw new CanonError("CANON_PROFILE_UNSUPPORTED", e.code);
      throw e;
    }

    // #201 fail-closed consumption site: the canonical profile stamped on the
    // action MUST be registered before we digest/store/dispatch it. An
    // unregistered profile (e.g. a corrupted or forged build) is rejected here
    // with a stable code rather than persisted.
    try {
      assertRegisteredProfile(build.action.profile);
    } catch (e) {
      if (e instanceof UnregisteredProfileError) throw new CanonError(e.code);
      throw e;
    }

    // Compute the canonical action digest + request envelope/hash up-front (they
    // are pure and needed for the binding + idempotency conflict check).
    const actionDigest = sha256HexPrefixed(jcsStringify(this.canonicalActionObject(build.action)));
    // Idempotency identity includes every adapter-validated policy input, not
    // only the outbound HTTP action. This is deliberately a separate,
    // domain-separated digest: policy-only signals such as X `summoned` must
    // conflict when changed without contaminating the canonical action digest.
    // `policyText` is a separate in-memory channel and is never included here.
    const policyInputDigest = computeProviderPolicyInputDigest(build.policyArgs);
    const canonicalBytes = jcsStringify(this.canonicalActionObject(build.action));

    // Idempotency replay lookup on the real operation id.
    const [priorBinding] = await this.db()
      .select()
      .from(providerActionBindings)
      .where(
        and(
          eq(providerActionBindings.tenantId, tenantId),
          eq(providerActionBindings.workspaceId, input.workspaceId),
          eq(providerActionBindings.actorAgentId, actorAgentId),
          eq(providerActionBindings.operationId, operation.id),
          eq(providerActionBindings.idempotencyKeyHash, input.idempotencyKeyHash),
        ),
      )
      .limit(1);
    if (priorBinding) {
      // A replay MUST match both the durable outbound action and the validated
      // policy inputs that authorized it. requestedAt/nonce differ per call, so
      // requestHash itself is not the replay key. New bindings persist the
      // policy-input digest inside their immutable, request-hash-bound envelope.
      // Legacy envelopes have no such member and retain the historical
      // action-only replay behavior; this is a bounded compatibility path for
      // pre-rollout rows, never used by a newly-created binding.
      const persistedPolicyInputDigest = (priorBinding.requestEnvelope as Record<string, unknown>)
        .policyInputDigest;
      if (
        priorBinding.actionDigest !== actionDigest ||
        (persistedPolicyInputDigest !== undefined &&
          persistedPolicyInputDigest !== policyInputDigest)
      ) {
        return {
          kind: "replay_conflict",
          code: "REPLAY_IDEMPOTENCY_CONFLICT",
          httpStatus: 409,
        };
      }
      return await this.outcomeFromBinding(priorBinding);
    }

    const intentId = `pa_${randomUUID()}`;

    // ── Step 2: single transaction — reload the account + operation, evaluate
    // access + policy against that fresh tx snapshot, and persist intent + binding
    // + required-audit outbox in the SAME transaction (closes the eval->commit
    // TOCTOU window entirely; the strict composite FKs also guarantee the rows
    // still exist at commit). The request envelope binds the operation revision
    // read INSIDE the tx. ──
    const accessDecisionId = randomUUID();
    // Outer-scope handles the tx fills so the post-commit branching can read them.
    let access!: { effect: "allow" | "deny"; doc: PersistedAccessDecisionV1 };
    let policy: PolicyResult | null = null;
    // #206: hoisted so the catch/drain-failure paths can reclaim reservations
    // even where TS narrows `policy` to never inside the tx-callback flow.
    let cumulativeSpendReservations: CumulativeSpendReservationHandle[] = [];
    let windowedInvokeReservation: WindowedInvokeReservationHandle | undefined;
    let requestHash = "";
    const effects: {
      access: "allow" | "deny";
      policy: "not_evaluated" | "hard_deny" | "approval_required" | "allow";
      status: string;
    } = { access: "deny", policy: "not_evaluated", status: "denied" };

    try {
      await this.db().transaction(async (tx) => {
        // Reload the account + operation by identity INSIDE the tx so access,
        // policy, and the persisted operation revision all read the SAME snapshot.
        // If either was concurrently deleted, the tx-scoped scope is gone: deny as
        // scope-not-found equivalent (persistence will fail closed anyway).
        const [txAccount] = await tx
          .select()
          .from(providerAccounts)
          .where(
            and(
              eq(providerAccounts.tenantId, tenantId),
              eq(providerAccounts.workspaceId, input.workspaceId),
              eq(providerAccounts.id, account.id),
            ),
          )
          .limit(1);
        const [txOperation] = await tx
          .select()
          .from(providerOperations)
          .where(
            and(
              eq(providerOperations.tenantId, tenantId),
              eq(providerOperations.workspaceId, input.workspaceId),
              eq(providerOperations.providerAccountId, account.id),
              eq(providerOperations.id, operation.id),
            ),
          )
          .limit(1);
        if (!txAccount || !txOperation) {
          throw new Error("provider-action: scope disappeared inside transaction");
        }

        // Bind the request envelope to the tx-read operation revision.
        const envelope = this.buildEnvelope(input, {
          tenantId,
          actorAgentId,
          providerAccountId: txAccount.id,
          operationId: txOperation.id,
          operationRevision: txOperation.revision,
          actionDigest,
          policyInputDigest,
        });
        requestHash = sha256HexPrefixed(jcsStringify(this.envelopeObject(envelope)));

        // Access is evaluated against the tx snapshot rows.
        access = await this.evaluateAccess(tx, {
          tenantId,
          workspaceId: input.workspaceId,
          actorAgentId,
          account: txAccount,
          operation: txOperation,
          environment,
          decisionId: accessDecisionId,
          intentId,
        });
        // Policy runs only on a successful access decision, over the tx operation.
        policy =
          access.effect === "allow"
            ? await this.evaluatePolicy({
                tenantId,
                workspaceId: input.workspaceId,
                actorAgentId,
                operation: txOperation,
                build,
                intentId,
                requestHash,
                actionDigest,
                // grant-scope cumulativeSpend aggregates over the matched grant
                // (deterministic: matchedGrantIds is sorted). Absent => grant
                // scope resolves to "" and the composer fails closed if a rule
                // aggregates over grant without one.
                grantId: access.doc.matchedGrantIds[0] ?? null,
              })
            : null;
        cumulativeSpendReservations = policy?.cumulativeSpendReservations ?? [];
        windowedInvokeReservation = policy?.windowedInvokeReservation;

        effects.access = access.effect;
        effects.policy =
          access.effect === "deny" ? "not_evaluated" : (policy as PolicyResult).doc.effect;
        if (effects.access === "deny") effects.status = "denied";
        else if (effects.policy === "hard_deny") effects.status = "denied";
        else if (effects.policy === "approval_required") effects.status = "pending_approval";
        else effects.status = "allowed_stub";

        const accessDecisionHash = sha256HexPrefixed(jcsStringify(access.doc));
        const policyDecisionHash = policy
          ? sha256HexPrefixed(jcsStringify((policy as PolicyResult).doc))
          : null;

        await tx.insert(intents).values({
          id: intentId,
          tenantId,
          agentId: actorAgentId,
          intentType: "provider-action",
          status:
            effects.status === "denied"
              ? "rejected"
              : effects.status === "pending_approval"
                ? "pending"
                : "authorized",
          resourceType: "provider-action",
          resourceId: operation.id,
          createdByType: "agent",
          createdById: actorAgentId,
          payload: { operationKey: input.operationKey, actionDigest },
          expiresAt: new Date(input.expiresAt),
        });

        // PR3 (§6.3): for the approval-required arm, build the exact approval
        // commitment + queue row inside THIS create transaction (AFTER the intent
        // insert the queue FK references). A missing PR1 execution dependency
        // (route/credential) throws ApprovalArmError => creation fails closed.
        let approvalQueueId: string | null = null;
        let approvalCommitmentHash: string | null = null;
        if (effects.status === "pending_approval") {
          const arm = await buildApprovalArm({
            tx,
            tenantId,
            workspaceId: input.workspaceId,
            intentId,
            actorAgentId,
            actorRevision: access.doc.dependencyRevisions.actor,
            account: txAccount,
            operation: txOperation,
            requestHash,
            actionDigest,
            accessDecisionId,
            accessDecisionHash,
            matchedBindings: access.doc.dependencyRevisions.bindings,
            matchedGrants: access.doc.dependencyRevisions.grants,
            policyDecisionId: (policy as PolicyResult).decisionId,
            policyDecisionHash: policyDecisionHash as string,
            policyRevisionHash: (policy as PolicyResult).doc.policyRevisionHash,
            evaluatorVersion: EVALUATOR_VERSION,
            requesterSeparation: extractRequesterSeparation(txOperation.requestProfile),
            // #205: read + fail-closed-validate the quorum config from the same
            // request-profile source. A malformed quorum throws ApprovalArmError
            // (creation fails closed); absent quorum => single-approver path.
            quorum: extractQuorumConfig(txOperation.requestProfile),
            requestedAt: input.requestedAt,
            expiresAt: input.expiresAt,
            // Bind the adapter profile from the validated build, never a
            // hardcoded provider (so X actions commit x.provider-action.v1).
            canonicalProfile: build.action.profile,
          });
          approvalQueueId = arm.queueId;
          approvalCommitmentHash = arm.commitmentHash;
        }

        await tx.insert(providerActionBindings).values({
          approvalQueueId,
          approvalCommitmentHash,
          intentId,
          tenantId,
          workspaceId: input.workspaceId,
          actorAgentId,
          providerAccountId: account.id,
          operationId: operation.id,
          operationRevision: access.doc.dependencyRevisions.operation,
          canonicalProfile: build.action.profile,
          canonicalActionBytes: Buffer.from(canonicalBytes, "utf8"),
          actionDigest,
          requestEnvelope: this.envelopeObject(envelope) as Record<string, unknown>,
          requestHash,
          idempotencyKeyHash: input.idempotencyKeyHash,
          safeSummary: build.safeSummary,
          accessDecisionId,
          accessEffect: effects.access,
          accessReasonCode: access.doc.reasonCode,
          matchedBindingIds: access.doc.matchedBindingIds,
          matchedGrantIds: access.doc.matchedGrantIds,
          dependencyRevisions: access.doc.dependencyRevisions as unknown as Record<string, unknown>,
          accessDecision: access.doc as unknown as Record<string, unknown>,
          accessDecisionHash,
          policyDecisionId: policy ? policy.decisionId : null,
          policyEffect: effects.policy,
          policyReasonCodes: policy ? policy.doc.reasonCodes : [],
          policyResults: policy
            ? (policy.doc.policyResults as unknown as Array<Record<string, unknown>>)
            : [],
          policyRevisionHash: policy ? policy.doc.policyRevisionHash : null,
          policyDecision: policy ? (policy.doc as unknown as Record<string, unknown>) : null,
          policyDecisionHash,
          status: effects.status,
        });

        // Required audit intent -> transactional outbox (drained post-commit).
        // PR5 C1: correlated lifecycle events set resource_type='provider_action'
        // and resource_id=intents.id (not the operation id) so PR5 can correlate
        // online by the lifecycle root.
        await tx.insert(providerActionAuditOutbox).values({
          tenantId,
          intentId,
          action:
            effects.status === "denied"
              ? "provider.action.denied"
              : effects.status === "pending_approval"
                ? "provider.action.approval_required"
                : "provider.action.allowed",
          resourceType: "provider_action",
          resourceId: intentId,
          metadata: {
            // PR5 C1: metadata.intentId is the offline-authoritative correlation
            // key (inside the signed eventsDigest).
            intentId,
            actorAgentId,
            operationKey: input.operationKey,
            actionDigest,
            requestHash,
            accessDecisionId,
            accessDecisionHash,
            accessEffect: effects.access,
            accessReasonCode: access.doc.reasonCode,
            policyDecisionId: policy?.decisionId ?? null,
            policyDecisionHash,
            policyEffect: effects.policy,
            policyReasonCodes: policy?.doc.reasonCodes ?? [],
            status: effects.status,
            requestId: input.requestId ?? null,
          },
        });
      });
    } catch (e) {
      // #206: the decision transaction failed to persist, so the action WILL NOT
      // execute (the stub is never reached). Reclaim any cumulative-spend
      // reservations taken during eval so a persistence failure does not leak
      // budget. This is a KNOWN non-execution (distinct from the stub-threw
      // outcome_unknown), so release is correct + fail-closed on the deny side.
      await this.finalizeCumulativeSpend(cumulativeSpendReservations, "failure");
      await this.finalizeWindowedInvoke(windowedInvokeReservation, "failure");
      // A missing PR1 execution dependency (route/credential) fails approval
      // creation CLOSED (spec §5.2) — surfaced as an evidence failure so no
      // partial approval arm is ever visible.
      if (e instanceof ApprovalArmError) {
        // A malformed #205 quorum config fails creation CLOSED at store time
        // (spec §7) and surfaces its specific code so the misconfig is
        // observable; a missing execution dependency (route/credential) uses
        // the generic evidence-failure code (spec §5.2). No partial approval
        // arm is ever visible either way.
        if (e.code === "APPROVAL_QUORUM_CONFIG_INVALID") {
          return {
            kind: "evidence_failure",
            code: "APPROVAL_QUORUM_CONFIG_INVALID",
            httpStatus: 422,
          };
        }
        return {
          kind: "evidence_failure",
          code: "EVIDENCE_DECISION_PERSIST_FAILED",
          httpStatus: 503,
        };
      }
      // Any other evaluation or persistence failure denies; the stub is never
      // called.
      return {
        kind: "evidence_failure",
        code: "EVIDENCE_DECISION_PERSIST_FAILED",
        httpStatus: 503,
      };
    }

    // ── Step 3: drain the required-audit outbox before the stub can run. ──
    const drained = await this.drainAuditOutbox(tenantId, intentId).catch(() => false);
    if (!drained) {
      // #206 (codex P1): the binding ALREADY committed. If its status is an
      // allow-committed `allowed_stub`, a later idempotent replay WILL execute it
      // via outcomeFromBinding WITHOUT re-evaluating or re-reserving. Releasing
      // the reservations here would then let that replay bypass the spend/count
      // cap entirely (durable row authorizes the stub while Redis no longer holds
      // the reservation). So for a replayable allow we DELIBERATELY DO NOT
      // release - the reservation is treated as outcome_unknown and ages out
      // (fail closed). For a denied/approval-committed binding the stub will
      // never run on replay, so we DO reclaim. `effects.status === "allowed_stub"`
      // is exactly the replayable-execute case.
      if (effects.status !== "allowed_stub") {
        await this.finalizeCumulativeSpend(cumulativeSpendReservations, "failure");
        await this.finalizeWindowedInvoke(windowedInvokeReservation, "failure");
      }
      return {
        kind: "evidence_failure",
        code: "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE",
        httpStatus: 503,
        intentId,
      };
    }

    // ── Terminal outcomes for deny / approval. ──
    if (effects.access === "deny") {
      // Access denied => policy never ran => no reservations to release, but be
      // defensive in case a future path reserves before access resolves.
      await this.finalizeCumulativeSpend(cumulativeSpendReservations, "failure");
      await this.finalizeWindowedInvoke(windowedInvokeReservation, "failure");
      return {
        kind: "access_denied",
        code: access.doc.reasonCode,
        httpStatus: 403,
        intentId,
        requestHash,
        actionDigest,
      };
    }
    if (effects.policy === "hard_deny") {
      // #206: reclaim any cumulative-spend reservations this decision holds. A
      // spend-cap breach already released its own reservations during eval; this
      // covers a deny for a DIFFERENT reason where a cumulativeSpend rule had
      // passed and reserved - the action will not execute, so free its budget.
      await this.finalizeCumulativeSpend(
        (policy as PolicyResult | null)?.cumulativeSpendReservations ?? [],
        "failure",
      );
      await this.finalizeWindowedInvoke(windowedInvokeReservation, "failure");
      const code = (policy as PolicyResult | null)?.doc.reasonCodes[0] ?? "POLICY_HARD_DENY";
      return {
        kind: "policy_denied",
        code,
        httpStatus: (POLICY_DENY_HTTP[code] ?? 403) as 403 | 503,
        intentId,
        requestHash,
        actionDigest,
      };
    }
    if (effects.policy === "approval_required") {
      // #206 KNOWN LIMITATION (codex P1, honest gap): a cumulativeSpend / maxCalls
      // cap combined with an approval rule is NOT enforced across the approval
      // lifecycle by THIS lane. The action does not execute now (it awaits a human
      // decision + a separate execute path in provider-approval.ts, which is
      // OUTSIDE this lane's scope fence and does NOT re-run evaluatePolicy or
      // re-reserve). Two imperfect create-time choices exist, neither correct
      // without touching the approval-execute path:
      //   - KEEP the reservation: it is pinned to DECISION time and ages out at
      //     the window edge, so an approval executed near/after that edge is
      //     UNDER-counted (allow-side error).
      //   - RELEASE the reservation: the queued action consumes no budget, and
      //     the execute path re-reserves nothing, so the cap is not enforced on
      //     the approval path AT ALL.
      // We RELEASE here so an action that is ultimately rejected/expired never
      // holds phantom budget that would wrongly DENY unrelated invokes
      // (over-enforcement of the immediate plane is the worse day-to-day failure).
      // Correct enforcement requires the approval-execute path to re-reserve at
      // EXECUTION time; that is a documented follow-up filed against the approval
      // plane (provider-approval.ts). See the PR honest-gaps section.
      await this.finalizeCumulativeSpend(
        (policy as PolicyResult | null)?.cumulativeSpendReservations ?? [],
        "failure",
      );
      await this.finalizeWindowedInvoke(windowedInvokeReservation, "failure");
      return {
        kind: "approval_required",
        code: "APPROVAL_REQUIRED",
        httpStatus: 202,
        intentId,
        requestHash,
        actionDigest,
      };
    }

    // ── Step 4: allow — call the in-process stub, then record the transition. ──
    const csReservations = (policy as PolicyResult | null)?.cumulativeSpendReservations ?? [];
    let stub: ProviderActionStubResult;
    try {
      stub = await executeProviderActionStub(intentId);
    } catch {
      // #206: OUTCOME_UNKNOWN. The stub threw AFTER we admitted + reserved; we
      // cannot prove the action did or did not spend. Deliberately DO NOT release
      // the spend OR the maxCalls reservation - both age out at the window edge.
      // Fail closed: never free a slot/budget that may have really been consumed
      // (a deny-side error is safe; an allow-side error is not).
      return {
        kind: "backend_unavailable",
        code: "BACKEND_STUB_UNAVAILABLE",
        httpStatus: 503,
        intentId,
        requestHash,
        actionDigest,
      };
    }
    // #206: known outcome. stub_succeeded => settle (keep counted); stub_failed
    // => release (reclaim spend budget + the maxCalls slot, the action did not
    // consume one).
    const outcome = stub.ok ? "success" : "failure";
    await this.finalizeCumulativeSpend(csReservations, outcome);
    await this.finalizeWindowedInvoke(
      (policy as PolicyResult | null)?.windowedInvokeReservation,
      outcome,
    );
    // Record the narrow allowed_stub -> stub_succeeded|stub_failed transition.
    await this.db()
      .update(providerActionBindings)
      .set({ status: stub.status, updatedAt: new Date() })
      .where(
        and(
          eq(providerActionBindings.intentId, intentId),
          eq(providerActionBindings.status, "allowed_stub"),
        ),
      );

    return {
      kind: "allowed",
      code: "POLICY_ALLOW",
      httpStatus: 200,
      intentId,
      requestHash,
      actionDigest,
      stub,
    };
  }

  /**
   * #201: finalize a deferred generic-http build against the resolved
   * operation's operator-authored descriptor. The descriptor is read from
   * `requestProfile.operationDescriptor`, STRICTLY validated
   * (`validateGenericHttpDescriptor`, fail-closed), and the caller-supplied
   * method + arguments are canonicalized against it. The resulting profile MUST
   * be a registered profile (it always is for a valid descriptor, but we assert
   * fail-closed). Throws {@link CanonError} / a descriptor error on any
   * ambiguity; NEVER a 500.
   */
  private finalizeGenericBuild(
    deferred: DeferredGenericBuild,
    requestProfile: Record<string, unknown>,
  ): GenericHttpActionBuild {
    const declaredProfile = (requestProfile as { profile?: unknown }).profile;
    // The operation must declare the generic-http profile AND be config-driven.
    if (!isConfigDrivenProfile(declaredProfile))
      throw new CanonError("CANON_PROFILE_UNSUPPORTED", "operation is not config-driven");
    const rawDescriptor = (requestProfile as { operationDescriptor?: unknown }).operationDescriptor;
    if (rawDescriptor === undefined)
      throw new CanonError("CANON_PROFILE_UNSUPPORTED", "missing generic-http descriptor");
    const descriptor = validateGenericHttpDescriptor(rawDescriptor);
    const built = buildGenericHttpAction(
      deferred.operationKey,
      descriptor,
      deferred.method,
      deferred.args,
    );
    // Fail-closed: the built profile must be registered (enforced at every
    // consumption site; asserted here at build time too).
    assertRegisteredProfile(built.action.profile);
    return built;
  }

  // ── Scope resolution (pre-intent) ──
  private async resolveScope(
    tenantId: string,
    workspaceId: string,
    providerAccountId: string,
    operationKey: string,
  ): Promise<{
    workspace: typeof workspaces.$inferSelect;
    account: typeof providerAccounts.$inferSelect;
    operation: typeof providerOperations.$inferSelect;
  } | null> {
    const [workspace] = await this.db()
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, workspaceId)))
      .limit(1);
    if (!workspace) return null;
    const [account] = await this.db()
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, tenantId),
          eq(providerAccounts.workspaceId, workspaceId),
          eq(providerAccounts.id, providerAccountId),
        ),
      )
      .limit(1);
    if (!account) return null;
    const [operation] = await this.db()
      .select()
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, tenantId),
          eq(providerOperations.workspaceId, workspaceId),
          eq(providerOperations.providerAccountId, providerAccountId),
          eq(providerOperations.operationKey, operationKey),
        ),
      )
      .limit(1);
    if (!operation) return null;
    return { workspace, account, operation };
  }

  // ── Access evaluation (spec §6.1) ──
  private async evaluateAccess(
    db: DbExecutor,
    args: {
      tenantId: string;
      workspaceId: string;
      actorAgentId: string;
      account: typeof providerAccounts.$inferSelect;
      operation: typeof providerOperations.$inferSelect;
      environment: PersistedAccessDecisionV1["environment"];
      decisionId: string;
      intentId: string;
    },
  ): Promise<{ effect: "allow" | "deny"; doc: PersistedAccessDecisionV1 }> {
    const decidedAt = new Date().toISOString();
    const now = new Date();
    const {
      tenantId,
      workspaceId,
      actorAgentId,
      account,
      operation,
      environment,
      decisionId,
      intentId,
    } = args;

    const [workspace] = await db
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, workspaceId)))
      .limit(1);

    const baseRevisions: DependencyRevisions = {
      actor: 1,
      workspace: workspace?.revision ?? 0,
      providerAccount: account.revision,
      operation: operation.revision,
      bindings: [],
      grants: [],
    };

    const mkDoc = (
      effect: "allow" | "deny",
      reasonCode: string,
      revisions: DependencyRevisions,
      matchedBindingIds: string[],
      matchedGrantIds: string[],
    ): PersistedAccessDecisionV1 => ({
      schemaVersion: "steward.provider-access-decision.v1",
      decisionId,
      intentId,
      tenantId,
      workspaceId,
      actor: { type: "agent", id: actorAgentId },
      providerAccountId: account.id,
      operationId: operation.id,
      operationKey: operation.operationKey,
      environment,
      effect,
      reasonCode,
      matchedBindingIds: [...matchedBindingIds].sort(byUuidBytes),
      matchedGrantIds: [...matchedGrantIds].sort(byUuidBytes),
      dependencyRevisions: {
        ...revisions,
        bindings: [...revisions.bindings].sort((a, b) => byUuidBytes(a.id, b.id)),
        grants: [...revisions.grants].sort((a, b) => byUuidBytes(a.id, b.id)),
      },
      decidedAt,
    });

    // Actor must be an active agent for the tenant.
    const [agent] = await db
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.tenantId, tenantId), eq(agents.id, actorAgentId)))
      .limit(1);
    if (!agent) {
      return {
        effect: "deny",
        doc: mkDoc("deny", "GRANT_RESOURCE_INACTIVE", baseRevisions, [], []),
      };
    }

    // Resource lifecycle: inactive workspace/account/operation or env mismatch.
    if (
      !workspace ||
      workspace.status !== "active" ||
      account.status !== "active" ||
      operation.status !== "active" ||
      workspace.environment !== environment
    ) {
      return {
        effect: "deny",
        doc: mkDoc("deny", "GRANT_RESOURCE_INACTIVE", baseRevisions, [], []),
      };
    }

    // Role bindings governing this agent + workspace.
    const bindingRows = await db
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.workspaceId, workspaceId),
          eq(providerRoleBindings.principalType, "agent"),
          eq(providerRoleBindings.principalId, actorAgentId),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    const matchedBindings = bindingRows.filter((binding) => {
      if (!activeAtRow(binding, now, environment)) return false;
      if (binding.providerAccountId && binding.providerAccountId !== account.id) return false;
      if (binding.roleKey === "workspace_operator")
        return binding.operationKeys.includes(operation.operationKey);
      if (binding.roleKey === "workspace_viewer")
        return (
          operation.riskClass === "read" && binding.operationKeys.includes(operation.operationKey)
        );
      return false;
    });

    const grantRows = await db
      .select()
      .from(providerGrants)
      .where(
        and(
          eq(providerGrants.tenantId, tenantId),
          eq(providerGrants.workspaceId, workspaceId),
          eq(providerGrants.providerAccountId, account.id),
          eq(providerGrants.agentId, actorAgentId),
          eq(providerGrants.status, "active"),
        ),
      );
    const matchedGrants = grantRows.filter(
      (grant) =>
        activeAtRow(grant, now, environment) &&
        grant.operationKeys.includes(operation.operationKey),
    );

    const revisions: DependencyRevisions = {
      ...baseRevisions,
      bindings: matchedBindings.map(({ id, revision }) => ({ id, revision })),
      grants: matchedGrants.map(({ id, revision }) => ({ id, revision })),
    };

    if (!matchedBindings.length && !matchedGrants.length) {
      return { effect: "deny", doc: mkDoc("deny", "GRANT_ABSENT", revisions, [], []) };
    }
    return {
      effect: "allow",
      doc: mkDoc(
        "allow",
        "provider_access_allowed",
        revisions,
        matchedBindings.map((b) => b.id),
        matchedGrants.map((g) => g.id),
      ),
    };
  }

  /**
   * #206: atomically reserve this invoke's spend for every governing
   * cumulativeSpend rule, and return the per-scope prior sums to feed the policy
   * composer.
   *
   * SINGLE-WINNER CONCURRENCY: each reservation is a single Redis Lua script
   * that prunes the trailing window, sums the survivors, and only admits when
   * `sum + amount <= max`. Two concurrent invokes therefore cannot both pass a
   * cap. The composer re-derives the same verdict from `priorSum` so the
   * persisted decision doc matches the reservation; on a REJECTED reservation we
   * feed a `priorSum` AT the cap so the composer's projected sum breaches and the
   * decision is a hard deny (reason POLICY_CUMULATIVE_SPEND_CAP_EXCEEDED).
   *
   * FAIL CLOSED: if the operation declares no spend field, or the declared field
   * is absent/non-integer, or the currency mismatches, we do NOT reserve and
   * leave the composer to deny (NO_SPEND_FIELD / INPUT_UNAVAILABLE /
   * CURRENCY_MISMATCH). A Redis error while reserving is treated as a breach for
   * that scope (deny), never a silent pass. Reservations already taken for OTHER
   * scopes on the same invoke are RELEASED if a later scope denies, so a denied
   * invoke never leaks budget.
   */
  private async reserveCumulativeSpendForInvoke(input: {
    rules: ProviderPolicyRule[];
    operationKey: string;
    agentId: string;
    grantId: string | null;
    spendDeclaration: { field: string; currency: string } | undefined;
    policyArgs: Record<string, unknown>;
  }): Promise<{
    contextSums: Record<string, number> | undefined;
    reservations: CumulativeSpendReservationHandle[];
  }> {
    const governing = extractGoverningCumulativeSpend(input.rules, input.operationKey);
    if (governing.length === 0) {
      return { contextSums: undefined, reservations: [] };
    }

    const sums: Record<string, number> = {};
    const reservations: CumulativeSpendReservationHandle[] = [];

    // Resolve this invoke's spend from the declared, validated policyArgs field.
    // Absent declaration or bad value => do NOT reserve; the composer fails closed.
    const decl = input.spendDeclaration;
    const rawSpend =
      decl && Object.hasOwn(input.policyArgs, decl.field)
        ? input.policyArgs[decl.field]
        : undefined;
    const spendValid =
      decl !== undefined &&
      typeof rawSpend === "number" &&
      Number.isInteger(rawSpend) &&
      rawSpend >= 0;
    const thisSpend = spendValid ? (rawSpend as number) : undefined;

    // Compute the bucket key (scope+window+max+currency) the COMPOSER reads for a
    // given cap, and the STREAM key (scope+scopeKey+currency) the Redis reservation
    // uses (codex P1: history keyed by stream, not cap threshold).
    const scopeKeyOf = (scope: "operation" | "agent" | "grant") =>
      scope === "operation" ? input.operationKey : scope === "grant" ? (input.grantId ?? "") : "";
    const bucketKeyOf = (g: (typeof governing)[number]) =>
      cumulativeSpendBucketKey({
        aggregateOver: g.aggregateOver,
        windowSeconds: g.windowSeconds,
        max: g.max,
        currency: g.currency,
      });

    // If we cannot price this invoke (no declaration / bad value / currency
    // mismatch on ANY governing cap), do NOT reserve at all: feed prior sum 0 for
    // every bucket so the composer reaches its OWN fail-closed check (which
    // prioritizes NO_SPEND_FIELD / CURRENCY_MISMATCH before reading the sum).
    const currencyMismatch =
      decl !== undefined && governing.some((g) => g.currency !== decl.currency);
    if (decl === undefined || thisSpend === undefined || currencyMismatch) {
      for (const g of governing) sums[bucketKeyOf(g)] = 0;
      return { contextSums: sums, reservations: [] };
    }

    // FAIL CLOSED on a grant-scoped cap with NO grant identity (codex P1): access
    // can be allowed via a role binding with an empty matchedGrantIds, in which
    // case a `grant`-scoped rule has no grant to scope to. Reserving against a
    // shared empty scopeKey would let unrelated agents share one fake bucket and
    // slip the cap. Deny instead: feed the bucket AT cap+1 so the composer
    // hard-denies (CUMULATIVE_SPEND_CAP_EXCEEDED), and take NO reservation.
    const grantScopedWithoutGrant = governing.some(
      (g) => g.aggregateOver === "grant" && (input.grantId === null || input.grantId.length === 0),
    );
    if (grantScopedWithoutGrant) {
      for (const g of governing) {
        sums[bucketKeyOf(g)] =
          g.aggregateOver === "grant" && (input.grantId === null || input.grantId.length === 0)
            ? g.max + 1
            : 0;
      }
      return { contextSums: sums, reservations: [] };
    }

    // GROUP caps by STREAM (scope+scopeKey+currency). A single invoke governed by
    // several caps on the same stream (e.g. a 1h AND a 24h cap, or two rules) is
    // reserved ONCE against that stream with ALL its caps checked atomically (the
    // invoke is counted once, never double-counted; codex P2). priorSums come back
    // per cap in the order supplied, which we map to each cap's bucket key.
    const streams = new Map<
      string,
      {
        stream: {
          agentId: string;
          scope: "operation" | "agent" | "grant";
          scopeKey: string;
          currency: string;
        };
        caps: Array<{ windowSeconds: number; max: number; bucketKey: string }>;
      }
    >();
    for (const g of governing) {
      const scopeKey = scopeKeyOf(g.aggregateOver);
      const streamId = `${g.aggregateOver}|${scopeKey}|${g.currency}`;
      let entry = streams.get(streamId);
      if (!entry) {
        entry = {
          stream: {
            agentId: input.agentId,
            scope: g.aggregateOver,
            scopeKey,
            currency: g.currency,
          },
          caps: [],
        };
        streams.set(streamId, entry);
      }
      const bucketKey = bucketKeyOf(g);
      // Dedupe identical caps within a stream (same window+max => same bucket).
      if (!entry.caps.some((c) => c.bucketKey === bucketKey)) {
        entry.caps.push({ windowSeconds: g.windowSeconds, max: g.max, bucketKey });
      }
    }

    let anyDeny = false;
    for (const { stream, caps } of streams.values()) {
      let reserved: Awaited<ReturnType<typeof reserveCumulativeSpend>>;
      try {
        reserved = await reserveCumulativeSpend({
          stream,
          caps: caps.map((c) => ({ windowSeconds: c.windowSeconds, max: c.max })),
          amount: thisSpend,
        });
      } catch {
        // Redis/parse failure => deny for every cap on this stream (missing
        // signal). Feed cap+1 so the composer denies with CAP_EXCEEDED.
        for (const c of caps) sums[c.bucketKey] = c.max + 1;
        anyDeny = true;
        continue;
      }
      // Map each cap's prior sum back to its bucket key.
      caps.forEach((c, i) => {
        sums[c.bucketKey] = reserved.priorSums[i] ?? c.max + 1;
      });
      if (reserved.ok) {
        reservations.push({
          stream,
          reservationId: reserved.reservationId as string,
          amount: thisSpend,
        });
      } else {
        // Rejected: at least one cap on this stream breached. Force those buckets
        // over their cap so the composer denies.
        caps.forEach((c, i) => {
          const prior = reserved.priorSums[i] ?? c.max + 1;
          if (prior + thisSpend > c.max) sums[c.bucketKey] = c.max + 1;
        });
        anyDeny = true;
      }
    }

    // If ANY stream denied, release the reservations we DID take so a denied
    // invoke never leaks budget.
    if (anyDeny && reservations.length > 0) {
      await Promise.all(
        reservations.map((r) =>
          releaseCumulativeSpend({
            stream: r.stream,
            reservationId: r.reservationId,
            amount: r.amount,
          }).catch(() => undefined),
        ),
      );
      return { contextSums: sums, reservations: [] };
    }

    return { contextSums: sums, reservations };
  }

  /**
   * Settle (success) or release (failure) the cumulative-spend reservations a
   * decision took. On outcome_unknown the caller passes neither and the
   * reservations age out at the window edge (fail closed). Safe on an empty list.
   */
  private async finalizeCumulativeSpend(
    reservations: CumulativeSpendReservationHandle[],
    outcome: "success" | "failure",
  ): Promise<void> {
    if (reservations.length === 0) return;
    await Promise.all(
      reservations.map((r) =>
        (outcome === "success"
          ? settleCumulativeSpend({ stream: r.stream, reservationId: r.reservationId })
          : releaseCumulativeSpend({
              stream: r.stream,
              reservationId: r.reservationId,
              amount: r.amount,
            })
        ).catch(() => undefined),
      ),
    );
  }

  /**
   * Settle (success => keep the slot counted) or release (failure => reclaim the
   * slot) an atomic windowed-invoke (maxCalls) reservation. On outcome_unknown
   * the caller passes neither and the slot ages out (fail closed). No-op when no
   * slot was taken.
   */
  private async finalizeWindowedInvoke(
    reservation: WindowedInvokeReservationHandle | undefined,
    outcome: "success" | "failure",
  ): Promise<void> {
    if (!reservation) return;
    if (outcome === "success") return; // keep the slot counted for its windows
    await releaseWindowedInvoke({
      agentId: reservation.agentId,
      operationKey: reservation.operationKey,
      reservationId: reservation.reservationId,
    }).catch(() => undefined);
  }

  // ── Policy evaluation (spec §6.2 / §6.3) ──
  private async evaluatePolicy(args: {
    tenantId: string;
    workspaceId: string;
    actorAgentId: string;
    operation: typeof providerOperations.$inferSelect;
    build: ConcreteProviderActionBuild;
    intentId: string;
    requestHash: string;
    actionDigest: string;
    grantId?: string | null;
  }): Promise<{
    doc: PersistedPolicyDecisionV1;
    evaluation: ProviderPolicyEvaluationV1;
    decisionId: string;
    /** Atomic cumulative-spend reservations taken during this evaluation. Settle
     *  on known-success, release on known-failure/deny, leave on outcome_unknown. */
    cumulativeSpendReservations: CumulativeSpendReservationHandle[];
    /** The atomic windowed-invoke (maxCalls) reservation slot (one per invoke,
     *  covering ALL count windows). Settle (keep) on known-success, release on
     *  deny/failure, leave on outcome_unknown. */
    windowedInvokeReservation?: WindowedInvokeReservationHandle;
  }> {
    const decidedAt = new Date().toISOString();
    const decisionId = randomUUID();
    const { operation, build } = args;

    // The capability-intent rules that govern this operation come from the
    // operation's request profile. PR2 reads the enabled capability-intent rules
    // declared on the provider operation's request_profile.policyRules; absent =>
    // no governing rules (default deny).
    const rules = extractCapabilityIntentRules(operation.requestProfile);

    // The in-memory-only tweet-text channel for X contentPolicy.blockedPatterns.
    // Present ONLY on a text-bearing X build; NEVER persisted (the decision doc,
    // safe-summary, and audit event stay text-free). A github build has no
    // policyText, so this is undefined and any content-pattern rule fails closed.
    const policyText = "policyText" in build ? build.policyText : undefined;

    // -- #206: cumulative-spend aggregate wiring + atomic reservation. --
    // Resolve the operation's declared spend field/currency and, for each
    // governing cumulativeSpend rule, ATOMICALLY reserve this invoke's spend
    // against the trailing-window cap. The reservation is the authoritative,
    // TOCTOU-free gate. The reserved priorSum is fed to the composer so its
    // in-policy check agrees with the reservation; a REJECTED reservation feeds a
    // prior sum AT the cap so the composer's projected sum breaches and denies. A
    // missing declaration / absent aggregate is left to the composer to fail
    // closed exactly as specified.
    const spendDeclaration = extractSpendDeclaration(operation.requestProfile);
    const cumulative = await this.reserveCumulativeSpendForInvoke({
      rules,
      operationKey: operation.operationKey,
      agentId: args.actorAgentId,
      grantId: args.grantId ?? null,
      spendDeclaration,
      policyArgs: build.policyArgs,
    });

    // #206 configurable count cap (maxCalls + callWindow): ATOMICALLY reserve one
    // invoke slot against the trailing-window count so concurrent invokes cannot
    // collectively exceed maxCalls (single-winner, like the spend path; codex P2).
    // The reserved priorCount is fed to the composer so its check agrees; a
    // REJECTED reservation feeds a count AT the cap so the composer denies. Absent
    // reservation (no governing maxCalls rule, or a Redis failure) leaves
    // windowedInvokeCount undefined => a maxCalls rule fails closed
    // (POLICY_INPUT_UNAVAILABLE). The slot is settled (kept) on a known-success
    // allow and released on any deny/failure below.
    // #206 configurable count caps: ATOMICALLY reserve ONE invoke slot against
    // ALL count windows at once (a single invoke is counted ONCE across an hourly
    // AND a daily cap; codex P2). Each window's count is fed to the composer keyed
    // by its own bucket. A rejection on ANY window denies (no slot taken); a
    // Redis failure feeds every cap AT its max so the composer fails closed.
    const govMaxCalls = extractGoverningMaxCalls(rules, operation.operationKey);
    let windowedInvokeCounts: Record<string, number> | undefined;
    let windowedInvokeReservation: WindowedInvokeReservationHandle | undefined;
    if (govMaxCalls.length > 0) {
      const counts: Record<string, number> = {};
      windowedInvokeCounts = counts;
      const wr = await reserveWindowedInvoke({
        agentId: args.actorAgentId,
        operationKey: operation.operationKey,
        caps: govMaxCalls.map((c) => ({ windowSeconds: c.windowSeconds, max: c.max })),
      });
      govMaxCalls.forEach((cap, i) => {
        const bucketKey = windowedInvokeBucketKey({
          windowSeconds: cap.windowSeconds,
          max: cap.max,
        });
        // On success feed the real prior count; on rejection/absence feed AT the
        // cap so the composer denies (count >= maxCalls) for the breaching cap.
        const prior = wr.priorCounts[i];
        counts[bucketKey] = wr.ok && typeof prior === "number" ? prior : (prior ?? cap.max);
      });
      if (wr.ok && wr.reservationId !== undefined) {
        windowedInvokeReservation = {
          agentId: args.actorAgentId,
          operationKey: operation.operationKey,
          reservationId: wr.reservationId,
        };
      }
      // A rejected multi-cap reserve takes NO slot, so there is nothing to
      // release here; the composer will deny from the fed counts.
    }

    const context: ProviderPolicyContext = {
      operationKey: operation.operationKey,
      args: build.policyArgs,
      method: build.method,
      // Host is carried context only (the composer never gates on it); derive it
      // from the adapter's canonical origin so X actions report api.x.com and
      // github actions report api.github.com, never a hardcoded provider.
      host: hostFromOrigin(build.action.origin),
      path: build.action.normalizedPath,
      // Trailing-hour count is not wired in PR2; rules that require it will
      // fail closed (POLICY_INPUT_UNAVAILABLE) exactly as specified.
      invokeCount1h: undefined,
      // #206 configurable count caps: per-cap trailing-window counts (undefined
      // when unwired => a maxCalls rule fails closed).
      ...(windowedInvokeCounts !== undefined ? { windowedInvokeCounts } : {}),
      ...(policyText !== undefined ? { policyText } : {}),
      // #206 cumulative-spend aggregate + declaration. spendDeclaration absent =>
      // a cumulativeSpend rule fails closed (NO_SPEND_FIELD). cumulativeSpend
      // carries the reserved priorSum per scope; absent scope => fail closed
      // (INPUT_UNAVAILABLE). See reserveCumulativeSpendForInvoke.
      ...(spendDeclaration !== undefined ? { spendDeclaration } : {}),
      ...(cumulative.contextSums !== undefined ? { cumulativeSpend: cumulative.contextSums } : {}),
      // Permissioned-X authoritative inputs (post count / accumulated spend /
      // now-minute) are NOT wired into the service in Phase 1 — exactly the same
      // posture as invokeCount1h above. A permissioned-X rule that REQUIRES one
      // of these inputs (maxPostsPerWindow / spendPolicy / quietHours) therefore
      // fails closed (POLICY_INPUT_UNAVAILABLE) until the trailing-window
      // accumulator lands. Content/reply/URL rules need no external input and are
      // fully live now.
      x: undefined,
    };

    const evaluation = composeProviderActionPolicyDecision(rules, context);

    // Per-rule revision hashes and the composite policy revision hash.
    const enabledGoverning = rules.filter(
      (r) => r.enabled && capabilitySelectorMatches(r.config, operation.operationKey),
    );
    const ruleSnapshots = enabledGoverning
      .map((r) => ({
        id: r.id,
        type: r.type,
        enabled: r.enabled,
        config: r.config,
        hash: ruleRevisionHash(r),
      }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.hash < b.hash ? -1 : 1));

    const policyRevisionHash = sha256HexPrefixed(
      jcsStringify({
        operationId: operation.id,
        operationRevision: operation.revision,
        actorAgentId: args.actorAgentId,
        evaluatorVersion: EVALUATOR_VERSION,
        rules: ruleSnapshots.map((r) => ({ id: r.id, hash: r.hash })),
      }),
    );

    const hashById = new Map(ruleSnapshots.map((r) => [r.id, r.hash]));
    const policyResults: PersistedPolicyDecisionV1["policyResults"] = evaluation.results
      .map((res) => ({
        policyId: res.policyId,
        policyType: POLICY_TYPE,
        applicable: true as const,
        configuredEffect: res.configuredEffect,
        outcome: res.outcome,
        reasonCode: res.reasonCode,
        ruleRevisionHash: hashById.get(res.policyId) ?? "",
      }))
      .sort((a, b) =>
        a.policyId < b.policyId
          ? -1
          : a.policyId > b.policyId
            ? 1
            : a.ruleRevisionHash < b.ruleRevisionHash
              ? -1
              : 1,
      );

    const doc: PersistedPolicyDecisionV1 = {
      schemaVersion: "steward.provider-policy-decision.v1",
      decisionId,
      intentId: args.intentId,
      requestHash: args.requestHash,
      actionDigest: args.actionDigest,
      operationId: operation.id,
      operationKey: operation.operationKey,
      effect: evaluation.effect,
      reasonCodes: evaluation.reasonCodes,
      policyResults,
      policyRevisionHash,
      evaluatorVersion: EVALUATOR_VERSION,
      decidedAt,
    };
    return {
      doc,
      evaluation,
      decisionId,
      cumulativeSpendReservations: cumulative.reservations,
      ...(windowedInvokeReservation !== undefined ? { windowedInvokeReservation } : {}),
    };
  }

  /**
   * C2 crash-recovery sweeper (spec §7.3). The required-audit outbox row commits
   * IN-TX with the intent/binding, but its drain into the signed chain happens
   * post-commit. A crash between commit and drain leaves an intent with an
   * UNDELIVERED outbox row and therefore ZERO signed correlated events — which
   * would break the C2 invariant (every persisted intent has >=1 signed event).
   *
   * This sweeper drains every undelivered outbox row for the tenant (optionally
   * scoped to one intent). It is safe to run repeatedly and concurrently: the
   * drain marks `delivered_at` per row after the signed append, and
   * `writeAuditEvent` is itself per-tenant serialized, so a signed event is
   * produced EXACTLY ONCE per outbox row. Call it opportunistically (any read
   * path) and/or from a periodic job; a killed drain is always recoverable.
   *
   * Returns the number of rows delivered in this pass.
   */
  async recoverUnsignedIntents(tenantId: string, intentId?: string): Promise<number> {
    const rows = await this.db()
      .select()
      .from(providerActionAuditOutbox)
      .where(
        and(
          eq(providerActionAuditOutbox.tenantId, tenantId),
          intentId
            ? eq(providerActionAuditOutbox.intentId, intentId)
            : (sql`true` as unknown as ReturnType<typeof eq>),
          sql`${providerActionAuditOutbox.deliveredAt} IS NULL`,
        ),
      );
    let delivered = 0;
    for (const row of rows) {
      // Crash-safe exactly-once (codex P1). The SOURCE OF TRUTH for "is this
      // event signed?" is the audit chain itself, keyed by the deterministic
      // correlation (tenant, resource_id=intentId, action). `delivered_at` is
      // only an optimization. We serialize the whole check+sign+mark per tenant
      // (same queue writeAuditEvent uses) so two in-process sweeps cannot both
      // sign, and if a prior sweep crashed AFTER signing but BEFORE marking, this
      // sweep observes the existing signed event and just marks the row — never
      // a duplicate, never a permanently-unsigned intent.
      const signedNow = await withTenantAuditQueue(row.tenantId, async () => {
        const existing = await this.db().execute(
          sql`SELECT 1 FROM audit_events
              WHERE tenant_id = ${row.tenantId}
                AND resource_type = ${row.resourceType}
                AND resource_id = ${row.resourceId}
                AND action = ${row.action}
              LIMIT 1`,
        );
        const existingRows = Array.isArray(existing)
          ? existing
          : ((existing as { rows?: unknown[] }).rows ?? []);
        if (existingRows.length === 0) {
          await appendAuditEvent({
            tenantId: row.tenantId,
            actorType: "agent",
            actorId: (row.metadata as { actorAgentId?: string }).actorAgentId ?? null,
            action: row.action,
            resourceType: row.resourceType,
            resourceId: row.resourceId,
            metadata: row.metadata as Record<string, unknown>,
          });
          return true;
        }
        return false;
      });
      // Mark delivered whether we just signed it or found it already signed.
      const marked = await this.db()
        .update(providerActionAuditOutbox)
        .set({ deliveredAt: new Date() })
        .where(
          and(
            eq(providerActionAuditOutbox.id, row.id),
            sql`${providerActionAuditOutbox.deliveredAt} IS NULL`,
          ),
        )
        .returning({ id: providerActionAuditOutbox.id });
      if (marked.length > 0 && signedNow) delivered += 1;
    }
    return delivered;
  }

  // ── Required-audit outbox drain (post-commit, pre-stub) ──
  private async drainAuditOutbox(tenantId: string, intentId: string): Promise<boolean> {
    // Delegate to the CAS-guarded recovery path so the inline drain and the
    // crash-recovery sweeper share exactly-once semantics (spec §7.3). Any signer
    // failure propagates (caller maps it to EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE).
    await this.recoverUnsignedIntents(tenantId, intentId);
    return true;
  }

  private async writeRequiredDenialAudit(
    tenantId: string,
    event: {
      action: string;
      resourceType: string;
      resourceId: string;
      metadata: Record<string, unknown>;
    },
  ): Promise<void> {
    await writeAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: (event.metadata.actorAgentId as string) ?? null,
      action: event.action,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      metadata: event.metadata,
    });
  }

  // ── helpers ──
  private canonicalActionObject(a: AnyCanonicalActionV1): Record<string, unknown> {
    return {
      profile: a.profile,
      method: a.method,
      origin: a.origin,
      normalizedPath: a.normalizedPath,
      orderedQueryPairs: a.orderedQueryPairs.map(([n, v]) => [n, v]),
      selectedHeaders: a.selectedHeaders.map(([n, v]) => [n, v]),
      canonicalBody: a.canonicalBody,
    };
  }

  private buildEnvelope(
    input: CreateProviderActionInput,
    ids: {
      tenantId: string;
      actorAgentId: string;
      providerAccountId: string;
      operationId: string;
      operationRevision: number;
      actionDigest: string;
      policyInputDigest: string;
    },
  ): ProviderRequestEnvelopeV1 {
    return {
      schemaVersion: "steward.provider-request.v1",
      tenantId: ids.tenantId,
      workspaceId: input.workspaceId,
      actorAgentId: ids.actorAgentId,
      providerAccountId: ids.providerAccountId,
      operationId: ids.operationId,
      operationRevision: ids.operationRevision,
      actionDigest: ids.actionDigest,
      policyInputDigest: ids.policyInputDigest,
      idempotencyKeyHash: input.idempotencyKeyHash,
      requestedAt: input.requestedAt,
      expiresAt: input.expiresAt,
      nonce: input.nonce,
    };
  }

  private envelopeObject(e: ProviderRequestEnvelopeV1): Record<string, unknown> {
    const envelope: Record<string, unknown> = {
      schemaVersion: e.schemaVersion,
      tenantId: e.tenantId,
      workspaceId: e.workspaceId,
      actorAgentId: e.actorAgentId,
      providerAccountId: e.providerAccountId,
      operationId: e.operationId,
      operationRevision: e.operationRevision,
      actionDigest: e.actionDigest,
      idempotencyKeyHash: e.idempotencyKeyHash,
      requestedAt: e.requestedAt,
      expiresAt: e.expiresAt,
      nonce: e.nonce,
    };
    if (e.policyInputDigest !== undefined) envelope.policyInputDigest = e.policyInputDigest;
    return envelope;
  }

  /**
   * Idempotent replay path: reconstruct the outcome from an existing binding.
   *
   * #206 RESERVATION REPLAY CAVEAT (codex P2, honest gap): cumulative-spend
   * reservation handles are in-memory to the ORIGINAL create call and are NOT
   * persisted on the binding. A replay here (or a crash between the binding
   * commit and the original finalize) therefore has no handle to settle/release.
   * This is deliberately FAIL-CLOSED, not a silent leak: on the original call a
   * crash after commit leaves the reservation as `outcome_unknown` (documented:
   * it ages out at the window edge, never freeing maybe-spent budget). A replay
   * that resolves to stub_succeeded is a real spend and SHOULD stay counted, so
   * not releasing is correct. A replay that resolves to stub_failed is the only
   * case where budget could be transiently over-counted for one window; that is
   * a bounded DENY-side error (safe), never an allow-side one. Crash-durable
   * reservation handles (persisted per binding + reconciled by the C2 sweeper)
   * are the follow-up; this lane does not add a migration for it.
   */
  private async outcomeFromBinding(
    b: typeof providerActionBindings.$inferSelect,
  ): Promise<ProviderActionOutcome> {
    if (b.status === "denied") {
      if (b.accessEffect === "deny")
        return {
          kind: "access_denied",
          code: b.accessReasonCode,
          httpStatus: 403,
          intentId: b.intentId,
          requestHash: b.requestHash,
          actionDigest: b.actionDigest,
        };
      const code = b.policyReasonCodes[0] ?? "POLICY_HARD_DENY";
      return {
        kind: "policy_denied",
        code,
        httpStatus: (POLICY_DENY_HTTP[code] ?? 403) as 403 | 503,
        intentId: b.intentId,
        requestHash: b.requestHash,
        actionDigest: b.actionDigest,
      };
    }
    // Approval-required lineage (PR3). A create-replay of a governed provider
    // action must NEVER report POLICY_ALLOW/stub_succeeded (that would fabricate
    // an allow for an action that requires a human decision). The agent's create
    // contract is 202 APPROVAL_REQUIRED regardless of where the out-of-band
    // approval lifecycle currently sits (pending/approved/denied/expired/stale/
    // execution_ready); the human decision + safe resume happen through the
    // /v2/provider-actions approval + execute routes, not this create path.
    if (
      b.status === "pending_approval" ||
      b.status === "approved" ||
      b.status === "execution_ready" ||
      b.status === "approval_denied" ||
      b.status === "approval_expired" ||
      b.status === "approval_stale"
    )
      return {
        kind: "approval_required",
        code: "APPROVAL_REQUIRED",
        httpStatus: 202,
        intentId: b.intentId,
        requestHash: b.requestHash,
        actionDigest: b.actionDigest,
      };
    // A binding still in `allowed_stub` means the ORIGINAL request committed the
    // decision but did NOT yet complete the required-audit drain + stub call (it
    // crashed / lost the connection between commit and the status transition). A
    // replay MUST NOT report a fabricated `stub_succeeded`. Instead we
    // idempotently COMPLETE the pending action: re-drain the required audit, then
    // run the stub and record the narrow allowed_stub -> stub_succeeded|stub_failed
    // transition. If audit still cannot be drained we deny (evidence unavailable)
    // with the stub never called.
    if (b.status === "allowed_stub") {
      const drained = await this.drainAuditOutbox(b.tenantId, b.intentId).catch(() => false);
      if (!drained) {
        return {
          kind: "evidence_failure",
          code: "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE",
          httpStatus: 503,
          intentId: b.intentId,
        };
      }
      let stub: ProviderActionStubResult;
      try {
        stub = await executeProviderActionStub(b.intentId);
      } catch {
        return {
          kind: "backend_unavailable",
          code: "BACKEND_STUB_UNAVAILABLE",
          httpStatus: 503,
          intentId: b.intentId,
          requestHash: b.requestHash,
          actionDigest: b.actionDigest,
        };
      }
      await this.db()
        .update(providerActionBindings)
        .set({ status: stub.status, updatedAt: new Date() })
        .where(
          and(
            eq(providerActionBindings.intentId, b.intentId),
            eq(providerActionBindings.status, "allowed_stub"),
          ),
        );
      return {
        kind: "allowed",
        code: "POLICY_ALLOW",
        httpStatus: 200,
        intentId: b.intentId,
        requestHash: b.requestHash,
        actionDigest: b.actionDigest,
        stub,
      };
    }

    // stub_succeeded / stub_failed: terminal, report the recorded result.
    return {
      kind: "allowed",
      code: "POLICY_ALLOW",
      httpStatus: 200,
      intentId: b.intentId,
      requestHash: b.requestHash,
      actionDigest: b.actionDigest,
      stub: {
        ok: b.status === "stub_succeeded",
        status: b.status === "stub_failed" ? "stub_failed" : "stub_succeeded",
        echo: { operationId: b.operationId, actionDigest: b.actionDigest },
      },
    };
  }
}

// ── module-scope helpers ──

/**
 * Extract the host from a canonical origin like `https://api.x.com`. The origin
 * is already canonicalized by the adapter (scheme https, no port, no path), so a
 * simple prefix strip is sufficient and total; a malformed origin (never emitted
 * by the adapters) falls back to the raw value rather than throwing, since this
 * value is non-authoritative policy context only.
 */
function hostFromOrigin(origin: string): string {
  const withoutScheme = origin.replace(/^https:\/\//, "");
  const slash = withoutScheme.indexOf("/");
  return slash === -1 ? withoutScheme : withoutScheme.slice(0, slash);
}

function activeAtRow(
  row: {
    status: string;
    notBefore?: Date | null;
    expiresAt?: Date | null;
    environment?: string | null;
  },
  now: Date,
  environment: string,
): boolean {
  return (
    row.status === "active" &&
    (!row.notBefore || row.notBefore <= now) &&
    (!row.expiresAt || row.expiresAt > now) &&
    (!row.environment || row.environment === environment)
  );
}

/**
 * Extract enabled capability-intent rule rows from a provider operation's
 * request_profile. The shape is `request_profile.policyRules: Array<{ id, type,
 * enabled, config }>`. Anything malformed is skipped defensively at the shape
 * level here; the composer independently fails closed on malformed GOVERNING
 * configs.
 */
function extractCapabilityIntentRules(
  requestProfile: Record<string, unknown>,
): ProviderPolicyRule[] {
  const raw = (requestProfile as { policyRules?: unknown }).policyRules;
  if (!Array.isArray(raw)) return [];
  const rules: ProviderPolicyRule[] = [];
  for (const r of raw) {
    if (typeof r !== "object" || r === null) continue;
    const row = r as Record<string, unknown>;
    if (typeof row.id !== "string" || typeof row.type !== "string") continue;
    rules.push({
      id: row.id,
      type: row.type,
      enabled: row.enabled !== false,
      config: (typeof row.config === "object" && row.config !== null
        ? (row.config as Record<string, unknown>)
        : {}) as Record<string, unknown>,
    });
  }
  return rules;
}

/**
 * Extract the operation's DECLARED spend field (#206). The OPERATION - not the
 * caller - declares which validated `policyArgs` field carries the per-invoke
 * spend amount and its currency, via
 * `request_profile.spendDeclaration: { field: string, currency: string }`.
 * Absent/malformed => undefined; a cumulativeSpend rule on such an operation
 * then fails closed (POLICY_CUMULATIVE_SPEND_NO_SPEND_FIELD) in the composer.
 * We NEVER infer a spend field - an operation that cannot move money simply
 * carries no declaration and can never be governed by a spend cap by accident.
 */
function extractSpendDeclaration(
  requestProfile: Record<string, unknown>,
): { field: string; currency: string } | undefined {
  const raw = (requestProfile as { spendDeclaration?: unknown }).spendDeclaration;
  if (typeof raw !== "object" || raw === null) return undefined;
  const decl = raw as Record<string, unknown>;
  if (
    typeof decl.field !== "string" ||
    decl.field.length === 0 ||
    typeof decl.currency !== "string" ||
    decl.currency.length === 0
  ) {
    return undefined;
  }
  return { field: decl.field, currency: decl.currency };
}

/**
 * The governing cumulativeSpend rules for an operation, with each rule's
 * resolved window seconds + scope + cap. Used to drive the atomic reservations
 * and the policy context's prior-sum signal.
 */
interface GoverningCumulativeSpend {
  ruleId: string;
  window: string;
  windowSeconds: number;
  currency: string;
  max: number;
  aggregateOver: "operation" | "agent" | "grant";
}

/**
 * Extract the governing cumulativeSpend constraints from the operation's enabled
 * capability-intent rules that name this operation. Only WELL-FORMED
 * cumulativeSpend blocks are returned; a malformed one is left to the composer
 * (which hard-denies on a malformed governing config), so we never silently
 * skip a broken cap. Returns [] when none govern.
 */
function extractGoverningCumulativeSpend(
  rules: ProviderPolicyRule[],
  operationKey: string,
): GoverningCumulativeSpend[] {
  const out: GoverningCumulativeSpend[] = [];
  for (const r of rules) {
    if (!r.enabled) continue;
    if (!capabilitySelectorMatches(r.config, operationKey)) continue;
    const constraints = (r.config as { constraints?: unknown }).constraints;
    if (typeof constraints !== "object" || constraints === null) continue;
    const cs = (constraints as { cumulativeSpend?: unknown }).cumulativeSpend;
    if (typeof cs !== "object" || cs === null) continue;
    const block = cs as Record<string, unknown>;
    const windowSeconds = parseIso8601DurationSecondsForApi(block.window);
    if (
      typeof block.window !== "string" ||
      windowSeconds === null ||
      typeof block.currency !== "string" ||
      block.currency.length === 0 ||
      typeof block.max !== "number" ||
      !Number.isInteger(block.max) ||
      block.max < 0 ||
      (block.aggregateOver !== "operation" &&
        block.aggregateOver !== "agent" &&
        block.aggregateOver !== "grant")
    ) {
      // Malformed cap: leave it to the composer to hard-deny. Do NOT reserve.
      continue;
    }
    out.push({
      ruleId: r.id,
      window: block.window,
      windowSeconds,
      currency: block.currency,
      max: block.max,
      aggregateOver: block.aggregateOver,
    });
  }
  return out;
}

/**
 * Extract the governing configurable count cap (maxCalls + callWindow) for an
 * operation, if exactly one well-formed one exists. Returns the resolved window
 * seconds + max, or undefined when none govern. A malformed one is left to the
 * composer to hard-deny. (Multiple count caps would each read the same window
 * bucket; we resolve the FIRST well-formed one to feed the shared count signal -
 * the composer still evaluates every rule against that count.)
 */
function extractGoverningMaxCalls(
  rules: ProviderPolicyRule[],
  operationKey: string,
): Array<{ windowSeconds: number; max: number }> {
  const out: Array<{ windowSeconds: number; max: number }> = [];
  const seen = new Set<string>();
  for (const r of rules) {
    if (!r.enabled) continue;
    if (!capabilitySelectorMatches(r.config, operationKey)) continue;
    const constraints = (r.config as { constraints?: unknown }).constraints;
    if (typeof constraints !== "object" || constraints === null) continue;
    const c = constraints as Record<string, unknown>;
    if (c.maxCalls === undefined && c.callWindow === undefined) continue;
    const windowSeconds = parseIso8601DurationSecondsForApi(c.callWindow);
    if (
      typeof c.maxCalls !== "number" ||
      !Number.isInteger(c.maxCalls) ||
      c.maxCalls < 0 ||
      typeof c.callWindow !== "string" ||
      windowSeconds === null
    ) {
      // Malformed: leave it to the composer to hard-deny. Do NOT read a count.
      continue;
    }
    // Each DISTINCT (window, max) is an independent count cap with its own count
    // (codex P2). Dedupe identical caps.
    const key = `${windowSeconds}:${c.maxCalls}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ windowSeconds, max: c.maxCalls });
  }
  return out;
}

/**
 * Restricted ISO-8601 duration -> positive integer seconds, mirroring the
 * policy-engine parser (P[nD]T[nH][nM][nS], PnW; Y/M rejected as ambiguous).
 * Kept local to avoid a runtime import cycle; the policy engine owns the
 * canonical parser and both must agree (a divergence would let a window the
 * policy accepts fail to reserve, or vice versa - covered by an E2E).
 */
function parseIso8601DurationSecondsForApi(input: unknown): number | null {
  if (typeof input !== "string" || input.length === 0) return null;
  const weeks = /^P(\d+)W$/.exec(input);
  if (weeks) {
    const n = Number(weeks[1]);
    if (!Number.isSafeInteger(n) || n <= 0) return null;
    const secs = n * 604800;
    if (secs > MAX_AGGREGATE_WINDOW_SECONDS) return null;
    return secs;
  }
  const m = /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/.exec(input);
  if (!m) return null;
  const [, dStr, hStr, mStr, sStr] = m;
  if (dStr === undefined && hStr === undefined && mStr === undefined && sStr === undefined) {
    return null;
  }
  const days = dStr === undefined ? 0 : Number(dStr);
  const hours = hStr === undefined ? 0 : Number(hStr);
  const mins = mStr === undefined ? 0 : Number(mStr);
  const secs = sStr === undefined ? 0 : Number(sStr);
  for (const n of [days, hours, mins, secs]) {
    if (!Number.isSafeInteger(n) || n < 0) return null;
  }
  const total = days * 86400 + hours * 3600 + mins * 60 + secs;
  if (!Number.isSafeInteger(total) || total <= 0) return null;
  if (total > MAX_AGGREGATE_WINDOW_SECONDS) return null;
  return total;
}

/**
 * Extract the operation's requester-separation requirement (spec I10). PR1 does
 * not yet ship a structured approval-requirements field, so PR3 reads it from
 * `request_profile.approvalRequirements.requesterSeparation` when present
 * (forward-compatible) and defaults to false. Documented deviation: when PR1
 * lands a first-class approval-requirements field the commitment builder should
 * read that instead.
 */
export function extractRequesterSeparation(requestProfile: Record<string, unknown>): boolean {
  const reqs = (requestProfile as { approvalRequirements?: unknown }).approvalRequirements;
  if (typeof reqs !== "object" || reqs === null) return false;
  return (reqs as { requesterSeparation?: unknown }).requesterSeparation === true;
}

/**
 * Extract + FAIL-CLOSED-validate the operation's #205 quorum config from
 * `request_profile.approvalRequirements.quorum`, the same forward-compatible
 * source as {@link extractRequesterSeparation}. Returns:
 *   - `undefined` when no quorum is configured => single-approver legacy path.
 *   - `{ threshold, eligibleApproverUserIds }` when a well-formed quorum is set.
 * THROWS {@link ApprovalArmError}("APPROVAL_QUORUM_CONFIG_INVALID") when a quorum
 * key is present but malformed (non-integer / <1 / > eligible-set size / empty
 * or duplicate or non-string eligible set / unknown members). Creation then
 * fails closed. A malformed quorum is NEVER stored (spec §7).
 *
 * NOTE: membership-of-eligible-users-in-the-workspace_approver-role is NOT
 * verified here (the request profile does not carry role state); it is enforced
 * per-approval at decide time via checkApprover (spec §5). Store-time validation
 * is purely structural: shape + threshold-reachability.
 */
export function extractQuorumConfig(
  requestProfile: Record<string, unknown>,
): { threshold: number; eligibleApproverUserIds: string[] } | undefined {
  const reqs = (requestProfile as { approvalRequirements?: unknown }).approvalRequirements;
  if (typeof reqs !== "object" || reqs === null) return undefined;
  const q = (reqs as { quorum?: unknown }).quorum;
  if (q === undefined || q === null) return undefined;
  if (typeof q !== "object" || Array.isArray(q)) {
    throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
  }
  const rec = q as Record<string, unknown>;
  // Reject unknown keys (fail closed on typos).
  for (const k of Object.keys(rec)) {
    if (k !== "threshold" && k !== "eligibleApproverUserIds") {
      throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
    }
  }
  const threshold = rec.threshold;
  const eligible = rec.eligibleApproverUserIds;
  if (
    typeof threshold !== "number" ||
    !Number.isInteger(threshold) ||
    threshold < 1 ||
    !Array.isArray(eligible) ||
    eligible.length === 0 ||
    !eligible.every((u) => typeof u === "string" && u.length > 0)
  ) {
    throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
  }
  const ids = eligible as string[];
  // No duplicate eligible ids (a duplicate would inflate the apparent set size
  // and could let a threshold exceed the true distinct-approver count).
  if (new Set(ids).size !== ids.length) {
    throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
  }
  // Threshold must be reachable within the distinct eligible set.
  if (threshold > ids.length) {
    throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
  }
  return { threshold, eligibleApproverUserIds: ids };
}

function capabilitySelectorMatches(config: Record<string, unknown>, operationKey: string): boolean {
  const caps = (config as { capabilities?: unknown }).capabilities;
  if (!Array.isArray(caps)) return false;
  return caps.some((c) => {
    if (typeof c !== "string") return false;
    if (c === operationKey) return true;
    if (c.endsWith(".*")) return operationKey.startsWith(c.slice(0, -1));
    return false;
  });
}

export const providerActionService = new ProviderActionService();
export { ProviderActionService };
