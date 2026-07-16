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
  type ProviderPolicyContext,
  type ProviderPolicyEvaluationV1,
  type ProviderPolicyRule,
} from "@stwd/policy-engine";
import type { GithubActionBuild } from "@stwd/provider-github";
import type { XActionBuild } from "@stwd/provider-x";
import {
  type GithubCanonicalActionV1,
  jcsStringify,
  type ProviderRequestEnvelopeV1,
  sha256HexPrefixed,
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
export type ProviderActionBuild = GithubActionBuild | XActionBuild;
/** The structurally-shared canonical action shape both adapters emit. */
type AnyCanonicalActionV1 = GithubCanonicalActionV1 | XCanonicalActionV1;
import { and, eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { appendAuditEvent, withTenantAuditQueue, writeAuditEvent } from "./audit";
import { ApprovalArmError, buildApprovalArm } from "./provider-approval";

const EVALUATOR_VERSION = "provider-action.v1";
const POLICY_TYPE = "capability-intent" as const;

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
      code: "EVIDENCE_DECISION_PERSIST_FAILED" | "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE";
      httpStatus: 503;
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
    const { principal, build } = input;
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
      await this.writeRequiredDenialAudit(tenantId, {
        action: "provider.action.denied",
        resourceType: "provider-action",
        resourceId: `${input.workspaceId}:${input.providerAccountId}:${input.operationKey}`,
        metadata: {
          reasonCode: "SCOPE_RESOURCE_NOT_FOUND",
          actorAgentId,
          actionDigest: sha256HexPrefixed(jcsStringify(this.canonicalActionObject(build.action))),
          requestId: input.requestId ?? null,
        },
      });
      return { kind: "scope_not_found", code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
    }

    const { workspace, account, operation } = resolved;
    const environment = workspace.environment as PersistedAccessDecisionV1["environment"];

    // Compute the canonical action digest + request envelope/hash up-front (they
    // are pure and needed for the binding + idempotency conflict check).
    const actionDigest = sha256HexPrefixed(jcsStringify(this.canonicalActionObject(build.action)));
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
      // A replay MUST match on the durable action binding. requestedAt/nonce
      // differ per call, so we compare the ACTION binding (digest + resource),
      // not the request hash which intentionally varies. Any different
      // action/resource for the same key => conflict.
      if (priorBinding.actionDigest !== actionDigest) {
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
              })
            : null;

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
      // A missing PR1 execution dependency (route/credential) fails approval
      // creation CLOSED (spec §5.2) — surfaced as an evidence failure so no
      // partial approval arm is ever visible.
      if (e instanceof ApprovalArmError) {
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
      return {
        kind: "evidence_failure",
        code: "EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE",
        httpStatus: 503,
        intentId,
      };
    }

    // ── Terminal outcomes for deny / approval. ──
    if (effects.access === "deny") {
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
    let stub: ProviderActionStubResult;
    try {
      stub = await executeProviderActionStub(intentId);
    } catch {
      return {
        kind: "backend_unavailable",
        code: "BACKEND_STUB_UNAVAILABLE",
        httpStatus: 503,
        intentId,
        requestHash,
        actionDigest,
      };
    }
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

  // ── Policy evaluation (spec §6.2 / §6.3) ──
  private async evaluatePolicy(args: {
    tenantId: string;
    workspaceId: string;
    actorAgentId: string;
    operation: typeof providerOperations.$inferSelect;
    build: ProviderActionBuild;
    intentId: string;
    requestHash: string;
    actionDigest: string;
  }): Promise<{
    doc: PersistedPolicyDecisionV1;
    evaluation: ProviderPolicyEvaluationV1;
    decisionId: string;
  }> {
    const decidedAt = new Date().toISOString();
    const decisionId = randomUUID();
    const { operation, build } = args;

    // The capability-intent rules that govern this operation come from the
    // operation's request profile. PR2 reads the enabled capability-intent rules
    // declared on the provider operation's request_profile.policyRules; absent =>
    // no governing rules (default deny).
    const rules = extractCapabilityIntentRules(operation.requestProfile);

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
    return { doc, evaluation, decisionId };
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
      idempotencyKeyHash: input.idempotencyKeyHash,
      requestedAt: input.requestedAt,
      expiresAt: input.expiresAt,
      nonce: input.nonce,
    };
  }

  private envelopeObject(e: ProviderRequestEnvelopeV1): Record<string, unknown> {
    return {
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
  }

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
