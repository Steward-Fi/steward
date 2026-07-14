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
import {
  type GithubCanonicalActionV1,
  jcsStringify,
  type ProviderRequestEnvelopeV1,
  sha256HexPrefixed,
} from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { writeAuditEvent } from "./audit";

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
  build: GithubActionBuild;
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
      return this.outcomeFromBinding(priorBinding);
    }

    // ── Build the request envelope + hash. ──
    const envelope = this.buildEnvelope(input, {
      tenantId,
      actorAgentId,
      providerAccountId: account.id,
      operationId: operation.id,
      operationRevision: operation.revision,
      actionDigest,
    });
    const requestHash = sha256HexPrefixed(jcsStringify(this.envelopeObject(envelope)));

    const intentId = `pa_${randomUUID()}`;

    // ── Evaluate access + policy OUTSIDE-but-consistent, then persist in a tx. ──
    // Access is evaluated against the resolved, stable rows (their revisions are
    // captured in the decision). Policy runs only on allow.
    const accessDecisionId = randomUUID();
    const access = await this.evaluateAccess({
      tenantId,
      workspaceId: input.workspaceId,
      actorAgentId,
      account,
      operation,
      environment,
      decisionId: accessDecisionId,
      intentId,
    });

    let policy: {
      doc: PersistedPolicyDecisionV1;
      evaluation: ProviderPolicyEvaluationV1;
      decisionId: string;
    } | null = null;
    if (access.effect === "allow") {
      policy = await this.evaluatePolicy({
        tenantId,
        workspaceId: input.workspaceId,
        actorAgentId,
        operation,
        build,
        intentId,
        requestHash,
        actionDigest,
      });
    }

    // Derive final status + effects.
    const accessEffect: "allow" | "deny" = access.effect;
    const policyEffect: "not_evaluated" | "hard_deny" | "approval_required" | "allow" =
      access.effect === "deny"
        ? "not_evaluated"
        : (policy as NonNullable<typeof policy>).doc.effect;

    let status: string;
    if (accessEffect === "deny") status = "denied";
    else if (policyEffect === "hard_deny") status = "denied";
    else if (policyEffect === "approval_required") status = "pending_approval";
    else status = "allowed_stub";

    const accessDecisionHash = sha256HexPrefixed(jcsStringify(access.doc));
    const policyDecisionHash = policy ? sha256HexPrefixed(jcsStringify(policy.doc)) : null;

    // ── Step 2: single transaction (intent + binding + outbox). ──
    try {
      await this.db().transaction(async (tx) => {
        await tx.insert(intents).values({
          id: intentId,
          tenantId,
          agentId: actorAgentId,
          intentType: "provider-action",
          status:
            status === "denied"
              ? "rejected"
              : status === "pending_approval"
                ? "pending"
                : "authorized",
          resourceType: "provider-action",
          resourceId: operation.id,
          createdByType: "agent",
          createdById: actorAgentId,
          payload: { operationKey: input.operationKey, actionDigest },
          expiresAt: new Date(input.expiresAt),
        });

        await tx.insert(providerActionBindings).values({
          intentId,
          tenantId,
          workspaceId: input.workspaceId,
          actorAgentId,
          providerAccountId: account.id,
          operationId: operation.id,
          operationRevision: operation.revision,
          canonicalProfile: build.action.profile,
          canonicalActionBytes: Buffer.from(canonicalBytes, "utf8"),
          actionDigest,
          requestEnvelope: this.envelopeObject(envelope) as Record<string, unknown>,
          requestHash,
          idempotencyKeyHash: input.idempotencyKeyHash,
          safeSummary: build.safeSummary,
          accessDecisionId,
          accessEffect,
          accessReasonCode: access.doc.reasonCode,
          matchedBindingIds: access.doc.matchedBindingIds,
          matchedGrantIds: access.doc.matchedGrantIds,
          dependencyRevisions: access.doc.dependencyRevisions as unknown as Record<string, unknown>,
          accessDecision: access.doc as unknown as Record<string, unknown>,
          accessDecisionHash,
          policyDecisionId: policy ? policy.decisionId : null,
          policyEffect,
          policyReasonCodes: policy ? policy.doc.reasonCodes : [],
          policyResults: policy
            ? (policy.doc.policyResults as unknown as Array<Record<string, unknown>>)
            : [],
          policyRevisionHash: policy ? policy.doc.policyRevisionHash : null,
          policyDecision: policy ? (policy.doc as unknown as Record<string, unknown>) : null,
          policyDecisionHash,
          status,
        });

        // Required audit intent -> transactional outbox (drained post-commit).
        await tx.insert(providerActionAuditOutbox).values({
          tenantId,
          intentId,
          action:
            status === "denied"
              ? "provider.action.denied"
              : status === "pending_approval"
                ? "provider.action.approval_required"
                : "provider.action.allowed",
          resourceType: "provider-action",
          resourceId: operation.id,
          metadata: {
            actorAgentId,
            operationKey: input.operationKey,
            actionDigest,
            requestHash,
            accessDecisionId,
            accessDecisionHash,
            accessEffect,
            accessReasonCode: access.doc.reasonCode,
            policyDecisionId: policy?.decisionId ?? null,
            policyDecisionHash,
            policyEffect,
            policyReasonCodes: policy?.doc.reasonCodes ?? [],
            status,
            requestId: input.requestId ?? null,
          },
        });
      });
    } catch {
      // Any persistence failure denies; the stub is never called.
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
    if (accessEffect === "deny") {
      return {
        kind: "access_denied",
        code: access.doc.reasonCode,
        httpStatus: 403,
        intentId,
        requestHash,
        actionDigest,
      };
    }
    if (policyEffect === "hard_deny") {
      const code = (policy as NonNullable<typeof policy>).doc.reasonCodes[0] ?? "POLICY_HARD_DENY";
      return {
        kind: "policy_denied",
        code,
        httpStatus: (POLICY_DENY_HTTP[code] ?? 403) as 403 | 503,
        intentId,
        requestHash,
        actionDigest,
      };
    }
    if (policyEffect === "approval_required") {
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
  private async evaluateAccess(args: {
    tenantId: string;
    workspaceId: string;
    actorAgentId: string;
    account: typeof providerAccounts.$inferSelect;
    operation: typeof providerOperations.$inferSelect;
    environment: PersistedAccessDecisionV1["environment"];
    decisionId: string;
    intentId: string;
  }): Promise<{ effect: "allow" | "deny"; doc: PersistedAccessDecisionV1 }> {
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

    const [workspace] = await this.db()
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
    const [agent] = await this.db()
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
    const bindingRows = await this.db()
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

    const grantRows = await this.db()
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
    build: GithubActionBuild;
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
      host: "api.github.com",
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

  // ── Required-audit outbox drain (post-commit, pre-stub) ──
  private async drainAuditOutbox(tenantId: string, intentId: string): Promise<boolean> {
    const rows = await this.db()
      .select()
      .from(providerActionAuditOutbox)
      .where(
        and(
          eq(providerActionAuditOutbox.tenantId, tenantId),
          eq(providerActionAuditOutbox.intentId, intentId),
          sql`${providerActionAuditOutbox.deliveredAt} IS NULL`,
        ),
      );
    for (const row of rows) {
      await writeAuditEvent({
        tenantId: row.tenantId,
        actorType: "agent",
        actorId: (row.metadata as { actorAgentId?: string }).actorAgentId ?? null,
        action: row.action,
        resourceType: row.resourceType,
        resourceId: row.resourceId,
        metadata: row.metadata as Record<string, unknown>,
      });
      await this.db()
        .update(providerActionAuditOutbox)
        .set({ deliveredAt: new Date() })
        .where(eq(providerActionAuditOutbox.id, row.id));
    }
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
  private canonicalActionObject(a: GithubCanonicalActionV1): Record<string, unknown> {
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

  private outcomeFromBinding(b: typeof providerActionBindings.$inferSelect): ProviderActionOutcome {
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
    if (b.status === "pending_approval")
      return {
        kind: "approval_required",
        code: "APPROVAL_REQUIRED",
        httpStatus: 202,
        intentId: b.intentId,
        requestHash: b.requestHash,
        actionDigest: b.actionDigest,
      };
    // allowed_stub / stub_succeeded / stub_failed
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
