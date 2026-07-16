/**
 * provider-approval.ts — PR3 sole transition owner for approval-required
 * provider actions (spec §6). It:
 *
 *   - builds the exact approval commitment at PR2 creation (createApprovalArm),
 *   - decides (approve/deny) with current-authority + recent-MFA + exact-request
 *     integrity checks,
 *   - expires and stales through the exact atomic state machine,
 *   - safely resumes an approved action to `execution_ready` WITHOUT executing
 *     anything, consuming the queue approval exactly once.
 *
 * Every state transition and its REQUIRED audit event commit atomically through
 * `withTenantAuditedTransaction` (I14). The service NEVER decrypts a credential,
 * calls the proxy, mints execution authorization, claims a nonce, or performs
 * network I/O (I15) — that is PR4.
 *
 * Correlation contract (PR5 C1): every lifecycle audit event sets top-level
 * `resource_type='provider_action'` and `resource_id=intents.id` in addition to
 * the signed `metadata.intentId`.
 */

import { randomUUID } from "node:crypto";
import {
  agents,
  approvalQueue,
  getDb,
  intents,
  providerAccounts,
  providerActionApprovals,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  userTenants,
  withTenantAuditedTransaction,
  workspaces,
} from "@stwd/db";
import {
  computeApprovalCommitmentHash,
  computeDecisionRequestHash,
  jcsStringify,
  PROVIDER_APPROVAL_AUDIT_SCHEMA,
  type ProviderApprovalAuditPayloadV1,
  type ProviderApprovalCommitmentV1,
  sha256HexPrefixed,
} from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";
import {
  mintProviderExecutionAuthorizationWithinTx,
  ProviderExecutionMintError,
} from "./provider-execution.js";

const RESUME_ACTOR = "steward-system" as const;
const MAX_MFA_AGE_MS = 300_000; // 5 minutes (spec §3.3, not tenant-configurable up)
const MFA_FUTURE_SKEW_MS = 30_000; // 30s upper tolerance

// ─── Result envelope ──────────────────────────────────────────────────────────

export interface ApprovalSuccess {
  ok: true;
  httpStatus: 200;
  id: string;
  status: string;
  version: number;
  requestHash: string;
  actionDigest: string;
  replayed?: boolean;
  resumeAttemptId?: string;
}

export interface ApprovalFailure {
  ok: false;
  code: string;
  httpStatus: number;
}

export type ApprovalResult = ApprovalSuccess | ApprovalFailure;

function fail(code: string, httpStatus: number): ApprovalFailure {
  return { ok: false, code, httpStatus };
}

// ─── Decision input (already validated by the route) ──────────────────────────

export interface DecideInput {
  intentId: string;
  tenantId: string;
  authenticatedUserId: string;
  sessionMfaVerifiedAt: number | undefined;
  requiredMfaAssurance?: string; // reserved; PR1 does not yet supply assurance
  decision: "approve" | "deny";
  expectedVersion: number;
  expectedRequestHash: string;
  expectedActionDigest: string;
  reasonCode: string | null;
  reason: string | null;
  idempotencyKey: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}

// ─── Row shapes ───────────────────────────────────────────────────────────────

type BindingRow = typeof providerActionBindings.$inferSelect;
type QueueRow = typeof approvalQueue.$inferSelect;

interface LoadedCase {
  intent: typeof intents.$inferSelect;
  binding: BindingRow;
  queue: QueueRow;
}

// ─── Commitment creation (called from the PR2 create tx, spec §6.3) ───────────

type DbBase = ReturnType<typeof getDb>;
type DbExecutor = DbBase | Parameters<Parameters<DbBase["transaction"]>[0]>[0];

/**
 * Build the exact approval commitment + queue row inside the PR2 create
 * transaction (spec §6.3 steps 3-5). Returns the commitment hash + queue id so
 * the caller can set them on the binding. THROWS if a required PR1 execution
 * dependency (route/credential) is missing — creation must fail closed (§5.2).
 *
 * The caller (provider-action-service) has already inserted the intent and is
 * inside the same transaction; it sets binding.approval_queue_id +
 * approval_commitment_hash on the binding insert with these return values.
 */
export async function buildApprovalArm(args: {
  tx: DbExecutor;
  tenantId: string;
  workspaceId: string;
  intentId: string;
  actorAgentId: string;
  actorRevision: number;
  account: typeof providerAccounts.$inferSelect;
  operation: typeof providerOperations.$inferSelect;
  requestHash: string;
  actionDigest: string;
  accessDecisionId: string;
  accessDecisionHash: string;
  matchedBindings: Array<{ id: string; revision: number }>;
  matchedGrants: Array<{ id: string; revision: number }>;
  policyDecisionId: string;
  policyDecisionHash: string;
  policyRevisionHash: string;
  evaluatorVersion: string;
  requesterSeparation: boolean;
  requestedAt: string;
  expiresAt: string;
  /**
   * The adapter canonical profile of the action being committed (e.g.
   * `github.provider-action.v1` or `x.provider-action.v1`). Bound into the
   * commitment so a resume recomputes the same document; sourced from the
   * validated action build, never hardcoded per provider.
   */
  canonicalProfile: ProviderApprovalCommitmentV1["operation"]["canonicalProfile"];
  /**
   * #205 flat M-of-N quorum config (already fail-closed-validated by the caller's
   * extractQuorumConfig). `undefined` => single-approver legacy path: the queue
   * row's quorum columns stay NULL/empty/0 and the commitment omits the quorum
   * member (byte-identical commitment to pre-#205). When present it is
   * re-validated here as defense in depth before it is committed/persisted.
   */
  quorum?: { threshold: number; eligibleApproverUserIds: string[] };
}): Promise<{ queueId: string; commitmentHash: string; commitment: ProviderApprovalCommitmentV1 }> {
  const tx = args.tx;

  // Route + credential dependencies MUST exist (spec §5.2). Missing => throw so
  // creation fails closed.
  const routeId = args.operation.secretRouteId;
  if (!routeId) {
    throw new ApprovalArmError("APPROVAL_ROUTE_UNAVAILABLE");
  }
  const [route] = await tx
    .select({ id: secretRoutes.id, authorityRevision: secretRoutes.authorityRevision })
    .from(secretRoutes)
    .where(and(eq(secretRoutes.tenantId, args.tenantId), eq(secretRoutes.id, routeId)))
    .limit(1);
  if (!route) {
    throw new ApprovalArmError("APPROVAL_ROUTE_UNAVAILABLE");
  }
  const secretId = args.account.credentialSecretId;
  const secretVersion = args.account.credentialVersion;
  if (!secretId || secretVersion == null) {
    throw new ApprovalArmError("APPROVAL_CREDENTIAL_UNAVAILABLE");
  }

  // #205 defense-in-depth: re-validate the quorum config shape at commit time so
  // a malformed quorum can never be persisted even if a future caller forgets
  // extractQuorumConfig (spec §7 fail-closed at store time). Distinctness of the
  // eligible set + threshold reachability are re-checked here.
  const quorum = args.quorum;
  if (quorum) {
    const ids = quorum.eligibleApproverUserIds;
    if (
      !Number.isInteger(quorum.threshold) ||
      quorum.threshold < 1 ||
      !Array.isArray(ids) ||
      ids.length === 0 ||
      !ids.every((u) => typeof u === "string" && u.length > 0) ||
      new Set(ids).size !== ids.length ||
      quorum.threshold > ids.length
    ) {
      throw new ApprovalArmError("APPROVAL_QUORUM_CONFIG_INVALID");
    }
  }

  const commitment: ProviderApprovalCommitmentV1 = {
    schemaVersion: "steward.provider-approval-commitment.v1",
    intentId: args.intentId,
    tenantId: args.tenantId,
    workspaceId: args.workspaceId,
    requestActor: { type: "agent", id: args.actorAgentId, revision: args.actorRevision },
    providerAccount: { id: args.account.id, revision: args.account.revision, status: "active" },
    operation: {
      id: args.operation.id,
      key: args.operation.operationKey,
      revision: args.operation.revision,
      riskClass: args.operation.riskClass,
      canonicalProfile: args.canonicalProfile,
    },
    requestHash: args.requestHash,
    actionDigest: args.actionDigest,
    accessDecision: {
      id: args.accessDecisionId,
      hash: args.accessDecisionHash,
      effect: "allow",
      matchedBindings: args.matchedBindings,
      matchedGrants: args.matchedGrants,
    },
    policyDecision: {
      id: args.policyDecisionId,
      hash: args.policyDecisionHash,
      effect: "approval_required",
      policyRevisionHash: args.policyRevisionHash,
      approvalPolicyRevisionHash: args.policyRevisionHash,
      evaluatorVersion: args.evaluatorVersion,
    },
    executionDependencies: {
      routeId: route.id,
      routeRevision: route.authorityRevision,
      secretId,
      secretVersion,
    },
    approvalRequirements: {
      role: "workspace_approver",
      requesterSeparation: args.requesterSeparation,
      maxMfaAgeSeconds: 300,
      requiredMfaAssurance: "current-session-mfa",
      // Additive: emitted ONLY when a quorum is configured, so the single-approver
      // commitment is byte-identical to pre-#205.
      ...(quorum
        ? {
            quorum: {
              threshold: quorum.threshold,
              eligibleApproverUserIds: quorum.eligibleApproverUserIds,
            },
          }
        : {}),
    },
    requestedAt: args.requestedAt,
    expiresAt: args.expiresAt,
  };

  const commitmentHash = computeApprovalCommitmentHash(commitment);
  const queueId = `aq_${randomUUID()}`;

  await tx.insert(approvalQueue).values({
    id: queueId,
    txId: null,
    agentId: args.actorAgentId,
    approvalKind: "provider_action",
    intentId: args.intentId,
    tenantId: args.tenantId,
    workspaceId: args.workspaceId,
    status: "pending",
    requestedByType: "agent",
    requestedById: args.actorAgentId,
    requestHash: args.requestHash,
    actionDigest: args.actionDigest,
    approvalCommitment: commitment as unknown as Record<string, unknown>,
    approvalCommitmentHash: commitmentHash,
    expectedBindingRevision: 1,
    expiresAt: new Date(args.expiresAt),
    // #205 quorum config columns. NULL/empty/0 for the single-approver path (the
    // CHECK in 0083 enforces this shape). When a quorum is set, the eligible set
    // + threshold are persisted here so decide() can re-validate against the
    // frozen set even if the commitment doc were ever tampered.
    quorumThreshold: quorum ? quorum.threshold : null,
    quorumEligibleUserIds: quorum ? quorum.eligibleApproverUserIds : [],
    quorumApprovalsCount: 0,
  });

  return { queueId, commitmentHash, commitment };
}

export class ApprovalArmError extends Error {
  constructor(public code: string) {
    super(code);
    this.name = "ApprovalArmError";
  }
}

// ─── Audit payload helper (C1 fields) ─────────────────────────────────────────

function buildAuditPayload(
  binding: BindingRow,
  queue: QueueRow,
  args: {
    approvalActorUserId: string | null;
    resumeActor: "steward-system" | null;
    bindingRevisionBefore: number | null;
    bindingRevisionAfter: number;
    fromStatus: string | null;
    toStatus: string;
    reasonCode: string;
    resumeAttemptId: string | null;
  },
): ProviderApprovalAuditPayloadV1 {
  return {
    schemaVersion: PROVIDER_APPROVAL_AUDIT_SCHEMA,
    intentId: binding.intentId,
    approvalQueueId: queue.id,
    tenantId: binding.tenantId,
    workspaceId: binding.workspaceId,
    requestActorAgentId: binding.actorAgentId,
    approvalActorUserId: args.approvalActorUserId,
    resumeActor: args.resumeActor,
    providerAccountId: binding.providerAccountId,
    operationId: binding.operationId,
    requestHash: binding.requestHash,
    actionDigest: binding.actionDigest,
    accessDecisionId: binding.accessDecisionId,
    accessDecisionHash: binding.accessDecisionHash,
    policyDecisionId: binding.policyDecisionId ?? "",
    policyDecisionHash: binding.policyDecisionHash ?? "",
    policyRevisionHash: binding.policyRevisionHash ?? "",
    approvalCommitmentHash: queue.approvalCommitmentHash ?? "",
    bindingRevisionBefore: args.bindingRevisionBefore,
    bindingRevisionAfter: args.bindingRevisionAfter,
    fromStatus: args.fromStatus,
    toStatus: args.toStatus,
    reasonCode: args.reasonCode,
    resumeAttemptId: args.resumeAttemptId,
    occurredAt: new Date().toISOString(),
  };
}

// ─── The service ──────────────────────────────────────────────────────────────

class ProviderApprovalService {
  private db() {
    return getDb();
  }

  // Test-only fault-injection hooks (production defaults are no-ops; not settable
  // from runtime input). Named per spec §13.
  faultHooks: Partial<
    Record<
      | "afterScopeLoad"
      | "afterIntegrity"
      | "afterAuthority"
      | "afterMfa"
      | "beforeAudit"
      | "afterAudit"
      | "beforeMint"
      | "beforeMintInsert"
      | "beforeMintAudit"
      | "afterMint"
      | "beforeCommit",
      () => void | Promise<void>
    >
  > = {};

  private async hook(name: keyof ProviderApprovalService["faultHooks"]): Promise<void> {
    const h = this.faultHooks[name];
    if (h) await h();
  }

  /** Load the intent/binding/queue tuple for a provider approval-required action. */
  private async loadCase(
    tx: DbExecutor,
    tenantId: string,
    intentId: string,
    lock: boolean,
  ): Promise<LoadedCase | { notFound: true } | { notApproval: true }> {
    const [binding] = await tx
      .select()
      .from(providerActionBindings)
      .where(
        and(
          eq(providerActionBindings.tenantId, tenantId),
          eq(providerActionBindings.intentId, intentId),
        ),
      )
      .limit(1);
    if (!binding) return { notFound: true };
    // Only approval-required lineage is governed here.
    if (binding.policyEffect !== "approval_required") return { notApproval: true };

    const [intent] = await tx
      .select()
      .from(intents)
      .where(and(eq(intents.tenantId, tenantId), eq(intents.id, intentId)))
      .limit(1);
    if (!intent) return { notFound: true };

    const [queue] = await tx
      .select()
      .from(approvalQueue)
      .where(
        and(
          eq(approvalQueue.approvalKind, "provider_action"),
          eq(approvalQueue.tenantId, tenantId),
          eq(approvalQueue.intentId, intentId),
        ),
      )
      .limit(1);
    if (!queue) return { notFound: true };

    // Stable lock order: intents, binding, queue (spec §13). The rows are already
    // read; re-select FOR UPDATE in order when a mutating transition needs them.
    if (lock) {
      await tx.execute(
        sql`SELECT id FROM intents WHERE tenant_id = ${tenantId} AND id = ${intentId} FOR UPDATE`,
      );
      await tx.execute(
        sql`SELECT intent_id FROM provider_action_bindings WHERE tenant_id = ${tenantId} AND intent_id = ${intentId} FOR UPDATE`,
      );
      await tx.execute(
        sql`SELECT id FROM approval_queue WHERE approval_kind = 'provider_action' AND tenant_id = ${tenantId} AND intent_id = ${intentId} FOR UPDATE`,
      );
    }
    return { intent, binding, queue };
  }

  // ── Integrity verification (spec §5.3) ──
  private verifyIntegrity(
    binding: BindingRow,
    queue: QueueRow,
  ): { ok: true } | { ok: false; code: string } {
    // 2/3. Re-hash the persisted canonical action bytes → action_digest. The
    // bytes are the UTF-8 of the JCS canonical action (PR2 stores
    // `jcsStringify(action)` as bytea and digests `sha256HexPrefixed(jcs)`); a
    // raw-byte sha256 is byte-identical to the string form.
    const rawBytes = new Uint8Array(binding.canonicalActionBytes as Uint8Array);
    const recomputedDigest = sha256HexPrefixed(rawBytes);
    if (recomputedDigest !== binding.actionDigest) {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    // 5. Re-JCS + hash the persisted envelope → request_hash.
    const recomputedReqHash = sha256HexPrefixed(
      jcsStringify(binding.requestEnvelope as Record<string, unknown>),
    );
    if (recomputedReqHash !== binding.requestHash) {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    // 6. Re-JCS + hash access decision + policy decision documents.
    const recomputedAccessHash = sha256HexPrefixed(
      jcsStringify(binding.accessDecision as Record<string, unknown>),
    );
    if (recomputedAccessHash !== binding.accessDecisionHash) {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    if (binding.policyDecision && binding.policyDecisionHash) {
      const recomputedPolicyHash = sha256HexPrefixed(
        jcsStringify(binding.policyDecision as Record<string, unknown>),
      );
      if (recomputedPolicyHash !== binding.policyDecisionHash) {
        return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
      }
    }
    // Re-hash the persisted commitment document → commitment hash.
    if (queue.approvalCommitment && queue.approvalCommitmentHash) {
      const recomputedCommitmentHash = computeApprovalCommitmentHash(
        queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1,
      );
      if (recomputedCommitmentHash !== queue.approvalCommitmentHash) {
        return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
      }
    } else {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    // 7. Cross-table agreement: queue request_hash/action_digest == binding.
    if (queue.requestHash !== binding.requestHash || queue.actionDigest !== binding.actionDigest) {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    // Commitment doc identity fields must equal binding columns.
    const c = queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1;
    if (
      c.intentId !== binding.intentId ||
      c.tenantId !== binding.tenantId ||
      c.workspaceId !== binding.workspaceId ||
      c.requestActor.id !== binding.actorAgentId ||
      c.requestHash !== binding.requestHash ||
      c.actionDigest !== binding.actionDigest ||
      c.accessDecision.id !== binding.accessDecisionId ||
      c.accessDecision.hash !== binding.accessDecisionHash ||
      c.policyDecision.id !== (binding.policyDecisionId ?? "") ||
      c.policyDecision.hash !== (binding.policyDecisionHash ?? "")
    ) {
      return { ok: false, code: "APPROVAL_COMMITMENT_INTEGRITY_MISMATCH" };
    }
    return { ok: true };
  }

  // ── Dependency re-evaluation against current authoritative state (§5.2) ──
  // Returns { ok } if every committed dependency still matches, else a specific
  // stale code. `requireApprovalRequired` gates policy: at approve/resume the
  // current policy must still be approval_required; at deny we tolerate a stale
  // NON-identity dependency so an approver can still deny (§6.5).
  private async revalidateDependencies(
    tx: DbExecutor,
    binding: BindingRow,
    queue: QueueRow,
  ): Promise<{ ok: true } | { ok: false; code: string }> {
    const c = queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1;
    const now = new Date();

    // Actor still an active agent.
    const [agent] = await tx
      .select({ id: agents.id, ownerUserId: agents.ownerUserId })
      .from(agents)
      .where(and(eq(agents.tenantId, binding.tenantId), eq(agents.id, binding.actorAgentId)))
      .limit(1);
    if (!agent) return { ok: false, code: "APPROVAL_DEPENDENCY_STALE" };

    // Workspace current + EXACT committed revision. The committed value lives in
    // the persisted PR2 access decision (dependencyRevisions.workspace); a
    // workspace-authority revision bump while the workspace stays active must
    // stale the action (exact dependency binding, codex P1).
    const [workspace] = await tx
      .select()
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, binding.tenantId), eq(workspaces.id, binding.workspaceId)))
      .limit(1);
    if (!workspace || workspace.status !== "active") {
      return { ok: false, code: "APPROVAL_DEPENDENCY_STALE" };
    }
    const committedWorkspaceRevision = (
      binding.dependencyRevisions as { workspace?: number } | null
    )?.workspace;
    if (
      typeof committedWorkspaceRevision === "number" &&
      workspace.revision !== committedWorkspaceRevision
    ) {
      return { ok: false, code: "APPROVAL_DEPENDENCY_STALE" };
    }

    // Provider account: exact revision + active status.
    const [account] = await tx
      .select()
      .from(providerAccounts)
      .where(
        and(
          eq(providerAccounts.tenantId, binding.tenantId),
          eq(providerAccounts.workspaceId, binding.workspaceId),
          eq(providerAccounts.id, binding.providerAccountId),
        ),
      )
      .limit(1);
    if (
      !account ||
      account.status !== "active" ||
      account.revision !== c.providerAccount.revision
    ) {
      return { ok: false, code: "APPROVAL_PROVIDER_ACCOUNT_STALE" };
    }

    // Operation: exact revision + active status.
    const [operation] = await tx
      .select()
      .from(providerOperations)
      .where(
        and(
          eq(providerOperations.tenantId, binding.tenantId),
          eq(providerOperations.workspaceId, binding.workspaceId),
          eq(providerOperations.providerAccountId, binding.providerAccountId),
          eq(providerOperations.id, binding.operationId),
        ),
      )
      .limit(1);
    if (
      !operation ||
      operation.status !== "active" ||
      operation.revision !== c.operation.revision
    ) {
      return { ok: false, code: "APPROVAL_OPERATION_STALE" };
    }

    // Route + credential commitments.
    if (!operation.secretRouteId || operation.secretRouteId !== c.executionDependencies.routeId) {
      return { ok: false, code: "APPROVAL_ROUTE_STALE" };
    }
    const [route] = await tx
      .select({ id: secretRoutes.id, authorityRevision: secretRoutes.authorityRevision })
      .from(secretRoutes)
      .where(
        and(
          eq(secretRoutes.tenantId, binding.tenantId),
          eq(secretRoutes.id, operation.secretRouteId),
        ),
      )
      .limit(1);
    if (!route || route.authorityRevision !== c.executionDependencies.routeRevision) {
      return { ok: false, code: "APPROVAL_ROUTE_STALE" };
    }
    if (
      account.credentialSecretId !== c.executionDependencies.secretId ||
      account.credentialVersion !== c.executionDependencies.secretVersion
    ) {
      return { ok: false, code: "APPROVAL_CREDENTIAL_STALE" };
    }

    // Matched grants/bindings: EVERY committed source must still exist, be
    // active, in-window, and retain the exact revision. Any committed source
    // that changed/vanished stales, even if another allow remains (I6/N32).
    for (const g of c.accessDecision.matchedGrants) {
      const [row] = await tx
        .select({
          revision: providerGrants.revision,
          status: providerGrants.status,
          notBefore: providerGrants.notBefore,
          expiresAt: providerGrants.expiresAt,
          environment: providerGrants.environment,
        })
        .from(providerGrants)
        .where(and(eq(providerGrants.tenantId, binding.tenantId), eq(providerGrants.id, g.id)))
        .limit(1);
      if (!row || row.status !== "active" || row.revision !== g.revision) {
        return { ok: false, code: "APPROVAL_GRANT_STALE" };
      }
      if ((row.notBefore && row.notBefore > now) || (row.expiresAt && row.expiresAt <= now)) {
        return { ok: false, code: "APPROVAL_GRANT_STALE" };
      }
    }
    for (const b of c.accessDecision.matchedBindings) {
      const [row] = await tx
        .select({
          revision: providerRoleBindings.revision,
          status: providerRoleBindings.status,
          notBefore: providerRoleBindings.notBefore,
          expiresAt: providerRoleBindings.expiresAt,
        })
        .from(providerRoleBindings)
        .where(
          and(
            eq(providerRoleBindings.tenantId, binding.tenantId),
            eq(providerRoleBindings.id, b.id),
          ),
        )
        .limit(1);
      if (!row || row.status !== "active" || row.revision !== b.revision) {
        return { ok: false, code: "APPROVAL_GRANT_STALE" };
      }
      if ((row.notBefore && row.notBefore > now) || (row.expiresAt && row.expiresAt <= now)) {
        return { ok: false, code: "APPROVAL_GRANT_STALE" };
      }
    }

    // Access decision: exact stored hash must still verify against the persisted
    // document AND the current effective committed set must equal the recorded
    // one (no new broader allow silently repurposed — N33). We recompute the
    // current matched grant/binding id-set for this actor/operation and require
    // it equals the committed id-set.
    const currentAccess = await this.currentMatchedSources(tx, binding, operation, workspace);
    const committedGrantIds = new Set(c.accessDecision.matchedGrants.map((g) => g.id));
    const committedBindingIds = new Set(c.accessDecision.matchedBindings.map((b) => b.id));
    if (
      !setsEqual(committedGrantIds, currentAccess.grantIds) ||
      !setsEqual(committedBindingIds, currentAccess.bindingIds)
    ) {
      return { ok: false, code: "APPROVAL_ACCESS_DECISION_STALE" };
    }

    return { ok: true };
  }

  /** Recompute the current matched grant/binding id-sets for the committed actor/operation. */
  private async currentMatchedSources(
    tx: DbExecutor,
    binding: BindingRow,
    operation: typeof providerOperations.$inferSelect,
    workspace: typeof workspaces.$inferSelect,
  ): Promise<{ grantIds: Set<string>; bindingIds: Set<string> }> {
    const now = new Date();
    const env = workspace.environment;
    const grantRows = await tx
      .select()
      .from(providerGrants)
      .where(
        and(
          eq(providerGrants.tenantId, binding.tenantId),
          eq(providerGrants.workspaceId, binding.workspaceId),
          eq(providerGrants.providerAccountId, binding.providerAccountId),
          eq(providerGrants.agentId, binding.actorAgentId),
          eq(providerGrants.status, "active"),
        ),
      );
    const grantIds = new Set(
      grantRows
        .filter(
          (g) =>
            (!g.notBefore || g.notBefore <= now) &&
            (!g.expiresAt || g.expiresAt > now) &&
            (!g.environment || g.environment === env) &&
            g.operationKeys.includes(operation.operationKey),
        )
        .map((g) => g.id),
    );
    const bindingRows = await tx
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, binding.tenantId),
          eq(providerRoleBindings.workspaceId, binding.workspaceId),
          eq(providerRoleBindings.principalType, "agent"),
          eq(providerRoleBindings.principalId, binding.actorAgentId),
          eq(providerRoleBindings.status, "active"),
        ),
      );
    const bindingIds = new Set(
      bindingRows
        .filter((b) => {
          if (b.notBefore && b.notBefore > now) return false;
          if (b.expiresAt && b.expiresAt <= now) return false;
          if (b.environment && b.environment !== env) return false;
          if (b.providerAccountId && b.providerAccountId !== binding.providerAccountId)
            return false;
          if (b.roleKey === "workspace_operator")
            return b.operationKeys.includes(operation.operationKey);
          if (b.roleKey === "workspace_viewer")
            return (
              operation.riskClass === "read" && b.operationKeys.includes(operation.operationKey)
            );
          return false;
        })
        .map((b) => b.id),
    );
    return { grantIds, bindingIds };
  }

  // ── Current-policy re-evaluation is a commitment-hash equality check for PR3.
  // The persisted policy document's revision hash must still match the operation
  // (operation revision equality above already covers rule-set drift because the
  // policy revision hash binds operationRevision). A current hard deny is
  // surfaced by the operation/policy revision changing → APPROVAL_OPERATION_STALE
  // or APPROVAL_POLICY_STALE. PR3 does not re-run the evaluator here; operation
  // revision + policy revision hash equality is the exact-binding rule.

  /**
   * Current human workspace authority, shared by approval decisions and the
   * execute-route caller gate. This is the PR3 authority predicate: current
   * tenant membership plus an active, in-window role binding for the exact
   * workspace and its current environment.
   */
  private async hasWorkspaceRoleAuthority(
    tx: DbExecutor,
    binding: BindingRow,
    userId: string,
    tenantId: string,
    roleKeys: ReadonlySet<"workspace_approver" | "workspace_admin">,
  ): Promise<{ ok: true } | { ok: false; reason: "membership" | "role" }> {
    const [membership] = await tx
      .select({ id: userTenants.id })
      .from(userTenants)
      .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, tenantId)))
      .limit(1)
      .for("update");
    if (!membership) return { ok: false, reason: "membership" };

    const [workspace] = await tx
      .select({ environment: workspaces.environment })
      .from(workspaces)
      .where(and(eq(workspaces.tenantId, tenantId), eq(workspaces.id, binding.workspaceId)))
      .limit(1)
      .for("update");
    if (!workspace) return { ok: false, reason: "role" };

    const now = new Date();
    const authorityRows = await tx
      .select()
      .from(providerRoleBindings)
      .where(
        and(
          eq(providerRoleBindings.tenantId, tenantId),
          eq(providerRoleBindings.workspaceId, binding.workspaceId),
          eq(providerRoleBindings.principalType, "human"),
          eq(providerRoleBindings.principalId, userId),
          eq(providerRoleBindings.status, "active"),
        ),
      )
      .for("update");
    const eligible = authorityRows.some(
      (row) =>
        roleKeys.has(row.roleKey as "workspace_approver" | "workspace_admin") &&
        (!row.notBefore || row.notBefore <= now) &&
        (!row.expiresAt || row.expiresAt > now) &&
        (!row.environment || row.environment === workspace.environment),
    );
    return eligible ? { ok: true } : { ok: false, reason: "role" };
  }

  // ── Approver eligibility (spec §3.2, §3.3) ──
  private async checkApprover(
    tx: DbExecutor,
    binding: BindingRow,
    queue: QueueRow,
    userId: string,
    tenantId: string,
    sessionMfaVerifiedAt: number | undefined,
    atResume: boolean,
  ): Promise<{ ok: true } | { ok: false; code: string; httpStatus: number }> {
    const authority = await this.hasWorkspaceRoleAuthority(
      tx,
      binding,
      userId,
      tenantId,
      new Set(["workspace_approver"]),
    );
    if (!authority.ok) {
      if (atResume) return { ok: false, code: "APPROVAL_APPROVER_STALE", httpStatus: 409 };
      return authority.reason === "membership"
        ? { ok: false, code: "APPROVAL_MEMBERSHIP_INACTIVE", httpStatus: 403 }
        : { ok: false, code: "APPROVAL_ROLE_REQUIRED", httpStatus: 403 };
    }

    // Requester separation (I10): if enabled and the approver is a known
    // controller of the requesting agent, ineligible.
    const c = queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1;
    if (c.approvalRequirements.requesterSeparation) {
      const [agent] = await tx
        .select({ ownerUserId: agents.ownerUserId })
        .from(agents)
        .where(and(eq(agents.tenantId, tenantId), eq(agents.id, binding.actorAgentId)))
        .limit(1);
      if (agent?.ownerUserId && agent.ownerUserId === userId) {
        return { ok: false, code: "APPROVAL_REQUESTER_SEPARATION_REQUIRED", httpStatus: 403 };
      }
    }

    // #205 quorum: the requester (agent owner) can NEVER count toward the
    // quorum, generalizing requester-separation to the M-of-N case regardless of
    // whether requesterSeparation was independently set. And the approver MUST be
    // a member of the frozen eligible set. Both checks fail closed if the
    // eligible set is malformed/empty at decide time (spec §7 eval-time).
    if (queue.quorumThreshold != null) {
      const [agent] = await tx
        .select({ ownerUserId: agents.ownerUserId })
        .from(agents)
        .where(and(eq(agents.tenantId, tenantId), eq(agents.id, binding.actorAgentId)))
        .limit(1);
      if (agent?.ownerUserId && agent.ownerUserId === userId) {
        return { ok: false, code: "APPROVAL_REQUESTER_SEPARATION_REQUIRED", httpStatus: 403 };
      }
      const eligible = queue.quorumEligibleUserIds ?? [];
      // Fail closed on a malformed persisted config (defense in depth; the
      // create-time CHECK + validation should make this unreachable).
      if (
        !Number.isInteger(queue.quorumThreshold) ||
        queue.quorumThreshold < 1 ||
        eligible.length === 0 ||
        queue.quorumThreshold > eligible.length ||
        new Set(eligible).size !== eligible.length
      ) {
        return { ok: false, code: "APPROVAL_QUORUM_CONFIG_INVALID", httpStatus: 422 };
      }
      if (!eligible.includes(userId)) {
        // Not in the eligible set: same 403 posture as a missing role (an
        // eligible-role holder who is nonetheless not on THIS action's approver
        // list cannot vote).
        return { ok: false, code: "APPROVAL_NOT_ELIGIBLE_APPROVER", httpStatus: 403 };
      }
    }

    // Recent MFA (only enforced at decision time, not resume — §9). At resume we
    // only require the approver still be eligible (checked above).
    if (!atResume) {
      const mfa = this.checkMfa(sessionMfaVerifiedAt);
      if (!mfa.ok) return mfa;
    }

    return { ok: true };
  }

  private checkMfa(
    verifiedAt: number | undefined,
  ): { ok: true } | { ok: false; code: string; httpStatus: number } {
    if (verifiedAt == null || !Number.isFinite(verifiedAt)) {
      return { ok: false, code: "APPROVAL_MFA_REQUIRED", httpStatus: 403 };
    }
    const nowMs = Date.now();
    if (verifiedAt > nowMs + MFA_FUTURE_SKEW_MS) {
      return { ok: false, code: "APPROVAL_MFA_TIMESTAMP_INVALID", httpStatus: 403 };
    }
    if (nowMs - verifiedAt > MAX_MFA_AGE_MS) {
      return { ok: false, code: "APPROVAL_MFA_STALE", httpStatus: 403 };
    }
    return { ok: true };
  }

  // ── Expiry helper: guarded atomic expiry (spec §6.6). Returns true if it
  // transitioned pending/approved → expired in this tx. ──
  private async expireIfDue(
    tx: DbExecutor,
    append: (ev: { tenantId: string } & Record<string, unknown>) => Promise<void>,
    loaded: LoadedCase,
  ): Promise<boolean> {
    const { binding, queue } = loaded;
    // DB time. drizzle's tx.execute returns either an array (postgres-js) or a
    // { rows } object (pglite/neon), so normalize.
    const dueRes = await tx.execute(sql`SELECT (${queue.expiresAt} <= now()) AS due`);
    const dueRows = (
      Array.isArray(dueRes) ? dueRes : ((dueRes as { rows?: unknown[] }).rows ?? [])
    ) as Array<{ due: boolean }>;
    const due = dueRows[0]?.due === true;
    if (!due) return false;
    if (!(queue.status === "pending" || queue.status === "approved")) return false;

    const before = binding.bindingRevision;
    const after = before + 1;
    // The decision-shape CHECK requires expired/stale rows to carry decision
    // IS NULL / consumed_at IS NULL. An approved-then-expired row must clear its
    // queue decision fields; the immutable decision evidence is preserved on the
    // binding (approval_actor_user_id/approved_at) and in the signed
    // provider.approval.decided audit event (I3 evidence, I14).
    const won = await tx
      .update(approvalQueue)
      .set({
        status: "expired",
        decision: null,
        resolvedAt: null,
        resolvedByType: null,
        resolvedById: null,
        resolvedBy: null,
        mfaVerifiedAt: null,
      })
      .where(
        and(eq(approvalQueue.id, queue.id), sql`${approvalQueue.status} IN ('pending','approved')`),
      )
      .returning({ id: approvalQueue.id });
    // Guarded CAS: if a concurrent winner already transitioned the row, do NOT
    // update the intent or append a duplicate expired event (codex P2).
    if (won.length === 0) return false;
    await tx
      .update(providerActionBindings)
      .set({
        status: "approval_expired",
        bindingRevision: after,
        expiredAt: new Date(),
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerActionBindings.intentId, binding.intentId),
          sql`${providerActionBindings.status} IN ('pending_approval','approved')`,
        ),
      );
    await tx
      .update(intents)
      .set({
        status: "expired",
        expiredBy: RESUME_ACTOR,
        expiredAt: new Date(),
        updatedAt: new Date(),
      })
      .where(eq(intents.id, binding.intentId));

    const payload = buildAuditPayload(binding, queue, {
      approvalActorUserId: null,
      resumeActor: RESUME_ACTOR,
      bindingRevisionBefore: before,
      bindingRevisionAfter: after,
      fromStatus: binding.status,
      toStatus: "approval_expired",
      reasonCode: "APPROVAL_EXPIRED",
      resumeAttemptId: null,
    });
    await append({
      tenantId: binding.tenantId,
      actorType: "system",
      actorId: RESUME_ACTOR,
      action: "provider.approval.expired",
      resourceType: "provider_action",
      resourceId: binding.intentId,
      metadata: payload as unknown as Record<string, unknown>,
    });
    return true;
  }

  // ── Stale transition (spec §6.7). One tx moves pending/approved → stale.
  // Returns false if a concurrent winner already moved the row (guarded CAS lost)
  // so the caller does NOT emit a duplicate transition or audit event (codex P2). ──
  private async staleTransition(
    tx: DbExecutor,
    append: (ev: { tenantId: string } & Record<string, unknown>) => Promise<void>,
    binding: BindingRow,
    queue: QueueRow,
    reasonCode: string,
  ): Promise<boolean> {
    const before = binding.bindingRevision;
    const after = before + 1;
    // See expireIfDue: stale rows must carry decision IS NULL per the shape CHECK;
    // the immutable decision evidence lives on the binding + audit chain.
    const won = await tx
      .update(approvalQueue)
      .set({
        status: "stale",
        decision: null,
        resolvedAt: null,
        resolvedByType: null,
        resolvedById: null,
        resolvedBy: null,
        mfaVerifiedAt: null,
      })
      .where(
        and(eq(approvalQueue.id, queue.id), sql`${approvalQueue.status} IN ('pending','approved')`),
      )
      .returning({ id: approvalQueue.id });
    // Loser: another attempt already transitioned the row. Emit nothing.
    if (won.length === 0) return false;
    await tx
      .update(providerActionBindings)
      .set({
        status: "approval_stale",
        bindingRevision: after,
        staleAt: new Date(),
        staleReasonCode: reasonCode,
        updatedAt: new Date(),
      })
      .where(
        and(
          eq(providerActionBindings.intentId, binding.intentId),
          sql`${providerActionBindings.status} IN ('pending_approval','approved')`,
        ),
      );
    await tx
      .update(intents)
      .set({
        status: "canceled",
        canceledBy: RESUME_ACTOR,
        canceledAt: new Date(),
        cancellationReason: reasonCode,
        updatedAt: new Date(),
      })
      .where(eq(intents.id, binding.intentId));
    const payload = buildAuditPayload(binding, queue, {
      approvalActorUserId: null,
      resumeActor: RESUME_ACTOR,
      bindingRevisionBefore: before,
      bindingRevisionAfter: after,
      fromStatus: binding.status,
      toStatus: "approval_stale",
      reasonCode,
      resumeAttemptId: null,
    });
    await append({
      tenantId: binding.tenantId,
      actorType: "system",
      actorId: RESUME_ACTOR,
      action: "provider.approval.staled",
      resourceType: "provider_action",
      resourceId: binding.intentId,
      metadata: payload as unknown as Record<string, unknown>,
    });
    return true;
  }

  // ── Terminal-state → outcome mapping for a loaded (non-transitioning) case. ──
  private terminalOutcome(binding: BindingRow, queue: QueueRow): ApprovalResult {
    const base = {
      id: binding.intentId,
      version: binding.bindingRevision,
      requestHash: binding.requestHash,
      actionDigest: binding.actionDigest,
    };
    switch (binding.status) {
      case "approval_denied":
        return fail("APPROVAL_TERMINAL", 409);
      case "approval_expired":
        return fail("APPROVAL_EXPIRED", 410);
      case "approval_stale":
        return fail("APPROVAL_TERMINAL", 409);
      case "execution_ready":
        return {
          ok: true,
          httpStatus: 200,
          status: "execution_ready",
          resumeAttemptId: binding.resumeAttemptId ?? undefined,
          ...base,
        };
      default:
        void queue;
        return fail("APPROVAL_STATE_CONFLICT", 409);
    }
  }

  // ── DECIDE (approve/deny), spec §6.4 / §6.5 ──
  async decide(input: DecideInput): Promise<ApprovalResult> {
    try {
      return await withTenantAuditedTransaction(input.tenantId, async (txRaw, appendRaw) => {
        const tx = txRaw as DbExecutor;
        const append = mapRequiredAuditFailure(appendRaw as unknown as ApprovalAuditAppend);

        const loaded = await this.loadCase(tx, input.tenantId, input.intentId, true);
        await this.hook("afterScopeLoad");
        if ("notFound" in loaded) return fail("SCOPE_RESOURCE_NOT_FOUND", 404);
        if ("notApproval" in loaded) return fail("APPROVAL_NOT_REQUIRED", 409);
        const { binding, queue } = loaded;

        // Decision idempotency: exact retry by same user+key returns existing.
        const idemHash = sha256HexPrefixed(input.idempotencyKey);
        const decisionReqHash = computeDecisionRequestHash({
          schemaVersion: "steward.provider-approval-decision.v1",
          tenantId: input.tenantId,
          workspaceId: binding.workspaceId,
          intentId: input.intentId,
          authenticatedUserId: input.authenticatedUserId,
          decision: input.decision,
          expectedVersion: input.expectedVersion,
          expectedRequestHash: input.expectedRequestHash,
          expectedActionDigest: input.expectedActionDigest,
          reasonCode: input.reasonCode,
          reason: input.reason,
        });

        // Decision idempotency replay. Only replay when THIS queue row is still
        // in a DECIDED state (approved/rejected/consumed). If the row later
        // expired/staled (which clears `decision` to NULL but retains the idem
        // hash), an exact retry must NOT report a stale success — it falls through
        // to the expiry/terminal handling below (codex P2).
        if (
          queue.decisionIdempotencyKeyHash &&
          queue.resolvedById === input.authenticatedUserId &&
          queue.decisionIdempotencyKeyHash === idemHash &&
          queue.decision != null &&
          (queue.status === "approved" ||
            queue.status === "rejected" ||
            queue.status === "consumed")
        ) {
          if (queue.decisionRequestHash === decisionReqHash) {
            // Exact retry → return existing decision.
            return this.decisionReplay(binding, queue);
          }
          return fail("APPROVAL_IDEMPOTENCY_CONFLICT", 409);
        }

        // Cross-action idempotency conflict (codex P2): the same approver reusing
        // this decision key on a DIFFERENT intent would violate the partial
        // unique index (tenant_id, resolved_by_id, decision_idempotency_key_hash)
        // and surface as an opaque 503. Detect it here and return the precise
        // 409 instead. Only relevant when we are about to WRITE the key (i.e. the
        // current row has not already recorded it).
        if (queue.decisionIdempotencyKeyHash !== idemHash) {
          const [conflict] = await tx
            .select({ id: approvalQueue.id })
            .from(approvalQueue)
            .where(
              and(
                eq(approvalQueue.approvalKind, "provider_action"),
                eq(approvalQueue.tenantId, input.tenantId),
                eq(approvalQueue.resolvedById, input.authenticatedUserId),
                eq(approvalQueue.decisionIdempotencyKeyHash, idemHash),
              ),
            )
            .limit(1);
          if (conflict && conflict.id !== queue.id) {
            return fail("APPROVAL_IDEMPOTENCY_CONFLICT", 409);
          }
        }

        // Expire first (DB time). Expiry wins over decision.
        if (queue.status === "pending" || queue.status === "approved") {
          const expired = await this.expireIfDue(tx, append, loaded);
          if (expired) return fail("APPROVAL_EXPIRED", 410);
        }

        // Terminal / non-pending state handling.
        if (binding.status !== "pending_approval") {
          // Different-key decision after resolution: allow same-user same-decision
          // replay=true, else conflict (§8.2).
          if (binding.status === "approved" || binding.status === "approval_denied") {
            if (
              queue.resolvedById === input.authenticatedUserId &&
              queue.decision === input.decision
            ) {
              return this.decisionReplay(binding, queue, true);
            }
            return fail("APPROVAL_ALREADY_DECIDED", 409);
          }
          return this.terminalOutcome(binding, queue);
        }

        // Optimistic-lock echoes (§6.4 step 4). These are echo values only.
        if (input.expectedVersion !== binding.bindingRevision) {
          return fail("APPROVAL_EXPECTED_VERSION_MISMATCH", 409);
        }
        if (input.expectedRequestHash !== binding.requestHash) {
          return fail("APPROVAL_REQUEST_HASH_MISMATCH", 409);
        }
        if (input.expectedActionDigest !== binding.actionDigest) {
          return fail("APPROVAL_ACTION_DIGEST_MISMATCH", 409);
        }

        // Integrity (§5.3). A persisted-integrity failure stales.
        const integ = this.verifyIntegrity(binding, queue);
        await this.hook("afterIntegrity");
        if (!integ.ok) {
          await this.staleTransition(tx, append, binding, queue, integ.code);
          return fail(integ.code, 409);
        }

        // Dependency re-eval. For approve, ANY committed dependency mismatch
        // stales. For deny, we still require integrity + scope but tolerate a
        // stale NON-identity dependency (approver may deny an unsafe request).
        const deps = await this.revalidateDependencies(tx, binding, queue);
        await this.hook("afterAuthority");
        if (!deps.ok && input.decision === "approve") {
          await this.staleTransition(tx, append, binding, queue, deps.code);
          return fail(deps.code, 409);
        }

        // Approver eligibility + MFA.
        const approver = await this.checkApprover(
          tx,
          binding,
          queue,
          input.authenticatedUserId,
          input.tenantId,
          input.sessionMfaVerifiedAt,
          false,
        );
        await this.hook("afterMfa");
        if (!approver.ok) return fail(approver.code, approver.httpStatus);

        // Denial reason required.
        if (input.decision === "deny" && !input.reasonCode) {
          return fail("APPROVAL_REASON_REQUIRED", 400);
        }

        const before = binding.bindingRevision;
        const after = before + 1;
        const nowTs = new Date();
        const mfaVerifiedAt = new Date(input.sessionMfaVerifiedAt as number);
        const mfaAgeMs = Date.now() - (input.sessionMfaVerifiedAt as number);

        // ── #205 QUORUM PATH ──────────────────────────────────────────────
        // A configured quorum threshold flips both approve and deny into the
        // multi-approver lifecycle. Absent quorum (threshold NULL) falls through
        // to the single-approver code below, byte-for-byte unchanged.
        if (queue.quorumThreshold != null) {
          return await this.decideQuorum({
            tx,
            append,
            binding,
            queue,
            input,
            before,
            after,
            nowTs,
            mfaVerifiedAt,
            mfaAgeMs,
            idemHash,
            decisionReqHash,
          });
        }

        if (input.decision === "approve") {
          const upd = await tx
            .update(approvalQueue)
            .set({
              status: "approved",
              decision: "approve",
              resolvedAt: nowTs,
              resolvedByType: "user",
              resolvedById: input.authenticatedUserId,
              resolvedBy: input.authenticatedUserId,
              mfaVerifiedAt,
              mfaAgeMsAtDecision: mfaAgeMs,
              reasonCode: input.reasonCode ?? null,
              reason: input.reason ?? null,
              decisionIdempotencyKeyHash: idemHash,
              decisionRequestHash: decisionReqHash,
            })
            .where(and(eq(approvalQueue.id, queue.id), eq(approvalQueue.status, "pending")))
            .returning({ id: approvalQueue.id });
          if (upd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

          await tx
            .update(providerActionBindings)
            .set({
              status: "approved",
              bindingRevision: after,
              approvalActorUserId: input.authenticatedUserId,
              approvedAt: nowTs,
              updatedAt: nowTs,
            })
            .where(
              and(
                eq(providerActionBindings.intentId, binding.intentId),
                eq(providerActionBindings.status, "pending_approval"),
                eq(providerActionBindings.bindingRevision, before),
              ),
            );
          await tx
            .update(intents)
            .set({
              status: "authorized",
              authorizedBy: `user:${input.authenticatedUserId}`,
              authorizedAt: nowTs,
              updatedAt: nowTs,
            })
            .where(eq(intents.id, binding.intentId));

          const payload = buildAuditPayload(binding, queue, {
            approvalActorUserId: input.authenticatedUserId,
            resumeActor: null,
            bindingRevisionBefore: before,
            bindingRevisionAfter: after,
            fromStatus: "pending_approval",
            toStatus: "approved",
            reasonCode: input.reasonCode ?? "approver_manual_approve",
            resumeAttemptId: null,
          });
          await this.hook("beforeAudit");
          await append({
            tenantId: binding.tenantId,
            actorType: "user",
            actorId: input.authenticatedUserId,
            action: "provider.approval.decided",
            resourceType: "provider_action",
            resourceId: binding.intentId,
            metadata: payload as unknown as Record<string, unknown>,
            ipAddress: input.ipAddress ?? null,
            userAgent: input.userAgent ?? null,
            requestId: input.requestId ?? null,
          });
          await this.hook("afterAudit");

          return {
            ok: true,
            httpStatus: 200,
            id: binding.intentId,
            status: "approved",
            version: after,
            requestHash: binding.requestHash,
            actionDigest: binding.actionDigest,
          };
        }

        // DENY.
        const upd = await tx
          .update(approvalQueue)
          .set({
            status: "rejected",
            decision: "deny",
            resolvedAt: nowTs,
            resolvedByType: "user",
            resolvedById: input.authenticatedUserId,
            resolvedBy: input.authenticatedUserId,
            mfaVerifiedAt,
            mfaAgeMsAtDecision: mfaAgeMs,
            reasonCode: input.reasonCode ?? null,
            reason: input.reason ?? null,
            decisionIdempotencyKeyHash: idemHash,
            decisionRequestHash: decisionReqHash,
          })
          .where(and(eq(approvalQueue.id, queue.id), eq(approvalQueue.status, "pending")))
          .returning({ id: approvalQueue.id });
        if (upd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

        await tx
          .update(providerActionBindings)
          .set({
            status: "approval_denied",
            bindingRevision: after,
            approvalActorUserId: input.authenticatedUserId,
            deniedAt: nowTs,
            updatedAt: nowTs,
          })
          .where(
            and(
              eq(providerActionBindings.intentId, binding.intentId),
              eq(providerActionBindings.status, "pending_approval"),
              eq(providerActionBindings.bindingRevision, before),
            ),
          );
        await tx
          .update(intents)
          .set({
            status: "rejected",
            rejectedBy: `user:${input.authenticatedUserId}`,
            rejectedAt: nowTs,
            rejectionReason: input.reasonCode ?? null,
            updatedAt: nowTs,
          })
          .where(eq(intents.id, binding.intentId));

        const payload = buildAuditPayload(binding, queue, {
          approvalActorUserId: input.authenticatedUserId,
          resumeActor: null,
          bindingRevisionBefore: before,
          bindingRevisionAfter: after,
          fromStatus: "pending_approval",
          toStatus: "approval_denied",
          reasonCode: input.reasonCode ?? "approver_manual_deny",
          resumeAttemptId: null,
        });
        await this.hook("beforeAudit");
        await append({
          tenantId: binding.tenantId,
          actorType: "user",
          actorId: input.authenticatedUserId,
          action: "provider.approval.decided",
          resourceType: "provider_action",
          resourceId: binding.intentId,
          metadata: payload as unknown as Record<string, unknown>,
          ipAddress: input.ipAddress ?? null,
          userAgent: input.userAgent ?? null,
          requestId: input.requestId ?? null,
        });
        await this.hook("afterAudit");

        return {
          ok: true,
          httpStatus: 200,
          id: binding.intentId,
          status: "approval_denied",
          version: after,
          requestHash: binding.requestHash,
          actionDigest: binding.actionDigest,
        };
      });
    } catch (e) {
      if (e instanceof AuditUnavailableError)
        return fail("EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE", 503);
      return fail("APPROVAL_PERSISTENCE_FAILED", 503);
    }
  }

  // ── #205 QUORUM DECISION (approve collects N distinct; single deny terminates)
  //
  // Called from decide() ONLY when queue.quorumThreshold != null, after all the
  // shared gates (idempotency, expiry, terminal-state, optimistic-lock echoes,
  // integrity, dependency re-eval, approver eligibility + MFA + eligible-set
  // membership + requester-separation). Runs inside the SAME audited tx with the
  // rows already FOR UPDATE-locked by loadCase.
  //
  // Invariants enforced here:
  //  - DENY WINS IMMEDIATELY: the first deny terminates the whole approval
  //    (pending -> rejected), regardless of collected approvals.
  //  - DISTINCTNESS: a provider_action_approvals UNIQUE(queue, approver) makes a
  //    second decision by the same approver a loud 409. Requester can never vote
  //    (checked upstream). N distinct users required.
  //  - EXACT-BIND per approval: every row stores request_hash/action_digest/
  //    commitment hash + the binding_revision it was cast at, so a later
  //    staleness (which bumps binding_revision and flips the queue to a terminal
  //    stale) invalidates the entire collected set.
  //  - SINGLE-WINNER Nth transition: the pending -> approved flip is a guarded
  //    CAS (WHERE status='pending' AND quorum_approvals_count>=threshold) so two
  //    concurrent Nth approvals produce exactly one execute-reachable transition.
  private async decideQuorum(ctx: {
    tx: DbExecutor;
    append: ApprovalAuditAppend;
    binding: BindingRow;
    queue: QueueRow;
    input: DecideInput;
    before: number;
    after: number;
    nowTs: Date;
    mfaVerifiedAt: Date;
    mfaAgeMs: number;
    idemHash: string;
    decisionReqHash: string;
  }): Promise<ApprovalResult> {
    const { tx, append, binding, queue, input, before, after, nowTs } = ctx;
    const threshold = queue.quorumThreshold as number;
    const userId = input.authenticatedUserId;

    // Per-approver idempotency + distinctness replay: if this exact approver
    // already recorded a decision on THIS queue, an exact retry (same idem key +
    // same decision-request-hash) replays; a different decision or different
    // request-hash is a loud conflict (they cannot change their vote).
    const [existing] = await tx
      .select()
      .from(providerActionApprovals)
      .where(
        and(
          eq(providerActionApprovals.approvalQueueId, queue.id),
          eq(providerActionApprovals.approverUserId, userId),
        ),
      )
      .limit(1);
    if (existing) {
      if (
        existing.decisionIdempotencyKeyHash === ctx.idemHash &&
        existing.decisionRequestHash === ctx.decisionReqHash
      ) {
        // Exact retry of the same vote by the same approver. Report the CURRENT
        // queue state (the vote already counted).
        return {
          ok: true,
          httpStatus: 200,
          id: binding.intentId,
          status: binding.status,
          version: binding.bindingRevision,
          requestHash: binding.requestHash,
          actionDigest: binding.actionDigest,
          replayed: true,
        };
      }
      // A second, DIFFERENT decision by the same approver is rejected loudly.
      return fail("APPROVAL_DUPLICATE_APPROVER", 409);
    }

    // Cross-action decision-idempotency-key reuse guard (mirrors the queue-row
    // guard): the same approver reusing this decision key on a DIFFERENT quorum
    // action would violate provider_action_approvals_idem_uniq and surface as an
    // opaque 503. Detect it and return the precise 409 instead.
    const [idemConflict] = await tx
      .select({ id: providerActionApprovals.id, queueId: providerActionApprovals.approvalQueueId })
      .from(providerActionApprovals)
      .where(
        and(
          eq(providerActionApprovals.tenantId, input.tenantId),
          eq(providerActionApprovals.approverUserId, userId),
          eq(providerActionApprovals.decisionIdempotencyKeyHash, ctx.idemHash),
        ),
      )
      .limit(1);
    if (idemConflict && idemConflict.queueId !== queue.id) {
      return fail("APPROVAL_IDEMPOTENCY_CONFLICT", 409);
    }

    // Record this distinct decision row bound to the CURRENT binding revision.
    // A concurrent duplicate loses the UNIQUE(queue, approver) race -> caught as
    // APPROVAL_DUPLICATE_APPROVER by the outer catch (it maps the unique
    // violation). We insert first so the tally can never exceed the distinct
    // decision count.
    try {
      await tx.insert(providerActionApprovals).values({
        approvalQueueId: queue.id,
        intentId: binding.intentId,
        tenantId: input.tenantId,
        workspaceId: binding.workspaceId,
        approverUserId: userId,
        decision: input.decision,
        bindingRevisionAtDecision: before,
        requestHash: binding.requestHash,
        actionDigest: binding.actionDigest,
        approvalCommitmentHash: queue.approvalCommitmentHash ?? "",
        decisionIdempotencyKeyHash: ctx.idemHash,
        decisionRequestHash: ctx.decisionReqHash,
        mfaVerifiedAt: ctx.mfaVerifiedAt,
        mfaAgeMsAtDecision: ctx.mfaAgeMs,
        reasonCode: input.reasonCode ?? null,
        reason: input.reason ?? null,
      });
    } catch (e) {
      // Distinctness / cross-action idem races land here.
      const code = (e as { code?: string } | null)?.code;
      if (code === "23505") {
        // Determine which unique index tripped by re-reading.
        const [dup] = await tx
          .select({ id: providerActionApprovals.id })
          .from(providerActionApprovals)
          .where(
            and(
              eq(providerActionApprovals.approvalQueueId, queue.id),
              eq(providerActionApprovals.approverUserId, userId),
            ),
          )
          .limit(1);
        if (dup) return fail("APPROVAL_DUPLICATE_APPROVER", 409);
        return fail("APPROVAL_IDEMPOTENCY_CONFLICT", 409);
      }
      throw e;
    }

    if (input.decision === "deny") {
      // DENY WINS IMMEDIATELY: terminate the whole approval regardless of tally.
      const upd = await tx
        .update(approvalQueue)
        .set({
          status: "rejected",
          decision: "deny",
          resolvedAt: nowTs,
          resolvedByType: "user",
          resolvedById: userId,
          resolvedBy: userId,
          mfaVerifiedAt: ctx.mfaVerifiedAt,
          mfaAgeMsAtDecision: ctx.mfaAgeMs,
          reasonCode: input.reasonCode ?? null,
          reason: input.reason ?? null,
          decisionIdempotencyKeyHash: ctx.idemHash,
          decisionRequestHash: ctx.decisionReqHash,
        })
        .where(and(eq(approvalQueue.id, queue.id), eq(approvalQueue.status, "pending")))
        .returning({ id: approvalQueue.id });
      if (upd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

      await tx
        .update(providerActionBindings)
        .set({
          status: "approval_denied",
          bindingRevision: after,
          approvalActorUserId: userId,
          deniedAt: nowTs,
          updatedAt: nowTs,
        })
        .where(
          and(
            eq(providerActionBindings.intentId, binding.intentId),
            eq(providerActionBindings.status, "pending_approval"),
            eq(providerActionBindings.bindingRevision, before),
          ),
        );
      await tx
        .update(intents)
        .set({
          status: "rejected",
          rejectedBy: `user:${userId}`,
          rejectedAt: nowTs,
          rejectionReason: input.reasonCode ?? null,
          updatedAt: nowTs,
        })
        .where(eq(intents.id, binding.intentId));

      const payload = buildAuditPayload(binding, queue, {
        approvalActorUserId: userId,
        resumeActor: null,
        bindingRevisionBefore: before,
        bindingRevisionAfter: after,
        fromStatus: "pending_approval",
        toStatus: "approval_denied",
        reasonCode: input.reasonCode ?? "approver_manual_deny",
        resumeAttemptId: null,
      });
      payload.quorumThreshold = threshold;
      payload.quorumApprovalsCount = queue.quorumApprovalsCount;
      await this.hook("beforeAudit");
      await append({
        tenantId: binding.tenantId,
        actorType: "user",
        actorId: userId,
        action: "provider.approval.decided",
        resourceType: "provider_action",
        resourceId: binding.intentId,
        metadata: payload as unknown as Record<string, unknown>,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        requestId: input.requestId ?? null,
      });
      await this.hook("afterAudit");

      return {
        ok: true,
        httpStatus: 200,
        id: binding.intentId,
        status: "approval_denied",
        version: after,
        requestHash: binding.requestHash,
        actionDigest: binding.actionDigest,
      };
    }

    // APPROVE: increment the guarded tally. The CAS increments only while the
    // queue is pending AND the tally is below threshold, so it can never exceed
    // the threshold. countAfter is the authoritative post-increment tally.
    const bumped = await tx
      .update(approvalQueue)
      .set({ quorumApprovalsCount: sql`${approvalQueue.quorumApprovalsCount} + 1` })
      .where(
        and(
          eq(approvalQueue.id, queue.id),
          eq(approvalQueue.status, "pending"),
          sql`${approvalQueue.quorumApprovalsCount} < ${threshold}`,
        ),
      )
      .returning({ count: approvalQueue.quorumApprovalsCount });
    if (bumped.length === 0) {
      // The queue is no longer pending or already at threshold: a concurrent
      // winner completed (or terminated) the quorum. The distinct decision row
      // we inserted is retained as evidence but does not advance a completed set.
      return fail("APPROVAL_STATE_CONFLICT", 409);
    }
    const countAfter = bumped[0].count as number;

    const quorumSatisfied = countAfter >= threshold;
    const toStatus = quorumSatisfied ? "approved" : "pending_approval";
    // Only the SATISFYING Nth approval advances the binding + intent + queue
    // decision. Partial approvals leave the binding pending_approval (execute
    // unreachable) and only bump the tally.
    let bindingRevisionAfter = before;
    if (quorumSatisfied) {
      bindingRevisionAfter = after;
      const qUpd = await tx
        .update(approvalQueue)
        .set({
          status: "approved",
          decision: "approve",
          resolvedAt: nowTs,
          resolvedByType: "user",
          resolvedById: userId,
          resolvedBy: userId,
          mfaVerifiedAt: ctx.mfaVerifiedAt,
          mfaAgeMsAtDecision: ctx.mfaAgeMs,
          reasonCode: input.reasonCode ?? null,
          reason: input.reason ?? null,
          decisionIdempotencyKeyHash: ctx.idemHash,
          decisionRequestHash: ctx.decisionReqHash,
        })
        .where(
          and(
            eq(approvalQueue.id, queue.id),
            eq(approvalQueue.status, "pending"),
            sql`${approvalQueue.quorumApprovalsCount} >= ${threshold}`,
          ),
        )
        .returning({ id: approvalQueue.id });
      // Guarded single-winner: if a concurrent Nth approval already flipped the
      // queue to approved, this loses. Our tally increment still counted, but we
      // do NOT advance the binding twice.
      if (qUpd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

      const bUpd = await tx
        .update(providerActionBindings)
        .set({
          status: "approved",
          bindingRevision: after,
          approvalActorUserId: userId,
          approvedAt: nowTs,
          updatedAt: nowTs,
        })
        .where(
          and(
            eq(providerActionBindings.intentId, binding.intentId),
            eq(providerActionBindings.status, "pending_approval"),
            eq(providerActionBindings.bindingRevision, before),
          ),
        )
        .returning({ intentId: providerActionBindings.intentId });
      if (bUpd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

      await tx
        .update(intents)
        .set({
          status: "authorized",
          authorizedBy: `user:${userId}`,
          authorizedAt: nowTs,
          updatedAt: nowTs,
        })
        .where(eq(intents.id, binding.intentId));
    }

    const payload = buildAuditPayload(binding, queue, {
      approvalActorUserId: userId,
      resumeActor: null,
      bindingRevisionBefore: before,
      bindingRevisionAfter,
      fromStatus: "pending_approval",
      toStatus: quorumSatisfied ? "approved" : "pending_approval",
      reasonCode: input.reasonCode ?? "approver_manual_approve",
      resumeAttemptId: null,
    });
    payload.quorumThreshold = threshold;
    payload.quorumApprovalsCount = countAfter;
    await this.hook("beforeAudit");
    await append({
      tenantId: binding.tenantId,
      actorType: "user",
      actorId: userId,
      action: "provider.approval.decided",
      resourceType: "provider_action",
      resourceId: binding.intentId,
      metadata: payload as unknown as Record<string, unknown>,
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
      requestId: input.requestId ?? null,
    });
    await this.hook("afterAudit");

    return {
      ok: true,
      httpStatus: 200,
      id: binding.intentId,
      status: toStatus,
      version: bindingRevisionAfter,
      requestHash: binding.requestHash,
      actionDigest: binding.actionDigest,
    };
  }

  private decisionReplay(binding: BindingRow, queue: QueueRow, replayed = false): ApprovalResult {
    const status =
      queue.decision === "approve"
        ? binding.status === "execution_ready"
          ? "execution_ready"
          : "approved"
        : "approval_denied";
    return {
      ok: true,
      httpStatus: 200,
      id: binding.intentId,
      status,
      version: binding.bindingRevision,
      requestHash: binding.requestHash,
      actionDigest: binding.actionDigest,
      replayed: replayed || undefined,
    };
  }

  // ── SAFE RESUME (approved → execution_ready), spec §6.8 ──
  async resume(input: {
    intentId: string;
    tenantId: string;
    caller?: { agentId?: string; userId?: string };
    ipAddress?: string | null;
    userAgent?: string | null;
    requestId?: string | null;
  }): Promise<ApprovalResult> {
    try {
      return await withTenantAuditedTransaction(input.tenantId, async (txRaw, appendRaw) => {
        const tx = txRaw as DbExecutor;
        const append = mapRequiredAuditFailure(appendRaw as unknown as ApprovalAuditAppend);

        const loaded = await this.loadCase(tx, input.tenantId, input.intentId, true);
        await this.hook("afterScopeLoad");
        if ("notFound" in loaded) return fail("SCOPE_RESOURCE_NOT_FOUND", 404);
        if ("notApproval" in loaded) return fail("APPROVAL_NOT_REQUIRED", 409);
        const { binding, queue } = loaded;
        if (input.caller && !(await this.isExecuteCallerAuthorized(tx, binding, input.caller))) {
          return fail("SCOPE_RESOURCE_NOT_FOUND", 404);
        }

        // Idempotent: already execution_ready returns same state. BUT a row that
        // reached execution_ready BEFORE this rollout (or via any path that did
        // not mint) has no v2 authorization, and the governed dispatcher REQUIRES
        // one (codex P2). So the idempotent path ALSO ensures the v2 nonce exists,
        // minting it in this same audited tx if absent. The mint is idempotent via
        // exec_auth_nonces_intent_uniq (K22/F01): a repeat resume that already has
        // a nonce is a no-op insert. Fails closed if the secret is absent (X7).
        if (binding.status === "execution_ready") {
          await this.hook("beforeMint");
          await mintProviderExecutionAuthorizationWithinTx(
            tx as unknown as Parameters<typeof mintProviderExecutionAuthorizationWithinTx>[0],
            append as unknown as Parameters<typeof mintProviderExecutionAuthorizationWithinTx>[1],
            {
              intentId: binding.intentId,
              tenantId: binding.tenantId,
              workspaceId: binding.workspaceId,
              actorAgentId: binding.actorAgentId,
              providerAccountId: binding.providerAccountId,
              operationId: binding.operationId,
              operationRevision: binding.operationRevision,
              requestHash: binding.requestHash,
              actionDigest: binding.actionDigest,
              approvalId: queue.id,
              approvalCommitmentHash: queue.approvalCommitmentHash ?? "",
              approvalCommitment:
                queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1,
              canonicalActionBytes: new Uint8Array(binding.canonicalActionBytes as Uint8Array),
              requestId: input.requestId ?? null,
            },
            {
              now: new Date(),
              ipAddress: input.ipAddress ?? null,
              userAgent: input.userAgent ?? null,
              requestId: input.requestId ?? null,
              hooks: {
                beforeInsert: () => this.hook("beforeMintInsert"),
                beforeAudit: () => this.hook("beforeMintAudit"),
              },
            },
          );
          await this.hook("afterMint");
          return {
            ok: true,
            httpStatus: 200,
            id: binding.intentId,
            status: "execution_ready",
            version: binding.bindingRevision,
            requestHash: binding.requestHash,
            actionDigest: binding.actionDigest,
            resumeAttemptId: binding.resumeAttemptId ?? undefined,
          };
        }

        // Expire first.
        if (queue.status === "pending" || queue.status === "approved") {
          const expired = await this.expireIfDue(tx, append, loaded);
          if (expired) return fail("APPROVAL_EXPIRED", 410);
        }

        if (binding.status !== "approved") {
          if (binding.status === "pending_approval") return fail("RESUME_NOT_APPROVED", 409);
          if (binding.status === "approval_denied") return fail("RESUME_NOT_APPROVED", 409);
          return this.terminalOutcome(binding, queue);
        }

        // Integrity + full dependency revalidation (§6.8 step 6-8).
        const integ = this.verifyIntegrity(binding, queue);
        await this.hook("afterIntegrity");
        if (!integ.ok) {
          await this.staleTransition(tx, append, binding, queue, integ.code);
          return fail(integ.code, 409);
        }
        const deps = await this.revalidateDependencies(tx, binding, queue);
        await this.hook("afterAuthority");
        if (!deps.ok) {
          await this.staleTransition(tx, append, binding, queue, deps.code);
          return fail(deps.code, 409);
        }

        // Approver still eligible at resume (I7). No MFA-age recheck (§9).
        const approverUserId = binding.approvalActorUserId as string;
        const approver = await this.checkApprover(
          tx,
          binding,
          queue,
          approverUserId,
          input.tenantId,
          undefined,
          true,
        );
        if (!approver.ok) {
          await this.staleTransition(tx, append, binding, queue, approver.code);
          return fail(approver.code, approver.httpStatus === 403 ? 409 : approver.httpStatus);
        }

        const before = binding.bindingRevision;
        const after = before + 1;
        const nowTs = new Date();
        const resumeAttemptId = randomUUID();

        const upd = await tx
          .update(approvalQueue)
          .set({ status: "consumed", consumedAt: nowTs, consumedBy: RESUME_ACTOR })
          .where(and(eq(approvalQueue.id, queue.id), eq(approvalQueue.status, "approved")))
          .returning({ id: approvalQueue.id });
        if (upd.length === 0) return fail("APPROVAL_STATE_CONFLICT", 409);

        await tx
          .update(providerActionBindings)
          .set({
            status: "execution_ready",
            bindingRevision: after,
            resumeActor: RESUME_ACTOR,
            resumeAttemptId,
            resumeValidatedAt: nowTs,
            updatedAt: nowTs,
          })
          .where(
            and(
              eq(providerActionBindings.intentId, binding.intentId),
              eq(providerActionBindings.status, "approved"),
              eq(providerActionBindings.bindingRevision, before),
            ),
          );
        await tx
          .update(intents)
          .set({ executedBy: RESUME_ACTOR, updatedAt: nowTs })
          .where(eq(intents.id, binding.intentId));

        const payload = buildAuditPayload(binding, queue, {
          approvalActorUserId: approverUserId,
          resumeActor: RESUME_ACTOR,
          bindingRevisionBefore: before,
          bindingRevisionAfter: after,
          fromStatus: "approved",
          toStatus: "execution_ready",
          reasonCode: "provider_resume_ready",
          resumeAttemptId,
        });
        await this.hook("beforeAudit");
        await append({
          tenantId: binding.tenantId,
          actorType: "system",
          actorId: RESUME_ACTOR,
          action: "provider.resume.ready",
          resourceType: "provider_action",
          resourceId: binding.intentId,
          metadata: payload as unknown as Record<string, unknown>,
          ipAddress: input.ipAddress ?? null,
          userAgent: input.userAgent ?? null,
          requestId: input.requestId ?? null,
        });
        await this.hook("afterAudit");

        // PR4 mint-within-tx (spec §2.3): mint the v2 execution authorization in
        // the SAME audited transaction as the resume, so approved→execution_ready
        // →authorization-minted is one atomic step (removes an extra crash window,
        // F01). Idempotent by exec_auth_nonces_intent_uniq (K22). Fails closed if
        // STEWARD_EXECUTION_AUTH_SECRET is absent (X7, P49). The whole resume tx
        // rolls back on mint failure, so a resume never lands execution_ready
        // without a mintable authorization.
        await this.hook("beforeMint");
        await mintProviderExecutionAuthorizationWithinTx(
          tx as unknown as Parameters<typeof mintProviderExecutionAuthorizationWithinTx>[0],
          append as unknown as Parameters<typeof mintProviderExecutionAuthorizationWithinTx>[1],
          {
            intentId: binding.intentId,
            tenantId: binding.tenantId,
            workspaceId: binding.workspaceId,
            actorAgentId: binding.actorAgentId,
            providerAccountId: binding.providerAccountId,
            operationId: binding.operationId,
            operationRevision: binding.operationRevision,
            requestHash: binding.requestHash,
            actionDigest: binding.actionDigest,
            approvalId: queue.id,
            approvalCommitmentHash: queue.approvalCommitmentHash ?? "",
            approvalCommitment: queue.approvalCommitment as unknown as ProviderApprovalCommitmentV1,
            canonicalActionBytes: new Uint8Array(binding.canonicalActionBytes as Uint8Array),
            requestId: input.requestId ?? null,
          },
          {
            now: nowTs,
            ipAddress: input.ipAddress ?? null,
            userAgent: input.userAgent ?? null,
            requestId: input.requestId ?? null,
            hooks: {
              beforeInsert: () => this.hook("beforeMintInsert"),
              beforeAudit: () => this.hook("beforeMintAudit"),
            },
          },
        );
        await this.hook("afterMint");

        return {
          ok: true,
          httpStatus: 200,
          id: binding.intentId,
          status: "execution_ready",
          version: after,
          requestHash: binding.requestHash,
          actionDigest: binding.actionDigest,
          resumeAttemptId,
        };
      });
    } catch (e) {
      if (e instanceof AuditUnavailableError)
        return fail("EVIDENCE_REQUIRED_AUDIT_UNAVAILABLE", 503);
      // v2 mint fail-closed: absent HMAC key rolls back the whole resume tx so
      // no execution_ready lands without a mintable authorization (X7, P49/F06).
      if (e instanceof ProviderExecutionMintError) {
        if (e.code === "EXEC_AUTH_KEY_UNAVAILABLE") return fail("EXEC_AUTH_KEY_UNAVAILABLE", 503);
        return fail("RESUME_PREPARATION_FAILED", 503);
      }
      return fail("RESUME_PREPARATION_FAILED", 503);
    }
  }

  private async isExecuteCallerAuthorized(
    tx: DbExecutor,
    binding: BindingRow,
    caller: { agentId?: string; userId?: string },
  ): Promise<boolean> {
    if (caller.agentId && caller.agentId === binding.actorAgentId) return true;
    return Boolean(
      caller.userId &&
        (
          await this.hasWorkspaceRoleAuthority(
            tx,
            binding,
            caller.userId,
            binding.tenantId,
            new Set(["workspace_approver", "workspace_admin"]),
          )
        ).ok,
    );
  }

  // ── Execute-route caller authority, §9.1 ──
  async authorizeExecuteCaller(
    tenantId: string,
    intentId: string,
    caller: { agentId?: string; userId?: string },
  ): Promise<{ ok: true } | { ok: false; code: "SCOPE_RESOURCE_NOT_FOUND"; httpStatus: 404 }> {
    const loaded = await this.loadCase(this.db(), tenantId, intentId, false);
    if ("notFound" in loaded || "notApproval" in loaded) {
      return { ok: false, code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
    }
    if (await this.isExecuteCallerAuthorized(this.db(), loaded.binding, caller)) {
      return { ok: true };
    }
    return { ok: false, code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
  }

  // ── GET approval detail for an eligible approver (safe summary + labels), §9.1 ──
  // The GET endpoint requires an eligible workspace approver with recent MFA
  // (even safe summaries are sensitive). Non-enumerating: any ineligibility on a
  // foreign/absent action returns the same 404 shape as absent.
  async getApprovalDetailForApprover(
    tenantId: string,
    intentId: string,
    userId: string,
    sessionMfaVerifiedAt: number,
  ): Promise<
    { ok: true; data: Record<string, unknown> } | { ok: false; code: string; httpStatus: number }
  > {
    const loaded = await this.loadCase(this.db(), tenantId, intentId, false);
    if ("notFound" in loaded)
      return { ok: false, code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
    if ("notApproval" in loaded)
      return { ok: false, code: "APPROVAL_NOT_REQUIRED", httpStatus: 409 };
    const { binding, queue } = loaded;
    const approver = await this.checkApprover(
      this.db(),
      binding,
      queue,
      userId,
      tenantId,
      sessionMfaVerifiedAt,
      false,
    );
    if (!approver.ok) {
      // Non-enumeration (I16, codex P2): an ineligible tenant member must NOT be
      // able to distinguish an existing approval action from an absent one on
      // this READ path. Membership/role/separation eligibility failures collapse
      // to the same 404 as an absent id. MFA failures are surfaced (they are not
      // enumeration signals: the caller already proved tenant membership and the
      // MFA gate is enforced at the route before this call).
      if (
        approver.code === "APPROVAL_MFA_REQUIRED" ||
        approver.code === "APPROVAL_MFA_STALE" ||
        approver.code === "APPROVAL_MFA_TIMESTAMP_INVALID"
      ) {
        return { ok: false, code: approver.code, httpStatus: approver.httpStatus };
      }
      return { ok: false, code: "SCOPE_RESOURCE_NOT_FOUND", httpStatus: 404 };
    }
    return {
      ok: true,
      data: {
        id: binding.intentId,
        status: binding.status,
        version: binding.bindingRevision,
        requestHash: binding.requestHash,
        actionDigest: binding.actionDigest,
        expiresAt: queue.expiresAt?.toISOString() ?? null,
        safeSummary: binding.safeSummary,
        operationId: binding.operationId,
        providerAccountId: binding.providerAccountId,
        workspaceId: binding.workspaceId,
      },
    };
  }
}

// ── module helpers ──

class AuditUnavailableError extends Error {}

type ApprovalAuditAppend = (event: { tenantId: string } & Record<string, unknown>) => Promise<void>;

function mapRequiredAuditFailure(append: ApprovalAuditAppend): ApprovalAuditAppend {
  return async (event) => {
    try {
      await append(event);
    } catch (cause) {
      const causeMessage = cause instanceof Error ? cause.message : String(cause);
      const error = new AuditUnavailableError(
        `required approval audit persistence failed: ${causeMessage}`,
      );
      error.cause = cause;
      if (cause && typeof cause === "object" && "code" in cause) {
        Object.assign(error, { code: (cause as { code?: unknown }).code });
      }
      throw error;
    }
  };
}

function setsEqual(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

export const providerApprovalService = new ProviderApprovalService();
export { AuditUnavailableError, ProviderApprovalService };
