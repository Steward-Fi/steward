/**
 * provider-approval.ts — PR3 exact-request approval commitment, decision, and
 * audit document schemas + their canonical hashes (spec §5, §7.2, §8.2).
 *
 * SECURITY POSTURE. Every builder here is on the evidence surface. The
 * commitment document is what an approval binds to and what safe resume
 * independently recomputes and compares byte-for-byte. It MUST be built ONLY
 * from persisted/authoritative fields and hashed with the SAME strict RFC 8785
 * JCS implementation PR2 owns (`jcsStringify`), never a bespoke serializer.
 *
 * This module is pure (no DB, no crypto beyond sha256HexPrefixed) so it can be
 * reused by the API service AND by an offline verifier (PR5) without pulling in
 * server dependencies.
 */

import { jcsStringify, sha256HexPrefixed } from "./provider-action.js";

// ─── Commitment document (spec §5.1) ──────────────────────────────────────────

export const PROVIDER_APPROVAL_COMMITMENT_SCHEMA =
  "steward.provider-approval-commitment.v1" as const;

export interface ProviderApprovalCommitmentV1 {
  schemaVersion: typeof PROVIDER_APPROVAL_COMMITMENT_SCHEMA;
  intentId: string;
  tenantId: string;
  workspaceId: string;
  requestActor: { type: "agent"; id: string; revision: number };
  providerAccount: { id: string; revision: number; status: "active" };
  operation: {
    id: string;
    key: string;
    revision: number;
    riskClass: string;
    // Adapter canonical profile. Widened from the github literal so the same
    // commitment schema binds X (`x.provider-action.v1`) and future adapters.
    // JCS hashes whatever string is present, so this is behavior-neutral for the
    // existing github digest corpus (the string value is unchanged there).
    canonicalProfile: "github.provider-action.v1" | "x.provider-action.v1";
  };
  requestHash: string;
  actionDigest: string;
  accessDecision: {
    id: string;
    hash: string;
    effect: "allow";
    matchedBindings: Array<{ id: string; revision: number }>;
    matchedGrants: Array<{ id: string; revision: number }>;
  };
  policyDecision: {
    id: string;
    hash: string;
    effect: "approval_required";
    policyRevisionHash: string;
    approvalPolicyRevisionHash: string;
    evaluatorVersion: string;
  };
  executionDependencies: {
    routeId: string;
    routeRevision: number;
    secretId: string;
    secretVersion: number;
  };
  approvalRequirements: {
    role: "workspace_approver";
    requesterSeparation: boolean;
    maxMfaAgeSeconds: 300;
    requiredMfaAssurance: "current-session-mfa" | "phishing-resistant";
    /**
     * #205 flat M-of-N quorum. ABSENT (undefined) => single-approver legacy path;
     * the commitment is then byte-for-byte identical to pre-quorum actions
     * because JCS omits an undefined member (verified by the single-approver
     * regression corpus). When present, `threshold` DISTINCT eligible approvals
     * are required. `eligibleApproverUserIds` is the frozen, workspace_approver
     * -scoped eligible set (UUIDs). The requester (agent owner) is never eligible
     * (enforced at decide time, generalizing requesterSeparation). Nested quorums
     * are OUT OF SCOPE (flat N-of-M only).
     */
    quorum?: {
      threshold: number;
      eligibleApproverUserIds: string[];
    };
  };
  requestedAt: string;
  expiresAt: string;
}

/** UUID-byte (lexicographic on the canonical string form) comparator. */
function byUuidBytes(a: { id: string }, b: { id: string }): number {
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/**
 * Produce the canonical object of the commitment with arrays sorted by UUID
 * bytes, exactly as §5.1 requires. Property order is irrelevant (JCS re-sorts),
 * but arrays must be pre-sorted because JCS preserves array order.
 */
export function canonicalApprovalCommitmentObject(
  c: ProviderApprovalCommitmentV1,
): Record<string, unknown> {
  return {
    schemaVersion: c.schemaVersion,
    intentId: c.intentId,
    tenantId: c.tenantId,
    workspaceId: c.workspaceId,
    requestActor: {
      type: c.requestActor.type,
      id: c.requestActor.id,
      revision: c.requestActor.revision,
    },
    providerAccount: {
      id: c.providerAccount.id,
      revision: c.providerAccount.revision,
      status: c.providerAccount.status,
    },
    operation: {
      id: c.operation.id,
      key: c.operation.key,
      revision: c.operation.revision,
      riskClass: c.operation.riskClass,
      canonicalProfile: c.operation.canonicalProfile,
    },
    requestHash: c.requestHash,
    actionDigest: c.actionDigest,
    accessDecision: {
      id: c.accessDecision.id,
      hash: c.accessDecision.hash,
      effect: c.accessDecision.effect,
      matchedBindings: [...c.accessDecision.matchedBindings]
        .sort(byUuidBytes)
        .map((b) => ({ id: b.id, revision: b.revision })),
      matchedGrants: [...c.accessDecision.matchedGrants]
        .sort(byUuidBytes)
        .map((g) => ({ id: g.id, revision: g.revision })),
    },
    policyDecision: {
      id: c.policyDecision.id,
      hash: c.policyDecision.hash,
      effect: c.policyDecision.effect,
      policyRevisionHash: c.policyDecision.policyRevisionHash,
      approvalPolicyRevisionHash: c.policyDecision.approvalPolicyRevisionHash,
      evaluatorVersion: c.policyDecision.evaluatorVersion,
    },
    executionDependencies: {
      routeId: c.executionDependencies.routeId,
      routeRevision: c.executionDependencies.routeRevision,
      secretId: c.executionDependencies.secretId,
      secretVersion: c.executionDependencies.secretVersion,
    },
    approvalRequirements: {
      role: c.approvalRequirements.role,
      requesterSeparation: c.approvalRequirements.requesterSeparation,
      maxMfaAgeSeconds: c.approvalRequirements.maxMfaAgeSeconds,
      requiredMfaAssurance: c.approvalRequirements.requiredMfaAssurance,
      // Additive quorum member. Emitted ONLY when configured, so an absent
      // quorum yields a canonical object byte-identical to the pre-#205 shape.
      // The eligible-approver set is sorted (UUID-byte order) because JCS
      // preserves array order and the commitment must be deterministic.
      ...(c.approvalRequirements.quorum
        ? {
            quorum: {
              threshold: c.approvalRequirements.quorum.threshold,
              eligibleApproverUserIds: [
                ...c.approvalRequirements.quorum.eligibleApproverUserIds,
              ].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
            },
          }
        : {}),
    },
    requestedAt: c.requestedAt,
    expiresAt: c.expiresAt,
  };
}

/** `approvalCommitmentHash` = sha256: hex of the JCS of the canonical commitment. */
export function computeApprovalCommitmentHash(c: ProviderApprovalCommitmentV1): string {
  return sha256HexPrefixed(jcsStringify(canonicalApprovalCommitmentObject(c)));
}

// ─── Human decision document (spec §8.2) ──────────────────────────────────────

export const PROVIDER_APPROVAL_DECISION_SCHEMA = "steward.provider-approval-decision.v1" as const;

export interface ProviderApprovalDecisionCommitmentV1 {
  schemaVersion: typeof PROVIDER_APPROVAL_DECISION_SCHEMA;
  tenantId: string;
  workspaceId: string;
  intentId: string;
  authenticatedUserId: string;
  decision: "approve" | "deny";
  expectedVersion: number;
  expectedRequestHash: string;
  expectedActionDigest: string;
  reasonCode: string | null;
  reason: string | null;
}

export function computeDecisionRequestHash(d: ProviderApprovalDecisionCommitmentV1): string {
  return sha256HexPrefixed(
    jcsStringify({
      schemaVersion: d.schemaVersion,
      tenantId: d.tenantId,
      workspaceId: d.workspaceId,
      intentId: d.intentId,
      authenticatedUserId: d.authenticatedUserId,
      decision: d.decision,
      expectedVersion: d.expectedVersion,
      expectedRequestHash: d.expectedRequestHash,
      expectedActionDigest: d.expectedActionDigest,
      reasonCode: d.reasonCode ?? null,
      reason: d.reason ?? null,
    }),
  );
}

// ─── Audit event payload (spec §7.2) ──────────────────────────────────────────

export const PROVIDER_APPROVAL_AUDIT_SCHEMA = "steward.provider-approval-audit.v1" as const;

export interface ProviderApprovalAuditPayloadV1 {
  schemaVersion: typeof PROVIDER_APPROVAL_AUDIT_SCHEMA;
  intentId: string;
  approvalQueueId: string;
  tenantId: string;
  workspaceId: string;
  requestActorAgentId: string;
  approvalActorUserId: string | null;
  resumeActor: "steward-system" | null;
  providerAccountId: string;
  operationId: string;
  requestHash: string;
  actionDigest: string;
  accessDecisionId: string;
  accessDecisionHash: string;
  policyDecisionId: string;
  policyDecisionHash: string;
  policyRevisionHash: string;
  approvalCommitmentHash: string;
  bindingRevisionBefore: number | null;
  bindingRevisionAfter: number;
  fromStatus: string | null;
  toStatus: string;
  reasonCode: string;
  resumeAttemptId: string | null;
  occurredAt: string;
  /**
   * #205 quorum progress. ABSENT for single-approver actions (byte-for-byte
   * unchanged audit payloads). When present, `quorumThreshold` is the required
   * DISTINCT-approval count and `quorumApprovalsCount` is the tally AFTER this
   * decision (so a partial-quorum approve carries count < threshold and the
   * satisfying Nth approve carries count === threshold). No second evidence
   * system: quorum progress rides the existing provider.approval.decided events.
   */
  quorumThreshold?: number;
  quorumApprovalsCount?: number;
}

// ─── Decision request body (public API shape, spec §8.2) ──────────────────────

export interface DecideProviderActionV1 {
  decision: "approve" | "deny";
  expectedVersion: number;
  expectedRequestHash: string;
  expectedActionDigest: string;
  reasonCode?: string;
  reason?: string;
  idempotencyKey: string;
}

/** The fixed reason-code list (spec §4.1: reason_code from a fixed list). */
export const APPROVAL_REASON_CODES = [
  "approver_manual_approve",
  "approver_manual_deny",
  "approver_risk_deny",
  "approver_scope_deny",
  "approver_duplicate_deny",
  "approver_other",
] as const;

export type ApprovalReasonCode = (typeof APPROVAL_REASON_CODES)[number];

export function isApprovalReasonCode(v: unknown): v is ApprovalReasonCode {
  return typeof v === "string" && (APPROVAL_REASON_CODES as readonly string[]).includes(v);
}
