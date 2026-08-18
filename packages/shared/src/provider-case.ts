/**
 * Correlated provider-case evidence: shared, crypto-free types.
 *
 * This module holds ONLY the manifest/evidence type contracts, the
 * `requiredRoles` completeness function, and stable reason-code constants. It
 * carries NO cryptography (signing/HMAC/canonicalization stays in `@stwd/db`
 * and `audit-checkpoint.ts`) so both the API assembler and the offline verifier
 * agree on the same typed vocabulary without duplicating trust-bearing code.
 *
 * Boundary (spec §0): the manifest is a DERIVED, deterministic index over the
 * already-signed audit chain. It mints no second case identifier (the case id
 * IS `intents.id`), adds no second ledger, and carries no independent trust —
 * every fact is checkable against a signed event (§2.3). See evidence spec E1–E8.
 */

export const PROVIDER_CASE_MANIFEST_SCHEMA_VERSION = "steward.provider-case-manifest.v1" as const;

/**
 * Role of a correlated audit event within a case — classifies WHICH lifecycle
 * link the event proves. This is evidence's own taxonomy; it is derived from the
 * event's `action` string at assembly time (see `roleForAction`). It is
 * deliberately decoupled from the exact `action` names so upstream taxonomy
 * drift (e.g. action-creation folding access+policy+approval-request into a single genesis
 * event) does not break correlation — the role is a semantic classifier.
 */
export type ProviderCaseEventRole =
  | "genesis"
  | "access_decided"
  | "policy_decided"
  | "approval_requested"
  | "approval_decided"
  | "approval_terminal"
  | "resume_ready"
  | "exec_authorized"
  | "exec_claimed"
  | "exec_denied_at_boundary"
  | "exec_dispatched"
  | "exec_terminal"
  | "exec_reconciled"
  // A correlated event whose action is not in the known taxonomy. It is listed
  // in the event index (linkage still proven) but NEVER satisfies a required
  // role, so an unknown/drifted action can never mis-satisfy completeness.
  | "unclassified";

/** Terminal state of a case, resolved from the authoritative binding columns. */
export type ProviderCaseTerminalState =
  | "denied_access"
  | "denied_policy"
  | "pending_approval"
  | "approval_denied"
  | "approval_expired"
  | "approval_staled"
  | "execution_ready"
  | "executing"
  | "succeeded"
  | "failed"
  | "outcome_unknown"
  | "unknown";

export type ProviderCaseCompleteness = "complete" | "incomplete" | "unknown";

/**
 * Stable incompleteness reason codes (spec §4.6). Each maps to a documented
 * meaning; none is ever silently upgraded to `complete`.
 */
export const PROVIDER_CASE_REASON = {
  AWAITING_TERMINAL_EVENT: "awaiting_terminal_event",
  OUTCOME_UNKNOWN_UNRECONCILED: "outcome_unknown_unreconciled",
  CHAIN_SEGMENT_BROKEN: "chain_segment_broken", // suffixed with @<seq>
  SAFE_SUMMARY_REDACTION_FAILED: "safe_summary_redaction_failed",
  MANIFEST_SIZE_EXCEEDED: "manifest_size_exceeded",
  BINDING_ROW_ABSENT: "binding_row_absent",
  QUEUE_ROW_ABSENT_FOR_APPROVAL_PATH: "queue_row_absent_for_approval_path",
  AUTHORIZATION_ROW_ABSENT_FOR_EXECUTION_PATH: "authorization_row_absent_for_execution_path",
  TERMINAL_STATE_UNRESOLVED: "terminal_state_unresolved",
} as const;

/** `missing_required_role:<role>` reason code builder (spec §4.6). */
export function missingRoleReason(role: ProviderCaseEventRole): string {
  return `missing_required_role:${role}`;
}

/** `chain_segment_broken@<seq>` reason code builder (spec §4.3/§4.6). */
export function chainSegmentBrokenReason(seq: number): string {
  return `${PROVIDER_CASE_REASON.CHAIN_SEGMENT_BROKEN}@${seq}`;
}

export type ProviderCaseDispatchState =
  | "none"
  | "claimed"
  | "dispatched"
  | "succeeded"
  | "failed"
  | "outcome_unknown";

/** One correlated audit-event entry in the manifest's signed-spine index. */
export interface ProviderCaseManifestEvent {
  seq: number;
  action: string;
  role: ProviderCaseEventRole;
  /** hex; MUST equal the bundle event's hmac at this seq (§2.3). */
  hmac: string;
}

export interface ProviderCaseManifestV1 {
  schemaVersion: typeof PROVIDER_CASE_MANIFEST_SCHEMA_VERSION;
  caseId: string; // = intents.id
  tenantId: string;
  workspaceId: string;

  // ── Provenance / actors (E5-safe: IDs only, never bodies) ──────────────
  requestActor: { type: "agent"; id: string; revision: number };
  approvalActor: { type: "user"; id: string } | null;
  resumeActor: "steward-system" | null;
  providerAccount: { id: string; revision: number };
  operation: {
    id: string;
    key: string;
    revision: number;
    canonicalProfile: string;
    riskClass: string;
  };

  // ── Action + decision commitments (hashes only, never canonical bytes) ──
  actionDigest: string;
  requestHash: string;
  idempotencyKeyHash: string;
  accessDecision: { id: string; hash: string; effect: "allow" | "deny" };
  policyDecision: { id: string | null; hash: string | null; effect: string };
  approvalCommitmentHash: string | null;

  // ── Execution outcome (execution-authorization) ────────────────────────────────────────────
  execution: {
    authorizationId: string | null;
    dispatchState: ProviderCaseDispatchState;
    /** HASH of the provider idempotency key, never the key (§3.4). */
    providerIdempotencyKeyHash: string | null;
    upstreamStatusCode: number | null;
    reconciled: boolean;
  } | null;

  // ── Dependency revisions (staleness provenance) ────────────────────────
  dependencyRevisions: {
    actor: number;
    workspace: number;
    providerAccount: number;
    operation: number;
    matchedGrants: Array<{ id: string; revision: number }>;
    matchedBindings: Array<{ id: string; revision: number }>;
    route: { id: string; revision: number } | null;
    secret: { id: string; version: number } | null;
    policyRevisionHash: string | null;
  };

  // ── Correlated audit-event index (the SIGNED spine linkage) ────────────
  events: ProviderCaseManifestEvent[]; // sorted by seq ascending
  eventSeqRange: { from: number; to: number } | null;

  // ── Honest completeness ────────────────────────────────────────────────
  terminalState: ProviderCaseTerminalState;
  completeness: ProviderCaseCompleteness;
  missingRequiredRoles: ProviderCaseEventRole[];
  incompletenessReasons: string[];

  // ── Optional safe summary (redacted, size-capped) ──────────────────────
  safeSummary: Record<string, unknown> | null;

  // ── Clock semantics ────────────────────────────────────────────────────
  genesisAt: string | null;
  terminalAt: string | null;
  /** advisory, NOT signed, excluded from any commitment (§2.2). */
  assembledAt: string;
}

/**
 * The `/v2/provider-actions/:id/evidence` envelope: manifest + the existing
 * signed audit bundle (contiguous chain segment spanning the case, §5.3).
 */
export interface ProviderCaseEvidenceV1 {
  version: 1;
  tenantId: string;
  caseId: string;
  manifest: ProviderCaseManifestV1;
  bundle: {
    version: 1;
    tenantId: string;
    range: { from: number; to: number; includesHead: boolean };
    canonicalizationSpec: string;
    events: unknown[]; // BundleEvent[] (typed in @stwd/api to avoid a crypto dep here)
    checkpoint: { payload: unknown; signature: string; publicKey: string };
    generatedAt: string;
  };
  completeness: ProviderCaseCompleteness;
  generatedAt: string;
}

/**
 * The normative required-role function (spec §4.4). Given a case's terminal
 * state, returns the ordered set of event roles that MUST be present (and
 * chain-linked) for the case to be `complete`. A role missing relative to this
 * set yields `incomplete`; a broken chain or unresolved state yields `unknown`.
 *
 * The event model folds action creation into a single genesis event
 * SINGLE genesis event (`provider.action.allowed|denied|approval_required`)
 * that carries the access AND policy decision hashes, rather than separate
 * `provider.access.decided` + `provider.policy.decided` events the spec §1.4
 * taxonomy anticipated. `roleForAction` maps that single genesis event to the
 * `genesis` role, and `requiredRoles` treats `genesis` as satisfying the
 * access/policy-decided requirement for the pre-approval terminal states. This
 * keeps completeness mechanical against the current event taxonomy.
 */
export function requiredRoles(terminalState: ProviderCaseTerminalState): ProviderCaseEventRole[] {
  switch (terminalState) {
    case "denied_access":
      return ["genesis"];
    case "denied_policy":
      return ["genesis"];
    case "pending_approval":
      // Genesis (approval_required) is itself the approval-request record; no
      // separate approval_requested event exists.
      return ["genesis"];
    case "approval_denied":
      return ["genesis", "approval_decided"];
    case "approval_expired":
      return ["genesis", "approval_terminal"];
    case "approval_staled":
      return ["genesis", "approval_terminal"];
    case "execution_ready":
      return ["genesis", "approval_decided", "resume_ready"];
    case "executing":
      return ["genesis", "exec_authorized", "exec_claimed"];
    case "succeeded":
    case "failed":
      return ["genesis", "exec_authorized", "exec_claimed", "exec_dispatched", "exec_terminal"];
    case "outcome_unknown":
      return ["genesis", "exec_authorized", "exec_claimed", "exec_dispatched", "exec_terminal"];
    default:
      // `unknown` and any future state: conservatively require the full chain;
      // always resolves to incomplete/unknown.
      return ["genesis", "exec_authorized", "exec_claimed", "exec_dispatched", "exec_terminal"];
  }
}

/**
 * Map a correlated event `action` string to its case role. Unknown actions map
 * to `null` (they are correlated but do not satisfy a required role). This is
 * the single point that couples evidence to the upstream event names; keep it in
 * sync with the action-creation/approval-lifecycle/execution-authorization taxonomies AS LANDED.
 */
export function roleForAction(action: string): ProviderCaseEventRole | null {
  switch (action) {
    // action-creation genesis (single folded event, all three arms are genesis).
    case "provider.action.allowed":
    case "provider.action.denied":
    case "provider.action.approval_required":
      return "genesis";
    // Spec-taxonomy names (kept for forward-compat if action-creation ever splits them).
    case "provider.access.decided":
      return "access_decided";
    case "provider.policy.decided":
      return "policy_decided";
    case "provider.approval.requested":
      return "approval_requested";
    // approval lifecycle.
    case "provider.approval.decided":
      return "approval_decided";
    case "provider.approval.expired":
    case "provider.approval.staled":
      return "approval_terminal";
    case "provider.resume.ready":
      return "resume_ready";
    // execution lifecycle.
    case "provider.execution.authorized":
      return "exec_authorized";
    case "provider.execution.claimed":
      return "exec_claimed";
    case "provider.execution.denied_at_boundary":
      return "exec_denied_at_boundary";
    case "provider.execution.dispatched":
      return "exec_dispatched";
    case "provider.execution.succeeded":
    case "provider.execution.failed":
    case "provider.execution.outcome_unknown":
      return "exec_terminal";
    case "provider.execution.reconciled":
      return "exec_reconciled";
    default:
      return null;
  }
}
