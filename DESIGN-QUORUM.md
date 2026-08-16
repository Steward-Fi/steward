# M-of-N Quorum Approval (issue #205): Design

## Goal
Generalize the single-approver provider-action approval lifecycle to N-of-M quorum,
while keeping the absent-quorum path byte-for-byte identical to today.

## Config source (NO capability-intent.ts edit, avoids #206 collision)
Quorum config is read from the operation's `request_profile.approvalRequirements.quorum`,
the SAME place `extractRequesterSeparation` already reads. Shape:

```
approvalRequirements: {
  requesterSeparation?: boolean,
  quorum?: { threshold: number, eligibleApproverIds: string[] }  // workspace_approver-scoped user ids
}
```

Absent `quorum` => single-approver legacy path (N=1 implicit, unchanged).

The policy engine (`composeProviderActionPolicyDecision`) is unchanged: it still
emits `approval_required`. The threshold + eligible set are commitment metadata,
bound into the approval commitment at create time, exactly like requesterSeparation.

## Schema (migration 0083)
1. `approval_queue` additive columns (nullable, default keeps legacy path):
   - `quorum_threshold integer` (NULL = single-approver)
   - `quorum_eligible_user_ids uuid[] NOT NULL DEFAULT '{}'`
   - `quorum_approvals_count integer NOT NULL DEFAULT 0`
2. New table `provider_action_approvals`: one row per DISTINCT approver decision.
   - PK id uuid
   - approval_queue_id FK -> approval_queue.id (cascade)
   - intent_id, tenant_id, workspace_id
   - approver_user_id uuid NOT NULL
   - decision varchar(16) NOT NULL ('approve'|'deny')
   - binding_revision_at_decision integer NOT NULL  (STALE binding: which revision this bound)
   - request_hash, action_digest (I10 exact bind per approval)
   - approval_commitment_hash (bind the exact commitment)
   - decision_idempotency_key_hash, decision_request_hash
   - mfa_verified_at, mfa_age_ms_at_decision
   - reason_code, reason
   - created_at
   - UNIQUE (approval_queue_id, approver_user_id)  -- distinctness: an approver counts once
   - UNIQUE (tenant_id, approver_user_id, decision_idempotency_key_hash)  -- cross-action idem

## Lifecycle
- QUORUM path (quorum_threshold NOT NULL):
  - approve: insert a distinct provider_action_approvals row (approve), increment
    quorum_approvals_count via guarded CAS. When count reaches threshold => transition
    queue.status pending->approved, binding pending_approval->approved (Nth winner picks
    the "approvalActorUserId" = the Nth approver; the full approver set lives in the
    approvals table + audit trail). N-1 approvals leave status pending (execute unreachable).
  - deny: DENY WINS IMMEDIATELY. First deny transitions pending->rejected regardless of count.
  - stale: ANY dependency/payload/integrity change stales the WHOLE set: binding transitions
    to approval_stale AND all collected provider_action_approvals rows are invalidated
    (the set is re-bound to binding_revision; a staleness bumps binding_revision, so every
    prior approval row that recorded an older binding_revision_at_decision is dead). We also
    hard-delete/ignore prior rows on re-entry after a revision bump: since the queue can only
    reach `approved` when threshold DISTINCT rows exist AT THE CURRENT binding_revision, a
    stale (which flips queue to `stale` terminal) makes the set unrecoverable.
  - distinctness: N DISTINCT user ids (unique index). requester-separation generalized:
    requester (agent owner) can never count. An approver approving twice: unique index
    rejects loudly (APPROVAL_DUPLICATE_APPROVER, 409).
  - eligibility: enforced per-approval at decide time (checkApprover: current membership +
    role + recent MFA + eligible-set membership). A user who lost eligibility between approvals
    cannot complete the quorum.
  - race: two concurrent Nth approvals -> guarded CAS on quorum_approvals_count + the
    pending->approved transition WHERE status='pending' AND count>=threshold ensures exactly
    one execute-reachable transition (mirror nonce single-winner).

- SINGLE path (quorum_threshold IS NULL): untouched. Existing decide() code runs verbatim.

## Fail-closed store-time + eval-time validation
- store (buildApprovalArm): reject threshold that is 0, negative, non-integer, > eligible set
  size, empty eligible set, eligible set with unknown/duplicate ids, or an eligible set that
  doesn't include enough non-requester members to ever reach threshold.
- eval (decide): re-validate threshold + eligible set from the persisted commitment;
  malformed => deny (APPROVAL_QUORUM_CONFIG_INVALID). Approver must be in eligible set.

## Audit
- Each distinct decision emits `provider.approval.decided` (existing action) with quorum
  progress in metadata (threshold, count-after).
- Terminal quorum-satisfied transition emits the existing `provider.approval.decided`
  (toStatus approved) carrying threshold/count. No second evidence system.

## Nested quorums: OUT OF SCOPE (flat N-of-M only), stated in PR body.
