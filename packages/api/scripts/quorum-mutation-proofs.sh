#!/usr/bin/env bash
# #205 quorum mutation-strength proofs. Each mutation weakens ONE security
# predicate of the M-of-N quorum lifecycle; a proof is valid iff the named test
# PASSES clean AND FAILS after the mutation. The file is restored after each
# proof (no .bak residue). Run from packages/api:
#
#   bash scripts/quorum-mutation-proofs.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

SVC="src/services/provider-approval.ts"
Q="src/__tests__/provider-approval-quorum.test.ts"

export STEWARD_PGLITE_MEMORY=true
export STEWARD_AUDIT_HMAC_KEY="${STEWARD_AUDIT_HMAC_KEY:-$(printf '0%.0s' {1..64})}"
export STEWARD_EXECUTION_AUTH_SECRET="${STEWARD_EXECUTION_AUTH_SECRET:-$(printf '1%.0s' {1..64})}"

pass_count=0
fail_count=0

# run_test <file> <filter> -> 0 if all pass (0 fail), 1 otherwise
run_test() {
  local out
  out=$(timeout 120 bun test --timeout 30000 "$1" -t "$2" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}

# proof <name> <file> <filter> <target> <sed-expr>
proof() {
  local name="$1" file="$2" filter="$3" target="$4" sedexpr="$5"
  echo "=== PROOF: $name ==="
  if run_test "$file" "$filter"; then
    echo "  baseline PASS"
  else
    echo "  baseline UNEXPECTED FAIL (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$target" "$target.bak"
  sed -i "$sedexpr" "$target"
  if run_test "$file" "$filter"; then
    echo "  post-mutation still PASSES (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# M1: WEAKEN THRESHOLD COMPARE. Satisfy the quorum at count >= threshold-1, so a
#     single (N-1) approval would already flip to approved. The boundary test
#     (N-1 must NOT be execute-reachable) must fail.
proof "M1 weaken threshold compare (boundary N-1)" "$Q" "boundary: first approval" "$SVC" \
  's/const quorumSatisfied = countAfter >= threshold;/const quorumSatisfied = countAfter >= threshold - 1;/'

# M2: DROP DISTINCTNESS. Skip the same-approver duplicate short-circuit so a
#     repeated approver would count again. The duplicate-approver test must fail.
proof "M2 drop distinctness (duplicate approver)" "$Q" "duplicate approver" "$SVC" \
  '1590s/return fail("APPROVAL_DUPLICATE_APPROVER", 409);/return { ok: true, httpStatus: 200, id: binding.intentId, status: binding.status, version: binding.bindingRevision, requestHash: binding.requestHash, actionDigest: binding.actionDigest };/'

# M3: DROP REQUESTER-SEPARATION. Let the requester (agent owner) count toward the
#     quorum by neutralizing the owner==approver guard in the quorum branch. The
#     "requester can never count" test must fail.
proof "M3 drop requester-separation (requester as approver)" "$Q" "can never count toward the quorum" "$SVC" \
  '922s/if (agent?.ownerUserId \&\& agent.ownerUserId === userId) {/if (false) {/'

# M4: SKIP STALENESS ON THE SET. Bypass the approve-path dependency staleness so
#     a mutated committed dependency after the first approval would NOT stale the
#     collected set. The stale-after-first-approval test must fail.
proof "M4 skip staleness on set (stale-after-first)" "$Q" "stale after first approval invalidates the whole set" "$SVC" \
  's/if (!deps.ok \&\& input.decision === "approve") {/if (false) {/'

# M5: DROP DENY-TERMINATES. Route a deny through the approve tally path instead of
#     the immediate-termination branch, so a deny no longer terminates the whole
#     approval. The deny-after-partial-quorum test must fail.
proof "M5 drop deny-terminates (deny after partial)" "$Q" "deny after a partial quorum terminates" "$SVC" \
  '1657s/if (input.decision === "deny") {/if (false) {/'

# M6: DROP ELIGIBLE-SET MEMBERSHIP. Accept any role-holder as an eligible quorum
#     approver even if they are not on the frozen eligible set. The
#     ineligible-Nth-approver (not in set) test must fail.
proof "M6 drop eligible-set membership (ineligible Nth approver)" "$Q" "not in eligible set" "$SVC" \
  '937s/if (!eligible.includes(userId)) {/if (false) {/'

echo ""
echo "==================================================="
echo "quorum mutation proofs: killed=$pass_count  survived/invalid=$fail_count"
[ "$fail_count" -eq 0 ] && echo "ALL MUTATIONS KILLED" || echo "SOME MUTATIONS SURVIVED"
exit "$fail_count"
