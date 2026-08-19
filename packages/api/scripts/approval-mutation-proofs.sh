#!/usr/bin/env bash
# Approval mutation-strength proofs. Each mutation weakens one security
# predicate; a proof is valid iff the named test PASSES clean AND FAILS after the
# mutation. The file is restored after each proof. Run from packages/api:
#
#   bash scripts/approval-mutation-proofs.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

SVC="src/services/provider-approval.ts"
NEG="src/__tests__/provider-approval-negative.test.ts"
CONC="src/__tests__/provider-approval-concurrency.test.ts"

pass_count=0
fail_count=0

# run_test <file> <filter> -> 0 if all pass (0 fail), 1 otherwise
run_test() {
  local out
  out=$(timeout 90 bun test --timeout 25000 "$1" -t "$2" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}

# proof <name> <file> <filter> <target> <sed-expr>
proof() {
  local name="$1" file="$2" filter="$3" target="$4" sedexpr="$5"
  echo "=== PROOF: $name ==="
  if run_test "$file" "$filter"; then
    echo "  baseline PASS ✓"
  else
    echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$target" "$target.bak"
  sed -i "$sedexpr" "$target"
  if run_test "$file" "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# M1: loosen MFA window (<=5m -> <=6m) → N12 (5m+1ms) must fail.
proof "M1 loosen MFA window (N12)" "$NEG" "N12" "$SVC" \
  's/const MAX_MFA_AGE_MS = 300_000;/const MAX_MFA_AGE_MS = 360_000;/'

# M2: accept ambient role (skip approver-binding requirement) → N04 must fail.
proof "M2 accept ambient role (N04)" "$NEG" "N04" "$SVC" \
  's/const eligible = approverRows.some(/const eligible = true || approverRows.some(/'

# M3: skip queue/binding request-hash + digest agreement → N26 must fail.
proof "M3 skip queue/binding hash agreement (N26)" "$NEG" "N26" "$SVC" \
  's/if (queue.requestHash !== binding.requestHash || queue.actionDigest !== binding.actionDigest) {/if (false) {/'

# M4: ignore secret version at resume → N39 must fail.
proof "M4 ignore secret version (N39)" "$NEG" "N39" "$SVC" \
  's/account.credentialVersion !== c.executionDependencies.secretVersion/false/'

# M5: skip the canonical-byte digest recomputation (accept any stored digest) →
#     N24 (tampered canonical bytes) must fail. Weaken the digest equality guard.
proof "M5 skip canonical-byte digest recompute (N24)" "$NEG" "N24" "$SVC" \
  's/if (recomputedDigest !== binding.actionDigest) {/if (false) {/'

# M6: mint a fresh resumeAttemptId on the idempotent return path → C05 must fail.
proof "M6 non-idempotent resumeAttemptId (C05)" "$CONC" "C05" "$SVC" \
  's/resumeAttemptId: binding.resumeAttemptId ?? undefined,/resumeAttemptId: randomUUID(),/'

echo ""
echo "==================================================="
echo "MUTATION PROOFS: $pass_count killed, $fail_count invalid"
echo "==================================================="
[ "$fail_count" -eq 0 ] && exit 0 || exit 1
