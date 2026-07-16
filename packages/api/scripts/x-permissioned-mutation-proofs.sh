#!/usr/bin/env bash
# Permissioned-X mutation-strength proofs. Each mutation weakens ONE
# permissioned-X policy guard; a proof is valid iff the named test PASSES clean
# AND FAILS after the mutation. The target file is restored after each proof.
#
# Guards live in the policy-engine composer (packages/policy-engine), so this
# script reaches up the monorepo to mutate that file and runs the fast, DB-less
# permissioned-X unit suite. Run from packages/api:
#
#   bash scripts/x-permissioned-mutation-proofs.sh
#
# A non-zero exit means at least one guard was NOT killed by its mutation (the
# test did not detect the weakening) — i.e. the guard is not load-bearing.
set -uo pipefail
cd "$(dirname "$0")/.."

ENGINE="../policy-engine/src/capability-intent.ts"
UNIT="../policy-engine/src/__tests__/permissioned-x.test.ts"

pass_count=0
fail_count=0

# run_test <file> <filter> -> 0 if all pass (0 fail), 1 otherwise
run_test() {
  local out
  out=$(cd ../policy-engine && timeout 90 bun test --timeout 25000 "src/__tests__/permissioned-x.test.ts" -t "$1" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}

# proof <name> <filter> <sed-expr>
proof() {
  local name="$1" filter="$2" sedexpr="$3"
  echo "=== PROOF: $name ==="
  if run_test "$filter"; then
    echo "  baseline PASS ✓"
  else
    echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$ENGINE" "$ENGINE.bak"
  sed -i "$sedexpr" "$ENGINE"
  if run_test "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (guard killed)"; pass_count=$((pass_count+1))
  fi
  mv "$ENGINE.bak" "$ENGINE"
}

# M1: reply summoned-only no longer denies an un-summoned reply.
proof "M1 summoned-only ignores summoned flag" "summoned-only denies an un-summoned reply" \
  's/if (!summoned) {/if (false) {/'

# M2: reply mode=none no longer forbids replies.
proof "M2 replyPolicy none no longer denies" "mode=none denies a reply" \
  's/if (x.replyPolicy.mode === "none") {/if (false) {/'

# M3: allowUrls=false no longer denies URL posts.
proof "M3 allowUrls=false ignores hasUrl" "allowUrls=false denies a URL post" \
  's/if (hasUrl) {/if (false) {/'

# M4: maxLength no longer enforced.
proof "M4 maxLength not enforced" "maxLength denies an over-length post" \
  's/if (len > x.contentPolicy.maxLength) {/if (false) {/'

# M5: blockedPatterns match no longer denies.
proof "M5 blockedPatterns match ignored" "blockedPatterns denies a matching text" \
  's/if (re.test(text)) {/if (false) {/'

# M6: maxPostsPerWindow cap no longer enforced.
proof "M6 rate cap not enforced" "denies when the window count is at/over the cap" \
  's/if (posts >= x.maxPostsPerWindow.max) {/if (false) {/'

# M7: spend cap no longer enforced.
proof "M7 spend cap not enforced" "denies when accumulated .* exceeds the cap" \
  's/if (projectedMicros > x.spendPolicy.maxSpendMicros) {/if (false) {/'

# M8: quiet-hours no longer denies.
proof "M8 quiet hours not enforced" "denies inside a non-wrapping window" \
  's/if (inWindow) {/if (false) {/'

# M9: url-post escalation no longer escalates (would silently allow the $0.20 post).
proof "M9 url escalation dropped" "urlPostRequiresApproval escalates a URL post to approval" \
  's/if (x.escalation.urlPostRequiresApproval === true && hasUrl === true) {/if (false) {/'

# M10: x-block-on-non-x-op no longer a config error (scope leak).
proof "M10 x block scope check dropped" "an x block on a NON-x operation is a config error" \
  's/if (!ctx.operationKey.startsWith("x.")) {/if (false) {/'

echo
echo "=== permissioned-X mutation proofs: $pass_count killed, $fail_count not-killed ==="
[ "$fail_count" -eq 0 ]
