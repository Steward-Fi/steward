#!/usr/bin/env bash
# cumulativeSpend + configurable-window mutation-strength proofs. Each
# mutation weakens ONE load-bearing guard; a proof is valid iff the named test
# PASSES clean AND FAILS after the mutation. The target file is restored after
# each proof.
#
# Three guards live in the policy-engine composer (capability-intent.ts) and are
# proven by the DB-less policy-engine unit suite. Two live in the Redis atomic
# reservation tracker (cumulative-spend-tracker.ts) and are proven by the
# redis tracker suite against a real Redis (STEWARD_REDIS_TESTS=1). Run from
# packages/api:
#
#   STEWARD_REDIS_TESTS=1 REDIS_URL=redis://localhost:6379 \
#     bash scripts/cumulative-spend-mutation-proofs.sh
#
# A non-zero exit means at least one guard was NOT killed by its mutation.
set -uo pipefail
cd "$(dirname "$0")/.."

ENGINE="../policy-engine/src/capability-intent.ts"
POLICY_UNIT="src/__tests__/cumulative-spend-cap.test.ts"          # in policy-engine
TRACKER="../redis/src/cumulative-spend-tracker.ts"
TRACKER_UNIT="src/__tests__/cumulative-spend-tracker.test.ts"     # in redis

pass_count=0
fail_count=0

# run_policy_test <filter> -> 0 if 0 fail
run_policy_test() {
  local out
  out=$(cd ../policy-engine && timeout 90 bun test --timeout 25000 "$POLICY_UNIT" -t "$1" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}
# run_tracker_test <filter> -> 0 if 0 fail (real Redis)
run_tracker_test() {
  local out
  out=$(cd ../redis && STEWARD_REDIS_TESTS=1 REDIS_URL="${REDIS_URL:-redis://localhost:6379}" \
        timeout 90 bun test --timeout 25000 "$TRACKER_UNIT" -t "$1" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}

# proof <name> <target-file> <runner> <filter> <sed-expr>
proof() {
  local name="$1" target="$2" runner="$3" filter="$4" sedexpr="$5"
  echo "=== PROOF: $name ==="
  if $runner "$filter"; then
    echo "  baseline PASS ✓"
  else
    echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$target" "$target.bak"
  sed -i "$sedexpr" "$target"
  if $runner "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (guard killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# M1: WEAKEN THE SUM COMPARE - projected > max becomes projected > max+1, so an
# over-cap invoke (exactly one micro over) no longer denies.
proof "M1 weaken cumulativeSpend sum compare" "$ENGINE" run_policy_test \
  "one micro over the boundary denies" \
  's/if (projected > cs.max) {/if (projected > cs.max + 1) {/'

# M2: SKIP THE MISSING-AGGREGATE DENY - an absent aggregate is treated as a zero
# window instead of a missing signal, so a cumulativeSpend rule silently passes.
proof "M2 skip missing-aggregate deny" "$ENGINE" run_policy_test \
  "missing aggregate block entirely => deny" \
  's/if (!agg) return PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE;/if (!agg) return null;/'

# M3: DROP THE CURRENCY CHECK - a mismatched currency no longer denies (silent FX).
proof "M3 drop currency-mismatch deny" "$ENGINE" run_policy_test \
  "operation currency != cap currency => deny" \
  's/if (decl.currency !== cs.currency) {/if (false) {/'

# M4: BREAK WINDOW AGEOUT - the reservation read uses an inclusive lower bound so
# an entry EXACTLY windowSeconds old is wrongly counted (should have aged out).
proof "M4 break trailing-window ageout boundary" "$TRACKER" run_tracker_test \
  "boundary: an entry EXACTLY windowSeconds old has aged out" \
  "s/redis.call('ZRANGEBYSCORE', KEYS\[1\], '(' .. windowStart, now)/redis.call('ZRANGEBYSCORE', KEYS[1], windowStart, now)/g"

# M5: DROP THE RESERVATION ATOMICITY GUARD - the Lua reserve no longer flags a
# cap breach before ZADD, so concurrent reserves can collectively exceed the cap.
proof "M5 drop reservation atomicity (cap check before add)" "$TRACKER" run_tracker_test \
  "100 parallel reserves of 100k against a 1M cap admit exactly 10" \
  's/if (sum + amount) > maxv then/if false then/'

# M6: DROP THE OVER-RETENTION WINDOW REJECT (codex P1) - a window beyond the 30d
# retention would silently clamp + under-enforce; removing the guard lets it
# reserve, so the over-retention test no longer throws.
proof "M6 drop over-retention window reject (P1)" "$TRACKER" run_tracker_test \
  "over-retention window" \
  's/w > 0 \&\& w <= MAX_WINDOW_SECONDS/w > 0/'

echo
echo "cumulativeSpend mutation proofs: killed=$pass_count  survived/errors=$fail_count"
[ "$fail_count" -eq 0 ] && [ "$pass_count" -ge 6 ]
