#!/usr/bin/env bash
# Evidence mutation-strength proofs. Each mutation weakens one evidence
# security predicate; a proof is valid iff the named test PASSES clean AND FAILS
# after the mutation. Every mutated file is restored after each proof.
#
#   Run from the repo root:  bash packages/api/scripts/evidence-mutation-proofs.sh
#
# Requires @stwd/shared + @stwd/redis + @stwd/db dist built (tsc) first.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

VERIFIER="scripts/verify-evidence-bundle.mjs"
SERVICE="packages/api/src/services/provider-case.ts"

VERIFY_TEST="src/__tests__/provider-case-verifier.test.ts"
EVI_TEST="src/__tests__/provider-case-evidence.integration.test.ts"
SVC_TEST="src/__tests__/provider-case-service.test.ts"

API="packages/api"
pass_count=0
fail_count=0

_run_once() {
  local file="$1" filter="$2" out
  out=$(cd "$API" && timeout 180 bun test --timeout 60000 "$file" -t "$filter" 2>&1)
  echo "$out" | grep -qE "^ *[1-9][0-9]* pass$" && echo "$out" | grep -qE "^ *0 fail$"
}
run_baseline() { local i; for i in 1 2 3; do _run_once "$1" "$2" && return 0; sleep 2; done; return 1; }
run_mutated() { local i; for i in 1 2 3; do _run_once "$1" "$2" || return 1; sleep 1; done; return 0; }

# proof <name> <test-file> <filter> <target> <sed-expr>
proof() {
  local name="$1" file="$2" filter="$3" target="$4" sedexpr="$5"
  echo "=== PROOF: $name ==="
  if run_baseline "$file" "$filter"; then echo "  baseline PASS ✓"
  else echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return; fi
  cp "$target" "$target.bak"
  sed -i "$sedexpr" "$target"
  if run_mutated "$file" "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# ── Verifier guards (spec §9.1) ──────────────────────────────────────────────

# M1: drop the manifest event hmac/action equality → N43 (manifest event that
#     does not match the signed bundle event must FAIL). Force the mismatch off.
proof "M1 drop manifest hmac==bundle check (N43)" "$VERIFY_TEST" "N43" "$VERIFIER" \
  's/if (be.hmac !== me.hmac) {/if (false) {/'

# M2: drop the forged-completeness guard → N09 (claim complete while a required
#     role is absent from the signed events must FAIL).
proof "M2 drop forged-completeness guard (N09)" "$EVI_TEST" "N09" "$VERIFIER" \
  's/if (manifest.completeness === "complete" \&\& actuallyMissing.length > 0) {/if (false) {/'

# M3: trust the embedded key without fingerprint match → N17/N35 (a supplied
#     but non-matching fingerprint must FAIL untrusted). Force the match true.
proof "M3 trust embedded key w/o fingerprint match (N17)" "$EVI_TEST" "N17" "$VERIFIER" \
  's/if (!expectedFps.includes(observedFp)) {/if (false) {/'

# M4: skip the manifest-fact-backing cross-check → N08 (a mutated manifest fact
#     with no backing signed event must FAIL). Neutralize the value comparison.
proof "M4 drop manifest fact-backing check (N08)" "$EVI_TEST" "N08" "$VERIFIER" \
  's/if (signedVal !== manifestVal) {/if (false) {/'

# M5: accept an unknown manifest schemaVersion → N44 (fail-closed on unknown).
proof "M5 accept unknown manifest schemaVersion (N44)" "$VERIFY_TEST" "N44" "$VERIFIER" \
  's/if (manifest.schemaVersion !== MANIFEST_SCHEMA_VERSION) {/if (false) {/'

# M6: drop the manifest tenant cross-check vs signed payload → N22.
proof "M6 drop manifest tenant cross-check (N22)" "$VERIFY_TEST" "N22" "$VERIFIER" \
  's/if (manifest.tenantId !== payload.tenantId) {/if (false) {/'

# M7: drop the events-content digest recompute equality → N19 (a mutated event
#     field must break the signed digest).
proof "M7 drop events-content digest check (N19)" "$VERIFY_TEST" "N19" "$VERIFIER" \
  's/if (recomputedDigest !== payload.eventsDigest) {/if (false) {/'

# M8: drop the eventsFromSeq/eventsToSeq bracketing check → N20.
proof "M8 drop seq-bracket check (N20)" "$VERIFY_TEST" "N20" "$VERIFIER" \
  's/if (payload.eventsToSeq !== events\[events.length - 1\].seq) {/if (false) {/'

# ── Service guards (spec §9.1) ───────────────────────────────────────────────

# M9: correlate by resource_id alone, dropping the metadata.intentId agreement
#     check → N23 (a forged event stolen into the case must be dropped).
proof "M9 drop metadata.intentId agreement (N23)" "$SVC_TEST" "event-theft" "$SERVICE" \
  's/if (metadata.intentId !== caseId) continue;/if (false) continue;/'

# M10: return 403 (not 404) for a foreign workspace → D2 enumeration. Here we
#      prove the WORKSPACE scoping drop: authorize-all instead of the caller set,
#      so the "foreign workspace → null" service test must fail (case leaks).
proof "M10 drop workspace scoping (D2 enumeration)" "$SVC_TEST" "foreign workspace" "$SERVICE" \
  's/if (!authorizedWorkspaceIds.includes(binding.workspaceId)) return null;/if (false) return null;/'

echo ""
echo "==================================================================="
echo "EVIDENCE MUTATION PROOFS: $pass_count killed, $fail_count invalid/survived"
echo "==================================================================="
[ "$fail_count" -eq 0 ] && exit 0 || exit 1
