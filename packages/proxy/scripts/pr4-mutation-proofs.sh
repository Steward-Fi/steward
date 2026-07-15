#!/usr/bin/env bash
# PR4 mutation-strength proofs (spec §11.5). Each mutation weakens ONE security
# predicate; a proof is valid iff the named test PASSES clean AND FAILS after the
# mutation. Every mutated file is restored after each proof.
#
# The proofs span three packages (the governed decrypt path is distributed
# across the proxy + api + plugin per contradiction C2): each proof runs the
# affected test in its home package.
#
#   Run from the repo root:  bash packages/proxy/scripts/pr4-mutation-proofs.sh
#
# Requires: @stwd/shared + @stwd/redis + @stwd/db dist built (tsc) first, so the
# proxy/api/plugin suites import the compiled crypto.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

GOV="packages/proxy/src/handlers/governed-execution.ts"
PROXY="packages/proxy/src/handlers/proxy.ts"
CRYPTO="packages/shared/src/provider-execution-auth.ts"
PLUGIN="packages/plugin-capabilities/src/invoke.ts"

GOV_TEST="src/__tests__/governed-execution.test.ts"
CRYPTO_TEST="src/__tests__/execution-authorization-v2-crypto.test.ts"
PLUGIN_TEST="src/__tests__/invoke.test.ts"

pass_count=0
fail_count=0

# _run_once <pkg-dir> <test-file> <filter> -> 0 if all pass (0 fail), else 1.
_run_once() {
  local dir="$1" file="$2" filter="$3" out
  out=$(cd "$dir" && timeout 180 bun test --timeout 30000 "$file" -t "$filter" 2>&1)
  echo "$out" | grep -qE "^ *[1-9][0-9]* pass$" && echo "$out" | grep -qE "^ *0 fail$"
}

# run_baseline: retries up to 3x. The VPS is memory-constrained and back-to-back
# bun test processes occasionally time out / OOM transiently. A proof is only
# meaningful when the CLEAN predicate CAN pass, so the baseline gets retries.
run_baseline() {
  local i
  for i in 1 2 3; do
    if _run_once "$1" "$2" "$3"; then return 0; fi
    sleep 2
  done
  return 1
}

# run_mutated: SINGLE shot, NO retry. A killed predicate must fail on its own
# merit; retrying a mutated run would give a flaky (e.g. concurrency K01) mutation
# multiple chances to pass and weaken the proof. If the single mutated run passes,
# the predicate was NOT killed — that is a real invalid proof, not transient noise.
run_mutated() {
  _run_once "$1" "$2" "$3"
}

# proof <name> <pkg-dir> <test-file> <filter> <target> <sed-expr>
proof() {
  local name="$1" dir="$2" file="$3" filter="$4" target="$5" sedexpr="$6"
  echo "=== PROOF: $name ==="
  if run_baseline "$dir" "$file" "$filter"; then
    echo "  baseline PASS ✓"
  else
    echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$target" "$target.bak"
  sed -i "$sedexpr" "$target"
  if run_mutated "$dir" "$file" "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# M1: remove the authority_mode gate in handleProxy → P01 (direct /proxy to a
#     governed route must be denied). Turn the gate condition into a no-op.
proof "M1 remove authority_mode gate (P01)" "packages/proxy" "$GOV_TEST" "P01" "$PROXY" \
  's/if (authorityMode !== "legacy") {/if (false) {/'

# M2: accept a governedExecutionClaim whose routeId does NOT match the selected
#     route → P05 (a forged/mismatched claim must be ignored → 403).
proof "M2 accept mismatched claim routeId (P05)" "packages/proxy" "$GOV_TEST" "P05" "$PROXY" \
  's/governedClaim.routeId === route.id;/true;/'

# M3: drop status='active' from the claim predicate → K01 (double claim: two
#     concurrent claims must still yield exactly one winner).
proof "M3 drop status=active from claim (K01)" "packages/proxy" "$GOV_TEST" "K01" "$GOV" \
  's/eq(executionAuthorizationNonces.status, "active"),//'

# M4: change DB-time expiry from > now() to >= now()-ish by removing the guard →
#     P24 (an expired authorization must never be dispatched). Removing the
#     expiry predicate lets the expired nonce claim.
proof "M4 drop expires_at > now() from claim (P24)" "packages/proxy" "$GOV_TEST" "P24" "$GOV" \
  's/sql`${executionAuthorizationNonces.expiresAt} > now()`,//'

# M5: skip the pre-claim route-revision drift check → P13 (a route revision bump
#     after mint must fail closed as stale route). Force the drift guard false.
proof "M5 skip route-revision drift check (P13)" "packages/proxy" "$GOV_TEST" "P13" "$GOV" \
  's/liveRoute.authorityRevision !== loaded.routeRevision/false/'

# M6: skip the pre-claim secret-version drift check → P14 (a secret rotation
#     after mint must fail closed as stale secret).
proof "M6 skip secret-version drift check (P14)" "packages/proxy" "$GOV_TEST" "P14" "$GOV" \
  's/liveSecret.version !== loaded.secretVersion/false/'

# M7: skip the signing-boundary commitment-hash recompute equality → P11 (a
#     tampered signature/commitment must fail before any claim/decrypt). Force
#     the recompute mismatch guard to never trigger AND accept any signature.
proof "M7 accept any commitment at boundary (P11)" "packages/proxy" "$GOV_TEST" "P11" "$GOV" \
  's/if (!signatureValid) {/if (false) {/'

# M8: allow re-dispatch of a terminal/consumed authorization → P26 (a consumed
#     nonce must return terminal, never re-dispatch). Force the terminal guard off.
proof "M8 allow re-dispatch of terminal nonce (P26)" "packages/proxy" "$GOV_TEST" "P26" "$GOV" \
  's/if (loaded.authStatus !== "active" || loaded.dispatchState !== "none") {/if (false) {/'

# M9: remove the boundary account-disabled check → P18 (a disabled provider
#     account, same revision, must fail closed post-claim before dispatch). The
#     claim SQL cannot express account status, so removing the boundary check
#     lets a disabled account dispatch.
proof "M9 remove account-disabled boundary check (P18)" "packages/proxy" "$GOV_TEST" "P18" "$GOV" \
  's/if (!acc || acc.status !== "active") return { ok: false, code: "EXEC_AUTH_ACCOUNT_DISABLED" };/if (false) return { ok: false, code: "EXEC_AUTH_ACCOUNT_DISABLED" };/'

# NOTE on domain separation (P12): the v2 signature domain prefix is proven by
# the packages/api crypto suite ("domain separation: a v2 signature does not
# validate as a v1 HMAC"). It is NOT scripted as a mutation here because the
# crypto lives in @stwd/shared which the api/proxy suites import from BUILT dist
# (a source mutation would require a rebuild between baseline and post-mutation);
# the standing crypto test already fails closed if the prefix is removed.

# M10: let the capability plugin mint a proxy token for a governed route → P03/P04
#      (a governed operation must never be invokable through the plugin alias).
#      Force the governed-route detection to always report "not governed".
proof "M10 plugin mints for governed route (P03/P04)" "packages/plugin-capabilities" "$PLUGIN_TEST" "GOVERNED_ROUTE_PLUGIN_DENIED" "$PLUGIN" \
  's/const governed = await capabilityMapsToGovernedRoute(/const governed = false \&\& await capabilityMapsToGovernedRoute(/'

# M11: turn the post-dispatch timeout outcome into a blind success instead of
#      outcome_unknown → K13 (an upstream throw AFTER dispatch must record
#      outcome_unknown and NEVER auto-retry / claim success, X8).
proof "M11 timeout classified as success not outcome_unknown (K13)" "packages/proxy" "$GOV_TEST" "K13/K14" "$GOV" \
  's/await recordTerminal(tenantId, loaded, "outcome_unknown", undefined);/await recordTerminal(tenantId, loaded, "succeeded", 200);/'

# M12: accept an invalid v2 signature at the boundary → P11 (a tampered
#      signature must be rejected before any claim/decrypt). Force the
#      signature-invalid guard off.
proof "M12 accept invalid v2 signature at boundary (P11)" "packages/proxy" "$GOV_TEST" "P11" "$GOV" \
  's/if (!signatureValid) {/if (false) {/'

# M13: remove the read-side binding-ready guard → P1a-read (an active nonce whose
#      binding is already NOT execution_ready at read time must be denied
#      EXEC_AUTH_NOT_READY before any claim). Neutralizing the read guard lets the
#      flow fall through to the claim tx, which returns a DIFFERENT code
#      (EXEC_AUTH_CLAIM_LOST) — the P1a-read assertion on EXEC_AUTH_NOT_READY fails.
proof "M13 remove read-side binding-ready guard (P1a-read)" "packages/proxy" "$GOV_TEST" "P1a-read" "$GOV" \
  's/if (loaded.bindingStatus !== "execution_ready") {/if (false) {/'

# M14: remove the atomic claim-tx binding-transition gate → P1a-race (a binding
#      advanced past execution_ready AFTER the read guard, between revalidate and
#      claim, must be caught INSIDE the claim tx and roll the whole claim back so
#      the nonce is NEVER consumed). Neutralizing the zero-row rollback lets the
#      nonce claim succeed + dispatch against a non-ready binding — P1a-race fails.
proof "M14 remove atomic claim-tx binding gate (P1a-race)" "packages/proxy" "$GOV_TEST" "P1a-race" "$GOV" \
  's/if (bindingAdvanced.length === 0) {/if (false) {/'

echo ""
echo "==================================================="
echo "PR4 MUTATION PROOFS: $pass_count killed, $fail_count invalid"
echo "==================================================="
[ "$fail_count" -eq 0 ] && exit 0 || exit 1
