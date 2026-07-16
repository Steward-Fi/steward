#!/usr/bin/env bash
# PR6 mutation-strength proofs (spec §5.3). Each mutation weakens ONE security/
# honesty predicate in PRODUCTION or SOURCE code; a proof is valid iff the named
# GUARD test PASSES clean AND FAILS after the mutation. Every mutated file is
# restored after each proof.
#
# IMPORTANT: mutations target the CODE THE TEST GUARDS (production source, page
# source, docs), NOT the test's own assertions. Weakening a test assertion would
# be a no-op when the real value already satisfies it — the pr5 convention is to
# mutate the guarded predicate itself.
#
#   Run from the repo root:  bash packages/api/scripts/pr6-mutation-proofs.sh
#
# Requires @stwd/shared + @stwd/redis dist built (tsc) first, and @stwd/proxy
# available to @stwd/api (devDependency added in PR6).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

API="packages/api"
PROXY="packages/proxy"
WEB="web"

# Guard test files.
INVENTORY_TEST="src/__tests__/fake-provider-transport-inventory.test.ts" # in PROXY
UX_TEST="src/app/dashboard/provider-trust-ux.test.ts"                     # in WEB
CLAIMS_TEST="src/__tests__/provider-authority-claims-scanner.test.ts"     # in API
COMPOSE_TEST="src/__tests__/provider-authority-compose-env.test.ts"       # in API

# Target (GUARDED) files — production source, page source, docs, config.
PROXY_SRC="$PROXY/src/handlers/proxy.ts"
FAKE="$PROXY/src/__tests__/fake-provider-transport.ts"
APPROVAL_PAGE="$WEB/src/app/dashboard/approvals/[id]/page.tsx"
CASE_PAGE="$WEB/src/app/dashboard/actions/[id]/page.tsx"
THREAT_DOC="docs/security/provider-authority-threat-model.mdx"
COMPOSE="deploy/enterprise-reference/docker-compose.yml"

pass_count=0
fail_count=0

# _run_once <pkg-dir> <test-file> <filter>
_run_once() {
  local dir="$1" file="$2" filter="$3" out
  out=$(cd "$dir" && timeout 120 bun test --timeout 60000 "$file" ${filter:+-t "$filter"} 2>&1)
  echo "$out" | grep -qE "^ *[1-9][0-9]* pass$" && echo "$out" | grep -qE "^ *0 fail$"
}
run_baseline() { local i; for i in 1 2 3; do _run_once "$1" "$2" "$3" && return 0; sleep 2; done; return 1; }
run_mutated() { local i; for i in 1 2; do _run_once "$1" "$2" "$3" || return 1; sleep 1; done; return 0; }

# proof <name> <pkg-dir> <test-file> <filter> <target> <perl-expr>
proof() {
  local name="$1" dir="$2" file="$3" filter="$4" target="$5" expr="$6"
  echo "=== PROOF: $name ==="
  if run_baseline "$dir" "$file" "$filter"; then echo "  baseline PASS ✓"
  else echo "  baseline UNEXPECTED FAIL ✗ (proof invalid)"; fail_count=$((fail_count+1)); return; fi
  cp "$target" "$target.bak"
  perl -0pi -e "$expr" "$target"
  if run_mutated "$dir" "$file" "$filter"; then
    echo "  post-mutation still PASSES ✗ (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS ✓ (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$target.bak" "$target"
}

# ── U1 static-inventory / SSRF guards (mutate PRODUCTION proxy.ts) ────────────

# 1: remove the default DNS-vetted forwarder binding → the "default is
#    DNS-vetted" seam assertion (PN02) must fail.
proof "1 seam: default forwarder must be forwardWithVettedDns (PN02)" \
  "$PROXY" "$INVENTORY_TEST" "the ONLY forwarder setter" "$PROXY_SRC" \
  's/let forwardProxyRequestForHandler: ProxyForwarder = forwardWithVettedDns;/let forwardProxyRequestForHandler: ProxyForwarder = (async () => new Response("")) as unknown as ProxyForwarder;/'

# 2: add a SECOND bare rebinding of the forwarder (an unauthorized swap path) →
#    the "exactly one bare assignment" seam guard (PN02) must fail.
proof "2 seam: extra forwarder rebinding path detected (PN02)" \
  "$PROXY" "$INVENTORY_TEST" "the ONLY forwarder setter" "$PROXY_SRC" \
  's/(export function __setForwardProxyRequestForTests\(forwarder: ProxyForwarder\): void \{)/$1\n  forwardProxyRequestForHandler = forwarder;/'

# 3: remove the SSRF public-DNS guard invocation → the "SSRF guards on the
#    forward path" assertion (U1) must fail.
proof "3 U1: SSRF public-DNS guard must remain on the forward path (U1)" \
  "$PROXY" "$INVENTORY_TEST" "SSRF/public-DNS guards remain present" "$PROXY_SRC" \
  's/await verifyProxyHostResolvesPublicly\(target\.host\)/\/* removed *\/ Promise.resolve(target.host)/'

# ── UX honesty / equal-weight guards (mutate PAGE source) ────────────────────

# 4: change the APPROVE button's class so it is no longer byte-identical to the
#    deny button (px-4 -> px-8 gives it more prominence) → the equal-weight
#    assertion (2 identical class strings) must drop to 1 and FAIL (M11).
proof "4 UX: equal-weight approve/deny (M11)" \
  "$WEB" "$UX_TEST" "equal-weight" "$APPROVAL_PAGE" \
  's/(aria-label="Approve this provider action"\s*\n\s*className="flex-1 )px-4 py-2/${1}px-8 py-2/'

# 5: drop the client-side required-reason gate → the M13 assertion must fail.
proof "5 UX: typed reason required for both decisions (M13)" \
  "$WEB" "$UX_TEST" "typed reason is required for BOTH" "$APPROVAL_PAGE" \
  's/if \(reason\.trim\(\)\.length === 0\) \{/if (false) {/'

# 6: make the completeness tone always success → the "verbatim / never upgraded"
#    assertion (PN34) must fail.
proof "6 UX: completeness rendered verbatim, never upgraded (PN34)" \
  "$WEB" "$UX_TEST" "completeness is rendered VERBATIM" "$CASE_PAGE" \
  's/if \(c === "complete"\) return "border-success/if (true) return "border-success/'

# 7: remove the out-of-band fingerprint verify command → the operator-key trust
#    limit assertion (E7) must fail.
proof "7 UX: operator-key trust limit + fingerprint verify command (E7)" \
  "$WEB" "$UX_TEST" "operator-key trust limit" "$CASE_PAGE" \
  's/--expected-key-fingerprint/--EMBEDDED-KEY-ONLY/g'

# 8: remove the credential-hash-only surface (leak the raw idempotency key) →
#    the "hashes only" assertion must fail.
proof "8 UX: only the provider idempotency HASH is surfaced (PN28-adjacent)" \
  "$WEB" "$UX_TEST" "no credential or canonical bytes" "$CASE_PAGE" \
  's/providerIdempotencyKeyHash/providerIdempotencyKeyRaw/g'

# ── Claims-discipline guard (mutate DOC) ─────────────────────────────────────

# 9: inject an affirmative prohibited claim → the prohibited-claim scanner
#    (U8/PN38) must fail.
proof "9 claims: prohibited exactly-once/operator-proof claim rejected (U8/PN38)" \
  "$API" "$CLAIMS_TEST" "provider-authority-threat-model" "$THREAT_DOC" \
  's/## Residual risks/This system is exactly-once and provides operator-integrity proof.\n\n## Residual risks/'

# ── Compose env fail-closed guard (mutate COMPOSE) ───────────────────────────

# 10: drop the required exec-auth secret from compose → the compose-env
#     verification (G2/U10) must fail.
proof "10 compose: exec-auth secret required in enterprise-reference (G2/U10)" \
  "$API" "$COMPOSE_TEST" "compose declares" "$COMPOSE" \
  's/STEWARD_EXECUTION_AUTH_SECRET: "\$\{STEWARD_EXECUTION_AUTH_SECRET:\?required\}"/# removed/g'

echo ""
echo "=== PR6 mutation proofs: $pass_count killed / $((pass_count + fail_count)) total ==="
if [ "$fail_count" -ne 0 ]; then
  echo "FAIL: $fail_count proof(s) did not behave as required."
  exit 1
fi
echo "OK: all mutations killed their named tests."
