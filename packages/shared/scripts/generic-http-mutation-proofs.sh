#!/usr/bin/env bash
# Generic-http profile mutation-strength proofs. Each mutation weakens ONE
# load-bearing security predicate of the generic-http descriptor validator /
# canonicalizer; a proof is valid iff the named test PASSES clean AND FAILS after
# the mutation. The file is restored after each proof (no .bak residue). Run from
# packages/shared:
#
#   bash scripts/generic-http-mutation-proofs.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

SRC="src/generic-http-provider-action.ts"
T="src/__tests__/generic-http-provider-action.test.ts"

pass_count=0
fail_count=0

run_test() {
  local out
  out=$(timeout 120 bun test "$1" -t "$2" 2>&1)
  echo "$out" | grep -qE "^ *0 fail$"
}

# proof <name> <filter> <perl-expr>. Uses perl -0pi so anchors can be exact
# (indentation-sensitive) without brittle line numbers.
proof() {
  local name="$1" filter="$2" perlexpr="$3"
  echo "=== PROOF: $name ==="
  if run_test "$T" "$filter"; then
    echo "  baseline PASS"
  else
    echo "  baseline UNEXPECTED FAIL (proof invalid)"; fail_count=$((fail_count+1)); return
  fi
  cp "$SRC" "$SRC.bak"
  perl -0pi -e "$perlexpr" "$SRC"
  if ! cmp -s "$SRC" "$SRC.bak"; then
    :
  else
    echo "  MUTATION DID NOT APPLY (anchor mismatch)"; mv "$SRC.bak" "$SRC"; fail_count=$((fail_count+1)); return
  fi
  if run_test "$T" "$filter"; then
    echo "  post-mutation still PASSES (mutation did not kill the test)"; fail_count=$((fail_count+1))
  else
    echo "  post-mutation FAILS (predicate killed)"; pass_count=$((pass_count+1))
  fi
  mv "$SRC.bak" "$SRC"
}

# M1: ACCEPT NON-HTTPS ORIGIN.
proof "M1 skip scheme check (accept non-https origin)" "rejects a non-https origin" \
  's/  if \(scheme !== "https"\)/  if (false)/'

# M2: WEAKEN DNS LABEL VALIDATION (accept invalid host labels).
proof "M2 weaken DNS label validation" "rejects a host with an invalid DNS label" \
  's{    if \(!/\^\[a-z0-9\]\(\[a-z0-9-\]\{0,61\}\[a-z0-9\]\)\?\$/\.test\(label\)\)}{    if (false)}'

# M3: ALLOW CREDENTIAL HEADER IN DESCRIPTOR.
proof "M3 allow credential header in descriptor" "rejects a credential header in the allowlist" \
  's/        FORBIDDEN_HEADERS\.has\(name\) \|\|/        (false \&\& FORBIDDEN_HEADERS.has(name)) ||/g'

# M4: WEAKEN INT MAX RANGE (accept out-of-range query int).
proof "M4 weaken int max range" "rejects an out-of-range int query" \
  's/      if \(opts\.max !== undefined \&\& value > opts\.max\)/      if (false)/'

# M5: SKIP SEGMENT ENCODING (raw value framed instead of encodeRfc3986).
proof "M5 skip segment encoding" "space in a segment value is percent-encoded" \
  's/    pathParts\.push\(encodeRfc3986\(stringForm\)\);/    pathParts.push(stringForm);/'

# M6: DROP STRING PATTERN ENFORCEMENT.
proof "M6 drop string pattern enforcement" "rejects a query value failing its pattern" \
  's/      if \(opts\.pattern \&\& !matchesLinearSafePattern\(opts\.pattern, v\)\)/      if (false)/'

# M7: DROP PROTO-POLLUTION ARG GUARD.
proof "M7 drop proto-pollution arg guard" "rejects prototype-pollution keys in arguments" \
  's/    if \(PROTO_POLLUTION_KEYS\.has\(k\)\)/    if (false)/'

# M8: DROP UNKNOWN-ARG REJECTION.
proof "M8 drop unknown-arg rejection" "rejects an unknown argument" \
  's/    if \(!consumed\.has\(k\)\)/    if (false)/'

# M9: ALLOW MULTIPLE VARIABLE-WIDTH TOKENS. This reintroduces an ambiguous
# grammar surface even though the custom matcher remains non-backtracking.
proof "M9 allow ambiguous variable-width repetitions" "rejects ReDoS-capable operator regexes" \
  's/      if \(variableIndex !== -1\) \{/      if (false) {/'

# M10: BYPASS THE OPTIONAL-QUANTIFIER SYNTAX REJECTION. The adversarial corpus
# must keep the historical `a?` backtracking payload outside the accepted
# language; the runtime matcher itself still never invokes RegExp.
proof "M10 admit optional-quantifier syntax" "rejects ReDoS-capable operator regexes" \
  's/"\$\|\(\)\{\}\*\+\?\]"\.includes\(char\)/"\$|(){}*+]".includes(char)/'

echo ""
echo "==================================================="
echo "generic-http mutation proofs: killed=$pass_count  survived/invalid=$fail_count"
[ "$fail_count" -eq 0 ] && echo "ALL MUTATIONS KILLED" || echo "SOME MUTATIONS SURVIVED"
exit "$fail_count"
