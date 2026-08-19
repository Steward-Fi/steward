#!/usr/bin/env bash
# client-entrypoint-mutation-proofs.sh
#
# Mutation proofs for the @stwd/shared/client contract test (issue #231).
# Each mutation weakens the client-safety guarantee, asserts the contract
# test FAILS, then restores the original and asserts it PASSES again.
#
#   Mutation 1: re-export the server-only provider-execution-auth module
#               from the client entrypoint (drags node:crypto into the
#               client graph).
#   Mutation 2: point a migrated web import back at the top-level
#               @stwd/shared barrel, which the Cloudflare client build must reject.
#
# Run from the repo root:  bash scripts/client-entrypoint-mutation-proofs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED="$ROOT/packages/shared"
CLIENT_TS="$SHARED/src/client.ts"
UTILS_TS="$ROOT/web/src/lib/utils.ts"
TEST_FILE="src/__tests__/client-entrypoint.test.ts"

run_contract_test() {
  (cd "$SHARED" && bunx tsc && bun test --isolate "$TEST_FILE") >/dev/null 2>&1
}

fail() {
  echo "MUTATION PROOF FAILED: $1" >&2
  exit 1
}

echo "== baseline: contract test must PASS on pristine tree"
run_contract_test || fail "baseline contract test did not pass"
echo "   PASS"

echo "== mutation 1: re-export provider-execution-auth from client entrypoint"
cp "$CLIENT_TS" "$CLIENT_TS.mutbak"
printf '\nexport * from "./provider-execution-auth.js";\n' >>"$CLIENT_TS"
if run_contract_test; then
  mv "$CLIENT_TS.mutbak" "$CLIENT_TS"
  fail "mutation 1 was NOT detected (test passed with server-only re-export)"
fi
mv "$CLIENT_TS.mutbak" "$CLIENT_TS"
echo "   KILLED (test failed as required)"

echo "== mutation 2: web utils.ts imports the top-level barrel again"
cp "$UTILS_TS" "$UTILS_TS.mutbak"
sed -i 's|from "@stwd/shared/client";|from "@stwd/shared";|' "$UTILS_TS"
if run_contract_test; then
  mv "$UTILS_TS.mutbak" "$UTILS_TS"
  fail "mutation 2 was NOT detected (test passed with barrel import in web)"
fi
mv "$UTILS_TS.mutbak" "$UTILS_TS"
echo "   KILLED (test failed as required)"

echo "== restore check: contract test must PASS again"
run_contract_test || fail "restore check failed, tree left dirty"
echo "   PASS"

echo "ALL MUTATION PROOFS GREEN"
