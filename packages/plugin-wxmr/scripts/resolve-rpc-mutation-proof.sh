#!/usr/bin/env bash
# Mutation proof for the salvaged resolveRpcUrl() blank-env fallthrough fix.
#
# The bug: Docker Compose passes `WXMR_SOLANA_RPC_URL: "${WXMR_SOLANA_RPC_URL:-}"`,
# so an operator who sets only SOLANA_RPC_URL receives a blank string for the
# wxmr-specific var. A bare `??` selects that empty string and silently drops the
# operator RPC in favor of the public mainnet default.
#
# This script weakens resolveRpcUrl() to the bare-`??` form, proves the guard
# test fails, then restores the hardened implementation and proves it passes.
# Run from packages/plugin-wxmr.
set -euo pipefail

FILE="src/index.ts"
BACKUP="$(mktemp)"
cp "$FILE" "$BACKUP"
restore() { cp "$BACKUP" "$FILE"; rm -f "$BACKUP"; }
trap restore EXIT

python3 - "$FILE" <<'PY'
import sys
p = sys.argv[1]
d = open(p).read()
mut = d.replace(
    '''export function resolveRpcUrl(): string | undefined {
  for (const candidate of [process.env.WXMR_SOLANA_RPC_URL, process.env.SOLANA_RPC_URL]) {
    const trimmed = candidate?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}''',
    '''export function resolveRpcUrl(): string | undefined {
  return process.env.WXMR_SOLANA_RPC_URL ?? process.env.SOLANA_RPC_URL;
}''')
assert mut != d, "mutation did not apply; guard code shape changed"
open(p, "w").write(mut)
print("MUTATED: resolveRpcUrl -> bare ??")
PY

echo "=== expect FAIL under mutation ==="
bun test src/__tests__/wxmr-bridge.test.ts -t "resolves the operator RPC" >/tmp/wxmr-mut.log 2>&1 || true
if grep -q "(fail)" /tmp/wxmr-mut.log; then
  echo "PROVEN: guard test fails when fix is weakened"
else
  echo "MUTATION NOT CAUGHT -- test is vacuous"; cat /tmp/wxmr-mut.log; exit 1
fi

restore
trap - EXIT

echo "=== expect PASS with hardened fix restored ==="
bun test src/__tests__/wxmr-bridge.test.ts -t "resolves the operator RPC"
echo "OK: mutation proof complete"
