#!/usr/bin/env bash
# Mutation proofs for the production local-custody acknowledgement gate (issue #213).
#
# For each mutation we WEAKEN the guard in vault-factory.ts, confirm the
# security test suite goes RED, then RESTORE the original and confirm GREEN.
# A guard that can be weakened without any test noticing is not a guard.
#
# Usage: bash scripts/custody-ack-gate-mutation-proofs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FACTORY="$ROOT/packages/api/src/services/vault-factory.ts"
BACKUP=""
LOG=""
BACKUP_READY=false
TEST="vault-factory.test.ts"

cleanup() {
  # Never restore from a merely-created (still empty) mktemp file. If the
  # initial source copy fails, overwriting FACTORY from that file would turn a
  # setup error into source destruction.
  if $BACKUP_READY; then
    cp "$BACKUP" "$FACTORY"
  fi
  [[ -n "$BACKUP" ]] && rm -f -- "$BACKUP"
  [[ -n "$LOG" ]] && rm -f -- "$LOG"
}
trap cleanup EXIT

# SEC-201: mktemp instead of a predictable /tmp path (symlink-safe on shared hosts).
# Install the cleanup trap before allocation so partial setup cannot leak files.
BACKUP="$(mktemp)"
LOG="$(mktemp -t custody-ack-mut.XXXXXX)"
cp "$FACTORY" "$BACKUP"
BACKUP_READY=true

run_tests() {
  ( cd "$ROOT/packages/api" && bun scripts/run-tests-isolated.ts "$TEST" ) >"$LOG" 2>&1
}

expect_red() {
  local label="$1"
  if run_tests; then
    echo "MUTATION SURVIVED ($label): tests still GREEN after weakening the guard. FAIL."
    tail -20 "$LOG"
    exit 1
  fi
  echo "  killed: $label (tests went RED as required)"
  cp "$BACKUP" "$FACTORY"
}

echo "[0] baseline: unmutated suite must be GREEN"
run_tests || { echo "baseline RED — fix before mutating"; tail -20 "$LOG"; exit 1; }
echo "  ok"

echo "[1] mutation: gate always returns early (never throws)"
# Neutralize the whole assertion body.
perl -0pi -e 's/(export function assertProductionCustodyAcknowledged\(mode: VaultMode\): void \{)/$1\n  return; \/\/ MUTATION/' "$FACTORY"
expect_red "assert becomes a no-op"

echo "[2] mutation: invert the production check (only fires OUTSIDE production)"
perl -0pi -e 's/if \(process\.env\.NODE_ENV !== "production"\) return;/if (process.env.NODE_ENV === "production") return; \/\/ MUTATION/' "$FACTORY"
expect_red "production check inverted"

echo "[3] mutation: treat any non-empty ack as acknowledged (drop exact 'true')"
perl -0pi -e 's/return process\.env\[LOCAL_CUSTODY_ACK_ENV\] === "true";/return Boolean(process.env[LOCAL_CUSTODY_ACK_ENV]); \/\/ MUTATION/' "$FACTORY"
expect_red "ack comparison loosened to truthy"

echo "[4] mutation: unknown mode reported as NOT plaintext-at-sign-time (fail open)"
perl -0pi -e 's/(    default: \{\n      \/\/ Unknown mode: fail closed \(treat as plaintext-exposing\)\.\n      const _exhaustive: never = mode;\n)      return true;/$1      return false; \/\/ MUTATION/' "$FACTORY"
expect_red "unknown mode fails open"

echo
echo "ALL MUTATIONS KILLED. Restoring original and confirming GREEN."
cp "$BACKUP" "$FACTORY"
run_tests || { echo "restore left suite RED — investigate"; tail -20 "$LOG"; exit 1; }
echo "GREEN. Mutation proofs complete."
