#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
rotation=scripts/rotate-master-password.ts
auth=packages/shared/src/provider-execution-auth.ts
rotation_copy=$(mktemp)
auth_copy=$(mktemp)
# SEC-201: mktemp instead of a predictable /tmp path (symlink-safe on shared hosts)
log_file=$(mktemp -t steward-key-rotation-mutation.XXXXXX)
cp "$rotation" "$rotation_copy"
cp "$auth" "$auth_copy"
restore() {
  cp "$rotation_copy" "$rotation"
  cp "$auth_copy" "$auth"
  rm -f "$rotation_copy" "$auth_copy" "$log_file"
}
trap restore EXIT

expect_killed() {
  local label=$1
  shift
  if "$@" >"$log_file" 2>&1; then
    echo "SURVIVED: $label" >&2
    exit 1
  fi
  echo "KILLED: $label"
}

mutate_rotation() {
  cp "$rotation_copy" "$rotation"
  python3 - "$rotation" "$1" "$2" <<'PY'
import sys
path, old, new = sys.argv[1:]
data = open(path).read()
assert old in data, old
data = data.replace(old, new, 1)
open(path, "w").write(data)
PY
}

mutate_rotation 'if (failures.length > 0) {' 'if (false) {'
expect_killed skip-complete-preflight bun test scripts/__tests__/rotate-master-password-cli.test.ts

mutate_rotation 'await db.transaction' 'await db.notATransaction'
expect_killed allow-partial-commit bun test scripts/__tests__/rotate-master-password-cli.test.ts

mutate_rotation 'const payload = JSON.parse(value.slice(WEBHOOK_PREFIX.length)) as EncryptedKey;' 'const payload = JSON.parse(value.slice(WEBHOOK_PREFIX.length)) as EncryptedKey; console.log("plaintext", value);'
expect_killed print-sensitive-material bun test scripts/__tests__/rotate-master-password-cli.test.ts

cp "$auth_copy" "$auth"
python3 - "$auth" <<'PY'
import sys
path = sys.argv[1]
data = open(path).read()
old = 'const active = keys[0];\n  if (commitment.keyId !== active.keyId) {'
new = 'const active = keys.find((key) => key.keyId === commitment.keyId) ?? keys[0];\n  if (commitment.keyId !== active.keyId) {'
assert old in data
data = data.replace(old, new, 1)
open(path, 'w').write(data)
PY
expect_killed sign-with-verify-only-old-key bun test packages/shared/src/__tests__/provider-execution-auth-rotation.test.ts
cp "$auth_copy" "$auth"

mutate_rotation '  "pending_proxy_requests",' ''
expect_killed omit-encrypted-inventory-class bun test scripts/__tests__/rotate-master-password-cli.test.ts

mutate_rotation 'name: `pending-proxy:${row.requestDigest}`' 'name: "pending-proxy:wrong-aad"'
expect_killed drop-aad-fidelity bun test packages/vault/src/__tests__/rotate-master-password.test.ts

# In-transaction drift guard: removing the mid-transaction failure abort must be
# caught (a row failing auth during the write pass has to roll the txn back).
mutate_rotation 'throw new Error(`${table} changed after preflight; transaction rolled back`);' '/* mutant: drift guard removed */;'
expect_killed allow-in-transaction-drift bun test scripts/__tests__/rotate-master-password-cli.test.ts

# Post-commit audit failure must be reported as COMPLETE (data is durable), not
# as an abort. Mislabelling the post-commit path as ABORTED would invite
# restoring an already-rotated database.
mutate_rotation 'ROTATION COMPLETE, but the completion audit event could not be written' 'ROTATION ABORTED after the completion audit event could not be written'
expect_killed post-commit-audit-mislabelled-as-abort bun test packages/vault/src/__tests__/rotate-master-password.real-pg.test.ts

echo 'All 8 key-rotation mutations killed.'
