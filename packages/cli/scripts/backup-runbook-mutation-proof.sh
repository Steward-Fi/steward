#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUNBOOK="$ROOT/docs/runbooks/backup-restore.md"
TEST="$ROOT/packages/cli/src/__tests__/backup-restore-docs.test.ts"
BACKUP="$(mktemp)"

restore() {
  cp "$BACKUP" "$RUNBOOK"
  rm -f "$BACKUP"
}
trap restore EXIT
cp "$RUNBOOK" "$BACKUP"

cd "$ROOT"
bun test "$TEST"

# Remove one doctor-required root name everywhere. The completeness contract
# must fail rather than silently accepting incomplete escrow guidance.
perl -pi -e 's/STEWARD_AUDIT_SIGNING_KEY/STEWARD_AUDIT_SIGNING_KEI/g' "$RUNBOOK"
if bun test "$TEST" > /tmp/steward-backup-runbook-mutation.log 2>&1; then
  cat /tmp/steward-backup-runbook-mutation.log
  echo "mutation survived: missing root-secret guidance was not detected" >&2
  exit 1
fi
grep -q "STEWARD_AUDIT_SIGNING_KEY must be included" \
  /tmp/steward-backup-runbook-mutation.log

restore
trap - EXIT
rm -f /tmp/steward-backup-runbook-mutation.log
bun test "$TEST"
echo "mutation killed: out-of-band secret completeness guard failed closed"
