#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TARGET="$ROOT/packages/api/src/services/policy-validation.ts"
TEST="$ROOT/packages/api/src/__tests__/policy-validation.test.ts"
BACKUP="$(mktemp)"
cp "$TARGET" "$BACKUP"

restore() {
  cp "$BACKUP" "$TARGET"
  rm -f "$BACKUP"
}
trap restore EXIT

expect_test_failure() {
  local label="$1"
  if (cd "$ROOT" && bun test "$TEST" >/tmp/steward-typed-data-mutation.log 2>&1); then
    echo "MUTATION SURVIVED: $label" >&2
    cat /tmp/steward-typed-data-mutation.log >&2
    exit 1
  fi
  echo "MUTATION KILLED: $label"
}

python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '    case "typed-data": {'
assert text.count(old) == 1
path.write_text(text.replace(old, '    case "typed-data-disabled": {', 1))
PY
expect_test_failure "missing typed-data switch arm"
cp "$BACKUP" "$TARGET"

python3 - "$TARGET" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '          config.messageConditions.length === 0 ||'
assert text.count(old) == 1
path.write_text(text.replace(old, '          false ||', 1))
PY
expect_test_failure "empty messageConditions permissive guard"
cp "$BACKUP" "$TARGET"

echo "All typed-data policy validation mutations were killed."
