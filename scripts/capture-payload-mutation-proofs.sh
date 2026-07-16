#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/packages/plugin-capabilities/src/capture-payload.ts"
TEST="$ROOT/packages/plugin-capabilities/src/__tests__/capture-payload.test.ts"
BACKUP="$(mktemp)"
cp "$SOURCE" "$BACKUP"
restore() { cp "$BACKUP" "$SOURCE"; rm -f "$BACKUP"; }
trap restore EXIT

run_expected_failure() {
  local label="$1"
  local output
  if output=$(cd "$ROOT" && bun test "$TEST" 2>&1); then
    printf 'MUTATION SURVIVED: %s\n%s\n' "$label" "$output" >&2
    exit 1
  fi
  printf 'mutation killed: %s\n' "$label"
  cp "$BACKUP" "$SOURCE"
}

python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); s=p.read_text(); old=".max(MAX_COOKIE_COUNT, `jar cannot exceed ${MAX_COOKIE_COUNT} cookies`)"; assert s.count(old)==1; p.write_text(s.replace(old, ".max(MAX_COOKIE_COUNT + 1, `jar cannot exceed ${MAX_COOKIE_COUNT} cookies`)"))' "$SOURCE"
run_expected_failure "cookie-count upper bound weakened"

python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); s=p.read_text(); old="cookieNames: jar.map((c) => c.name),"; assert s.count(old)==1; p.write_text(s.replace(old, "cookieNames: jar.map((c) => `${c.name}:${c.value}`),"))' "$SOURCE"
run_expected_failure "redaction includes cookie values"

printf 'all capture-payload mutations killed\n'
