#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="$ROOT/packages/api/src/routes/metrics.ts"
SHARED="$ROOT/packages/shared/src/security-metrics.ts"
TMP="$(mktemp -d)"
cleanup() {
  cp "$TMP/metrics-route.ts" "$API"
  cp "$TMP/security-metrics.ts" "$SHARED"
  rm -rf "$TMP"
}
trap cleanup EXIT
cp "$API" "$TMP/metrics-route.ts"
cp "$SHARED" "$TMP/security-metrics.ts"

python3 - "$API" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
old='if (!securityMetricsEnabled()) {'
assert s.count(old) == 1
open(p,'w').write(s.replace(old, 'if (false) {'))
PY
if (cd "$ROOT/packages/api" && bun test --timeout 30000 src/__tests__/metrics-endpoint.test.ts >/dev/null 2>&1); then
  echo "FAIL: disabled endpoint exposure mutation survived" >&2
  exit 1
fi
cp "$TMP/metrics-route.ts" "$API"
echo "PASS: endpoint exposure guard mutation was killed"

python3 - "$SHARED" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read()
old_guard='if (!allowed.includes(value as T)) return;'
old_observe='incrementBounded(denials, classifyDenialReason(reasonCode), DENIAL_REASON_CLASSES);'
old_render='for (const reasonClass of DENIAL_REASON_CLASSES) {'
assert s.count(old_guard) == 1
assert s.count(old_observe) == 1
assert s.count(old_render) == 1
s=s.replace(old_guard, 'if (false) return;')
s=s.replace(old_observe, 'incrementBounded(denials, String(reasonCode), DENIAL_REASON_CLASSES);')
s=s.replace(old_render, 'for (const reasonClass of denials.keys()) {')
open(p,'w').write(s)
PY
if (cd "$ROOT/packages/shared" && bun test --timeout 30000 src/__tests__/security-metrics.test.ts >/dev/null 2>&1); then
  echo "FAIL: bounded label allowlist mutation survived" >&2
  exit 1
fi
echo "PASS: bounded label allowlist mutation was killed"
