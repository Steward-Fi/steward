#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
TOOLS="packages/mcp/src/tools.ts"
API="packages/mcp/src/provider-api.ts"
TOOLS_SAVE="$(mktemp)"
API_SAVE="$(mktemp)"
cp "$TOOLS" "$TOOLS_SAVE"
cp "$API" "$API_SAVE"
cleanup() {
  cp "$TOOLS_SAVE" "$TOOLS"
  cp "$API_SAVE" "$API"
  rm -f "$TOOLS_SAVE" "$API_SAVE"
}
trap cleanup EXIT

expect_red() {
  local name="$1"
  if bun test packages/mcp/src/__tests__/provider-tools.test.ts -t "$name" >/tmp/steward-mcp-mutation.log 2>&1; then
    echo "mutation unexpectedly GREEN: $name" >&2
    cat /tmp/steward-mcp-mutation.log >&2
    exit 1
  fi
  echo "RED confirmed: $name"
}
restore_green() {
  cp "$TOOLS_SAVE" "$TOOLS"
  cp "$API_SAVE" "$API"
  bun test packages/mcp/src/__tests__/provider-tools.test.ts >/dev/null
  echo "GREEN restored"
}

# Tenant binding and caller-controlled host fields depend on strict schemas.
python3 -c 'p="packages/mcp/src/tools.ts";s=open(p).read();s=s.replace("schema: z.object({ actionId: providerCaseId }).strict(),", "schema: z.object({ actionId: providerCaseId }).passthrough(),", 1);open(p,"w").write(s)'
expect_red "rejects tenant, workspace substitution"
restore_green

# Credential-bearing keys must be replaced, not traversed.
python3 -c 'p="packages/mcp/src/provider-api.ts";s=open(p).read();s=s.replace("SENSITIVE_KEY.test(key)\n        ? \"[redacted]\"\n        : sanitizeProviderPayload(nested, depth + 1)", "sanitizeProviderPayload(nested, depth + 1)");open(p,"w").write(s)'
expect_red "removes credential canaries"
restore_green

# Pending responses must retain machine-readable policy detail.
python3 -c 'p="packages/mcp/src/tools.ts";s=open(p).read();s=s.replace("structuredContent: structured,", "structuredContent: {},");open(p,"w").write(s)'
expect_red "preserves pending approval"
restore_green

# Invalid action ids must not reach transport.
python3 -c 'p="packages/mcp/src/tools.ts";s=open(p).read();start=s.index("const providerCaseId = z");end=s.index("const idempotencyKey", start);s=s[:start]+"const providerCaseId = z.string();\n"+s[end:];open(p,"w").write(s)'
expect_red "rejects malformed action ids"
restore_green

echo "4/4 provider-action mutation proofs passed"
