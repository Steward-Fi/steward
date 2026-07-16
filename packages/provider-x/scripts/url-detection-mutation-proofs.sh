#!/usr/bin/env bash
# URL detection mutation proofs. Each mutation must turn the focused green
# regression into red, then the original source is restored without residue.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SOURCE="$ROOT/packages/provider-x/src/operations.ts"
BACKUP="$(mktemp)"
cp "$SOURCE" "$BACKUP"
trap 'cp "$BACKUP" "$SOURCE"; rm -f "$BACKUP"' EXIT

run_provider() {
  cd "$ROOT/packages/provider-x" && timeout 90 bun test src/__tests__/operations.test.ts -t "$1"
}
run_e2e() {
  cd "$ROOT/packages/api" && timeout 150 bun test src/__tests__/provider-x-permissioned-e2e.test.ts -t "$1"
}
proof() {
  local name="$1" filter="$2" runner="$3" mutation="$4"
  echo "=== $name ==="
  cp "$BACKUP" "$SOURCE"
  "$runner" "$filter" >/dev/null || { echo "baseline RED"; return 1; }
  python3 -c "$mutation" "$SOURCE"
  if "$runner" "$filter" >/dev/null 2>&1; then
    echo "mutation survived"
    return 1
  fi
  echo "mutation killed"
  cp "$BACKUP" "$SOURCE"
}

proof "M1 remove bare IPv4 branch" "detects bare IPv4" run_provider \
'p=__import__("sys").argv[1];s=open(p).read();old="  if (/\\b\\d{1,3}(?:\\.\\d{1,3}){3}(?:\\/\\S*)?(?=$|[^\\d.])/i.test(detectionText)) return true;";assert old in s;open(p,"w").write(s.replace(old,"  if (false) return true;"))'
proof "M2 remove format-control stripping" "control-obfuscated URLs" run_provider \
'p=__import__("sys").argv[1];s=open(p).read();old="  const detectionText = text.replace(/\\p{Cf}/gu, \"\");";assert old in s;open(p,"w").write(s.replace(old,"  const detectionText = text;"))'
proof "M3 weaken hasUrl pricing and policy propagation" "URL pricing signal and approval escalation" run_e2e \
'p=__import__("sys").argv[1];s=open(p).read();old="  const policyArgs: Record<string, unknown> = {\n    isReply: replyToTweetId !== undefined,\n    hasUrl,";assert old in s;open(p,"w").write(s.replace(old,old.replace("    hasUrl,", "    hasUrl: false,")))'
proof "M4 strip controls from posted and canonical text" "keeps control-obfuscated text byte-exact" run_provider \
'p=__import__("sys").argv[1];s=open(p).read();old="  const text = validateTweetText(args.text);";assert old in s;q=chr(34);new="  const text = validateTweetText(args.text).replace(/\\p{Cf}/gu, "+q+q+");";open(p,"w").write(s.replace(old,new))'

echo "4/4 mutations killed"
