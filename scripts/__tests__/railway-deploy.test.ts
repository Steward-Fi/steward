/**
 * SEC-129 regression tests — railway-deploy.sh must fail closed by default
 * and redact secrets from dumped Railway logs.
 *
 * The fail-closed default is asserted as a source contract (the script is not
 * safely sourceable — it performs API calls at runtime). The redact_secrets
 * filter is extracted from the real script and exercised behaviorally.
 */
import { describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const SCRIPT = join(import.meta.dir, "..", "railway-deploy.sh");
const source = readFileSync(SCRIPT, "utf8");

function redact(input: string): string {
  return execFileSync(
    "bash",
    ["-c", `eval "$(sed -n '/^redact_secrets()/,/^}/p' "$1")"; redact_secrets`, "bash", SCRIPT],
    { input, encoding: "utf8" },
  );
}

describe("SEC-129 railway-deploy.sh fails closed by default", () => {
  test("no-log control-plane rejection is a hard failure unless explicitly downgraded", () => {
    // Pre-fix: LOGS_EMPTY=1 exited 0 unless RAILWAY_STRICT=true — CI went
    // green on a deploy that never happened.
    expect(source).not.toContain("RAILWAY_STRICT");
    expect(source).toContain("RAILWAY_ALLOW_REJECTED_DEPLOY:-false");
    // finish_failure must exit 1 on the default path.
    const finish = source.match(/finish_failure\(\) \{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(finish).toContain("exit 0");
    expect(finish.trim().endsWith("exit 1")).toBe(true);
  });

  test("dumped logs are piped through redact_secrets", () => {
    expect(source).toMatch(/echo "\$build_logs" \| redact_secrets/);
    expect(source).toMatch(/echo "\$deploy_logs" \| redact_secrets/);
  });
});

describe("SEC-129 redact_secrets filter", () => {
  test("redacts postgres DSN passwords, bearer tokens, KEY= assignments, stw_ keys, long hex", () => {
    const out = redact(
      [
        "connecting to postgresql://steward:hunter2@db.internal:5432/steward",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "STEWARD_JWT_SECRET=abc123def456",
        "tenant key stw_9f8e7d6c5b4a issued",
        "master 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef done",
        "ordinary log line stays",
      ].join("\n"),
    );
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9.payload.sig");
    expect(out).not.toContain("abc123def456");
    expect(out).not.toContain("9f8e7d6c5b4a");
    expect(out).not.toContain("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    expect(out).toContain("postgresql://steward:");
    expect(out).toContain("ordinary log line stays");
  });
});
