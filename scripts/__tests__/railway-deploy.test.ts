/**
 * SEC-129 regression tests — railway-deploy.sh must fail closed by default
 * and redact secrets from dumped Railway logs.
 *
 * The fail-closed default is asserted as a source contract (the script is not
 * safely sourceable — it performs API calls at runtime). The redact_secrets
 * filter is extracted from the real script and exercised behaviorally.
 */
import { describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
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

function dryRun(imageDigest: string, imageTag?: string) {
  return spawnSync("bash", [SCRIPT, ...(imageTag ? [imageTag] : []), "--dry-run"], {
    encoding: "utf8",
    env: {
      ...process.env,
      RAILWAY_TOKEN: "test-token",
      RAILWAY_SERVICE_ID: "test-service",
      RAILWAY_ENV_ID: "test-environment",
      RAILWAY_IMAGE_DIGEST: imageDigest,
      RAILWAY_HEALTH_URL: "https://example.test",
      RAILWAY_REQUIRE_HEALTH: "true",
    },
  });
}

describe("SEC-129 railway-deploy.sh fails closed by default", () => {
  test("no-log control-plane rejection is a hard failure unless explicitly downgraded", () => {
    // LOGS_EMPTY=1 must fail even when RAILWAY_STRICT is not set, so CI cannot
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

describe("immutable Railway image selection", () => {
  test("passes a validated digest to Railway without converting it to a tag", () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const result = dryRun(digest);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`ghcr.io/steward-fi/steward@${digest}`);
    expect(result.stdout).not.toContain(`ghcr.io/steward-fi/steward:${digest}`);
  });

  test("rejects a malformed digest before a deployment mutation", () => {
    const result = dryRun("sha256:not-a-digest");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Invalid image digest");
    expect(result.stdout).not.toContain("Deploying");
  });

  test("rejects simultaneous tag and digest selectors", () => {
    const result = dryRun(`sha256:${"a".repeat(64)}`, "main");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Choose exactly one image selector");
    expect(result.stdout).not.toContain("Deploying");
  });

  test("production health enforcement fails before a deployment mutation", () => {
    const result = spawnSync("bash", [SCRIPT, "main", "--dry-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        RAILWAY_TOKEN: "test-token",
        RAILWAY_SERVICE_ID: "test-service",
        RAILWAY_ENV_ID: "test-environment",
        RAILWAY_HEALTH_URL: "",
        RAILWAY_REQUIRE_HEALTH: "true",
      },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("RAILWAY_HEALTH_URL is required");
    expect(result.stdout).not.toContain("Deploying");
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
