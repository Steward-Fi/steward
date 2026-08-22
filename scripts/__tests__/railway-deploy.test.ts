/**
 * SEC-129 regression tests — railway-deploy.sh must fail closed by default,
 * redact secrets from dumped Railway logs, and wait for a delayed healthy
 * container without accepting an unreachable deployment.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { isPublicIp, resolvePublicHttpsOrigin } from "../validate-public-origin.mjs";

const repoRoot = resolve(import.meta.dir, "../..");
const SCRIPT = join(repoRoot, "scripts/railway-deploy.sh");
const source = readFileSync(SCRIPT, "utf8");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((dir) => rm(dir, { recursive: true })));
});

function redact(input: string): string {
  return execFileSync(
    "bash",
    ["-c", `eval "$(sed -n '/^redact_secrets()/,/^}/p' "$1")"; redact_secrets`, "bash", SCRIPT],
    { input, encoding: "utf8" },
  );
}

async function fakeRailwayRun(
  healthyAfter: number,
  healthTimeout = 4,
  readyAfter = 1,
  healthUrl: string | null = "https://example.test",
  remoteIp = "1.1.1.1",
  dnsAnswers = "1.1.1.1",
) {
  const dir = await mkdtemp(join(tmpdir(), "steward-railway-deploy-"));
  temporaryDirectories.push(dir);
  const stateFile = join(dir, "health-attempts");
  const readyStateFile = join(dir, "ready-attempts");
  const curlLog = join(dir, "curl-arguments");
  const fakeCurl = join(dir, "curl");
  const fakeNode = join(dir, "node");
  const fakeSleep = join(dir, "sleep");

  await writeFile(
    fakeCurl,
    `#!/bin/sh
args="$*"
printf '%s\n' "$args" >> "$FAKE_CURL_LOG"
case "$args" in
  *example.test/health*)
    count=0
    [ ! -f "$FAKE_HEALTH_STATE" ] || count=$(cat "$FAKE_HEALTH_STATE")
    count=$((count + 1))
    echo "$count" > "$FAKE_HEALTH_STATE"
    if [ "$count" -ge "$FAKE_HEALTHY_AFTER" ]; then printf '200 %s' "$FAKE_REMOTE_IP"; else printf '000 '; fi
    ;;
  *example.test/ready*)
    count=0
    [ ! -f "$FAKE_READY_STATE" ] || count=$(cat "$FAKE_READY_STATE")
    count=$((count + 1))
    echo "$count" > "$FAKE_READY_STATE"
    if [ "$count" -ge "$FAKE_READY_AFTER" ]; then printf '200 %s' "$FAKE_REMOTE_IP"; else printf '503 %s' "$FAKE_REMOTE_IP"; fi
    ;;
  *serviceInstanceUpdate*) printf '%s\n' '{"data":{"serviceInstanceUpdate":true}}' ;;
  *serviceInstanceDeployV2*) printf '%s\n' '{"data":{"serviceInstanceDeployV2":"deployment-test"}}' ;;
  *'deployments(input:'*) printf '%s\n' '{"data":{"deployments":{"edges":[{"node":{"id":"deployment-test","status":"SUCCESS","createdAt":"2026-01-01T00:00:00Z"}}]}}}' ;;
  *'deployment(id:'*) printf '%s\n' '{"data":{"deployment":{"id":"deployment-test","status":"SUCCESS"}}}' ;;
  *buildLogs*) printf '%s\n' '{"data":{"buildLogs":[{"message":"build diagnostic"}]}}' ;;
  *deploymentLogs*) printf '%s\n' '{"data":{"deploymentLogs":[{"message":"runtime diagnostic {\\"STEWARD_JWT_SECRET\\":\\"abc123def456\\",\\"CACHE_URL\\":\\"rediss://default:redis-json-secret@cache.internal:6380/0\\"} STEWARD_MASTER_PASSWORD: hunter2 RAILWAY_TOKEN = token123 STEWARD_API_KEY=\\u0027single secret value\\u0027 BROKER_URI=amqps://worker:broker-secret@mq.internal/vhost WEBHOOK_URL=https://hooks.example.test/webhook-path-secret callback=https://example.test/callback?code=oauth-code-secret&state=public-state"}]}}' ;;
  *) printf '%s\n' '{}' ;;
esac
`,
  );
  await writeFile(
    fakeNode,
    `#!/bin/sh
if [ "\${2:-}" = "--resolve-origin" ]; then
  origin=$($REAL_NODE "$1" "$3") || exit 1
  old_ifs=$IFS
  IFS=,
  for address in $FAKE_DNS_ANSWERS; do
    "$REAL_NODE" "$1" --ip "$address" >/dev/null 2>&1 || exit 1
  done
  IFS=$old_ifs
  printf %s "$origin"
  exit 0
fi
exec "$REAL_NODE" "$@"
`,
  );
  await writeFile(fakeSleep, '#!/bin/sh\n[ "$1" = "10" ] && exit 0\nexec /bin/sleep "$@"\n');
  await Promise.all([chmod(fakeCurl, 0o755), chmod(fakeNode, 0o755), chmod(fakeSleep, 0o755)]);

  const child = Bun.spawn(["bash", SCRIPT, "sha-test"], {
    cwd: repoRoot,
    env: {
      ...Bun.env,
      PATH: `${dir}:${Bun.env.PATH ?? ""}`,
      FAKE_HEALTH_STATE: stateFile,
      FAKE_READY_STATE: readyStateFile,
      FAKE_CURL_LOG: curlLog,
      FAKE_HEALTHY_AFTER: String(healthyAfter),
      FAKE_READY_AFTER: String(readyAfter),
      FAKE_REMOTE_IP: remoteIp,
      FAKE_DNS_ANSWERS: dnsAnswers,
      REAL_NODE: process.execPath,
      RAILWAY_TOKEN: "test-token",
      RAILWAY_SERVICE_ID: "test-service",
      RAILWAY_ENV_ID: "test-environment",
      RAILWAY_HEALTH_URL: healthUrl ?? "",
      RAILWAY_HEALTH_TIMEOUT: String(healthTimeout),
      RAILWAY_HEALTH_INTERVAL: "1",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  const curlArguments = (await Bun.file(curlLog).exists()) ? await Bun.file(curlLog).text() : "";
  return { exitCode, output: stdout + stderr, curlArguments };
}

describe("SEC-129 railway-deploy.sh fails closed by default", () => {
  test("no-log control-plane rejection is a hard failure unless explicitly downgraded", () => {
    expect(source).not.toContain("RAILWAY_STRICT");
    expect(source).toContain("RAILWAY_ALLOW_REJECTED_DEPLOY:-false");
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
  test("redacts credential-bearing URIs, sensitive query parameters, structured assignments, stw_ keys, and long hex", () => {
    const out = redact(
      [
        "connecting to postgresql://steward:hunter2@db.internal:5432/steward",
        "redis cache redis://default:redis-password@cache.internal:6379/0",
        "rediss cache rediss://:encoded%40password@cache.internal:6380/0",
        "broker amqps://worker:broker-password@mq.internal/vhost",
        "callback https://agent:http-password@example.test/callback",
        "token-user https://opaque-access-token@example.test/private",
        "signed https://objects.example.test/item?X-Amz-Credential=aws-credential&X-Amz-Signature=aws-signature&safe=visible",
        "oauth https://example.test/callback?code=oauth-code&state=visible-state&access_token=oauth-token",
        'CACHE_URL="redis://default:quoted-url-secret@cache.internal:6379/0"',
        "BROKER_URI='amqps://worker:single-url-secret@mq.internal/vhost'",
        '{"DATABASE_DSN":"postgresql://steward:json-url-secret@db.internal/steward"}',
        "UPSTREAM_URL: https://user:yaml-url-secret@example.test/path",
        "WEBHOOK_URL=https://hooks.example.test/unguessable-path-secret",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "STEWARD_JWT_SECRET=abc123def456",
        '{"STEWARD_JWT_SECRET":"json-secret-value"}',
        "STEWARD_MASTER_PASSWORD: yaml-secret-value",
        "RAILWAY_TOKEN = spaced-secret-value",
        "STEWARD_API_KEY='single quoted secret value'",
        "tenant key stw_9f8e7d6c5b4a issued",
        "master 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef done",
        "ordinary log line stays",
      ].join("\n"),
    );
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("redis-password");
    expect(out).not.toContain("encoded%40password");
    expect(out).not.toContain("broker-password");
    expect(out).not.toContain("http-password");
    expect(out).not.toContain("opaque-access-token");
    expect(out).not.toContain("aws-credential");
    expect(out).not.toContain("aws-signature");
    expect(out).not.toContain("oauth-code");
    expect(out).not.toContain("oauth-token");
    expect(out).not.toContain("quoted-url-secret");
    expect(out).not.toContain("single-url-secret");
    expect(out).not.toContain("json-url-secret");
    expect(out).not.toContain("yaml-url-secret");
    expect(out).not.toContain("unguessable-path-secret");
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9.payload.sig");
    expect(out).not.toContain("abc123def456");
    expect(out).not.toContain("json-secret-value");
    expect(out).not.toContain("yaml-secret-value");
    expect(out).not.toContain("spaced-secret-value");
    expect(out).not.toContain("single quoted secret value");
    expect(out).not.toContain("9f8e7d6c5b4a");
    expect(out).not.toContain("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    expect(out).toContain("postgresql://steward:");
    expect(out).toContain("safe=visible");
    expect(out).toContain("state=visible-state");
    expect(out).toContain("ordinary log line stays");
  });
});

describe("Railway staging deployment", () => {
  test("rejects deployment acceptance when no public probe authority is configured", async () => {
    const result = await fakeRailwayRun(1, 2, 1, null);
    expect(result.exitCode).toBe(1);
    expect(result.output).toContain("RAILWAY_HEALTH_URL is required for deployment acceptance");
    expect(result.curlArguments).not.toContain("serviceInstanceUpdate");
  }, 15_000);

  for (const invalidOrigin of [
    "http://example.test",
    "https://user:secret@example.test",
    "https://example.test/private",
    "https://example.test?token=secret",
    "https://localhost",
    "https://127.0.0.1",
    "https://10.0.0.1",
    "https://169.254.1.1",
    "https://192.88.99.1",
    "https://[::1]",
    "https://[fc00::1]",
    "https://[2001:2::1]",
    "https://[2001:10::1]",
    "https://[3fff::1]",
  ]) {
    test(`rejects ${invalidOrigin.split(":")[0]} invalid probe authority before mutation`, async () => {
      const result = await fakeRailwayRun(1, 2, 1, invalidOrigin);
      expect(result.exitCode).toBe(1);
      expect(result.curlArguments).not.toContain("serviceInstanceUpdate");
      expect(result.curlArguments).not.toContain("serviceInstanceDeployV2");
      expect(result.output).not.toContain("secret");
    });
  }

  test("rejects any private DNS answer before the first deployment mutation", async () => {
    const result = await fakeRailwayRun(
      1,
      2,
      1,
      "https://example.test",
      "1.1.1.1",
      "1.1.1.1,10.0.0.8",
    );
    expect(result.exitCode).toBe(1);
    expect(result.curlArguments).not.toContain("serviceInstanceUpdate");
    expect(result.curlArguments).not.toContain("serviceInstanceDeployV2");
  });

  test("waits through delayed health before accepting the deployment", async () => {
    const result = await fakeRailwayRun(3);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("Health check attempt 2: HTTP 000");
    expect(result.output).toContain("Health check passed");
    expect(result.output).toContain("Readiness check passed");
    for (const call of result.curlArguments
      .split("\n")
      .filter((line) => line.includes("graphql"))) {
      expect(call).toContain("--connect-timeout 5");
      expect(call).toContain("--max-time 20");
    }
  }, 15_000);

  test("rejects a public-looking authority whose successful probe resolves privately", async () => {
    const result = await fakeRailwayRun(1, 2, 1, "https://example.test", "10.0.0.8");
    expect(result.exitCode).toBe(1);
    expect(result.output).toContain("Health check failed");
  }, 15_000);

  test("rejects a live deployment whose durable readiness never passes", async () => {
    const result = await fakeRailwayRun(1, 2, 999);
    expect(result.exitCode).toBe(1);
    expect(result.output).toMatch(/Readiness check failed after [1-9][0-9]* attempts? \/ 2s/);
    expect(result.output).toContain("Railway deployment diagnostics");
  }, 15_000);

  test("prints Railway diagnostics when health never becomes ready", async () => {
    const result = await fakeRailwayRun(999, 2);
    expect(result.exitCode).toBe(1);
    expect(result.output).toMatch(/Health check failed after [1-9][0-9]* attempts? \/ 2s/);
    expect(result.output).toContain("Railway deployment diagnostics");
    expect(result.output).toContain("runtime diagnostic");
    expect(result.output).not.toContain("abc123def456");
    expect(result.output).not.toContain("hunter2");
    expect(result.output).not.toContain("token123");
    expect(result.output).not.toContain("single secret value");
    expect(result.output).not.toContain("redis-json-secret");
    expect(result.output).not.toContain("broker-secret");
    expect(result.output).not.toContain("webhook-path-secret");
    expect(result.output).not.toContain("oauth-code-secret");
    expect(result.output).toContain("state=public-state");
    expect(result.output).toContain("…REDACTED…");
    expect(result.output).not.toContain('Response: {"data"');
    for (const call of result.curlArguments
      .split("\n")
      .filter((line) => line.includes("graphql"))) {
      expect(call).toContain("--connect-timeout 5");
      expect(call).toContain("--max-time 20");
    }
  }, 15_000);
});

describe("public deployment authority classification", () => {
  test("conservatively rejects special-purpose IPv4 and IPv6 registries", () => {
    for (const address of [
      "192.88.99.1",
      "2001:2::1",
      "2001:10::1",
      "2001:db8::1",
      "3fff::1",
      "fc00::1",
    ]) {
      expect(isPublicIp(address)).toBe(false);
    }
    for (const address of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]) {
      expect(isPublicIp(address)).toBe(true);
    }
  });

  test("rejects a hostname when any resolved address is non-public", async () => {
    await expect(
      resolvePublicHttpsOrigin("https://health.example", async () => [
        { address: "1.1.1.1", family: 4 },
        { address: "2001:10::1", family: 6 },
      ]),
    ).rejects.toThrow("non-public");
    await expect(
      resolvePublicHttpsOrigin("https://health.example", async () => [
        { address: "1.1.1.1", family: 4 },
        { address: "2606:4700:4700::1111", family: 6 },
      ]),
    ).resolves.toBe("https://health.example");
  });
});
