import { afterEach, describe, expect, test } from "bun:test";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../..");
const script = join(repoRoot, "scripts/staging-database-release.sh");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })));
});

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "steward-staging-release-"));
  temporaryDirectories.push(directory);
  const log = join(directory, "calls.log");
  const curlCount = join(directory, "curl-count");
  const sourceSha = "a".repeat(40);

  await writeFile(
    join(directory, "git"),
    `#!/bin/bash
if [[ "$1" == "rev-parse" ]]; then printf '%s\n' "${sourceSha}"; exit 0; fi
if [[ "$1" == "diff" ]]; then exit 0; fi
exit 9
`,
  );
  await writeFile(
    join(directory, "bun"),
    `#!/bin/bash
printf 'bun:%s\n' "$*" >> "$FAKE_CALL_LOG"
if [[ "\${FAKE_BUN_LEAK:-false}" == "true" ]]; then
  printf 'driver failed DATABASE_URL=%s\n' "\${DATABASE_URL:-}" >&2
fi
`,
  );
  await writeFile(
    join(directory, "psql"),
    `#!/bin/bash
case "\${PGDATABASE:-}" in
  *migrator*) kind=migration; role=steward_migrator ;;
  *operator*) kind=operator; role=steward_operator ;;
  *railway-app*) kind=app; role=steward_app ;;
  *) kind=unknown; role=unknown ;;
esac
printf 'psql:%s:%s\n' "$kind" "$*" >> "$FAKE_CALL_LOG"
if [[ "$*" == *"SELECT current_user"* ]]; then
  case "$kind" in
    app) override=FAKE_APP_ROLE ;;
    migration) override=FAKE_MIGRATION_ROLE ;;
    operator) override=FAKE_OPERATOR_ROLE ;;
    *) override=FAKE_UNKNOWN_ROLE ;;
  esac
  printf '%s\n' "\${!override:-$role}"
elif [[ "$*" == *"pg_control_system"* ]]; then
  if [[ "\${FAKE_FINGERPRINT_DENIED:-false}" == "true" ]]; then
    printf 'permission denied for function pg_control_system\n' >&2
    exit 1
  fi
  case "$kind" in
    app) override=FAKE_APP_FINGERPRINT ;;
    migration) override=FAKE_MIGRATION_FINGERPRINT ;;
    operator) override=FAKE_OPERATOR_FINGERPRINT ;;
    *) override=FAKE_UNKNOWN_FINGERPRINT ;;
  esac
  printf '%s\n' "\${!override:-cluster:steward:42}"
fi
`,
  );
  await writeFile(
    join(directory, "curl"),
    `#!/bin/bash
printf 'curl:%s\n' "$*" >> "$FAKE_CALL_LOG"
if [[ "$*" == *"variablesForServiceDeployment"* ]]; then
  count=$(($(cat "$FAKE_CURL_COUNT" 2>/dev/null || echo 0) + 1))
  printf '%s' "$count" > "$FAKE_CURL_COUNT"
  if [[ "\${FAKE_GRAPHQL_ERROR:-false}" == "true" ]]; then
    printf '%s\n' '{"errors":[{"message":"DATABASE_URL=postgres://app:graphql-secret@db/steward RAILWAY_TOKEN=railway-secret"}]}'
    exit 0
  fi
  deployment=deployment-old
  image=ghcr.io/steward-fi/steward:sha-old
  if [[ "\${FAKE_CHANGED_DEPLOYMENT:-false}" == "true" && "$count" -gt 1 ]]; then
    deployment=deployment-new
    image=ghcr.io/steward-fi/steward:sha-new
  fi
  printf '{"data":{"variablesForServiceDeployment":{"DATABASE_URL":"postgres://railway-app:app-secret@db/steward"},"serviceInstance":{"source":{"image":"%s"},"latestDeployment":{"id":"%s","status":"SUCCESS"}}}}\n' "$image" "$deployment"
elif [[ "$*" == *"/health"* || "$*" == *"/ready"* ]]; then
  if [[ "\${FAKE_READY_FAILURE:-false}" == "true" && "$*" == *"/ready"* ]]; then
    printf '503 1.1.1.1'
  else
    printf '200 1.1.1.1'
  fi
else
  printf '{}\n'
fi
`,
  );
  await writeFile(
    join(directory, "node"),
    `#!/bin/bash
if [[ "\${2:-}" == "--resolve-origin" ]]; then
  "$REAL_NODE" "$1" "$3"
  exit $?
fi
if [[ "\${2:-}" == "--ip" ]]; then exit 0; fi
exec "$REAL_NODE" "$@"
`,
  );
  await writeFile(join(directory, "sleep"), "#!/bin/bash\nexit 0\n");
  await Promise.all(
    ["git", "bun", "psql", "curl", "node", "sleep"].map((name) =>
      chmod(join(directory, name), 0o755),
    ),
  );

  return {
    log,
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      REAL_NODE: process.execPath,
      FAKE_CALL_LOG: log,
      FAKE_CURL_COUNT: curlCount,
      STEWARD_RELEASE_SOURCE_SHA: sourceSha,
      STEWARD_RELEASE_IMAGE_TAG: `sha-${sourceSha}`,
      STEWARD_MIGRATION_DATABASE_URL: "postgres://migrator:migration-secret@db/steward",
      STEWARD_OPERATOR_DATABASE_URL: "postgres://operator:operator-secret@db/steward",
      STEWARD_APP_DATABASE_ROLE: "steward_app",
      STEWARD_MIGRATION_DATABASE_ROLE: "steward_migrator",
      STEWARD_OPERATOR_DATABASE_ROLE: "steward_operator",
      STEWARD_BOOTSTRAP_DATABASE_ROLE: "steward_bootstrap_owner",
      STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
      STEWARD_PLUGINS: "trading,capabilities",
      RAILWAY_TOKEN: "railway-secret",
      RAILWAY_PROJECT_ID: "project-test",
      RAILWAY_SERVICE_ID: "service-test",
      RAILWAY_ENV_ID: "environment-test",
      RAILWAY_HEALTH_URL: "https://public.test",
      RAILWAY_DIRECT_HEALTH_URL: "https://direct.test",
      RAILWAY_COMPATIBILITY_TIMEOUT: "1",
      RAILWAY_COMPATIBILITY_INTERVAL: "1",
    },
  };
}

function run(env: Record<string, string | undefined>) {
  return Bun.spawnSync(["bash", script], { cwd: repoRoot, env });
}

describe("automatic staging database release", () => {
  test("uses Railway's rendered app database and proves old-image compatibility", async () => {
    const f = await fixture();
    const result = run(f.env);
    expect(result.exitCode).toBe(0);
    const calls = await Bun.file(f.log).text();
    expect(calls).toContain("variablesForServiceDeployment");
    expect(calls).toContain("psql:app:");
    expect(calls).toContain("packages/api migrate");
    expect(calls).toContain("rls-bootstrap.sql");
    expect(calls).toContain("rls-activate.sql");
    expect(calls).toContain("verify-database-release.ts");
    expect(calls).toContain("https://public.test/ready");
    expect(calls).toContain("https://direct.test/ready");
  });

  test("fails before mutation when a privileged credential targets another database", async () => {
    const f = await fixture();
    const result = run({ ...f.env, FAKE_OPERATOR_FINGERPRINT: "other:database:1:10.0.0.3:5432" });
    expect(result.exitCode).not.toBe(0);
    const calls = await Bun.file(f.log).text();
    expect(calls).not.toContain("packages/api migrate");
    expect(`${result.stdout}${result.stderr}`).toContain(
      "database credentials do not target the Railway service database",
    );
  });

  test("fails before mutation when Railway's rendered URL reaches the wrong role", async () => {
    const f = await fixture();
    const result = run({ ...f.env, FAKE_APP_ROLE: "steward_operator" });
    expect(result.exitCode).not.toBe(0);
    expect(await Bun.file(f.log).text()).not.toContain("packages/api migrate");
  });

  test("fails before mutation when a role cannot prove the stable cluster identity", async () => {
    const f = await fixture();
    const result = run({ ...f.env, FAKE_FINGERPRINT_DENIED: "true" });
    expect(result.exitCode).not.toBe(0);
    expect(await Bun.file(f.log).text()).not.toContain("packages/api migrate");
    expect(`${result.stdout}${result.stderr}`).toContain(
      "could not derive the Railway application database fingerprint",
    );
  });

  test("fails cutover when the old image is not ready on the released schema", async () => {
    const f = await fixture();
    const result = run({ ...f.env, FAKE_READY_FAILURE: "true" });
    expect(result.exitCode).not.toBe(0);
    const calls = await Bun.file(f.log).text();
    expect(calls).toContain("packages/api migrate");
    expect(`${result.stdout}${result.stderr}`).toContain(
      "existing-image public readiness failed after the schema release",
    );
  });

  test("fails when the Railway deployment changes during release", async () => {
    const f = await fixture();
    const result = run({ ...f.env, FAKE_CHANGED_DEPLOYMENT: "true" });
    expect(result.exitCode).not.toBe(0);
    expect(`${result.stdout}${result.stderr}`).toContain(
      "Railway deployment changed during the database release",
    );
  });

  test("redacts rendered-variable GraphQL errors and driver failures", async () => {
    const graphql = await fixture();
    const graphqlResult = run({ ...graphql.env, FAKE_GRAPHQL_ERROR: "true" });
    const graphqlOutput = `${graphqlResult.stdout}${graphqlResult.stderr}`;
    expect(graphqlResult.exitCode).not.toBe(0);
    expect(graphqlOutput).not.toContain("graphql-secret");
    expect(graphqlOutput).not.toContain("railway-secret");
    expect(graphqlOutput).toContain("REDACTED");

    const driver = await fixture();
    const driverResult = run({ ...driver.env, FAKE_BUN_LEAK: "true" });
    const driverOutput = `${driverResult.stdout}${driverResult.stderr}`;
    expect(driverResult.exitCode).toBe(0);
    expect(driverOutput).not.toContain("migration-secret");
    expect(driverOutput).not.toContain("app-secret");
    expect(driverOutput).toContain("REDACTED");
  });
});
