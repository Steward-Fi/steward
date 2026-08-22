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

async function fixture(options: { failPsqlCall?: number; leakSecrets?: boolean } = {}) {
  const directory = await mkdtemp(join(tmpdir(), "steward-staging-release-"));
  temporaryDirectories.push(directory);
  const log = join(directory, "calls.log");
  const count = join(directory, "psql-count");
  const bun = join(directory, "bun");
  const psql = join(directory, "psql");

  await writeFile(
    bun,
    `#!/bin/bash\nprintf 'bun:%s\\n' "$*" >> "${log}"\n${options.leakSecrets ? 'printf "driver failed DATABASE_URL=%s\\n" "$DATABASE_URL" >&2\n' : ""}`,
  );
  await writeFile(
    psql,
    `#!/bin/bash
count=$(($(cat "${count}" 2>/dev/null || echo 0) + 1))
echo "$count" > "${count}"
printf 'psql:%s\n' "$*" >> "${log}"
${
  options.failPsqlCall
    ? `if [[ "$count" -eq ${options.failPsqlCall} ]]; then\n${options.leakSecrets ? '  printf "postgres connection failed: %s\\n" "$PGDATABASE" >&2\n' : ""}  exit 7\nfi`
    : "true"
}
if [[ "$*" == *"SELECT current_user"* ]]; then
  case "$PGDATABASE" in
    *migrator*) printf '%s\n' "\${FAKE_MIGRATION_ROLE:-steward_migrator}" ;;
    *operator*) printf '%s\n' "\${FAKE_OPERATOR_ROLE:-steward_operator}" ;;
    *app*) printf '%s\n' "\${FAKE_APP_ROLE:-steward_app}" ;;
    *) exit 8 ;;
  esac
fi
`,
  );
  await Promise.all([chmod(bun, 0o755), chmod(psql, 0o755)]);
  const sourceSha = (await Bun.$`git rev-parse HEAD`.cwd(repoRoot).text()).trim();
  return {
    log,
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH}`,
      STEWARD_RELEASE_SOURCE_SHA: sourceSha,
      STEWARD_RELEASE_IMAGE_TAG: `sha-${sourceSha}`,
      STEWARD_MIGRATION_DATABASE_URL: "postgres://migrator:one@db/steward",
      STEWARD_OPERATOR_DATABASE_URL: "postgres://operator:two@db/steward",
      STEWARD_APP_DATABASE_URL: "postgres://app:three@db/steward",
      STEWARD_APP_DATABASE_ROLE: "steward_app",
      STEWARD_MIGRATION_DATABASE_ROLE: "steward_migrator",
      STEWARD_OPERATOR_DATABASE_ROLE: "steward_operator",
      STEWARD_BOOTSTRAP_DATABASE_ROLE: "steward_bootstrap_owner",
      STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
      STEWARD_PLUGINS: "trading,capabilities",
    },
  };
}

describe("automatic staging database release", () => {
  test("runs migrate, bootstrap, activation, then restricted-role verification", async () => {
    const testFixture = await fixture();
    const result = Bun.spawnSync(["bash", script], { cwd: repoRoot, env: testFixture.env });
    expect(result.exitCode).toBe(0);
    const calls = await Bun.file(testFixture.log).text();
    expect(
      calls
        .split("\n")
        .filter(Boolean)
        .map((line) => line.split(":", 1)[0]),
    ).toEqual(["psql", "psql", "psql", "bun", "psql", "psql", "bun"]);
    expect(calls).toContain("packages/api migrate");
    expect(calls).toContain("rls-bootstrap.sql");
    expect(calls).toContain("rls-activate.sql");
    expect(calls).toContain("verify-database-release.ts");
  });

  test("fails closed before activation and verification when bootstrap fails", async () => {
    const testFixture = await fixture({ failPsqlCall: 4 });
    const result = Bun.spawnSync(["bash", script], { cwd: repoRoot, env: testFixture.env });
    expect(result.exitCode).toBe(7);
    const calls = await Bun.file(testFixture.log).text();
    expect(calls).toContain("rls-bootstrap.sql");
    expect(calls).not.toContain("rls-activate.sql");
    expect(calls).not.toContain("verify-database-release.ts");
  });

  test("fails closed before mutation when a URL reaches the wrong role", async () => {
    const testFixture = await fixture();
    const result = Bun.spawnSync(["bash", script], {
      cwd: repoRoot,
      env: { ...testFixture.env, FAKE_MIGRATION_ROLE: "steward_operator" },
    });
    expect(result.exitCode).not.toBe(0);
    const calls = await Bun.file(testFixture.log).text();
    expect(calls).toContain("SELECT current_user");
    expect(calls).not.toContain("packages/api migrate");
    expect(calls).not.toContain("rls-bootstrap.sql");
  });

  test("redacts database credentials from failed release diagnostics", async () => {
    const testFixture = await fixture({ failPsqlCall: 4, leakSecrets: true });
    const result = Bun.spawnSync(["bash", script], { cwd: repoRoot, env: testFixture.env });
    expect(result.exitCode).toBe(7);
    const output = `${result.stdout.toString()}${result.stderr.toString()}`;
    expect(output).not.toContain(testFixture.env.STEWARD_MIGRATION_DATABASE_URL);
    expect(output).not.toContain(testFixture.env.STEWARD_OPERATOR_DATABASE_URL);
    expect(output).not.toContain(testFixture.env.STEWARD_APP_DATABASE_URL);
    expect(output).not.toContain(":one@");
    expect(output).not.toContain(":two@");
    expect(output).not.toContain(":three@");
    expect(output).toContain("REDACTED");
  });

  test("rejects unbound tags and shared database identities before any command", async () => {
    const testFixture = await fixture();
    for (const env of [
      { ...testFixture.env, STEWARD_RELEASE_IMAGE_TAG: "develop" },
      {
        ...testFixture.env,
        STEWARD_OPERATOR_DATABASE_URL: testFixture.env.STEWARD_MIGRATION_DATABASE_URL,
      },
    ]) {
      const result = Bun.spawnSync(["bash", script], { cwd: repoRoot, env });
      expect(result.exitCode).not.toBe(0);
    }
    expect(await Bun.file(testFixture.log).exists()).toBe(false);
  });
});
