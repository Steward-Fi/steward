/**
 * SEC-050 regression test — migrate.sh must not expose the database password
 * in psql's argv (visible to every local user via ps / /proc/<pid>/cmdline).
 *
 * Runs the real scripts/migrate.sh with a fake `psql` shim first on PATH
 * that records its argv and environment; asserts the password travels via
 * PGPASSWORD and the connection string on argv carries no credentials.
 */
import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO_ROOT = join(import.meta.dir, "..", "..");
const CAPTURE = "capture.txt";

// The real migration script invokes the psql shim once per migration file.
// Loaded CI runners can exceed Bun's 5s default even though each shim exits
// immediately, so keep this behavioral suite deterministic.
setDefaultTimeout(15_000);

function runMigrate(databaseUrl: string): { argv: string; env: string } {
  const dir = mkdtempSync(join(tmpdir(), "migrate-sh-test-"));
  try {
    const shim = join(dir, "psql");
    writeFileSync(
      shim,
      `#!/bin/bash\necho "$@" > "${join(dir, CAPTURE)}"\necho "PGPASSWORD=$PGPASSWORD" >> "${join(dir, CAPTURE)}"\nexit 0\n`,
    );
    chmodSync(shim, 0o755);
    execFileSync("bash", [join(REPO_ROOT, "scripts", "migrate.sh")], {
      env: {
        ...process.env,
        PATH: `${dir}:${process.env.PATH}`,
        DATABASE_URL: databaseUrl,
      },
      stdio: "pipe",
    });
    const capture = readFileSync(join(dir, CAPTURE), "utf8");
    const [argvLine, envLine] = capture.trim().split("\n");
    return { argv: argvLine ?? "", env: envLine ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe.serial("SEC-050 scripts/migrate.sh keeps the DB password out of psql argv", () => {
  test("password in DATABASE_URL is passed via PGPASSWORD, never argv", () => {
    const { argv, env } = runMigrate("postgresql://steward:s3cret-pw@db.example:5432/steward");
    expect(argv).not.toContain("s3cret-pw");
    expect(argv).toContain("postgresql://steward@db.example:5432/steward");
    expect(env).toBe("PGPASSWORD=s3cret-pw");
  });

  test("percent-encoded password is decoded for PGPASSWORD", () => {
    const { argv, env } = runMigrate("postgresql://steward:p%40ss%2Fw0rd@db.example/steward");
    expect(argv).not.toContain("p%40ss%2Fw0rd");
    expect(env).toBe("PGPASSWORD=p@ss/w0rd");
  });

  test("passwordless URL still works with an empty PGPASSWORD", () => {
    const { argv, env } = runMigrate("postgresql://steward@db.example:5432/steward");
    expect(argv).toContain("postgresql://steward@db.example:5432/steward");
    expect(env).toBe("PGPASSWORD=");
  });

  test("libpq query-string password is removed from argv", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward@db.example:5432/steward?sslmode=require&password=query%40secret",
    );
    expect(argv).not.toContain("query%40secret");
    expect(argv).not.toContain("password=");
    expect(argv).toContain("sslmode=require");
    expect(env).toBe("PGPASSWORD=query@secret");
  });

  test("query password takes precedence and neither credential reaches argv", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:userinfo-secret@db.example/steward?password=query-secret",
    );
    expect(argv).not.toContain("userinfo-secret");
    expect(argv).not.toContain("query-secret");
    expect(env).toBe("PGPASSWORD=query-secret");
  });
});
