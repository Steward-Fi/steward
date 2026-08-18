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

  test("raw question mark in libpq userinfo never reaches argv", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:sec?ret@db.example/steward?sslmode=require",
    );
    expect(argv).toContain("postgresql://steward@db.example/steward?sslmode=require");
    expect(argv).not.toContain("sec?ret");
    expect(env).toBe("PGPASSWORD=sec?ret");
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

  test("preserves non-password libpq query encoding byte-for-byte", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward@db.example/steward?options=-c%20statement_timeout%3D5s&password=a+b",
    );
    expect(argv).toContain("options=-c%20statement_timeout%3D5s");
    expect(argv).not.toContain("password=");
    expect(env).toBe("PGPASSWORD=a+b");
  });

  test("preserves an at sign in a non-password query value", () => {
    const { argv, env } = runMigrate(
      "postgresql://db.example/steward?application_name=ops@steward&password=query-secret",
    );
    expect(argv).toContain("application_name=ops@steward");
    expect(argv).not.toContain("query-secret");
    expect(env).toBe("PGPASSWORD=query-secret");
  });

  test("preserves valid libpq multi-host authorities", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:multi%40secret@db-a.example:5432,db-b.example:5433/steward?target_session_attrs=read-write",
    );
    expect(argv).toContain(
      "postgresql://steward@db-a.example:5432,db-b.example:5433/steward?target_session_attrs=read-write",
    );
    expect(env).toBe("PGPASSWORD=multi@secret");
  });

  test("preserves valid libpq percent-encoded Unix-socket hosts", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:socket-secret@%2Fvar%2Frun%2Fpostgresql/steward",
    );
    expect(argv).toContain("postgresql://steward@%2Fvar%2Frun%2Fpostgresql/steward");
    expect(env).toBe("PGPASSWORD=socket-secret");
  });

  test("query password takes precedence and neither credential reaches argv", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:userinfo-secret@db.example/steward?password=query-secret",
    );
    expect(argv).not.toContain("userinfo-secret");
    expect(argv).not.toContain("query-secret");
    expect(env).toBe("PGPASSWORD=query-secret");
  });

  test("uses the last non-empty duplicate query password like libpq", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:userinfo-secret@db.example/steward?password=first-secret&password=&password=last-secret&password=",
    );
    expect(argv).not.toContain("userinfo-secret");
    expect(argv).not.toContain("first-secret");
    expect(argv).not.toContain("last-secret");
    expect(argv).not.toContain("password=");
    expect(env).toBe("PGPASSWORD=last-secret");
  });

  test("empty query passwords retain a non-empty userinfo password", () => {
    const { argv, env } = runMigrate(
      "postgresql://steward:userinfo-secret@db.example/steward?password=&sslmode=require&password=",
    );
    expect(argv).not.toContain("userinfo-secret");
    expect(argv).not.toContain("password=");
    expect(argv).toContain("sslmode=require");
    expect(env).toBe("PGPASSWORD=userinfo-secret");
  });
});
