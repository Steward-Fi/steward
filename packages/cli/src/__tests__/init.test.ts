import { describe, expect, test } from "bun:test";
import { createPublicKey, sign, verify } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const CLI_ENTRY = join(dirname(dirname(fileURLToPath(import.meta.url))), "index.ts");

// Prove the generated Ed25519 seed is compatible with the API's real parser,
// not a replica: load the actual audit-checkpoint module at runtime. A dynamic
// non-literal specifier keeps tsc's rootDir happy (packages/api is outside
// packages/cli) while bun still resolves it for the test run.
const auditCheckpointModule = "../../../api/src/services/audit-checkpoint";
const { parseSigningKey, publicKeyPem } = (await import(auditCheckpointModule)) as {
  parseSigningKey: (raw: string) => import("node:crypto").KeyObject;
  publicKeyPem: (key: import("node:crypto").KeyObject) => string;
};

import { runInit } from "../init";

function mode(path: string): number {
  return statSync(path).mode & 0o777;
}

function envValue(source: string, key: string): string | undefined {
  for (const line of source.split(/\r?\n/)) {
    const idx = line.indexOf("=");
    if (idx <= 0) continue;
    if (line.slice(0, idx) === key) return line.slice(idx + 1).replace(/^'|'$/g, "");
  }
  return undefined;
}

describe("steward init", () => {
  test("writes supported audit signing key material", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      const result = runInit({ envPath });
      const env = readFileSync(envPath, "utf8");

      expect(result.auditSigningKeyFormat).toBe("hex-seed");
      expect(env).toContain("STEWARD_AUDIT_SIGNING_KEY=");
      expect(env).toMatch(/STEWARD_AUDIT_SIGNING_KEY=[0-9a-f]{64}/);
      expect(env).toContain("platform:tenant:create");
      expect(env).toContain("platform:trade:operator");
      // Auth placeholders emitted for symmetry so operators can fill them in.
      expect(env).toContain("STEWARD_TENANT_ID=");
      expect(env).toContain("STEWARD_TOKEN=");
      expect(env).toContain("STEWARD_TENANT_KEY=");
      expect(env).toContain("REDIS_URL=redis://redis:6379");
      expect(env).not.toContain("127.0.0.1:5432");
      expect(env).not.toContain("http://127.0.0.1:3200");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generates distinct admin, migration, runtime, and platform database authorities", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      const env = readFileSync(envPath, "utf8");

      const postgresPassword = envValue(env, "POSTGRES_PASSWORD");
      const appPassword = envValue(env, "STEWARD_DB_APP_PASSWORD");
      const migrationPassword = envValue(env, "STEWARD_DB_MIGRATION_PASSWORD");
      const platformPassword = envValue(env, "STEWARD_DB_PLATFORM_PASSWORD");
      const databaseUrl = envValue(env, "DATABASE_URL");
      expect(postgresPassword).toMatch(/^[0-9a-f]{48}$/);
      expect(appPassword).toMatch(/^[0-9a-f]{48}$/);
      expect(migrationPassword).toMatch(/^[0-9a-f]{48}$/);
      expect(platformPassword).toMatch(/^[0-9a-f]{48}$/);
      expect(
        new Set([postgresPassword, appPassword, migrationPassword, platformPassword]).size,
      ).toBe(4);
      expect(databaseUrl).toBe(`postgresql://steward_app:${appPassword}@postgres:5432/steward`);
      expect(envValue(env, "MIGRATION_DATABASE_URL")).toBe(
        `postgresql://steward_migrator:${migrationPassword}@postgres:5432/steward`,
      );
      expect(envValue(env, "STEWARD_ADMIN_DATABASE_URL")).toBe(
        `postgresql://steward:${postgresPassword}@postgres:5432/steward`,
      );
      expect(envValue(env, "STEWARD_PLATFORM_DATABASE_URL")).toBe(
        `postgresql://steward_platform:${platformPassword}@postgres:5432/steward`,
      );
      expect(envValue(env, "STEWARD_APP_DATABASE_ROLE")).toBe("steward_app");
      expect(envValue(env, "STEWARD_BOOTSTRAP_DATABASE_ROLE")).toBe("steward_bootstrap_owner");
      expect(envValue(env, "STEWARD_MIGRATION_DATABASE_ROLE")).toBe("steward_migrator");
      expect(envValue(env, "STEWARD_PLATFORM_DATABASE_ROLE")).toBe("steward_platform");
      expect(envValue(env, "STEWARD_BOOTSTRAP_SET_ROLE_PASSWORDS")).toBe("true");
      expect(env).not.toContain("steward-change-me");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("requires and preserves all external database authorities", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      expect(() =>
        runInit({
          envPath,
          databaseUrl: "postgresql://app:p@db.internal:5432/steward",
        }),
      ).toThrow(/admin-database-url.*migration-database-url.*platform-database-url/);
      runInit({
        envPath,
        databaseUrl: "postgresql://app:p@db.internal:5432/steward",
        adminDatabaseUrl: "postgresql://admin:p@db.internal:5432/steward",
        migrationDatabaseUrl: "postgresql://migrator:p@db.internal:5432/steward",
        platformDatabaseUrl: "postgresql://platform:p@db.internal:5432/steward",
        apiUrl: "http://127.0.0.1:3200",
      });
      const env = readFileSync(envPath, "utf8");
      expect(env).toContain("DATABASE_URL=postgresql://app:p@db.internal:5432/steward");
      expect(env).toContain(
        "STEWARD_ADMIN_DATABASE_URL=postgresql://admin:p@db.internal:5432/steward",
      );
      expect(env).toContain(
        "MIGRATION_DATABASE_URL=postgresql://migrator:p@db.internal:5432/steward",
      );
      expect(env).toContain(
        "STEWARD_PLATFORM_DATABASE_URL=postgresql://platform:p@db.internal:5432/steward",
      );
      expect(env).toContain("STEWARD_ALLOW_INSECURE_DB=\n");
      expect(env).toContain("STEWARD_DB_APP_PASSWORD=\n");
      expect(env).toContain("STEWARD_DB_MIGRATION_PASSWORD=\n");
      expect(env).toContain("STEWARD_DB_PLATFORM_PASSWORD=\n");
      expect(env).toContain("STEWARD_BOOTSTRAP_SET_ROLE_PASSWORDS=false");
      expect(env).toContain("STEWARD_API_URL=http://127.0.0.1:3200");
      // Explicit override wins; the generated POSTGRES_PASSWORD is left as its
      // own random value (operator supplies matching credentials in the URL).
      expect(env).not.toContain("steward-change-me");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("created file is mode 0600", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      expect(mode(envPath)).toBe(0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("no-force refuses and leaves an existing file byte-identical", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      const original = "EXISTING=please-do-not-touch\nSTEWARD_AUDIT_SIGNING_KEY=notreal\n";
      writeFileSync(envPath, original);
      const before = readFileSync(envPath);
      expect(() => runInit({ envPath })).toThrow(/already exists/);
      const after = readFileSync(envPath);
      expect(after.equals(before)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("--force over a 0644 file yields mode 0600 and replaced content", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      writeFileSync(envPath, "OLD_SECRET=world-readable-leak\n");
      chmodSync(envPath, 0o644);
      expect(mode(envPath)).toBe(0o644);

      runInit({ envPath, force: true });

      // Atomic temp-file + rename must leave the final file 0600, never 0644,
      // so forced secrets are never world-readable.
      expect(mode(envPath)).toBe(0o600);
      const env = readFileSync(envPath, "utf8");
      expect(env).not.toContain("OLD_SECRET");
      expect(env).toContain("STEWARD_AUDIT_SIGNING_KEY=");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("refuses to write through a symlink even with --force", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const target = join(dir, "real-target.env");
      writeFileSync(target, "TARGET=untouched\n");
      const link = join(dir, ".env");
      symlinkSync(target, link);

      expect(() => runInit({ envPath: link, force: true })).toThrow(/symlink/);
      // Target must be untouched (no secrets written through the link).
      expect(readFileSync(target, "utf8")).toBe("TARGET=untouched\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("two inits produce different secrets", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const a = join(dir, "a.env");
      const b = join(dir, "b.env");
      runInit({ envPath: a });
      runInit({ envPath: b });
      const ea = readFileSync(a, "utf8");
      const eb = readFileSync(b, "utf8");
      const keys = [
        "POSTGRES_PASSWORD",
        "STEWARD_DB_APP_PASSWORD",
        "STEWARD_DB_MIGRATION_PASSWORD",
        "STEWARD_MASTER_PASSWORD",
        "STEWARD_JWT_SECRET",
        "STEWARD_EXECUTION_AUTH_SECRET",
        "STEWARD_KDF_SALT",
        "STEWARD_AUDIT_HMAC_KEY",
        "STEWARD_AUDIT_SIGNING_KEY",
        "STEWARD_PLATFORM_KEY",
        "STEWARD_PROXY_REQUEST_SIGNING_SECRETS",
      ];
      for (const key of keys) {
        const va = envValue(ea, key);
        const vb = envValue(eb, key);
        expect(va).toBeTruthy();
        expect(vb).toBeTruthy();
        expect(va).not.toBe(vb);
      }

      expect(ea).not.toContain("STEWARD_SESSION_SECRET=");
      expect(eb).not.toContain("STEWARD_SESSION_SECRET=");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("generated Ed25519 seed parses + signs/verifies via the API parser", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      const seed = envValue(readFileSync(envPath, "utf8"), "STEWARD_AUDIT_SIGNING_KEY");
      expect(seed).toMatch(/^[0-9a-f]{64}$/);

      // Prove real compat with packages/api audit-checkpoint parse logic.
      const privateKey = parseSigningKey(seed as string);
      expect(privateKey.asymmetricKeyType).toBe("ed25519");
      const pubPem = publicKeyPem(privateKey);
      const msg = new TextEncoder().encode("steward-audit-checkpoint-test");
      const signature = sign(null, msg, privateKey);
      const ok = verify(null, msg, createPublicKey({ key: pubPem, format: "pem" }), signature);
      expect(ok).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("real `steward init` command leaks no generated secret to stdout or stderr", async () => {
    // Spawn the ACTUAL CLI entrypoint as a subprocess (not runInit internals)
    // so we prove real command behavior: whatever the command prints to the
    // operator's terminal must never contain a generated secret value. This
    // is the real leak surface (logs, CI output, screen-shares), which a
    // unit test of runInit's return value cannot cover.
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      const proc = Bun.spawn(["bun", "run", CLI_ENTRY, "init", "--env", envPath], {
        stdout: "pipe",
        stderr: "pipe",
      });
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
        proc.exited,
      ]);

      expect(exitCode).toBe(0);

      // The command must emit a safe receipt (the InitResult JSON): the env
      // path + status, and NOTHING secret. Assert the receipt is present so a
      // future silent/garbled command is caught too.
      expect(stdout).toContain('"envPath":');
      expect(stdout).toContain(envPath);
      expect(stdout).toContain('"auditSigningKeyFormat": "hex-seed"');

      // Read every generated secret from the file the command actually wrote,
      // then assert none of those complete values appear in either stream.
      const env = readFileSync(envPath, "utf8");
      const secretKeys = [
        "POSTGRES_PASSWORD",
        "STEWARD_DB_APP_PASSWORD",
        "STEWARD_DB_MIGRATION_PASSWORD",
        "STEWARD_MASTER_PASSWORD",
        "STEWARD_JWT_SECRET",
        "STEWARD_EXECUTION_AUTH_SECRET",
        "STEWARD_KDF_SALT",
        "STEWARD_AUDIT_HMAC_KEY",
        "STEWARD_AUDIT_SIGNING_KEY",
        "STEWARD_PLATFORM_KEY",
        "STEWARD_PROXY_REQUEST_SIGNING_SECRETS",
      ];
      const combined = stdout + stderr;
      expect(env).not.toContain("STEWARD_SESSION_SECRET=");
      for (const key of secretKeys) {
        const value = envValue(env, key);
        expect(value).toBeTruthy();
        // The full generated secret must never surface in operator-visible output.
        expect(combined).not.toContain(value as string);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15_000);

  test("--migrate never executes a CWD-relative decoy migrate.ts", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-migrate-"));
    const previousCwd = process.cwd();
    try {
      // Decoy at <cwd>/packages/db/src/migrate.ts: exits 0 and drops a marker.
      // `steward init --migrate` executes exactly this path.
      const decoyDir = join(dir, "packages", "db", "src");
      mkdirSync(decoyDir, { recursive: true });
      const marker = join(dir, "decoy-executed");
      writeFileSync(
        join(decoyDir, "migrate.ts"),
        `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "pwned");\n`,
      );
      process.chdir(dir);
      // The SHIPPED migrator runs instead: against a refused port it exits
      // non-zero, so runInit throws — and the decoy never ran.
      expect(() =>
        runInit({
          envPath: join(dir, ".env"),
          runMigrations: true,
          databaseUrl: "postgresql://app:p@127.0.0.1:1/steward",
          adminDatabaseUrl: "postgresql://admin:p@127.0.0.1:1/steward",
          migrationDatabaseUrl: "postgresql://migrator:p@127.0.0.1:1/steward",
          platformDatabaseUrl: "postgresql://platform:p@127.0.0.1:1/steward",
        }),
      ).toThrow(/migrations failed/i);
      expect(existsSync(marker)).toBe(false);
    } finally {
      process.chdir(previousCwd);
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15_000);

  test("--migrate does not default STEWARD_ALLOW_INSECURE_DB on for the child", async () => {
    // With NODE_ENV=production and a non-loopback DATABASE_URL lacking a
    // verifying sslmode, the shipped migrator must hit the db package's TLS
    // gate. The CLI must not force STEWARD_ALLOW_INSECURE_DB=true into the
    // child env, silently disabling that gate. The child must receive the value.
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-migrate-tls-"));
    try {
      const envPath = join(dir, ".env");
      const childEnv: Record<string, string | undefined> = {
        ...process.env,
        NODE_ENV: "production",
      };
      delete childEnv.STEWARD_ALLOW_INSECURE_DB;
      const proc = Bun.spawn(
        [
          "bun",
          "run",
          CLI_ENTRY,
          "init",
          "--env",
          envPath,
          "--migrate",
          "--database-url",
          "postgresql://app:p@192.0.2.1:5432/steward",
          "--admin-database-url",
          "postgresql://admin:p@192.0.2.1:5432/steward",
          "--migration-database-url",
          "postgresql://migrator:p@192.0.2.1:5432/steward",
          "--platform-database-url",
          "postgresql://platform:p@192.0.2.1:5432/steward",
        ],
        { env: childEnv, stdout: "pipe", stderr: "pipe" },
      );
      const [stderr, exitCode] = await Promise.all([new Response(proc.stderr).text(), proc.exited]);
      expect(exitCode).toBe(1);
      // SEC-087: the child reached the TLS gate rather than attempting a
      // network connection. The migrator exposes only this fixed diagnostic
      // code; raw exception text and the connection URL remain redacted.
      expect(stderr).toContain('errorCode: "DB_TLS_REQUIRED"');
      expect(stderr).not.toContain("192.0.2.1");
      expect(stderr).not.toContain("sslmode=verify-full");
      expect(stderr).not.toContain("STEWARD_ALLOW_INSECURE_DB=true —");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 15_000);

  test("generated env does not pre-acknowledge local plaintext key custody", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      const env = readFileSync(envPath, "utf8");
      // The production custody gate must require a deliberate operator ack:
      // the line ships commented out (guidance retained), never active.
      expect(envValue(env, "STEWARD_ACK_LOCAL_CUSTODY")).toBeUndefined();
      expect(env).toContain("# STEWARD_ACK_LOCAL_CUSTODY=true");
      expect(env).toContain("docs/security/custody-posture.md");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("emitted env contains no secret material outside its assigned values", () => {
    // Guard against accidentally echoing a generated secret into a comment or a
    // second variable. Every generated hex secret value must appear exactly once.
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      const env = readFileSync(envPath, "utf8");
      const secretKeys = [
        "POSTGRES_PASSWORD",
        "STEWARD_MASTER_PASSWORD",
        "STEWARD_JWT_SECRET",
        "STEWARD_EXECUTION_AUTH_SECRET",
        "STEWARD_KDF_SALT",
        "STEWARD_AUDIT_HMAC_KEY",
        "STEWARD_AUDIT_SIGNING_KEY",
        "STEWARD_PROXY_REQUEST_SIGNING_SECRETS",
      ];
      for (const key of secretKeys) {
        const value = envValue(env, key) as string;
        expect(value).toBeTruthy();
        const occurrences = env.split(value).length - 1;
        // Each database secret appears in its assignment and exactly one URL.
        const expected = key.startsWith("STEWARD_DB_") || key === "POSTGRES_PASSWORD" ? 2 : 1;
        expect(occurrences).toBe(expected);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
