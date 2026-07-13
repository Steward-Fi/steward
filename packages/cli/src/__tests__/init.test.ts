import { describe, expect, test } from "bun:test";
import { createPublicKey, sign, verify } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// Prove the generated Ed25519 seed is compatible with the API's real parser,
// not a replica: importing the actual audit-checkpoint parsing logic.
import { parseSigningKey, publicKeyPem } from "../../../api/src/services/audit-checkpoint";
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

  test("default DATABASE_URL password matches generated POSTGRES_PASSWORD", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({ envPath });
      const env = readFileSync(envPath, "utf8");

      const postgresPassword = envValue(env, "POSTGRES_PASSWORD");
      const databaseUrl = envValue(env, "DATABASE_URL");
      expect(postgresPassword).toMatch(/^[0-9a-f]{48}$/);
      expect(databaseUrl).toBeDefined();
      const urlPassword = databaseUrl?.match(
        /^postgresql:\/\/steward:([^@]+)@postgres:5432\/steward$/,
      )?.[1];
      expect(urlPassword).toBeDefined();
      // The single generated password must be interpolated into BOTH values so
      // postgres and api/proxy/migrations agree on a fresh install (no
      // split-brain steward-change-me default).
      expect(urlPassword).toBe(postgresPassword);
      expect(env).not.toContain("steward-change-me");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("honors --database-url and --api-url overrides", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({
        envPath,
        databaseUrl: "postgresql://u:p@db.internal:5432/steward",
        apiUrl: "http://127.0.0.1:3200",
      });
      const env = readFileSync(envPath, "utf8");
      expect(env).toContain("DATABASE_URL=postgresql://u:p@db.internal:5432/steward");
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
        "STEWARD_MASTER_PASSWORD",
        "STEWARD_JWT_SECRET",
        "STEWARD_SESSION_SECRET",
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
        "STEWARD_SESSION_SECRET",
        "STEWARD_KDF_SALT",
        "STEWARD_AUDIT_HMAC_KEY",
        "STEWARD_AUDIT_SIGNING_KEY",
        "STEWARD_PROXY_REQUEST_SIGNING_SECRETS",
      ];
      for (const key of secretKeys) {
        const value = envValue(env, key) as string;
        expect(value).toBeTruthy();
        const occurrences = env.split(value).length - 1;
        // POSTGRES_PASSWORD legitimately appears twice (assignment + DATABASE_URL);
        // every other secret must appear exactly once.
        const expected = key === "POSTGRES_PASSWORD" ? 2 : 1;
        expect(occurrences).toBe(expected);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
