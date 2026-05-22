#!/usr/bin/env bun
/**
 * SOC2 technical compliance smoke check.
 *
 * Runs a set of read-only checks against the current deployment's
 * configuration and runtime state. Exits 0 if every check passes, 1 if any
 * required check fails. Designed for cron / pre-deploy gates.
 *
 *   bun run scripts/soc2-check.ts
 *   bun run scripts/soc2-check.ts --json     # machine-readable
 *   bun run scripts/soc2-check.ts --strict   # also fail on warnings
 *
 * Checks are mapped to SOC2 Trust Services Criteria. Each result includes:
 *   - status: pass | fail | warn | skip
 *   - control: e.g. "CC6.1", "CC7.2"
 *   - reason: human-readable explanation
 *
 * This script does NOT mutate state. Safe to run in production.
 */

import { execSync } from "node:child_process";

type Status = "pass" | "fail" | "warn" | "skip";

interface Check {
  id: string;
  control: string;
  status: Status;
  reason: string;
}

const checks: Check[] = [];

function record(id: string, control: string, status: Status, reason: string) {
  checks.push({ id, control, status, reason });
}

function isProd(): boolean {
  return process.env.NODE_ENV === "production";
}

// ─── CC6.1 / CC6.7 — confidentiality + transport ─────────────────────────────

function checkMasterPassword() {
  const v = process.env.STEWARD_MASTER_PASSWORD;
  if (!v) {
    return record("master_password_set", "CC6.1", "fail", "STEWARD_MASTER_PASSWORD not set");
  }
  if (v.length < 32) {
    return record(
      "master_password_strength",
      "CC6.1",
      isProd() ? "fail" : "warn",
      `STEWARD_MASTER_PASSWORD is ${v.length} chars — require ≥32 of random entropy`,
    );
  }
  record("master_password_set", "CC6.1", "pass", "STEWARD_MASTER_PASSWORD set with ≥32 chars");
}

function checkJwtSecret() {
  const v = process.env.STEWARD_JWT_SECRET ?? process.env.STEWARD_SESSION_SECRET;
  if (!v) {
    return record(
      "jwt_secret_set",
      "CC6.1",
      isProd() ? "fail" : "warn",
      "STEWARD_JWT_SECRET not set",
    );
  }
  if (v.length < 32) {
    return record(
      "jwt_secret_strength",
      "CC6.1",
      isProd() ? "fail" : "warn",
      `STEWARD_JWT_SECRET is ${v.length} chars — require ≥32`,
    );
  }
  if (process.env.STEWARD_SESSION_SECRET && !process.env.STEWARD_JWT_SECRET) {
    return record(
      "jwt_secret_canonical_name",
      "CC8.1",
      "warn",
      "Using deprecated STEWARD_SESSION_SECRET; rename to STEWARD_JWT_SECRET",
    );
  }
  record("jwt_secret_set", "CC6.1", "pass", "JWT secret set with ≥32 chars");
}

function checkKdfSalt() {
  const v = process.env.STEWARD_KDF_SALT;
  if (!v) {
    return record(
      "kdf_salt_set",
      "CC6.1",
      isProd() ? "fail" : "warn",
      "STEWARD_KDF_SALT not set — default 'steward-vault-v1' is public",
    );
  }
  if (!/^[0-9a-fA-F]{32,}$/.test(v)) {
    return record(
      "kdf_salt_strength",
      "CC6.1",
      "warn",
      "STEWARD_KDF_SALT should be ≥32 hex chars of random entropy",
    );
  }
  record("kdf_salt_set", "CC6.1", "pass", "STEWARD_KDF_SALT set with sufficient entropy");
}

function checkAuditHmacKey() {
  const v = process.env.STEWARD_AUDIT_HMAC_KEY;
  if (!v) {
    return record(
      "audit_hmac_key_set",
      "CC7.2",
      isProd() ? "fail" : "warn",
      "STEWARD_AUDIT_HMAC_KEY not set — audit chain falls back to dev key",
    );
  }
  if (v.length < 32) {
    return record(
      "audit_hmac_key_strength",
      "CC7.2",
      "warn",
      `STEWARD_AUDIT_HMAC_KEY is ${v.length} chars — require ≥32 hex`,
    );
  }
  // Trust-boundary check: the audit HMAC key MUST differ from JWT secret and
  // master password, else DB-write attackers may also hold the audit key.
  if (v === process.env.STEWARD_JWT_SECRET || v === process.env.STEWARD_MASTER_PASSWORD) {
    return record(
      "audit_hmac_key_isolation",
      "CC7.2",
      "fail",
      "STEWARD_AUDIT_HMAC_KEY must be distinct from JWT/master secrets (trust-boundary violation)",
    );
  }
  record(
    "audit_hmac_key_set",
    "CC7.2",
    "pass",
    "Audit HMAC key set and isolated from other secrets",
  );
}

function checkDatabaseTls() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    return record("database_tls", "CC6.7", "skip", "DATABASE_URL not set (embedded/PGLite mode?)");
  }
  if (/^postgres(ql)?:\/\/[^@]*@(localhost|127\.0\.0\.1|::1)/.test(url)) {
    return record(
      "database_tls",
      "CC6.7",
      "pass",
      "DATABASE_URL points at localhost — TLS not required",
    );
  }
  if (/sslmode=(require|verify-ca|verify-full)/.test(url)) {
    return record("database_tls", "CC6.7", "pass", "DATABASE_URL enforces TLS via sslmode");
  }
  if (process.env.STEWARD_ALLOW_INSECURE_DB === "true") {
    return record(
      "database_tls",
      "CC6.7",
      "warn",
      "STEWARD_ALLOW_INSECURE_DB=true — TLS bypass explicitly enabled",
    );
  }
  record(
    "database_tls",
    "CC6.7",
    isProd() ? "fail" : "warn",
    "DATABASE_URL does not include sslmode=require — DB traffic may be plaintext",
  );
}

function checkBindHost() {
  const host = process.env.STEWARD_BIND_HOST ?? "127.0.0.1";
  if (host === "0.0.0.0" && isProd() && process.env.STEWARD_BEHIND_PROXY !== "true") {
    return record(
      "bind_host",
      "CC6.6",
      "warn",
      "Binding 0.0.0.0 in production — confirm a TLS-terminating reverse proxy is in front (set STEWARD_BEHIND_PROXY=true to acknowledge)",
    );
  }
  record("bind_host", "CC6.6", "pass", `Bind host ${host}`);
}

// ─── CC7.1 / CC8.1 — change management + monitoring ──────────────────────────

function checkBunAudit() {
  try {
    execSync("bun audit --audit-level=critical", { stdio: "pipe" });
    record("bun_audit_critical", "CC7.1", "pass", "No critical CVEs in dependency tree");
  } catch (e) {
    record(
      "bun_audit_critical",
      "CC7.1",
      "fail",
      `bun audit reported critical vulnerabilities — ${(e as Error).message.split("\n")[0]}`,
    );
  }
  try {
    execSync("bun audit --audit-level=high", { stdio: "pipe" });
    record("bun_audit_high", "CC7.1", "pass", "No high CVEs in dependency tree");
  } catch {
    record(
      "bun_audit_high",
      "CC7.1",
      "warn",
      "bun audit reported high-severity CVEs (non-blocking)",
    );
  }
}

function checkFrozenLockfile() {
  try {
    execSync("bun install --frozen-lockfile --dry-run", { stdio: "pipe" });
    record("lockfile_frozen", "CC8.1", "pass", "Lockfile passes --frozen-lockfile check");
  } catch {
    record(
      "lockfile_frozen",
      "CC8.1",
      "fail",
      "bun.lock is out of sync with package.json files — supply-chain integrity gap",
    );
  }
}

// ─── Output ──────────────────────────────────────────────────────────────────

function main() {
  checkMasterPassword();
  checkJwtSecret();
  checkKdfSalt();
  checkAuditHmacKey();
  checkDatabaseTls();
  checkBindHost();
  checkBunAudit();
  checkFrozenLockfile();

  const strict = process.argv.includes("--strict");
  const json = process.argv.includes("--json");

  if (json) {
    console.log(JSON.stringify({ checks }, null, 2));
  } else {
    const icon = { pass: "✓", fail: "✗", warn: "!", skip: "·" } as const;
    for (const c of checks) {
      console.log(`  ${icon[c.status]} [${c.control}] ${c.id} — ${c.reason}`);
    }
    const counts = checks.reduce(
      (acc, c) => ((acc[c.status] = (acc[c.status] ?? 0) + 1), acc),
      {} as Record<Status, number>,
    );
    console.log(
      `\n${counts.pass ?? 0} pass · ${counts.warn ?? 0} warn · ${counts.fail ?? 0} fail · ${counts.skip ?? 0} skip`,
    );
  }

  const failed = checks.some((c) => c.status === "fail");
  const warned = checks.some((c) => c.status === "warn");
  process.exit(failed || (strict && warned) ? 1 : 0);
}

main();
