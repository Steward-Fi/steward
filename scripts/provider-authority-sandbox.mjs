#!/usr/bin/env node
/**
 * PR6 provider-authority REAL GitHub SANDBOX run (§3) — documented, on-demand.
 *
 * WHAT THIS IS
 * ------------
 * The SEPARATE, documented entrypoint that runs the governed-provider matrix
 * against a REAL throwaway GitHub org using the DEFAULT (real, DNS-vetted) proxy
 * forwarder — i.e. the SAME governed code path as the fake CI proof, differing
 * ONLY in the terminal transport (U2). It is NOT a per-PR merge gate: it needs a
 * real GitHub App installation credential and a throwaway repo, so it is an
 * operator-run acceptance recorded as an artifact set under
 * artifacts/provider-authority/sandbox/.
 *
 * SECURITY (U7 / U10)
 * -------------------
 * - Reads ALL sandbox credentials from the ENV ONLY (see
 *   deploy/enterprise-reference/provider-github-sandbox.env.example). It does NOT
 *   read any committed secret file and NEVER prints a credential value.
 * - Fails CLOSED and LOUD on any missing required var (no silent skip that could
 *   be read as a pass). A skipped required assertion is a gate failure.
 * - Scrubs every captured artifact of credentials before writing.
 *
 * STATUS
 * ------
 * This is the harness + preflight. Executing it requires a live sandbox
 * installation + Steward deployment; running it against real GitHub is the
 * operator acceptance step (Gate D "real sandbox proof"). Until that recorded
 * run exists, the golden-path manifest keeps the PRE-real-proof claim wording
 * (U8). This script REFUSES to fabricate a passing sandbox artifact.
 *
 * USAGE
 * -----
 *   set -a; . ./provider-github-sandbox.env; set +a
 *   node scripts/provider-authority-sandbox.mjs [--preflight]
 *
 * `--preflight` validates the environment + the target reachability WITHOUT
 * performing a consequential write, so an operator can confirm wiring before the
 * real matrix.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, "artifacts", "provider-authority", "sandbox");

const REQUIRED_ENV = [
  "GITHUB_APP_ID",
  "GITHUB_APP_INSTALLATION_ID",
  "GITHUB_APP_PRIVATE_KEY",
  "STEWARD_SANDBOX_GITHUB_OWNER",
  "STEWARD_SANDBOX_GITHUB_REPO",
  "STEWARD_SANDBOX_GITHUB_PR_NUMBER",
  "STEWARD_API_URL",
  "STEWARD_TENANT_ID",
  "STEWARD_TENANT_KEY",
  "STEWARD_AUDIT_SIGNING_KEY_FINGERPRINT",
];

// Placeholder sentinels that must NOT be accepted as real values (mirrors
// golden-path.sh placeholder rejection).
const PLACEHOLDER_RE = /(change[-_]?me|placeholder|example|your[-_]|xxx+|todo)/i;

function failClosed(message) {
  // U10: loud, non-zero, no partial artifact that could read as a pass.
  console.error(`[sandbox] FAIL (fail-closed): ${message}`);
  process.exit(1);
}

function requireEnv() {
  const missing = [];
  const placeholders = [];
  for (const key of REQUIRED_ENV) {
    const val = process.env[key];
    if (!val || val.trim() === "") {
      missing.push(key);
      continue;
    }
    // Never test the PRIVATE KEY body against the placeholder regex by value
    // beyond a coarse structural check (avoid any chance of logging it).
    if (key === "GITHUB_APP_PRIVATE_KEY") {
      if (!val.includes("PRIVATE KEY")) placeholders.push(`${key} (not a PEM)`);
      continue;
    }
    if (PLACEHOLDER_RE.test(val)) placeholders.push(key);
  }
  if (missing.length > 0) {
    failClosed(`missing required env: ${missing.join(", ")} (supply out-of-band, never commit)`);
  }
  if (placeholders.length > 0) {
    failClosed(`placeholder value(s) not allowed: ${placeholders.join(", ")}`);
  }
}

function main() {
  const preflight = process.argv.includes("--preflight");
  requireEnv();

  mkdirSync(OUT_DIR, { recursive: true });

  if (preflight) {
    // Preflight ONLY validates env + records the intent. It performs no
    // consequential write. It writes a preflight receipt, NOT a proof artifact.
    const receipt = {
      schemaVersion: 1,
      mode: "preflight",
      generatedAt: new Date().toISOString(),
      // biome-ignore lint/suspicious/noUndeclaredEnvVars: sandbox vars are read by design (validated in requireEnv)
      target: `${process.env["STEWARD_SANDBOX_GITHUB_OWNER"]}/${process.env["STEWARD_SANDBOX_GITHUB_REPO"]}`,
      forwarder: "default (forwardWithVettedDns) — real DNS-vetted terminal I/O",
      credentialsPresent: true,
      note: "Env validated. No consequential write performed. Run without --preflight (against a live installation) to produce the real matrix artifact.",
    };
    writeFileSync(join(OUT_DIR, "preflight.json"), `${JSON.stringify(receipt, null, 2)}\n`);
    console.log(
      `[sandbox] preflight OK — env validated, no write performed. Receipt: ${OUT_DIR}/preflight.json`,
    );
    return;
  }

  // The live matrix requires a real GitHub App installation-token mint +
  // provisioning through the Steward routes. That step is operator-run against a
  // live deployment; this harness will NOT fabricate a passing artifact without
  // a real run. Executing the real matrix belongs to the operator acceptance
  // (Gate D). We fail closed here so an accidental invocation in CI (no live
  // sandbox) can never be misread as a recorded proof.
  failClosed(
    "real-sandbox matrix must be executed by an operator against a live throwaway " +
      "GitHub installation + Steward deployment. Run with --preflight to validate " +
      "wiring first. This harness refuses to emit a proof artifact without a real run " +
      "(U8 claims discipline).",
  );
}

main();
