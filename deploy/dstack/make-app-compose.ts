#!/usr/bin/env bun
/**
 * Generate the dstack app-compose.json manifest for Steward.
 *
 * dstack measures the sha256 of app-compose.json as `compose_hash`, which is
 * bound into the CVM's TDX quote (RTMR3) and is what
 * `AttestationMeasurement.configHash` pins in the signed measurement registry.
 * This script produces the manifest DETERMINISTICALLY from
 * docker-compose.dstack.yml so the hash is reproducible by any outside party:
 *
 *   bun deploy/dstack/make-app-compose.ts            # writes app-compose.json + prints hash
 *   bun deploy/dstack/make-app-compose.ts --check    # verify committed manifest is current
 *
 * Schema follows dstack vmm-cli `create_app_compose` (manifest_version 2):
 * https://github.com/Dstack-TEE/dstack/blob/master/dstack/vmm/src/vmm-cli.py
 *
 * allowed_envs lists the names (never values) of secrets the operator encrypts
 * to the KMS at deploy time. Adding an env name changes compose_hash, so
 * widening the secret surface is always a visible, PR-gated measurement change.
 */

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const composePath = join(here, "docker-compose.dstack.yml");
const outputPath = join(here, "app-compose.json");

/**
 * Secret/config names allowed to cross into the CVM via dstack's KMS-encrypted
 * env. Values are encrypted on the operator machine and released only to a CVM
 * whose measurement the KMS has authorized. Names only — never values.
 */
export const ALLOWED_ENVS: readonly string[] = [
  // Required secrets
  "POSTGRES_PASSWORD",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_EXECUTION_AUTH_SECRET",
  "STEWARD_KDF_SALT",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_PROXY_REQUEST_SIGNING_SECRET",
  // Optional third-party database (else in-CVM postgres)
  "DATABASE_URL",
  // Custody posture acknowledgement (deliberate operator decision)
  "STEWARD_ACK_LOCAL_CUSTODY",
  // Optional platform configuration
  "STEWARD_PLATFORM_KEYS",
  "STEWARD_PLATFORM_KEY_SCOPES",
  "ALLOW_USER_TENANT_CREATION",
  "AGENT_TOKEN_EXPIRY",
  "RPC_URL",
  "CHAIN_ID",
  "STEWARD_PLUGINS",
  "APP_URL",
  "RESEND_API_KEY",
  "EMAIL_FROM",
  "PASSKEY_RP_NAME",
  "PASSKEY_RP_ID",
  "PASSKEY_ORIGIN",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "DISCORD_CLIENT_ID",
  "DISCORD_CLIENT_SECRET",
  "SIWE_ALLOWED_DOMAINS",
];

export interface StewardAppCompose {
  manifest_version: 2;
  name: string;
  runner: "docker-compose";
  docker_compose_file: string;
  kms_enabled: boolean;
  gateway_enabled: boolean;
  local_key_provider_enabled: boolean;
  key_provider_id: string;
  public_logs: boolean;
  public_sysinfo: boolean;
  allowed_envs: string[];
  no_instance_id: boolean;
  secure_time: boolean;
}

export function buildAppCompose(dockerComposeFile: string): StewardAppCompose {
  return {
    manifest_version: 2,
    name: "steward",
    runner: "docker-compose",
    docker_compose_file: dockerComposeFile,
    // KMS is REQUIRED: it is the only sanctioned path for secrets into the CVM
    // and gates key release on the measurement allowlist.
    kms_enabled: true,
    gateway_enabled: true,
    local_key_provider_enabled: false,
    key_provider_id: "",
    // Logs may carry operational detail; keep them operator-only. Steward's
    // trust story is the quote + measurement registry, not log transparency.
    public_logs: false,
    public_sysinfo: true,
    allowed_envs: [...ALLOWED_ENVS],
    no_instance_id: false,
    secure_time: true,
  };
}

export function renderAppCompose(dockerComposeFile: string): string {
  // Match vmm-cli formatting: json.dumps(indent=4, ensure_ascii=False) + no
  // trailing newline, so our compose_hash matches what dstack tooling computes.
  return JSON.stringify(buildAppCompose(dockerComposeFile), null, 4);
}

export function composeHash(manifest: string): string {
  return createHash("sha256").update(manifest, "utf8").digest("hex");
}

if (import.meta.main) {
  const dockerComposeFile = readFileSync(composePath, "utf8");
  const rendered = renderAppCompose(dockerComposeFile);
  const hash = composeHash(rendered);

  if (process.argv.includes("--check")) {
    let committed: string;
    try {
      committed = readFileSync(outputPath, "utf8");
    } catch {
      console.error(`missing ${outputPath}; run: bun deploy/dstack/make-app-compose.ts`);
      process.exit(1);
    }
    if (committed !== rendered) {
      console.error(
        "deploy/dstack/app-compose.json is stale (docker-compose.dstack.yml or manifest settings changed).",
      );
      console.error("Regenerate with: bun deploy/dstack/make-app-compose.ts");
      process.exit(1);
    }
    console.log(`app-compose.json is current. compose_hash=${hash}`);
    process.exit(0);
  }

  writeFileSync(outputPath, rendered);
  console.log(`wrote ${outputPath}`);
  console.log(`compose_hash=${hash}`);
  console.log(
    "Next: pin this hash into docs/attestation/measurements.json via deploy/dstack/pin-measurement.ts",
  );
}
