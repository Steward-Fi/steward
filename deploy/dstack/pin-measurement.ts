#!/usr/bin/env bun
/**
 * Pin the expected dstack measurement for a Steward deployment into the signed
 * measurement registry (docs/attestation/measurements.json, from PR #248).
 *
 * The pinned pair is:
 *   imageDigest = dstack OS image hash (digest.txt in the guest image tarball,
 *                 or `app_info.os_image_hash` from a verified quote)
 *   configHash  = sha256 of app-compose.json (computed locally from this repo,
 *                 reproducible by anyone via make-app-compose.ts)
 *
 * Usage:
 *   bun deploy/dstack/pin-measurement.ts \
 *     --deployment phala-prod \
 *     --os-image-hash <hex from digest.txt> \
 *     [--endpoint https://steward.example.com/quote] \
 *     [--registry docs/attestation/measurements.json] \
 *     [--status pending|active] \
 *     [--notes "..."]
 *
 * The script REFUSES to sign. It updates `payload` (bumping updatedAt) and
 * clears `signatures`, then prints the canonical payload digest that release
 * signers must sign offline:
 *
 *   1. Run this script; commit the payload diff on a branch.
 *   2. Each release signer verifies the compose hash independently
 *      (`bun deploy/dstack/make-app-compose.ts --check`), then signs the
 *      canonical payload (ed25519 over canonicalizeJson(payload)) and adds
 *      their signature entry.
 *   3. Open a PR containing ONLY the measurement + signature change plus
 *      build/deploy evidence. Two-person rule per docs/ATTESTATION.md.
 *
 * New deployments should land as status "pending" and flip to "active" in the
 * PR that carries the verified deploy evidence.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type MeasurementRegistryFile,
  registryPayloadDigest,
} from "../../packages/attestation/src/registry.js";
import { composeHash, renderAppCompose } from "./make-app-compose.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

const deployment = arg("deployment");
const osImageHash = arg("os-image-hash");
const endpoint = arg("endpoint");
const registryPath = arg("registry") ?? join(repoRoot, "docs", "attestation", "measurements.json");
const status = (arg("status") ?? "pending") as "pending" | "active";
const notes = arg("notes");

if (!deployment || !osImageHash) {
  console.error(
    "usage: bun deploy/dstack/pin-measurement.ts --deployment <name> --os-image-hash <hex> [--endpoint <url>] [--status pending|active] [--notes <text>]",
  );
  process.exit(2);
}
if (status !== "pending" && status !== "active") {
  console.error("--status must be pending or active");
  process.exit(2);
}
if (!/^(0x)?[0-9a-fA-F]{64}$/.test(osImageHash)) {
  console.error("--os-image-hash must be a 32-byte hex digest (dstack digest.txt value)");
  process.exit(2);
}

const dockerComposeFile = readFileSync(join(here, "docker-compose.dstack.yml"), "utf8");
const manifest = renderAppCompose(dockerComposeFile);
const expectedComposeHash = composeHash(manifest);

const committedManifest = readFileSync(join(here, "app-compose.json"), "utf8");
if (committedManifest !== manifest) {
  console.error(
    "deploy/dstack/app-compose.json is stale; run `bun deploy/dstack/make-app-compose.ts` first so the pinned configHash matches the committed manifest.",
  );
  process.exit(1);
}

const registry = JSON.parse(readFileSync(registryPath, "utf8")) as MeasurementRegistryFile;

registry.payload.deployments[deployment] = {
  provider: "dstack-tdx",
  measurement: {
    imageDigest: osImageHash.replace(/^0x/, ""),
    configHash: expectedComposeHash,
  },
  ...(endpoint ? { endpoint } : {}),
  status,
  notes:
    notes ??
    `Pinned by deploy/dstack/pin-measurement.ts. configHash = sha256(deploy/dstack/app-compose.json); reproduce with: bun deploy/dstack/make-app-compose.ts`,
};
registry.payload.updatedAt = new Date().toISOString();
// Payload changed: existing signatures are void. Signing happens OFFLINE by
// release key holders; this script never touches private keys.
registry.signatures = [];

writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`);

console.log(`updated ${registryPath}`);
console.log(`deployment:            ${deployment} (${status})`);
console.log(`measurement.imageDigest: ${osImageHash.replace(/^0x/, "")}`);
console.log(`measurement.configHash:  ${expectedComposeHash}`);
console.log(`canonical payload sha256 (sign this): ${registryPayloadDigest(registry.payload)}`);
console.log(
  "signatures[] cleared — collect ed25519 signatures over the canonical payload from release key holders before merging (two-person rule).",
);
