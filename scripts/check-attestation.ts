#!/usr/bin/env bun
import {
  createDstackTdxProvider,
  type MeasurementRegistryFile,
  verifyQuoteAgainstRegistry,
  verifyRegistrySignatures,
} from "@stwd/attestation";

const endpoint = process.env.STEWARD_ATTESTATION_ENDPOINT;
const deployment = process.env.STEWARD_ATTESTATION_DEPLOYMENT ?? "local-dev";
const registryPath =
  process.env.STEWARD_MEASUREMENT_REGISTRY ?? "docs/attestation/measurements.json";
const requiredSignaturesRaw = process.env.STEWARD_REGISTRY_REQUIRED_SIGNATURES ?? "1";
const requiredSignatures = Number(requiredSignaturesRaw);
// SEC-007: an empty or malformed count must hard-fail — Number("") === 0 and
// NaN would otherwise silently disable the registry signature gate.
if (!Number.isInteger(requiredSignatures) || requiredSignatures < 1) {
  console.error(
    `STEWARD_REGISTRY_REQUIRED_SIGNATURES must be a positive integer, got "${requiredSignaturesRaw}"`,
  );
  process.exit(2);
}
const trustedKeyIds = process.env.STEWARD_REGISTRY_TRUSTED_KEY_IDS?.split(",")
  .map((keyId) => keyId.trim())
  .filter(Boolean);
const trustedKeyFingerprints = process.env.STEWARD_REGISTRY_TRUSTED_KEY_SHA256?.split(",")
  .map((fingerprint) => fingerprint.trim())
  .filter(Boolean);
// SEC-027: without a pinned trust anchor anyone can re-sign a tampered
// registry, so require one (or an explicit local-dev opt-out).
const allowUnpinned = process.env.STEWARD_REGISTRY_ALLOW_UNPINNED === "true";
if (!trustedKeyFingerprints?.length && !allowUnpinned) {
  console.error(
    "no cryptographic registry trust anchor configured: set " +
      "STEWARD_REGISTRY_TRUSTED_KEY_SHA256 (key IDs are selectors, not trust anchors), " +
      "or STEWARD_REGISTRY_ALLOW_UNPINNED=true for local development only",
  );
  process.exit(2);
}
// SEC-086: optionally pin the registry identity and reject registries older
// than the last-known-good update (rollback/replay protection).
const expectedRegistryId = process.env.STEWARD_REGISTRY_ID;
const minimumUpdatedAt = process.env.STEWARD_REGISTRY_MIN_UPDATED_AT;

if (!endpoint) {
  console.error(
    "STEWARD_ATTESTATION_ENDPOINT is required (for example https://steward.example.com/quote)",
  );
  process.exit(2);
}

const registry = (await Bun.file(registryPath).json()) as MeasurementRegistryFile;
const registryOk = verifyRegistrySignatures(
  registry,
  requiredSignatures,
  trustedKeyIds,
  trustedKeyFingerprints,
  { expectedRegistryId, minimumUpdatedAt, dangerouslyAllowUnpinned: allowUnpinned },
);
if (!registryOk.ok) {
  console.error(`measurement registry signature check failed: ${registryOk.reason}`);
  process.exit(1);
}

const nonce = crypto.randomUUID();
const response = await fetch(
  `${endpoint}${endpoint.includes("?") ? "&" : "?"}nonce=${encodeURIComponent(nonce)}`,
);
if (!response.ok && response.status !== 503) {
  console.error(`quote endpoint failed: ${response.status} ${await response.text()}`);
  process.exit(1);
}

const rawQuote = await response.json();
const provider = createDstackTdxProvider();
const verifiedQuote = await provider.verifyQuote(rawQuote.raw?.quote ?? rawQuote.raw ?? rawQuote, {
  nonce,
});
const match = verifyQuoteAgainstRegistry(verifiedQuote, registry, deployment);
if (!match.ok) {
  console.error(`attestation measurement check failed: ${match.reason}`);
  console.error(
    JSON.stringify(
      { provider: verifiedQuote.provider, measurement: verifiedQuote.measurement },
      null,
      2,
    ),
  );
  process.exit(1);
}

console.log(`attestation measurement ok for ${deployment}`);
