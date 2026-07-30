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
const requiredSignatures = Number(process.env.STEWARD_REGISTRY_REQUIRED_SIGNATURES ?? "1");
const trustedKeyIds = process.env.STEWARD_REGISTRY_TRUSTED_KEY_IDS?.split(",")
  .map((keyId) => keyId.trim())
  .filter(Boolean);
const trustedKeyFingerprints = process.env.STEWARD_REGISTRY_TRUSTED_KEY_SHA256?.split(",")
  .map((fingerprint) => fingerprint.trim())
  .filter(Boolean);

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
