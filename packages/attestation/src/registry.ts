import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import type { AttestationMeasurement, AttestationProviderId, AttestationQuote } from "./types.js";

export interface MeasurementRegistryDeployment {
  provider: AttestationProviderId;
  measurement: AttestationMeasurement;
  endpoint?: string;
  status: "active" | "pending" | "retired";
  notes?: string;
}

export interface MeasurementRegistryPayload {
  schemaVersion: 1;
  registryId: string;
  updatedAt: string;
  deployments: Record<string, MeasurementRegistryDeployment>;
}

export interface MeasurementRegistrySignature {
  keyId: string;
  algorithm: "ed25519";
  publicKeyPem: string;
  signatureBase64: string;
}

export interface MeasurementRegistryFile {
  payload: MeasurementRegistryPayload;
  signatures: MeasurementRegistrySignature[];
}

export interface RegistryVerificationResult {
  ok: boolean;
  reason?: string;
  matchedDeployment?: string;
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalizeJson(entry)).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalizeJson(entry)}`)
    .join(",")}}`;
}

export function registryPayloadDigest(payload: MeasurementRegistryPayload): string {
  return createHash("sha256").update(canonicalizeJson(payload)).digest("hex");
}

export function verifyRegistrySignatures(
  registry: MeasurementRegistryFile,
  requiredSignatureCount = 1,
  trustedKeyIds?: readonly string[],
  trustedPublicKeySha256?: readonly string[],
): RegistryVerificationResult {
  if (registry.payload.schemaVersion !== 1)
    return { ok: false, reason: "unsupported registry schema" };

  const trustedIds = trustedKeyIds ? new Set(trustedKeyIds) : undefined;
  const trustedFingerprints = trustedPublicKeySha256 ? new Set(trustedPublicKeySha256) : undefined;
  const candidateSignatures = registry.signatures.filter((signature) => {
    if (trustedIds && !trustedIds.has(signature.keyId)) return false;
    if (
      trustedFingerprints &&
      !trustedFingerprints.has(publicKeyFingerprint(signature.publicKeyPem))
    ) {
      return false;
    }
    return true;
  });
  if (candidateSignatures.length < requiredSignatureCount) {
    return {
      ok: false,
      reason: `registry has ${candidateSignatures.length} trusted signature candidate(s), needs ${requiredSignatureCount}`,
    };
  }

  const payload = Buffer.from(canonicalizeJson(registry.payload));
  let validCount = 0;
  for (const signature of candidateSignatures) {
    if (signature.algorithm !== "ed25519") continue;
    const valid = verifySignature(
      null,
      payload,
      createPublicKey(signature.publicKeyPem),
      Buffer.from(signature.signatureBase64, "base64"),
    );
    if (valid) validCount += 1;
  }

  if (validCount < requiredSignatureCount) {
    return {
      ok: false,
      reason: `registry has ${validCount} valid trusted signature(s), needs ${requiredSignatureCount}`,
    };
  }
  return { ok: true };
}

export function publicKeyFingerprint(publicKeyPem: string): string {
  return createHash("sha256").update(publicKeyPem.replace(/\r\n/g, "\n").trim()).digest("hex");
}

export function verifyQuoteAgainstRegistry(
  quote: AttestationQuote,
  registry: MeasurementRegistryFile,
  deployment: string,
): RegistryVerificationResult {
  const entry = registry.payload.deployments[deployment];
  if (!entry) return { ok: false, reason: `unknown deployment: ${deployment}` };
  if (entry.status !== "active")
    return { ok: false, reason: `deployment ${deployment} is ${entry.status}` };
  if (!quote.verified) return { ok: false, reason: "quote was not cryptographically verified" };
  if (entry.provider !== quote.provider) {
    return {
      ok: false,
      reason: `provider mismatch: expected ${entry.provider}, got ${quote.provider}`,
    };
  }
  if (entry.measurement.imageDigest !== quote.measurement.imageDigest) {
    return { ok: false, reason: "image digest mismatch" };
  }
  if (entry.measurement.configHash !== quote.measurement.configHash) {
    return { ok: false, reason: "config hash mismatch" };
  }
  return { ok: true, matchedDeployment: deployment };
}
