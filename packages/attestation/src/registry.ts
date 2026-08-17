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

export interface RegistryVerificationOptions {
  /**
   * Pin the expected registry id. Prevents cross-environment registry file
   * swaps when the same keys sign multiple registries.
   */
  expectedRegistryId?: string;
  /**
   * Reject registries whose `updatedAt` is older than this ISO timestamp
   * (last-known-good), so historically valid signed registries cannot be
   * replayed to roll back retired measurements.
   */
  minimumUpdatedAt?: string;
  /**
   * Explicitly accept a registry with no pinned trust anchor. Without
   * trustedKeyIds/trustedPublicKeySha256 any tampered file can simply be
   * re-signed with an attacker key, so unpinned verification fails closed
   * unless this flag is set. Local development only.
   */
  dangerouslyAllowUnpinned?: boolean;
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
  options?: RegistryVerificationOptions,
): RegistryVerificationResult {
  // SEC-007: an empty/malformed configured count must fail closed, never
  // silently disable the signature gate (Number("") === 0, NaN comparisons
  // are always false).
  if (!Number.isInteger(requiredSignatureCount) || requiredSignatureCount < 1) {
    return {
      ok: false,
      reason: `invalid requiredSignatureCount: ${requiredSignatureCount} (must be an integer >= 1)`,
    };
  }
  if (registry.payload.schemaVersion !== 1)
    return { ok: false, reason: "unsupported registry schema" };

  // SEC-086: bind registry metadata so signed files cannot be swapped across
  // environments or replayed to roll back retired measurements.
  if (options?.expectedRegistryId && registry.payload.registryId !== options.expectedRegistryId) {
    return {
      ok: false,
      reason: `registryId mismatch: expected ${options.expectedRegistryId}, got ${registry.payload.registryId}`,
    };
  }
  if (options?.minimumUpdatedAt) {
    const updatedAt = Date.parse(registry.payload.updatedAt);
    const minimum = Date.parse(options.minimumUpdatedAt);
    if (!Number.isFinite(updatedAt)) {
      return { ok: false, reason: "registry updatedAt is not a valid timestamp" };
    }
    if (!Number.isFinite(minimum)) {
      return { ok: false, reason: "minimumUpdatedAt is not a valid timestamp" };
    }
    if (updatedAt < minimum) {
      return {
        ok: false,
        reason: `registry updatedAt ${registry.payload.updatedAt} is older than minimum ${options.minimumUpdatedAt}`,
      };
    }
  }

  const trustedIds = trustedKeyIds ? new Set(trustedKeyIds) : undefined;
  const trustedFingerprints = trustedPublicKeySha256 ? new Set(trustedPublicKeySha256) : undefined;
  // SEC-027: with no pinned trust anchor the signature check is pure ceremony
  // — anyone can re-sign a tampered registry — so fail closed unless the
  // caller explicitly opts into unpinned verification.
  if (!trustedIds && !trustedFingerprints && !options?.dangerouslyAllowUnpinned) {
    return {
      ok: false,
      reason:
        "no registry trust anchor configured: pass trustedKeyIds or trustedPublicKeySha256 " +
        "(or dangerouslyAllowUnpinned for local development only)",
    };
  }
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
  // SEC-008: count DISTINCT keys, not signature array entries — the same
  // signature pasted twice must not satisfy a two-person quorum.
  const validKeyFingerprints = new Set<string>();
  for (const signature of candidateSignatures) {
    if (signature.algorithm !== "ed25519") continue;
    const valid = verifySignature(
      null,
      payload,
      createPublicKey(signature.publicKeyPem),
      Buffer.from(signature.signatureBase64, "base64"),
    );
    if (valid) validKeyFingerprints.add(publicKeyFingerprint(signature.publicKeyPem));
  }
  const validCount = validKeyFingerprints.size;

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
