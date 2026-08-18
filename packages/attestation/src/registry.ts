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
   * trustedPublicKeySha256 any tampered file can simply be re-signed with an
   * attacker key. Key ids are registry-controlled selectors, not trust
   * anchors. Unpinned verification fails closed unless this flag is set.
   * Local development only.
   */
  dangerouslyAllowUnpinned?: boolean;
}

const MAX_REGISTRY_SIGNATURES = 64;
const MAX_REGISTRY_PAYLOAD_BYTES = 1024 * 1024;
const MAX_PUBLIC_KEY_PEM_BYTES = 16 * 1024;

function parseEd25519PublicKey(publicKeyPem: unknown): {
  key: ReturnType<typeof createPublicKey>;
  fingerprint: string;
} | null {
  if (
    typeof publicKeyPem !== "string" ||
    Buffer.byteLength(publicKeyPem, "utf8") > MAX_PUBLIC_KEY_PEM_BYTES ||
    !publicKeyPem.trim().startsWith("-----BEGIN PUBLIC KEY-----") ||
    !publicKeyPem.trim().endsWith("-----END PUBLIC KEY-----")
  ) {
    return null;
  }
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return null;
    const spki = key.export({ type: "spki", format: "der" });
    return {
      key,
      fingerprint: createHash("sha256").update(spki).digest("hex"),
    };
  } catch {
    return null;
  }
}

function decodeEd25519Signature(signatureBase64: unknown): Buffer | null {
  if (
    typeof signatureBase64 !== "string" ||
    signatureBase64.length !== 88 ||
    !/^[A-Za-z0-9+/]{86}==$/.test(signatureBase64)
  ) {
    return null;
  }
  const decoded = Buffer.from(signatureBase64, "base64");
  if (decoded.byteLength !== 64 || decoded.toString("base64") !== signatureBase64) return null;
  return decoded;
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
  if (
    !registry ||
    typeof registry !== "object" ||
    !registry.payload ||
    typeof registry.payload !== "object" ||
    !Array.isArray(registry.signatures)
  ) {
    return { ok: false, reason: "malformed measurement registry" };
  }
  if (registry.signatures.length > MAX_REGISTRY_SIGNATURES) {
    return {
      ok: false,
      reason: `registry has too many signatures (max ${MAX_REGISTRY_SIGNATURES})`,
    };
  }
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

  const trustedIds = trustedKeyIds?.length ? new Set(trustedKeyIds) : undefined;
  let trustedFingerprints: Set<string> | undefined;
  if (trustedPublicKeySha256?.length) {
    if (trustedPublicKeySha256.some((fingerprint) => !/^[a-f0-9]{64}$/i.test(fingerprint))) {
      return { ok: false, reason: "trusted public-key fingerprints must be 64 hex characters" };
    }
    trustedFingerprints = new Set(
      trustedPublicKeySha256.map((fingerprint) => fingerprint.toLowerCase()),
    );
  }
  // SEC-027: with no pinned trust anchor the signature check is pure ceremony
  // — anyone can re-sign a tampered registry — so fail closed unless the
  // caller explicitly opts into unpinned verification.
  // keyId is metadata inside the attacker-controlled registry file, not a
  // cryptographic identity. It may narrow a fingerprint-pinned key set, but
  // can never establish trust by itself: an attacker can reuse an allowed id
  // with a newly generated key and re-sign a modified payload.
  if (!trustedFingerprints && !options?.dangerouslyAllowUnpinned) {
    return {
      ok: false,
      reason:
        "no cryptographic registry trust anchor configured: pass trustedPublicKeySha256 " +
        "(or dangerouslyAllowUnpinned for local development only)",
    };
  }
  const candidateSignatures: Array<{
    signature: MeasurementRegistrySignature;
    key: ReturnType<typeof createPublicKey>;
    fingerprint: string;
  }> = [];
  for (const value of registry.signatures as unknown[]) {
    if (!value || typeof value !== "object") continue;
    const signature = value as MeasurementRegistrySignature;
    if (
      signature.algorithm !== "ed25519" ||
      typeof signature.keyId !== "string" ||
      (trustedIds && !trustedIds.has(signature.keyId))
    ) {
      continue;
    }
    const parsed = parseEd25519PublicKey(signature.publicKeyPem);
    if (!parsed || (trustedFingerprints && !trustedFingerprints.has(parsed.fingerprint))) continue;
    candidateSignatures.push({ signature, ...parsed });
  }
  if (candidateSignatures.length < requiredSignatureCount) {
    return {
      ok: false,
      reason: `registry has ${candidateSignatures.length} trusted signature candidate(s), needs ${requiredSignatureCount}`,
    };
  }

  let payload: Buffer;
  try {
    payload = Buffer.from(canonicalizeJson(registry.payload));
  } catch {
    return { ok: false, reason: "registry payload is not canonicalizable JSON" };
  }
  if (payload.byteLength > MAX_REGISTRY_PAYLOAD_BYTES) {
    return { ok: false, reason: "registry payload exceeded the 1 MiB limit" };
  }
  // SEC-008: count DISTINCT keys, not signature array entries — the same
  // signature pasted twice must not satisfy a two-person quorum.
  const validKeyFingerprints = new Set<string>();
  for (const candidate of candidateSignatures) {
    const signatureBytes = decodeEd25519Signature(candidate.signature.signatureBase64);
    if (!signatureBytes) continue;
    try {
      const valid = verifySignature(null, payload, candidate.key, signatureBytes);
      // Count the canonical SPKI key, not textual PEM formatting. Re-wrapping
      // one PEM must not turn one signing key into two quorum participants.
      if (valid) {
        validKeyFingerprints.add(candidate.fingerprint);
      }
    } catch {
      // A malformed attacker-supplied key is an invalid signature candidate,
      // not an exception that may crash the verifier process.
    }
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
  const parsed = parseEd25519PublicKey(publicKeyPem);
  if (!parsed) throw new Error("public key must be a bounded Ed25519 SPKI PEM");
  return parsed.fingerprint;
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
