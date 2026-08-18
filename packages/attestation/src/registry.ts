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
const MAX_REGISTRY_PAYLOAD_DEPTH = 64;
const MAX_REGISTRY_PAYLOAD_NODES = 100_000;
const MAX_REGISTRY_JSON_DEPTH = MAX_REGISTRY_PAYLOAD_DEPTH + 8;
const MAX_REGISTRY_JSON_STRUCTURAL_TOKENS = 100_000;
const MAX_PUBLIC_KEY_PEM_BYTES = 16 * 1024;
export const MAX_MEASUREMENT_REGISTRY_FILE_BYTES = 4 * 1024 * 1024;
const MAX_REGISTRY_DEPLOYMENTS = 1024;
const REGISTRY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PROVIDER_IDS = new Set<AttestationProviderId>([
  "dstack-tdx",
  "noop-dev",
  "aws-nitro",
  "amd-sev-snp",
]);
const DEPLOYMENT_STATUSES = new Set(["active", "pending", "retired"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isBoundedText(value: unknown, maxBytes: number, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    (allowEmpty || value.length > 0) &&
    Buffer.byteLength(value, "utf8") <= maxBytes
  );
}

function hasOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return snapshotDataProperties(value, allowed) !== null;
}

function snapshotDataProperties(
  value: unknown,
  allowed: ReadonlySet<string>,
): Record<string, unknown> | null {
  if (!isPlainObject(value)) return null;
  const snapshot: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !("value" in descriptor)) return null;
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function snapshotBoundedArray(value: unknown, maxItems: number): unknown[] | null {
  if (!Array.isArray(value)) return null;
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    !lengthDescriptor ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > maxItems
  ) {
    return null;
  }
  const length = lengthDescriptor.value as number;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== length + 1 || !keys.includes("length")) return null;
  const snapshot: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !("value" in descriptor)) return null;
    snapshot.push(descriptor.value);
  }
  return snapshot;
}

function validateRegistryPayload(payload: unknown): string | null {
  if (!isPlainObject(payload)) return "registry payload must be an object";
  if (!hasOnlyKeys(payload, new Set(["schemaVersion", "registryId", "updatedAt", "deployments"])))
    return "registry payload has unknown fields";
  if (payload.schemaVersion !== 1) return "unsupported registry schema";
  if (typeof payload.registryId !== "string" || !REGISTRY_ID_PATTERN.test(payload.registryId))
    return "registryId is invalid";
  if (!isBoundedText(payload.updatedAt, 64)) return "registry updatedAt is invalid";
  const updatedAt = Date.parse(payload.updatedAt);
  if (!Number.isFinite(updatedAt) || new Date(updatedAt).toISOString() !== payload.updatedAt)
    return "registry updatedAt must be a canonical ISO timestamp";
  if (!isPlainObject(payload.deployments)) return "registry deployments must be an object";
  const deployments = Object.entries(payload.deployments);
  if (deployments.length > MAX_REGISTRY_DEPLOYMENTS)
    return `registry has too many deployments (max ${MAX_REGISTRY_DEPLOYMENTS})`;

  let estimatedBytes = 256;
  const addText = (value: string) => {
    estimatedBytes += Buffer.byteLength(JSON.stringify(value), "utf8") + 16;
    return estimatedBytes <= MAX_REGISTRY_PAYLOAD_BYTES;
  };
  for (const [deploymentId, rawEntry] of deployments) {
    if (!REGISTRY_ID_PATTERN.test(deploymentId) || !addText(deploymentId))
      return "registry deployment id is invalid or payload is too large";
    if (!isPlainObject(rawEntry)) return `deployment ${deploymentId} must be an object`;
    if (!hasOnlyKeys(rawEntry, new Set(["provider", "measurement", "endpoint", "status", "notes"])))
      return `deployment ${deploymentId} has unknown fields`;
    if (!PROVIDER_IDS.has(rawEntry.provider as AttestationProviderId))
      return `deployment ${deploymentId} has an invalid provider`;
    if (!DEPLOYMENT_STATUSES.has(rawEntry.status as string))
      return `deployment ${deploymentId} has an invalid status`;
    if (!isPlainObject(rawEntry.measurement))
      return `deployment ${deploymentId} measurement must be an object`;
    if (!hasOnlyKeys(rawEntry.measurement, new Set(["imageDigest", "configHash"])))
      return `deployment ${deploymentId} measurement has unknown fields`;
    if (
      !isBoundedText(rawEntry.measurement.imageDigest, 1024) ||
      !isBoundedText(rawEntry.measurement.configHash, 1024) ||
      !addText(rawEntry.measurement.imageDigest) ||
      !addText(rawEntry.measurement.configHash)
    )
      return `deployment ${deploymentId} measurement is invalid or payload is too large`;
    if (
      rawEntry.endpoint !== undefined &&
      (!isBoundedText(rawEntry.endpoint, 2048) || !addText(rawEntry.endpoint))
    )
      return `deployment ${deploymentId} endpoint is invalid or payload is too large`;
    if (
      rawEntry.notes !== undefined &&
      (!isBoundedText(rawEntry.notes, 4096, true) || !addText(rawEntry.notes))
    )
      return `deployment ${deploymentId} notes are invalid or payload is too large`;
  }
  return null;
}

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

class RegistryPayloadLimitError extends Error {}

class RegistryJsonError extends SyntaxError {}

/**
 * Validate JSON grammar and reject duplicate decoded object names before
 * JSON.parse can apply last-key-wins semantics. Property names are decoded
 * with the platform parser, so raw and escape-equivalent spellings compare as
 * the same key.
 */
function assertUnambiguousRegistryJson(text: string): void {
  let offset = 0;
  let structuralTokens = 0;
  const fail = (message: string): never => {
    throw new RegistryJsonError(message);
  };
  const countToken = (): void => {
    structuralTokens += 1;
    if (structuralTokens > MAX_REGISTRY_JSON_STRUCTURAL_TOKENS) {
      fail("measurement registry JSON exceeded the structural token limit");
    }
  };
  const skipWhitespace = (): void => {
    while (/^[\u0009\u000a\u000d\u0020]$/.test(text[offset] ?? "")) offset += 1;
  };
  const parseString = (): string => {
    const start = offset;
    if (text[offset] !== '"') fail("measurement registry file is not valid JSON");
    countToken();
    offset += 1;
    while (offset < text.length) {
      const codeUnit = text.charCodeAt(offset);
      if (text[offset] === '"') {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset)) as string;
        } catch {
          return fail("measurement registry file is not valid JSON");
        }
      }
      if (codeUnit <= 0x1f) fail("measurement registry file is not valid JSON");
      if (text[offset] === "\\") {
        offset += 1;
        const escape = text[offset];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(offset + 1, offset + 5))) {
            fail("measurement registry file is not valid JSON");
          }
          offset += 5;
          continue;
        }
        if (!escape || !'"\\/bfnrt'.includes(escape)) {
          fail("measurement registry file is not valid JSON");
        }
      }
      offset += 1;
    }
    return fail("measurement registry file is not valid JSON");
  };
  const parseNumber = (): void => {
    if (text[offset] === "-") offset += 1;
    if (text[offset] === "0") {
      offset += 1;
    } else {
      if (!/^[1-9]$/.test(text[offset] ?? "")) fail("measurement registry file is not valid JSON");
      while (/^[0-9]$/.test(text[offset] ?? "")) offset += 1;
    }
    if (text[offset] === ".") {
      offset += 1;
      if (!/^[0-9]$/.test(text[offset] ?? "")) fail("measurement registry file is not valid JSON");
      while (/^[0-9]$/.test(text[offset] ?? "")) offset += 1;
    }
    if (text[offset] === "e" || text[offset] === "E") {
      offset += 1;
      if (text[offset] === "+" || text[offset] === "-") offset += 1;
      if (!/^[0-9]$/.test(text[offset] ?? "")) fail("measurement registry file is not valid JSON");
      while (/^[0-9]$/.test(text[offset] ?? "")) offset += 1;
    }
  };
  const parseValue = (containerDepth: number): void => {
    skipWhitespace();
    const token = text[offset];
    if (token === '"') {
      parseString();
      return;
    }
    if (token === "{" || token === "[") {
      if (containerDepth >= MAX_REGISTRY_JSON_DEPTH) {
        fail(`measurement registry JSON exceeded the maximum depth of ${MAX_REGISTRY_JSON_DEPTH}`);
      }
      countToken();
      offset += 1;
      skipWhitespace();
      if (token === "{") {
        const keys = new Set<string>();
        if (text[offset] === "}") {
          offset += 1;
          return;
        }
        while (true) {
          skipWhitespace();
          const key = parseString();
          if (keys.has(key)) fail("measurement registry JSON contains a duplicate object key");
          keys.add(key);
          skipWhitespace();
          if (text[offset] !== ":") fail("measurement registry file is not valid JSON");
          countToken();
          offset += 1;
          parseValue(containerDepth + 1);
          skipWhitespace();
          if (text[offset] === "}") {
            offset += 1;
            return;
          }
          if (text[offset] !== ",") fail("measurement registry file is not valid JSON");
          countToken();
          offset += 1;
        }
      }
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      while (true) {
        parseValue(containerDepth + 1);
        skipWhitespace();
        if (text[offset] === "]") {
          offset += 1;
          return;
        }
        if (text[offset] !== ",") fail("measurement registry file is not valid JSON");
        countToken();
        offset += 1;
      }
    }
    if (token === "-" || /^[0-9]$/.test(token ?? "")) {
      parseNumber();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return;
      }
    }
    fail("measurement registry file is not valid JSON");
  };

  parseValue(0);
  skipWhitespace();
  if (offset !== text.length) fail("measurement registry file is not valid JSON");
}

/** Parse a registry file through the same byte and complexity limits as the verifier. */
export function parseMeasurementRegistryJson(bytes: Uint8Array): MeasurementRegistryFile {
  if (bytes.byteLength > MAX_MEASUREMENT_REGISTRY_FILE_BYTES) {
    throw new Error("measurement registry file exceeded the 4 MiB ingestion limit");
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("measurement registry file is not valid UTF-8 JSON");
  }

  assertUnambiguousRegistryJson(text);
  try {
    return JSON.parse(text) as MeasurementRegistryFile;
  } catch {
    throw new Error("measurement registry file is not valid JSON");
  }
}

export function canonicalizeJson(value: unknown): string {
  const chunks: string[] = [];
  let bytes = 0;
  let nodes = 0;
  const ancestors = new Set<object>();

  const append = (chunk: string): void => {
    bytes += Buffer.byteLength(chunk, "utf8");
    if (bytes > MAX_REGISTRY_PAYLOAD_BYTES) {
      throw new RegistryPayloadLimitError("registry payload exceeded the 1 MiB limit");
    }
    chunks.push(chunk);
  };

  const visit = (entry: unknown, depth: number): void => {
    if (depth > MAX_REGISTRY_PAYLOAD_DEPTH) {
      throw new RegistryPayloadLimitError(
        `registry payload exceeded the maximum depth of ${MAX_REGISTRY_PAYLOAD_DEPTH}`,
      );
    }
    nodes += 1;
    if (nodes > MAX_REGISTRY_PAYLOAD_NODES) {
      throw new RegistryPayloadLimitError(
        `registry payload exceeded the maximum node count of ${MAX_REGISTRY_PAYLOAD_NODES}`,
      );
    }
    if (entry === null || typeof entry === "boolean") {
      append(JSON.stringify(entry));
      return;
    }
    if (typeof entry === "string") {
      if (!isWellFormedUnicode(entry)) throw new Error("JSON string contains a lone surrogate");
      if (Buffer.byteLength(entry, "utf8") > MAX_REGISTRY_PAYLOAD_BYTES) {
        throw new RegistryPayloadLimitError("registry payload exceeded the 1 MiB limit");
      }
      append(JSON.stringify(entry));
      return;
    }
    if (typeof entry === "number") {
      if (!Number.isFinite(entry)) throw new Error("non-finite JSON number");
      append(JSON.stringify(entry));
      return;
    }
    if (typeof entry !== "object") throw new Error("value is not JSON-serializable");
    if (ancestors.has(entry)) throw new Error("cyclic JSON value");
    ancestors.add(entry);
    try {
      if (Array.isArray(entry)) {
        if (entry.length > MAX_REGISTRY_PAYLOAD_NODES) {
          throw new RegistryPayloadLimitError(
            `registry payload exceeded the maximum node count of ${MAX_REGISTRY_PAYLOAD_NODES}`,
          );
        }
        const ownKeys = Reflect.ownKeys(entry);
        if (ownKeys.length !== entry.length + 1 || !ownKeys.includes("length"))
          throw new Error("sparse or decorated JSON array");
        append("[");
        for (let index = 0; index < entry.length; index += 1) {
          if (index > 0) append(",");
          const descriptor = Object.getOwnPropertyDescriptor(entry, String(index));
          if (!descriptor?.enumerable || !("value" in descriptor))
            throw new Error("sparse or decorated JSON array");
          visit(descriptor.value, depth + 1);
        }
        append("]");
        return;
      }
      if (!isPlainObject(entry)) throw new Error("value is not a plain JSON object");
      const ownKeys = Reflect.ownKeys(entry);
      if (ownKeys.length > MAX_REGISTRY_PAYLOAD_NODES) {
        throw new RegistryPayloadLimitError(
          `registry payload exceeded the maximum node count of ${MAX_REGISTRY_PAYLOAD_NODES}`,
        );
      }
      const entries = ownKeys.map((key): [string, unknown] => {
        if (typeof key !== "string" || !isWellFormedUnicode(key))
          throw new Error("JSON object has a non-JSON property key");
        const descriptor = Object.getOwnPropertyDescriptor(entry, key);
        if (!descriptor?.enumerable || !("value" in descriptor))
          throw new Error("JSON object has a non-JSON property");
        return [key, descriptor.value];
      });
      entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      append("{");
      for (const [index, [key, item]] of entries.entries()) {
        if (index > 0) append(",");
        if (Buffer.byteLength(key, "utf8") > MAX_REGISTRY_PAYLOAD_BYTES) {
          throw new RegistryPayloadLimitError("registry payload exceeded the 1 MiB limit");
        }
        append(JSON.stringify(key));
        append(":");
        visit(item, depth + 1);
      }
      append("}");
    } finally {
      ancestors.delete(entry);
    }
  };
  visit(value, 0);
  return chunks.join("");
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
  let registryPayload: MeasurementRegistryPayload;
  let canonicalPayload: string;
  let signatureValues: unknown[];
  try {
    const envelope = snapshotDataProperties(registry, new Set(["payload", "signatures"]));
    if (!envelope || !("payload" in envelope) || !("signatures" in envelope)) {
      return { ok: false, reason: "malformed measurement registry" };
    }
    const signatureLength = Object.getOwnPropertyDescriptor(
      envelope.signatures as object,
      "length",
    );
    if (
      signatureLength &&
      "value" in signatureLength &&
      Number.isSafeInteger(signatureLength.value) &&
      signatureLength.value > MAX_REGISTRY_SIGNATURES
    ) {
      return {
        ok: false,
        reason: `registry has too many signatures (max ${MAX_REGISTRY_SIGNATURES})`,
      };
    }
    const signatures = snapshotBoundedArray(envelope.signatures, MAX_REGISTRY_SIGNATURES);
    if (!signatures) {
      return { ok: false, reason: "malformed measurement registry" };
    }
    signatureValues = signatures;
    canonicalPayload = canonicalizeJson(envelope.payload);
    registryPayload = JSON.parse(canonicalPayload) as MeasurementRegistryPayload;
  } catch (error) {
    if (error instanceof RegistryPayloadLimitError) {
      return { ok: false, reason: error.message };
    }
    return { ok: false, reason: "malformed measurement registry" };
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
  let payloadError: string | null;
  try {
    payloadError = validateRegistryPayload(registryPayload);
  } catch {
    return { ok: false, reason: "malformed measurement registry payload" };
  }
  if (payloadError) return { ok: false, reason: payloadError };
  let payload: Buffer;
  try {
    payload = Buffer.from(canonicalPayload);
  } catch (error) {
    if (error instanceof RegistryPayloadLimitError) {
      return { ok: false, reason: error.message };
    }
    return { ok: false, reason: "registry payload is not canonicalizable JSON" };
  }
  if (payload.byteLength > MAX_REGISTRY_PAYLOAD_BYTES) {
    return { ok: false, reason: "registry payload exceeded the 1 MiB limit" };
  }

  // SEC-086: bind registry metadata so signed files cannot be swapped across
  // environments or replayed to roll back retired measurements.
  if (options?.expectedRegistryId && registryPayload.registryId !== options.expectedRegistryId) {
    return {
      ok: false,
      reason: `registryId mismatch: expected ${options.expectedRegistryId}, got ${registryPayload.registryId}`,
    };
  }
  if (options?.minimumUpdatedAt) {
    const updatedAt = Date.parse(registryPayload.updatedAt);
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
        reason: `registry updatedAt ${registryPayload.updatedAt} is older than minimum ${options.minimumUpdatedAt}`,
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
  const parsedSignatures: Array<{
    signature: MeasurementRegistrySignature;
    key: ReturnType<typeof createPublicKey>;
    fingerprint: string;
    signatureBytes: Buffer;
  }> = [];
  try {
    for (const value of signatureValues) {
      const signatureRecord = snapshotDataProperties(
        value,
        new Set(["keyId", "algorithm", "publicKeyPem", "signatureBase64"]),
      );
      if (!signatureRecord) {
        return { ok: false, reason: "registry has a malformed signature entry" };
      }
      const signature = signatureRecord as unknown as MeasurementRegistrySignature;
      if (
        signature.algorithm !== "ed25519" ||
        typeof signature.keyId !== "string" ||
        !REGISTRY_ID_PATTERN.test(signature.keyId)
      ) {
        return { ok: false, reason: "registry has a malformed signature entry" };
      }
      const parsed = parseEd25519PublicKey(signature.publicKeyPem);
      const signatureBytes = decodeEd25519Signature(signature.signatureBase64);
      if (!parsed || !signatureBytes) {
        return { ok: false, reason: "registry has a malformed signature entry" };
      }
      parsedSignatures.push({ signature, ...parsed, signatureBytes });
    }
  } catch {
    return { ok: false, reason: "registry has a malformed signature entry" };
  }
  const candidateSignatures = parsedSignatures.filter(
    ({ signature, fingerprint }) =>
      (!trustedIds || trustedIds.has(signature.keyId)) &&
      (!trustedFingerprints || trustedFingerprints.has(fingerprint)),
  );
  if (candidateSignatures.length < requiredSignatureCount) {
    return {
      ok: false,
      reason: `registry has ${candidateSignatures.length} trusted signature candidate(s), needs ${requiredSignatureCount}`,
    };
  }

  // SEC-008: count DISTINCT keys, not signature array entries — the same
  // signature pasted twice must not satisfy a two-person quorum.
  const validKeyFingerprints = new Set<string>();
  for (const candidate of candidateSignatures) {
    try {
      const valid = verifySignature(null, payload, candidate.key, candidate.signatureBytes);
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
  let registryPayload: MeasurementRegistryPayload;
  let payloadError: string | null;
  try {
    const envelope = snapshotDataProperties(registry, new Set(["payload", "signatures"]));
    if (!envelope || !("payload" in envelope) || !("signatures" in envelope)) {
      return { ok: false, reason: "malformed measurement registry payload" };
    }
    registryPayload = JSON.parse(canonicalizeJson(envelope.payload)) as MeasurementRegistryPayload;
    payloadError = validateRegistryPayload(registryPayload);
  } catch {
    return { ok: false, reason: "malformed measurement registry payload" };
  }
  if (payloadError) return { ok: false, reason: payloadError };
  let quoteSnapshot: Omit<AttestationQuote, "measurement"> & {
    measurement: AttestationQuote["measurement"];
  };
  let malformedQuote: boolean;
  try {
    const quoteRecord = snapshotDataProperties(
      quote,
      new Set(["provider", "measurement", "timestamp", "verified", "raw"]),
    );
    const measurement = snapshotDataProperties(
      quoteRecord?.measurement,
      new Set(["imageDigest", "configHash"]),
    );
    if (!quoteRecord || !measurement) {
      return { ok: false, reason: "malformed attestation quote" };
    }
    quoteSnapshot = {
      ...(quoteRecord as unknown as Omit<AttestationQuote, "measurement">),
      measurement: measurement as unknown as AttestationQuote["measurement"],
    };
    const timestamp = quoteSnapshot.timestamp;
    malformedQuote =
      typeof quoteSnapshot.verified !== "boolean" ||
      !PROVIDER_IDS.has(quoteSnapshot.provider as AttestationProviderId) ||
      !isBoundedText(quoteSnapshot.measurement.imageDigest, 1024) ||
      !isBoundedText(quoteSnapshot.measurement.configHash, 1024) ||
      !isBoundedText(timestamp, 64) ||
      !Number.isFinite(Date.parse(timestamp)) ||
      new Date(timestamp).toISOString() !== timestamp;
  } catch {
    return { ok: false, reason: "malformed attestation quote" };
  }
  if (malformedQuote) return { ok: false, reason: "malformed attestation quote" };
  if (typeof deployment !== "string" || !REGISTRY_ID_PATTERN.test(deployment))
    return { ok: false, reason: "malformed deployment id" };
  const entry = Object.hasOwn(registryPayload.deployments, deployment)
    ? registryPayload.deployments[deployment]
    : undefined;
  if (!entry) return { ok: false, reason: `unknown deployment: ${deployment}` };
  if (entry.status !== "active")
    return { ok: false, reason: `deployment ${deployment} is ${entry.status}` };
  if (!quoteSnapshot.verified)
    return { ok: false, reason: "quote was not cryptographically verified" };
  if (entry.provider !== quoteSnapshot.provider) {
    return {
      ok: false,
      reason: `provider mismatch: expected ${entry.provider}, got ${quoteSnapshot.provider}`,
    };
  }
  if (entry.measurement.imageDigest !== quoteSnapshot.measurement.imageDigest) {
    return { ok: false, reason: "image digest mismatch" };
  }
  if (entry.measurement.configHash !== quoteSnapshot.measurement.configHash) {
    return { ok: false, reason: "config hash mismatch" };
  }
  return { ok: true, matchedDeployment: deployment };
}
