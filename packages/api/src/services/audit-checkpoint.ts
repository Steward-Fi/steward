/**
 * Ed25519 audit checkpoint signer.
 *
 * The per-tenant audit chain (services/audit.ts) is tamper-evident but keyed
 * with a SYMMETRIC HMAC secret: only the operator (who holds
 * STEWARD_AUDIT_HMAC_KEY) can verify it. An third-party auditor cannot
 * independently confirm the chain without being handed that secret — which
 * would also let them forge it.
 *
 * A checkpoint fixes this. At bundle time we sign a small, canonical statement
 * about the chain head with an Ed25519 PRIVATE key (STEWARD_AUDIT_SIGNING_KEY)
 * whose PUBLIC key can be published freely. Anyone holding only the public key
 * can verify:
 *   - the operator asserted "at time T, tenant X's chain head was seq=N with
 *     hmac=H, containing `expectedCount` events above `floorSeq`",
 *   - and that assertion has not been altered.
 *
 * Combined with the exported event list (whose linkage an auditor recomputes
 * locally — see scripts/verify-evidence-bundle.mjs), this proves the exported
 * set is exactly the set the operator committed to at signing time.
 *
 * WHAT A CHECKPOINT DOES NOT PROVE: it does not prevent an operator who holds
 * BOTH the HMAC key and the signing key from constructing a self-consistent but
 * fabricated history and then signing it. The Ed25519 signature raises the bar
 * from "trust the operator's secret HMAC" to "trust the operator's published,
 * append-only, third-partyly-witnessable checkpoints"; anchoring beyond that
 * (third-party timestamping / transparency log) is explicitly out of scope for v1.
 *
 * Zero new dependencies: uses node:crypto Ed25519 primitives.
 */

import { createPrivateKey, createPublicKey, type KeyObject, sign, verify } from "node:crypto";

// This package is typechecked with @cloudflare/workers-types in scope, whose
// `Buffer` shadows Node's and lacks `concat` / "base64". We therefore avoid
// `Buffer` entirely and work with `Uint8Array` + the tiny encoders below.

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function utf8ToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Canonical checkpoint payload. Field order here is NOT authoritative — the
 * signed bytes come from `canonicalCheckpointBytes`, which sorts keys. */
export interface CheckpointPayload {
  /** Schema version of the checkpoint payload. */
  v: 1;
  /** Tenant whose chain this checkpoint commits to. */
  tenantId: string;
  /** Sequence number of the chain head at checkpoint time. */
  seq: number;
  /** Hex-encoded HMAC of the head event. */
  headHmac: string;
  /** Number of live events at/above `floorSeq` committed by this checkpoint. */
  expectedCount: number;
  /** Retention floor: events at or below this seq have been archived+dropped. */
  floorSeq: number;
  /** ISO-8601 timestamp the checkpoint was produced. */
  timestamp: string;
  /** Software version that produced the checkpoint (provenance breadcrumb). */
  softwareVersion: string;
}

export interface SignedCheckpoint {
  payload: CheckpointPayload;
  /** Base64 Ed25519 signature over `canonicalCheckpointBytes(payload)`. */
  signature: string;
  /** SPKI PEM of the Ed25519 public key (safe to publish). */
  publicKey: string;
}

/**
 * Deterministic canonical JSON encoding of a checkpoint payload.
 *
 * Keys are sorted; there is no insignificant whitespace. This is the EXACT byte
 * sequence that gets signed and that the offline verifier must reconstruct. Any
 * change to a field (or key ordering) changes the signed bytes, so a verifier
 * that reconstructs it independently detects any post-signing mutation.
 */
export function canonicalCheckpointBytes(payload: CheckpointPayload): Uint8Array {
  const ordered: Record<string, unknown> = {};
  const source = payload as unknown as Record<string, unknown>;
  for (const key of Object.keys(source).sort()) {
    ordered[key] = source[key];
  }
  return utf8ToBytes(JSON.stringify(ordered));
}

class AuditSigningKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditSigningKeyError";
  }
}

export { AuditSigningKeyError };

const ED25519_SEED_LEN = 32;
// PKCS#8 DER prefix for an Ed25519 private key carrying a raw 32-byte seed.
// (SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET
// STRING <32 bytes> } }). Prepending this to a raw seed yields a DER a
// KeyObject can import — lets us accept bare 32-byte seeds with no new deps.
const PKCS8_ED25519_SEED_PREFIX = hexToBytes("302e020100300506032b657004220420");

function seedToPkcs8Der(seed: Uint8Array): Uint8Array {
  return concatBytes(PKCS8_ED25519_SEED_PREFIX, seed);
}

function looksLikePem(value: string): boolean {
  return value.includes("-----BEGIN");
}

function tryDecodeHex(value: string): Uint8Array | null {
  const trimmed = value.trim();
  if (trimmed.length === ED25519_SEED_LEN * 2 && /^[0-9a-fA-F]+$/.test(trimmed)) {
    return hexToBytes(trimmed);
  }
  return null;
}

function tryDecodeBase64Seed(value: string): Uint8Array | null {
  const trimmed = value.trim();
  // Base64 (or base64url) of a 32-byte seed is 43 chars (no pad) or 44 (padded).
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) return null;
  let decoded: Uint8Array;
  try {
    decoded = base64ToBytes(trimmed);
  } catch {
    return null;
  }
  return decoded.length === ED25519_SEED_LEN ? decoded : null;
}

/**
 * Parse STEWARD_AUDIT_SIGNING_KEY into an Ed25519 private KeyObject. Accepts:
 *   - PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----")
 *   - raw 32-byte seed as hex (64 chars)
 *   - raw 32-byte seed as base64 / base64url
 *
 * Throws AuditSigningKeyError on anything that isn't one of those, or that
 * parses but isn't an Ed25519 key.
 */
export function parseSigningKey(raw: string): KeyObject {
  const value = (raw ?? "").trim();
  if (value.length === 0) {
    throw new AuditSigningKeyError("STEWARD_AUDIT_SIGNING_KEY is empty");
  }

  let key: KeyObject;
  if (looksLikePem(value)) {
    try {
      key = createPrivateKey({ key: value, format: "pem" });
    } catch (err) {
      throw new AuditSigningKeyError(
        `STEWARD_AUDIT_SIGNING_KEY is not a valid PEM private key: ${(err as Error).message}`,
      );
    }
  } else {
    const seed = tryDecodeHex(value) ?? tryDecodeBase64Seed(value);
    if (!seed) {
      throw new AuditSigningKeyError(
        "STEWARD_AUDIT_SIGNING_KEY must be a PKCS#8 PEM, a 32-byte hex seed (64 hex chars), " +
          "or a 32-byte base64/base64url seed. Generate one with: " +
          "openssl genpkey -algorithm ed25519 -out audit-signing.pem",
      );
    }
    try {
      // Node accepts a Uint8Array here at runtime; the DER key-input type is
      // narrowed to Buffer, which @cloudflare/workers-types shadows in this
      // package, so widen through unknown.
      key = createPrivateKey({
        key: seedToPkcs8Der(seed) as unknown as string,
        format: "der",
        type: "pkcs8",
      });
    } catch (err) {
      throw new AuditSigningKeyError(
        `STEWARD_AUDIT_SIGNING_KEY seed could not be imported: ${(err as Error).message}`,
      );
    }
  }

  if (key.asymmetricKeyType !== "ed25519") {
    throw new AuditSigningKeyError(
      `STEWARD_AUDIT_SIGNING_KEY must be an Ed25519 key, got ${key.asymmetricKeyType ?? "unknown"}`,
    );
  }
  return key;
}

/** SPKI PEM of the public half of an Ed25519 private key. */
export function publicKeyPem(privateKey: KeyObject): string {
  const pub = createPublicKey(privateKey);
  return pub.export({ format: "pem", type: "spki" }).toString();
}

export interface AuditCheckpointSigner {
  sign(payload: CheckpointPayload): SignedCheckpoint;
  readonly publicKeyPem: string;
}

/**
 * Build a signer from an explicit key string. Prefer `getCheckpointSigner`
 * (env-backed, cached) in application code; this exists for tests and for the
 * bundle route to construct a signer from configured env.
 */
export function createCheckpointSigner(rawKey: string): AuditCheckpointSigner {
  const privateKey = parseSigningKey(rawKey);
  const pubPem = publicKeyPem(privateKey);
  return {
    publicKeyPem: pubPem,
    sign(payload: CheckpointPayload): SignedCheckpoint {
      const bytes = canonicalCheckpointBytes(payload);
      // Ed25519 uses `null` for the digest algorithm (PureEdDSA).
      const signature = sign(null, bytes, privateKey);
      return {
        payload,
        signature: bytesToBase64(new Uint8Array(signature)),
        publicKey: pubPem,
      };
    },
  };
}

let cachedSigner: AuditCheckpointSigner | null = null;
let cachedSignerKeySource: string | null = null;

/**
 * Whether an audit signing key is configured. Callers (bundle route) use this
 * to decide between hard-fail (production) and disabled-with-warning (dev).
 */
export function isCheckpointSigningConfigured(): boolean {
  const env = process.env.STEWARD_AUDIT_SIGNING_KEY;
  return typeof env === "string" && env.trim().length > 0;
}

/**
 * Cached env-backed signer. Throws AuditSigningKeyError if
 * STEWARD_AUDIT_SIGNING_KEY is unset or invalid — callers must gate on
 * `isCheckpointSigningConfigured()` first if they want to handle absence
 * gracefully.
 */
export function getCheckpointSigner(): AuditCheckpointSigner {
  const env = process.env.STEWARD_AUDIT_SIGNING_KEY ?? "";
  if (env.trim().length === 0) {
    throw new AuditSigningKeyError(
      "STEWARD_AUDIT_SIGNING_KEY is not configured. Generate one with: " +
        "openssl genpkey -algorithm ed25519 -out audit-signing.pem",
    );
  }
  if (cachedSigner && cachedSignerKeySource === env) {
    return cachedSigner;
  }
  cachedSigner = createCheckpointSigner(env);
  cachedSignerKeySource = env;
  return cachedSigner;
}

/** Test hook: drop the cached signer so a changed env var takes effect. */
export function resetCheckpointSignerCache(): void {
  cachedSigner = null;
  cachedSignerKeySource = null;
}

/**
 * Verify a signed checkpoint with its embedded public key. Used by the online
 * bundle path as a self-check; the authoritative third-party check is the
 * standalone offline verifier.
 */
export function verifyCheckpoint(checkpoint: SignedCheckpoint): boolean {
  try {
    const pub = createPublicKey({ key: checkpoint.publicKey, format: "pem" });
    if (pub.asymmetricKeyType !== "ed25519") return false;
    return verify(
      null,
      canonicalCheckpointBytes(checkpoint.payload),
      pub,
      base64ToBytes(checkpoint.signature),
    );
  } catch {
    return false;
  }
}
