import {
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import { executionAuthorizationNonces, getDb, policies } from "@stwd/db";
import {
  canonicalJsonStringify,
  type ExecutionAuthorization,
  type ExecutionCapability,
  type NormalizedEvmExecutionPayload,
  normalizeEvmExecutionPayload,
  type PolicyRule,
  type ProviderExecutionCommitmentV2,
  providerExecutionSignatureInput,
  type SignRequest,
} from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";

export const EXECUTION_AUTHORIZATION_TTL_MS = 60_000;
const EXECUTION_AUTHORIZATION_HKDF_INFO = "steward:execution-authorization:hmac:v1";
const EXECUTION_AUTHORIZATION_HKDF_SALT = "steward:execution-authorization:salt:v1";

export class ExecutionAuthorizationError extends Error {
  constructor(
    message: string,
    readonly code:
      | "missing_signature"
      | "invalid_signature"
      | "expired"
      | "context_mismatch"
      | "nonce_consumed"
      | "secret_unavailable",
  ) {
    super(message);
    this.name = "ExecutionAuthorizationError";
  }
}

export function canonicalJson(value: unknown): string {
  return canonicalJsonStringify(value);
}

export function sha256Hex(value: unknown): string {
  return createHash("sha256").update(canonicalJsonStringify(value)).digest("hex");
}

/**
 * Canonical normalized EVM sign intent. Delegates to the SINGLE shared
 * normalizer so the API minting side and the GovernedVault verification side
 * digest byte-identical payloads. Throws on malformed numeric caller fields.
 */
export function executionPayloadForEvmSign(request: SignRequest): NormalizedEvmExecutionPayload {
  return normalizeEvmExecutionPayload(request);
}

export function executionPayloadDigestForEvmSign(request: SignRequest): string {
  return sha256Hex(executionPayloadForEvmSign(request));
}

export async function policyRevisionHashForAgent(agentId: string): Promise<string> {
  const rows = await getDb()
    .select({
      id: policies.id,
      type: policies.type,
      enabled: policies.enabled,
      config: policies.config,
      updatedAt: policies.updatedAt,
    })
    .from(policies)
    .where(eq(policies.agentId, agentId));
  return sha256Hex(
    rows
      .map((row) => ({
        id: row.id,
        type: row.type,
        enabled: row.enabled,
        config: row.config,
        updatedAt: row.updatedAt.toISOString(),
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  );
}

export function policyRevisionHashForPolicySet(policySet: readonly PolicyRule[]): string {
  return sha256Hex(
    policySet
      .map((policy) => ({
        id: policy.id,
        type: policy.type,
        enabled: policy.enabled,
        config: policy.config,
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  );
}

export interface MintExecutionAuthorizationInput {
  requestId: string;
  tenantId: string;
  agentId: string;
  capability: ExecutionCapability;
  payloadDigest: string;
  backend: ExecutionAuthorization["backend"];
  policyRevisionHash?: string;
  approvalId?: string;
  idempotencyKey?: string;
  now?: Date;
}

export async function mintExecutionAuthorization(
  input: MintExecutionAuthorizationInput,
): Promise<ExecutionAuthorization> {
  const now = input.now ?? new Date();
  const expiresAt = new Date(now.getTime() + EXECUTION_AUTHORIZATION_TTL_MS);
  const authorization: ExecutionAuthorization = {
    id: randomUUID(),
    requestId: input.requestId,
    tenantId: input.tenantId,
    agentId: input.agentId,
    capability: input.capability,
    payloadDigest: input.payloadDigest,
    backend: input.backend,
    policyRevisionHash: input.policyRevisionHash,
    approvalId: input.approvalId,
    nonce: base64Url(randomBytes(24)),
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    status: "active",
    idempotencyKey: input.idempotencyKey,
  };
  authorization.signature = signExecutionAuthorization(authorization);

  await getDb().insert(executionAuthorizationNonces).values({
    authorizationId: authorization.id,
    requestId: authorization.requestId,
    tenantId: authorization.tenantId,
    agentId: authorization.agentId,
    capability: authorization.capability,
    backend: authorization.backend,
    payloadDigest: authorization.payloadDigest,
    policyRevisionHash: authorization.policyRevisionHash,
    approvalId: authorization.approvalId,
    nonce: authorization.nonce,
    signature: authorization.signature,
    idempotencyKey: authorization.idempotencyKey,
    status: "active",
    issuedAt: now,
    expiresAt,
  });

  return authorization;
}

export interface ConsumeExecutionAuthorizationContext {
  tenantId: string;
  agentId: string;
  capability: ExecutionCapability;
  backend: ExecutionAuthorization["backend"];
  payloadDigest: string;
}

export async function consumeExecutionAuthorization(
  authorization: ExecutionAuthorization,
  expected: ConsumeExecutionAuthorizationContext,
): Promise<void> {
  verifyExecutionAuthorization(authorization, expected);
  const [row] = await getDb()
    .update(executionAuthorizationNonces)
    .set({ status: "consumed", consumedAt: new Date() })
    .where(
      and(
        eq(executionAuthorizationNonces.authorizationId, authorization.id),
        eq(executionAuthorizationNonces.nonce, authorization.nonce),
        eq(executionAuthorizationNonces.status, "active"),
        sql`${executionAuthorizationNonces.expiresAt} > now()`,
      ),
    )
    .returning({ id: executionAuthorizationNonces.id });
  if (!row) {
    throw new ExecutionAuthorizationError(
      "Execution authorization nonce is expired or already consumed",
      Date.parse(authorization.expiresAt) <= Date.now() ? "expired" : "nonce_consumed",
    );
  }
}

export function verifyExecutionAuthorization(
  authorization: ExecutionAuthorization,
  expected: ConsumeExecutionAuthorizationContext,
): void {
  if (!authorization.signature) {
    throw new ExecutionAuthorizationError(
      "Execution authorization is missing a signature",
      "missing_signature",
    );
  }
  if (Date.parse(authorization.expiresAt) <= Date.now()) {
    throw new ExecutionAuthorizationError("Execution authorization has expired", "expired");
  }
  if (
    authorization.tenantId !== expected.tenantId ||
    authorization.agentId !== expected.agentId ||
    authorization.capability !== expected.capability ||
    authorization.backend !== expected.backend ||
    authorization.payloadDigest !== expected.payloadDigest ||
    authorization.status !== "active"
  ) {
    throw new ExecutionAuthorizationError(
      "Execution authorization context does not match the signing request",
      "context_mismatch",
    );
  }
  const expectedSignature = signExecutionAuthorization(authorization);
  if (!constantTimeEqual(authorization.signature, expectedSignature)) {
    throw new ExecutionAuthorizationError(
      "Execution authorization signature is invalid",
      "invalid_signature",
    );
  }
}

function signExecutionAuthorization(authorization: ExecutionAuthorization): string {
  return base64Url(
    createHmac("sha256", executionAuthorizationKey())
      .update(canonicalJson(signaturePayload(authorization)))
      .digest(),
  );
}

function executionAuthorizationKey(): Uint8Array {
  const secret = process.env.STEWARD_JWT_SECRET?.trim();
  if (!secret) {
    throw new ExecutionAuthorizationError(
      "STEWARD_JWT_SECRET is required for execution authorization",
      "secret_unavailable",
    );
  }
  const key = hkdfSync(
    "sha256",
    new TextEncoder().encode(secret),
    new TextEncoder().encode(EXECUTION_AUTHORIZATION_HKDF_SALT),
    new TextEncoder().encode(EXECUTION_AUTHORIZATION_HKDF_INFO),
    32,
  );
  return key instanceof ArrayBuffer ? new Uint8Array(key) : (key as Uint8Array);
}

function signaturePayload(authorization: ExecutionAuthorization): Record<string, unknown> {
  return {
    id: authorization.id,
    requestId: authorization.requestId,
    tenantId: authorization.tenantId,
    agentId: authorization.agentId,
    capability: authorization.capability,
    payloadDigest: authorization.payloadDigest,
    backend: authorization.backend,
    policyRevisionHash: authorization.policyRevisionHash ?? null,
    approvalId: authorization.approvalId ?? null,
    nonce: authorization.nonce,
    issuedAt: authorization.issuedAt,
    expiresAt: authorization.expiresAt,
    status: authorization.status,
    idempotencyKey: authorization.idempotencyKey ?? null,
  };
}

function constantTimeEqual(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBuffer = encoder.encode(left);
  const rightBuffer = encoder.encode(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function base64Url(value: Uint8Array): string {
  const binary = Array.from(value, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// ─────────────────────────────────────────────────────────────────────────────
// PR4: provider execution authorization v2 signing (spec §3.2)
//
// v2 uses STEWARD_EXECUTION_AUTH_SECRET, SEPARATE from STEWARD_JWT_SECRET, with
// domain-separated HKDF + a keyId rotation list. The active (first) key signs;
// all listed keys verify for the token TTL window. If the secret is absent at
// mint OR claim we FAIL CLOSED (X7) and NEVER fall back to STEWARD_JWT_SECRET.
// Wallet/EVM v1 (above) is untouched.
// ─────────────────────────────────────────────────────────────────────────────

const EXECUTION_AUTH_V2_HKDF_SALT = "steward:execution-authorization:v2:salt";
const EXECUTION_AUTH_V2_HKDF_INFO = "steward:execution-authorization:v2:hmac";

export class ProviderExecutionAuthV2Error extends Error {
  constructor(
    message: string,
    readonly code: "secret_unavailable" | "unknown_key" | "signature_invalid",
  ) {
    super(message);
    this.name = "ProviderExecutionAuthV2Error";
  }
}

interface V2KeyEntry {
  keyId: string;
  key: Uint8Array;
}

/**
 * Parse STEWARD_EXECUTION_AUTH_SECRET into a keyId->key rotation list.
 *
 * Format is a comma-separated list of `keyId:secret` pairs; the FIRST entry is
 * the active signing key, all entries verify. A bare secret with no `keyId:`
 * prefix is treated as a single key with the reserved keyId `v2-default`.
 *
 * Each key is HKDF-derived with distinct salt/info from v1 so the derived keys
 * can never collide with the v1 (STEWARD_JWT_SECRET) key material.
 */
function loadExecutionAuthV2Keys(): V2KeyEntry[] {
  const raw = process.env.STEWARD_EXECUTION_AUTH_SECRET?.trim();
  if (!raw) {
    throw new ProviderExecutionAuthV2Error(
      "STEWARD_EXECUTION_AUTH_SECRET is required for provider execution authorization v2",
      "secret_unavailable",
    );
  }
  const entries: V2KeyEntry[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (trimmed.length === 0) continue;
    // `keyId:secret` — split on the FIRST colon only (secret may contain colons).
    const idx = trimmed.indexOf(":");
    let keyId: string;
    let secret: string;
    if (idx === -1) {
      keyId = "v2-default";
      secret = trimmed;
    } else {
      keyId = trimmed.slice(0, idx).trim();
      secret = trimmed.slice(idx + 1).trim();
    }
    if (keyId.length === 0 || secret.length === 0) continue;
    if (seen.has(keyId)) continue;
    seen.add(keyId);
    const derived = hkdfSync(
      "sha256",
      new TextEncoder().encode(secret),
      new TextEncoder().encode(EXECUTION_AUTH_V2_HKDF_SALT),
      new TextEncoder().encode(EXECUTION_AUTH_V2_HKDF_INFO),
      32,
    );
    entries.push({
      keyId,
      key: derived instanceof ArrayBuffer ? new Uint8Array(derived) : (derived as Uint8Array),
    });
  }
  if (entries.length === 0) {
    throw new ProviderExecutionAuthV2Error(
      "STEWARD_EXECUTION_AUTH_SECRET contained no usable key entries",
      "secret_unavailable",
    );
  }
  return entries;
}

/** The active (first) v2 keyId + key used for minting. Fails closed if absent. */
export function activeExecutionAuthV2Key(): V2KeyEntry {
  return loadExecutionAuthV2Keys()[0];
}

/** True if a v2 secret is configured (used by config-prereq checks). */
export function isExecutionAuthV2SecretConfigured(): boolean {
  try {
    loadExecutionAuthV2Keys();
    return true;
  } catch {
    return false;
  }
}

/**
 * Sign a v2 commitment with the ACTIVE key. The signature is
 * base64url(HMAC(v2Key, SIG_DOMAIN || JCS(commitment))). The commitment MUST
 * already carry `keyId = activeExecutionAuthV2Key().keyId`. Fails closed if the
 * secret is absent.
 */
export function signProviderExecutionCommitmentV2(
  commitment: ProviderExecutionCommitmentV2,
): string {
  const keys = loadExecutionAuthV2Keys();
  const active = keys[0];
  if (commitment.keyId !== active.keyId) {
    // Only the active key mints; a mismatch is a programming error, fail closed.
    throw new ProviderExecutionAuthV2Error(
      "commitment keyId does not match the active signing key",
      "unknown_key",
    );
  }
  return base64Url(
    createHmac("sha256", active.key)
      .update(providerExecutionSignatureInput(commitment))
      .digest(),
  );
}

/**
 * Verify a v2 signature against the commitment. The commitment's `keyId` selects
 * the verifying key from the rotation list (all listed keys verify for the TTL
 * window). Returns true only if that key produces the exact signature. Fails
 * closed (throws) if the secret is absent; returns false for an unknown keyId or
 * a bad signature.
 */
export function verifyProviderExecutionCommitmentV2(
  commitment: ProviderExecutionCommitmentV2,
  signature: string,
): boolean {
  const keys = loadExecutionAuthV2Keys();
  const entry = keys.find((k) => k.keyId === commitment.keyId);
  if (!entry) return false;
  const expected = base64Url(
    createHmac("sha256", entry.key)
      .update(providerExecutionSignatureInput(commitment))
      .digest(),
  );
  return constantTimeEqual(signature, expected);
}
