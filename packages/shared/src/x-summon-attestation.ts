import { createPublicKey, verify } from "node:crypto";
import { jcsStringify, sha256HexPrefixed } from "./provider-action.js";

export const X_SUMMON_ATTESTATION_SCHEMA = "steward.x-summon-attestation.v1" as const;
export const X_SUMMON_ATTESTATION_DOMAIN = "steward.x-summon-attestation.v1\n" as const;
const MAX_VALIDITY_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 30_000;
const EXACT_KEYS = new Set([
  "schemaVersion",
  "keyId",
  "tenantId",
  "workspaceId",
  "actorAgentId",
  "providerAccountId",
  "operationKey",
  "sourcePostId",
  "idempotencyKeyHash",
  "summoned",
  "attestedAt",
  "expiresAt",
  "signature",
]);
const RFC3339_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const B64URL_64 = /^[A-Za-z0-9_-]{86}$/;
const B64URL_32 = /^[A-Za-z0-9_-]{43}$/;

export interface XSummonAttestationV1 {
  schemaVersion: typeof X_SUMMON_ATTESTATION_SCHEMA;
  keyId: string;
  tenantId: string;
  workspaceId: string;
  actorAgentId: string;
  providerAccountId: string;
  operationKey: "x.tweet.create";
  sourcePostId: string;
  idempotencyKeyHash: string;
  summoned: true;
  attestedAt: string;
  expiresAt: string;
  signature: string;
}

export interface XSummonAttestationExpected {
  tenantId: string;
  workspaceId: string;
  actorAgentId: string;
  providerAccountId: string;
  sourcePostId: string;
  idempotencyKeyHash: string;
}

function canonicalClaims(a: XSummonAttestationV1): Record<string, unknown> {
  return {
    schemaVersion: a.schemaVersion,
    keyId: a.keyId,
    tenantId: a.tenantId,
    workspaceId: a.workspaceId,
    actorAgentId: a.actorAgentId,
    providerAccountId: a.providerAccountId,
    operationKey: a.operationKey,
    sourcePostId: a.sourcePostId,
    idempotencyKeyHash: a.idempotencyKeyHash,
    summoned: a.summoned,
    attestedAt: a.attestedAt,
    expiresAt: a.expiresAt,
  };
}

export function xSummonAttestationSignatureInput(a: XSummonAttestationV1): string {
  return `${X_SUMMON_ATTESTATION_DOMAIN}${jcsStringify(canonicalClaims(a))}`;
}

export function computeXSummonAttestationDigest(a: XSummonAttestationV1): string {
  return sha256HexPrefixed(jcsStringify({ ...canonicalClaims(a), signature: a.signature }));
}

function parseAttestation(value: unknown): XSummonAttestationV1 | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const a = value as Record<string, unknown>;
  if (
    Object.keys(a).some((key) => !EXACT_KEYS.has(key)) ||
    Object.keys(a).length !== EXACT_KEYS.size
  )
    return null;
  if (
    a.schemaVersion !== X_SUMMON_ATTESTATION_SCHEMA ||
    typeof a.keyId !== "string" ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(a.keyId) ||
    typeof a.tenantId !== "string" ||
    typeof a.workspaceId !== "string" ||
    typeof a.actorAgentId !== "string" ||
    typeof a.providerAccountId !== "string" ||
    a.operationKey !== "x.tweet.create" ||
    typeof a.sourcePostId !== "string" ||
    !/^[0-9]{1,25}$/.test(a.sourcePostId) ||
    typeof a.idempotencyKeyHash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(a.idempotencyKeyHash) ||
    a.summoned !== true ||
    typeof a.attestedAt !== "string" ||
    !RFC3339_MILLIS.test(a.attestedAt) ||
    typeof a.expiresAt !== "string" ||
    !RFC3339_MILLIS.test(a.expiresAt) ||
    typeof a.signature !== "string" ||
    !B64URL_64.test(a.signature)
  )
    return null;
  return a as unknown as XSummonAttestationV1;
}

function readKey(keysJson: string | undefined, keyId: string): Uint8Array | null {
  if (!keysJson || keysJson.length > 16 * 1024) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(keysJson);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length === 0 || entries.length > 16) return null;
  for (const [id, value] of entries) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id) || typeof value !== "string" || !B64URL_32.test(value))
      return null;
  }
  const encoded = (parsed as Record<string, string>)[keyId];
  return encoded ? new Uint8Array(Buffer.from(encoded, "base64url")) : null;
}

export type XSummonAttestationVerification =
  | { ok: true; attestation: XSummonAttestationV1; digest: string }
  | { ok: false; reason: string };

export function verifyXSummonAttestation(
  value: unknown,
  expected: XSummonAttestationExpected,
  keysJson: string | undefined,
  now = new Date(),
): XSummonAttestationVerification {
  const a = parseAttestation(value);
  if (!a) return { ok: false, reason: "malformed" };
  if (
    a.tenantId !== expected.tenantId ||
    a.workspaceId !== expected.workspaceId ||
    a.actorAgentId !== expected.actorAgentId ||
    a.providerAccountId !== expected.providerAccountId ||
    a.sourcePostId !== expected.sourcePostId ||
    a.idempotencyKeyHash !== expected.idempotencyKeyHash
  )
    return { ok: false, reason: "binding_mismatch" };
  const attestedAt = Date.parse(a.attestedAt);
  const expiresAt = Date.parse(a.expiresAt);
  if (
    !Number.isFinite(attestedAt) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= attestedAt ||
    expiresAt - attestedAt > MAX_VALIDITY_MS ||
    attestedAt > now.getTime() + MAX_FUTURE_SKEW_MS ||
    expiresAt <= now.getTime()
  )
    return { ok: false, reason: "stale" };
  const rawKey = readKey(keysJson, a.keyId);
  if (!rawKey || rawKey.byteLength !== 32) return { ok: false, reason: "unknown_key" };
  try {
    const derPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKey = createPublicKey({
      key: Buffer.concat([derPrefix, Buffer.from(rawKey)]),
      format: "der",
      type: "spki",
    });
    const valid = verify(
      null,
      Buffer.from(xSummonAttestationSignatureInput(a), "utf8"),
      publicKey,
      Buffer.from(a.signature, "base64url"),
    );
    return valid
      ? { ok: true, attestation: a, digest: computeXSummonAttestationDigest(a) }
      : { ok: false, reason: "signature_invalid" };
  } catch {
    return { ok: false, reason: "signature_invalid" };
  }
}
