/** Durable, tenant-scoped signed JSONL audit archives and chain-safe pruning. */

import { createHash, createPublicKey, type KeyObject, randomUUID, sign, verify } from "node:crypto";
import { getDb } from "@stwd/db";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { sql } from "drizzle-orm";
import { type AuditReadExecutor, verifyAuditChain, withTenantAuditedTransaction } from "./audit";
import { parseSigningKey, publicKeyPem } from "./audit-checkpoint";

export const MIN_AUDIT_RETENTION_DAYS = 30;
export const MAX_AUDIT_RETENTION_DAYS = 3650;
export const MIN_ARCHIVE_CHUNK_SIZE = 1;
export const MAX_ARCHIVE_CHUNK_SIZE = 10_000;
export const MAX_ARCHIVE_EVENTS_PER_RUN = 50_000;
export const MAX_ARCHIVE_CHUNKS = 2_048;
/** Leaves 256 KiB for the API envelope, signature, key, and JSON wrapper under
 * the CLI and composed app's 1 MiB request/response ceilings. */
export const MAX_ARCHIVE_MANIFEST_BYTES = 768 * 1024;
/** Must stay aligned with the fully composed app's global request-body limit.
 * Restore uploads are exact signed JSONL chunks, so every archive we create
 * must be uploadable again through the public API. */
export const MAX_ARCHIVE_CHUNK_BYTES = 1024 * 1024;

export interface AuditRetentionPolicyValue {
  tenantId: string;
  enabled: boolean;
  retentionDays: number;
  archiveChunkSize: number;
  revision: number;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditArchiveChunkManifest {
  index: number;
  fromSeq: number;
  toSeq: number;
  eventCount: number;
  sha256: string;
  byteLength: number;
  file: string;
}

export interface AuditArchiveManifestPayload {
  schemaVersion: "steward.audit-archive.v1";
  archiveId: string;
  tenantId: string;
  createdAt: string;
  fromSeq: number;
  toSeq: number;
  eventCount: number;
  signingKeyId: string;
  retentionPolicyRevision: number | null;
  startPrevHash: string;
  endHmac: string;
  format: "application/x-ndjson";
  chunks: AuditArchiveChunkManifest[];
}

export interface SignedAuditArchiveManifest {
  manifest: AuditArchiveManifestPayload;
  manifestSha256: string;
  signature: string;
  publicKey: string;
  status: "sealed" | "pruned";
  sealedAt: string;
  prunedAt: string | null;
  durabilityAcknowledgement: AuditArchiveDurabilityAcknowledgement | null;
}

export interface AuditArchiveDurabilityAcknowledgementPayload {
  schemaVersion: "steward.audit-archive-durability.v1";
  archiveId: string;
  tenantId: string;
  manifestSha256: string;
  durabilityUri: string;
  objectVersion: string;
  acknowledgedAt: string;
}

export interface AuditArchiveDurabilityAcknowledgement {
  payload: AuditArchiveDurabilityAcknowledgementPayload;
  keyId: string;
  signature: string;
  acknowledgementSha256: string;
}

const KEY_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DURABILITY_URI_PATTERN = /^(?:s3|gs|azure|https):\/\/[^\s]{1,1900}$/;

function parseTrustedKeyRegistry(envName: string): Readonly<Record<string, string>> {
  const raw = runtimeEnvironmentValue(envName)?.trim();
  if (!raw) return Object.freeze({});
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${envName} must be a JSON object mapping key ids to PEM public keys`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${envName} must be a JSON object mapping key ids to PEM public keys`);
  }
  const registry: Record<string, string> = {};
  for (const [keyId, pem] of Object.entries(parsed as Record<string, unknown>)) {
    if (!KEY_ID_PATTERN.test(keyId) || typeof pem !== "string") {
      throw new Error(`${envName} contains an invalid key id or public key`);
    }
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error(`${envName}.${keyId} must be an Ed25519 public key`);
    }
    registry[keyId] = key.export({ format: "pem", type: "spki" }).toString();
  }
  return Object.freeze(registry);
}

function currentArchiveSigningIdentity(): {
  keyId: string;
  privateKey: KeyObject;
  publicKey: string;
} {
  const keyId = runtimeEnvironmentValue("STEWARD_AUDIT_SIGNING_KEY_ID")?.trim() ?? "";
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new Error("STEWARD_AUDIT_SIGNING_KEY_ID is required for audit archives");
  }
  const privateKey = parseSigningKey(runtimeEnvironmentValue("STEWARD_AUDIT_SIGNING_KEY") ?? "");
  const publicKey = publicKeyPem(privateKey);
  const trusted = parseTrustedKeyRegistry("STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS");
  const configured = trusted[keyId];
  if (!configured || configured !== publicKey) {
    throw new Error("The audit archive signing key id is not bound to its trusted public key");
  }
  return { keyId, privateKey, publicKey };
}

function trustedArchiveSigningKey(keyId: string): KeyObject {
  const pem = parseTrustedKeyRegistry("STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS")[keyId];
  if (!pem) throw new Error("Audit archive manifest signing key id is not trusted");
  return createPublicKey(pem);
}

function trustedDurabilityKey(keyId: string): KeyObject {
  const pem = parseTrustedKeyRegistry("STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS")[keyId];
  if (!pem) throw new Error("Audit archive durability acknowledgement key id is not trusted");
  return createPublicKey(pem);
}

export interface AuditArchiveResult extends SignedAuditArchiveManifest {
  archiveId: string;
  reused: boolean;
}

interface AuditEventRow {
  tenant_id: string;
  seq: number | string;
  prev_hash: unknown;
  hmac: unknown;
  actor_type: string;
  actor_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  metadata: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  created_at: Date | string;
}

function rowsFromExecute<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  if (result && typeof result === "object" && Array.isArray((result as { rows?: unknown }).rows)) {
    return (result as { rows: T[] }).rows;
  }
  return [];
}

function canonicalJsonValue(value: unknown): unknown {
  if (value === undefined || value === null) return null;
  if (Array.isArray(value)) return value.map(canonicalJsonValue);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((key) => [key, canonicalJsonValue((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(canonicalJsonValue(value)));
}

function assertManifestTransportBounds(manifest: AuditArchiveManifestPayload): Uint8Array {
  if (manifest.chunks.length < 1 || manifest.chunks.length > MAX_ARCHIVE_CHUNKS) {
    throw new Error(`Audit archive manifest exceeds the ${MAX_ARCHIVE_CHUNKS} chunk limit`);
  }
  const bytes = canonicalBytes(manifest);
  if (bytes.length > MAX_ARCHIVE_MANIFEST_BYTES) {
    throw new Error(
      `Audit archive manifest exceeds the ${MAX_ARCHIVE_MANIFEST_BYTES} byte transport limit`,
    );
  }
  return bytes;
}

function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function bytesToHex(value: unknown): string {
  const bytes =
    value instanceof Uint8Array
      ? value
      : ArrayBuffer.isView(value)
        ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
        : new Uint8Array(value as ArrayBuffer);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9+/]{86}==$/.test(value)) {
    throw new Error("Audit archive receipt signature is not canonical base64");
  }
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  if (bytes.length !== 64) throw new Error("Audit archive receipt signature has invalid length");
  return bytes;
}

function asIso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function validateInteger(name: string, value: number, min: number, max: number): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
}

function archiveLine(row: AuditEventRow): string {
  return JSON.stringify(
    canonicalJsonValue({
      v: 1,
      tenantId: row.tenant_id,
      seq: Number(row.seq),
      prevHash: bytesToHex(row.prev_hash),
      hmac: bytesToHex(row.hmac),
      actorType: row.actor_type,
      actorId: row.actor_id,
      action: row.action,
      resourceType: row.resource_type,
      resourceId: row.resource_id,
      metadata: row.metadata ?? {},
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      requestId: row.request_id,
      createdAt: asIso(row.created_at),
    }),
  );
}

async function lockTenantAuditWriter(
  tx: { execute(query: ReturnType<typeof sql>): Promise<unknown> },
  tenantId: string,
) {
  if (
    runtimeEnvironmentValue("STEWARD_DB_MODE") !== "pglite" &&
    runtimeEnvironmentValue("STEWARD_PGLITE_MEMORY") !== "true"
  ) {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`,
    );
  }
}

function parseStoredManifest(row: Record<string, unknown>): SignedAuditArchiveManifest {
  if (
    !row.manifest ||
    !row.signature ||
    !row.public_key ||
    !row.manifest_sha256 ||
    !row.sealed_at
  ) {
    throw new Error("Audit archive receipt is not durably sealed");
  }
  const manifest = row.manifest as unknown as AuditArchiveManifestPayload;
  const manifestBytes = canonicalBytes(manifest);
  if (sha256Hex(manifestBytes) !== String(row.manifest_sha256)) {
    throw new Error("Audit archive receipt manifest digest does not match");
  }
  if (!KEY_ID_PATTERN.test(manifest.signingKeyId) || manifest.signingKeyId !== row.signing_key_id) {
    throw new Error("Audit archive receipt signing key identity does not match its manifest");
  }
  const publicKey = trustedArchiveSigningKey(manifest.signingKeyId);
  const trustedPublicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    row.public_key !== trustedPublicKeyPem ||
    !verify(null, manifestBytes, publicKey, base64ToBytes(String(row.signature)))
  ) {
    throw new Error("Audit archive receipt signature does not verify");
  }
  if (
    manifest.archiveId !== String(row.id) ||
    manifest.tenantId !== String(row.tenant_id) ||
    manifest.fromSeq !== Number(row.from_seq) ||
    manifest.toSeq !== Number(row.to_seq) ||
    manifest.eventCount !== Number(row.event_count) ||
    manifest.retentionPolicyRevision !==
      (row.retention_policy_revision == null ? null : Number(row.retention_policy_revision))
  ) {
    throw new Error("Audit archive receipt identity does not match its manifest");
  }
  const durabilityAcknowledgement = parseStoredDurabilityAcknowledgement(row, manifest);
  return {
    manifest,
    manifestSha256: String(row.manifest_sha256),
    signature: String(row.signature),
    publicKey: String(row.public_key),
    status: row.status === "pruned" ? "pruned" : "sealed",
    sealedAt: asIso(row.sealed_at as Date | string),
    prunedAt: row.pruned_at ? asIso(row.pruned_at as Date | string) : null,
    durabilityAcknowledgement,
  };
}

function validateDurabilityAcknowledgementPayload(
  payload: AuditArchiveDurabilityAcknowledgementPayload,
  manifest: AuditArchiveManifestPayload,
  manifestSha256: string,
): void {
  if (
    payload.schemaVersion !== "steward.audit-archive-durability.v1" ||
    payload.archiveId !== manifest.archiveId ||
    payload.tenantId !== manifest.tenantId ||
    payload.manifestSha256 !== manifestSha256 ||
    !/^[0-9a-f]{64}$/.test(payload.manifestSha256) ||
    !DURABILITY_URI_PATTERN.test(payload.durabilityUri) ||
    payload.objectVersion.length < 1 ||
    payload.objectVersion.length > 512 ||
    !Number.isFinite(Date.parse(payload.acknowledgedAt))
  ) {
    throw new Error("Audit archive durability acknowledgement payload is invalid");
  }
  const acknowledgedAt = Date.parse(payload.acknowledgedAt);
  const sealedAt = Date.parse(manifest.createdAt);
  if (acknowledgedAt < sealedAt || acknowledgedAt > Date.now() + 5 * 60_000) {
    throw new Error("Audit archive durability acknowledgement timestamp is invalid");
  }
}

function parseStoredDurabilityAcknowledgement(
  row: Record<string, unknown>,
  manifest: AuditArchiveManifestPayload,
): AuditArchiveDurabilityAcknowledgement | null {
  if (
    row.durability_ack == null &&
    row.durability_ack_key_id == null &&
    row.durability_ack_signature == null &&
    row.durability_ack_sha256 == null
  ) {
    return null;
  }
  if (
    !row.durability_ack ||
    !row.durability_ack_key_id ||
    !row.durability_ack_signature ||
    !row.durability_ack_sha256
  ) {
    throw new Error("Audit archive durability acknowledgement is incomplete");
  }
  const payload = row.durability_ack as unknown as AuditArchiveDurabilityAcknowledgementPayload;
  const keyId = String(row.durability_ack_key_id);
  const signature = String(row.durability_ack_signature);
  const acknowledgementSha256 = String(row.durability_ack_sha256);
  validateDurabilityAcknowledgementPayload(payload, manifest, String(row.manifest_sha256));
  const bytes = canonicalBytes(payload);
  if (sha256Hex(bytes) !== acknowledgementSha256) {
    throw new Error("Audit archive durability acknowledgement digest does not match");
  }
  if (!verify(null, bytes, trustedDurabilityKey(keyId), base64ToBytes(signature))) {
    throw new Error("Audit archive durability acknowledgement signature does not verify");
  }
  return { payload, keyId, signature, acknowledgementSha256 };
}

export async function getAuditRetentionPolicy(
  tenantId: string,
): Promise<AuditRetentionPolicyValue> {
  const rows = rowsFromExecute<Record<string, unknown>>(
    await getDb().execute(sql`
      SELECT tenant_id, enabled, retention_days, archive_chunk_size, revision, updated_by, created_at, updated_at
      FROM audit_retention_policies WHERE tenant_id = ${tenantId} LIMIT 1
    `),
  );
  const row = rows[0];
  if (!row) {
    return {
      tenantId,
      enabled: false,
      retentionDays: 365,
      archiveChunkSize: 1000,
      revision: 0,
      updatedBy: null,
      createdAt: "",
      updatedAt: "",
    };
  }
  return {
    tenantId: String(row.tenant_id),
    enabled: Boolean(row.enabled),
    retentionDays: Number(row.retention_days),
    archiveChunkSize: Number(row.archive_chunk_size),
    revision: Number(row.revision),
    updatedBy: row.updated_by == null ? null : String(row.updated_by),
    createdAt: asIso(row.created_at as Date | string),
    updatedAt: asIso(row.updated_at as Date | string),
  };
}

export async function setAuditRetentionPolicy(input: {
  tenantId: string;
  enabled: boolean;
  retentionDays: number;
  archiveChunkSize: number;
  updatedBy: string | null;
}): Promise<AuditRetentionPolicyValue> {
  validateInteger(
    "retentionDays",
    input.retentionDays,
    MIN_AUDIT_RETENTION_DAYS,
    MAX_AUDIT_RETENTION_DAYS,
  );
  validateInteger(
    "archiveChunkSize",
    input.archiveChunkSize,
    MIN_ARCHIVE_CHUNK_SIZE,
    MAX_ARCHIVE_CHUNK_SIZE,
  );
  await withTenantAuditedTransaction(input.tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    await tx.execute(sql`
      INSERT INTO audit_retention_policies
        (tenant_id, enabled, retention_days, archive_chunk_size, revision, updated_by, created_at, updated_at)
      VALUES
        (${input.tenantId}, ${input.enabled}, ${input.retentionDays}, ${input.archiveChunkSize}, 1,
         ${input.updatedBy}, now(), now())
      ON CONFLICT (tenant_id) DO UPDATE
        SET enabled = EXCLUDED.enabled,
            retention_days = EXCLUDED.retention_days,
            archive_chunk_size = EXCLUDED.archive_chunk_size,
            revision = audit_retention_policies.revision + 1,
            updated_by = EXCLUDED.updated_by,
            updated_at = now()
    `);
    const policyRows = rowsFromExecute<{ revision: number | string }>(
      await tx.execute(sql`
        SELECT revision FROM audit_retention_policies WHERE tenant_id = ${input.tenantId}
      `),
    );
    await appendRequiredAudit({
      tenantId: input.tenantId,
      actorType: "user",
      actorId: input.updatedBy,
      action: "audit.retention_policy.updated",
      resourceType: "audit_retention_policy",
      resourceId: input.tenantId,
      metadata: {
        enabled: input.enabled,
        retentionDays: input.retentionDays,
        archiveChunkSize: input.archiveChunkSize,
        revision: Number(policyRows[0]?.revision),
      },
    });
  });
  return getAuditRetentionPolicy(input.tenantId);
}

async function verifyStoredArchiveChunks(
  tx: { execute(query: ReturnType<typeof sql>): Promise<unknown> },
  manifest: AuditArchiveManifestPayload,
): Promise<void> {
  const rows = rowsFromExecute<Record<string, unknown>>(
    await tx.execute(sql`
      SELECT chunk_index, from_seq, to_seq, event_count, sha256, byte_length, jsonl
      FROM audit_archive_chunks
      WHERE archive_id = ${manifest.archiveId}::uuid
      ORDER BY chunk_index ASC
      FOR UPDATE
    `),
  );
  if (rows.length !== manifest.chunks.length || rows.length === 0) {
    throw new Error("Audit archive durable chunk set is incomplete");
  }
  let expectedSeq = manifest.fromSeq;
  let observedEvents = 0;
  let previousHmac = manifest.startPrevHash;
  for (let index = 0; index < manifest.chunks.length; index++) {
    const expected = manifest.chunks[index];
    const row = rows[index];
    const jsonl = String(row.jsonl);
    const byteLength = new TextEncoder().encode(jsonl).length;
    if (
      expected.index !== index ||
      expected.file !== `chunk-${String(index).padStart(6, "0")}.jsonl` ||
      Number(row.chunk_index) !== index ||
      Number(row.from_seq) !== expected.fromSeq ||
      Number(row.to_seq) !== expected.toSeq ||
      Number(row.event_count) !== expected.eventCount ||
      String(row.sha256) !== expected.sha256 ||
      Number(row.byte_length) !== expected.byteLength ||
      byteLength !== expected.byteLength ||
      sha256Hex(jsonl) !== expected.sha256 ||
      expected.fromSeq !== expectedSeq ||
      expected.eventCount !== expected.toSeq - expected.fromSeq + 1
    ) {
      throw new Error(`Audit archive durable chunk ${index} does not match its signed manifest`);
    }
    const lines = jsonl.endsWith("\n") ? jsonl.slice(0, -1).split("\n") : [];
    if (lines.length !== expected.eventCount) {
      throw new Error(`Audit archive durable chunk ${index} event count does not match`);
    }
    for (const line of lines) {
      let event: Record<string, unknown>;
      try {
        event = JSON.parse(line) as Record<string, unknown>;
      } catch {
        throw new Error(`Audit archive durable chunk ${index} contains invalid JSONL`);
      }
      if (
        event.v !== 1 ||
        event.tenantId !== manifest.tenantId ||
        event.seq !== expectedSeq ||
        event.prevHash !== previousHmac ||
        typeof event.hmac !== "string" ||
        !/^[0-9a-f]{64}$/.test(event.hmac)
      ) {
        throw new Error(
          `Audit archive durable chunk ${index} chain is invalid at seq ${expectedSeq}`,
        );
      }
      previousHmac = event.hmac;
      expectedSeq++;
      observedEvents++;
    }
  }
  if (
    expectedSeq !== manifest.toSeq + 1 ||
    observedEvents !== manifest.eventCount ||
    previousHmac !== manifest.endHmac
  ) {
    throw new Error("Audit archive durable chunk set does not cover the signed range");
  }
}

export async function createAuditArchive(input: {
  tenantId: string;
  fromSeq: number;
  toSeq: number;
  chunkSize: number;
  retentionPolicyRevision?: number;
}): Promise<AuditArchiveResult> {
  validateInteger("fromSeq", input.fromSeq, 1, Number.MAX_SAFE_INTEGER);
  validateInteger("toSeq", input.toSeq, input.fromSeq, Number.MAX_SAFE_INTEGER);
  validateInteger("chunkSize", input.chunkSize, MIN_ARCHIVE_CHUNK_SIZE, MAX_ARCHIVE_CHUNK_SIZE);
  const eventCount = input.toSeq - input.fromSeq + 1;
  if (eventCount > MAX_ARCHIVE_EVENTS_PER_RUN) {
    throw new Error(`Archive range cannot exceed ${MAX_ARCHIVE_EVENTS_PER_RUN} events per run`);
  }
  if (
    input.retentionPolicyRevision !== undefined &&
    (!Number.isSafeInteger(input.retentionPolicyRevision) || input.retentionPolicyRevision < 1)
  ) {
    throw new Error("retentionPolicyRevision must be a positive safe integer");
  }

  return withTenantAuditedTransaction(input.tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    const sourceVerification = await verifyAuditChain(input.tenantId, {
      fromSeq: input.fromSeq,
      toSeq: input.toSeq,
      requireHead: true,
      executor: tx as unknown as AuditReadExecutor,
    });
    if (!sourceVerification.valid || sourceVerification.count !== eventCount) {
      const brokenAt = sourceVerification.valid
        ? input.fromSeq + sourceVerification.count
        : sourceVerification.brokenAt;
      throw new Error(`Audit archive source failed HMAC verification at seq ${brokenAt}`);
    }
    const existing = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives
        WHERE tenant_id = ${input.tenantId} AND from_seq = ${input.fromSeq} AND to_seq = ${input.toSeq}
          AND source = 'native'
          AND retention_policy_revision IS NOT DISTINCT FROM ${input.retentionPolicyRevision ?? null}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (existing && (existing.status === "sealed" || existing.status === "pruned")) {
      const parsed = parseStoredManifest(existing);
      if (parsed.manifest.retentionPolicyRevision !== (input.retentionPolicyRevision ?? null)) {
        throw new Error("Existing archive was sealed under a different retention authority");
      }
      await verifyStoredArchiveChunks(tx, parsed.manifest);
      return {
        archiveId: String(existing.id),
        reused: true,
        ...parsed,
      };
    }

    const archiveId = existing ? String(existing.id) : randomUUID();
    if (!existing) {
      await tx.execute(sql`
        INSERT INTO audit_archives
          (id, tenant_id, from_seq, to_seq, event_count, retention_policy_revision,
           status, created_at, updated_at)
        VALUES
          (${archiveId}::uuid, ${input.tenantId}, ${input.fromSeq}, ${input.toSeq}, ${eventCount},
           ${input.retentionPolicyRevision ?? null}, 'building', now(), now())
      `);
    } else {
      await tx.execute(sql`DELETE FROM audit_archive_chunks WHERE archive_id = ${archiveId}::uuid`);
      await tx.execute(sql`
        UPDATE audit_archives
        SET retention_policy_revision = ${input.retentionPolicyRevision ?? null}, updated_at = now()
        WHERE id = ${archiveId}::uuid AND tenant_id = ${input.tenantId} AND status = 'building'
      `);
    }

    const chunks: AuditArchiveChunkManifest[] = [];
    let firstRow: AuditEventRow | undefined;
    let lastRow: AuditEventRow | undefined;
    let observedCount = 0;
    let index = 0;
    for (let cursor = input.fromSeq; cursor <= input.toSeq; ) {
      const chunkTo = Math.min(input.toSeq, cursor + input.chunkSize - 1);
      const rows = rowsFromExecute<AuditEventRow>(
        await tx.execute(sql`
          SELECT tenant_id, seq, prev_hash, hmac, actor_type, actor_id, action,
                 resource_type, resource_id, metadata, ip_address, user_agent, request_id, created_at
          FROM audit_events
          WHERE tenant_id = ${input.tenantId} AND seq BETWEEN ${cursor} AND ${chunkTo}
          ORDER BY seq ASC
        `),
      );
      if (rows.length !== chunkTo - cursor + 1 || Number(rows[0]?.seq) !== cursor) {
        throw new Error(`Audit archive source is not contiguous at seq ${cursor}`);
      }
      for (let i = 1; i < rows.length; i++) {
        if (Number(rows[i].seq) !== Number(rows[i - 1].seq) + 1) {
          throw new Error(
            `Audit archive source is not contiguous at seq ${Number(rows[i - 1].seq) + 1}`,
          );
        }
        if (bytesToHex(rows[i].prev_hash) !== bytesToHex(rows[i - 1].hmac)) {
          throw new Error(`Audit archive source chain is broken at seq ${Number(rows[i].seq)}`);
        }
      }
      if (lastRow && bytesToHex(rows[0].prev_hash) !== bytesToHex(lastRow.hmac)) {
        throw new Error(`Audit archive source chain is broken at seq ${cursor}`);
      }
      const encoded = rows.map((row) => {
        const line = `${archiveLine(row)}\n`;
        return { row, line, byteLength: new TextEncoder().encode(line).length };
      });
      for (const item of encoded) {
        if (item.byteLength > MAX_ARCHIVE_CHUNK_BYTES) {
          throw new Error(
            `Audit event at seq ${Number(item.row.seq)} exceeds the public archive chunk limit`,
          );
        }
      }
      for (let offset = 0; offset < encoded.length; ) {
        if (index >= MAX_ARCHIVE_CHUNKS) {
          throw new Error(
            `Audit archive requires more than ${MAX_ARCHIVE_CHUNKS} chunks; narrow the sequence range`,
          );
        }
        const batchStart = offset;
        let byteLength = 0;
        while (
          offset < encoded.length &&
          byteLength + encoded[offset].byteLength <= MAX_ARCHIVE_CHUNK_BYTES
        ) {
          byteLength += encoded[offset].byteLength;
          offset++;
        }
        const batch = encoded.slice(batchStart, offset);
        const batchFirst = batch[0].row;
        const batchLast = batch[batch.length - 1].row;
        const fromSeq = Number(batchFirst.seq);
        const toSeq = Number(batchLast.seq);
        const jsonl = batch.map((item) => item.line).join("");
        const chunk = {
          index,
          fromSeq,
          toSeq,
          eventCount: batch.length,
          sha256: sha256Hex(jsonl),
          byteLength,
          file: `chunk-${String(index).padStart(6, "0")}.jsonl`,
        };
        await tx.execute(sql`
          INSERT INTO audit_archive_chunks
            (archive_id, chunk_index, from_seq, to_seq, event_count, sha256, byte_length, jsonl)
          VALUES
            (${archiveId}::uuid, ${index}, ${fromSeq}, ${toSeq}, ${batch.length}, ${chunk.sha256},
             ${chunk.byteLength}, ${jsonl})
        `);
        chunks.push(chunk);
        firstRow ??= batchFirst;
        lastRow = batchLast;
        observedCount += batch.length;
        index++;
      }
      cursor = chunkTo + 1;
    }
    if (!firstRow || !lastRow || observedCount !== eventCount) {
      throw new Error("Audit archive event count changed while sealing");
    }

    const createdAt = new Date().toISOString();
    const signingIdentity = currentArchiveSigningIdentity();
    const manifest: AuditArchiveManifestPayload = {
      schemaVersion: "steward.audit-archive.v1",
      archiveId,
      tenantId: input.tenantId,
      createdAt,
      fromSeq: input.fromSeq,
      toSeq: input.toSeq,
      eventCount,
      signingKeyId: signingIdentity.keyId,
      retentionPolicyRevision: input.retentionPolicyRevision ?? null,
      startPrevHash: bytesToHex(firstRow.prev_hash),
      endHmac: bytesToHex(lastRow.hmac),
      format: "application/x-ndjson",
      chunks,
    };
    const manifestBytes = assertManifestTransportBounds(manifest);
    const manifestSha256 = sha256Hex(manifestBytes);
    const signature = bytesToBase64(sign(null, manifestBytes, signingIdentity.privateKey));
    await tx.execute(sql`
      UPDATE audit_archives
      SET status = 'sealed', manifest = ${JSON.stringify(manifest)}::jsonb,
          manifest_sha256 = ${manifestSha256}, signature = ${signature},
          signing_key_id = ${signingIdentity.keyId}, public_key = ${signingIdentity.publicKey},
          sealed_at = now(), updated_at = now()
      WHERE id = ${archiveId}::uuid AND tenant_id = ${input.tenantId}
    `);
    const sealed = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives WHERE id = ${archiveId}::uuid AND tenant_id = ${input.tenantId}
      `),
    )[0];
    if (!sealed) throw new Error("Audit archive receipt failed to persist");
    const parsed = parseStoredManifest(sealed);
    await verifyStoredArchiveChunks(tx, parsed.manifest);
    await appendRequiredAudit({
      tenantId: input.tenantId,
      actorType: "system",
      action: "audit.archive.sealed",
      resourceType: "audit_archive",
      resourceId: archiveId,
      metadata: {
        fromSeq: input.fromSeq,
        toSeq: input.toSeq,
        eventCount,
        manifestSha256,
        signingKeyId: signingIdentity.keyId,
        retentionPolicyRevision: input.retentionPolicyRevision ?? null,
      },
    });
    return { archiveId, reused: false, ...parsed };
  });
}

export async function recordAuditArchiveDurabilityAcknowledgement(input: {
  tenantId: string;
  archiveId: string;
  payload: AuditArchiveDurabilityAcknowledgementPayload;
  keyId: string;
  signature: string;
  actorId?: string | null;
  requestId?: string | null;
}): Promise<{ acknowledgement: AuditArchiveDurabilityAcknowledgement; reused: boolean }> {
  if (!KEY_ID_PATTERN.test(input.keyId)) {
    throw new Error("Audit archive durability acknowledgement key id is invalid");
  }
  return withTenantAuditedTransaction(input.tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    const receipt = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives
        WHERE id = ${input.archiveId}::uuid AND tenant_id = ${input.tenantId}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!receipt || (receipt.status !== "sealed" && receipt.status !== "pruned")) {
      throw new Error("A sealed tenant archive is required before durability acknowledgement");
    }
    const parsed = parseStoredManifest(receipt);
    await verifyStoredArchiveChunks(tx, parsed.manifest);
    validateDurabilityAcknowledgementPayload(input.payload, parsed.manifest, parsed.manifestSha256);
    const bytes = canonicalBytes(input.payload);
    const acknowledgementSha256 = sha256Hex(bytes);
    if (!verify(null, bytes, trustedDurabilityKey(input.keyId), base64ToBytes(input.signature))) {
      throw new Error("Audit archive durability acknowledgement signature does not verify");
    }
    const acknowledgement: AuditArchiveDurabilityAcknowledgement = {
      payload: input.payload,
      keyId: input.keyId,
      signature: input.signature,
      acknowledgementSha256,
    };
    if (parsed.durabilityAcknowledgement) {
      if (
        sha256Hex(canonicalBytes(parsed.durabilityAcknowledgement)) ===
        sha256Hex(canonicalBytes(acknowledgement))
      ) {
        return { acknowledgement: parsed.durabilityAcknowledgement, reused: true };
      }
      throw new Error("Audit archive durability acknowledgement is immutable");
    }
    const updated = rowsFromExecute<{ id: string }>(
      await tx.execute(sql`
        UPDATE audit_archives
        SET durability_ack = ${JSON.stringify(input.payload)}::jsonb,
            durability_ack_key_id = ${input.keyId},
            durability_ack_signature = ${input.signature},
            durability_ack_sha256 = ${acknowledgementSha256},
            durability_ack_at = now(),
            updated_at = now()
        WHERE id = ${input.archiveId}::uuid AND tenant_id = ${input.tenantId}
          AND durability_ack IS NULL
        RETURNING id
      `),
    );
    if (updated.length !== 1) {
      throw new Error("Audit archive durability acknowledgement was concurrently recorded");
    }
    await appendRequiredAudit({
      tenantId: input.tenantId,
      actorType: input.actorId ? "user" : "system",
      actorId: input.actorId ?? null,
      action: "audit.archive.durability_acknowledged",
      resourceType: "audit_archive",
      resourceId: input.archiveId,
      metadata: {
        manifestSha256: parsed.manifestSha256,
        acknowledgementSha256,
        keyId: input.keyId,
        durabilityUri: input.payload.durabilityUri,
        objectVersion: input.payload.objectVersion,
      },
      requestId: input.requestId ?? null,
    });
    return { acknowledgement, reused: false };
  });
}

export async function pruneSealedAuditArchive(
  tenantId: string,
  archiveId: string,
  context: { actorId?: string | null; requestId?: string | null } = {},
): Promise<{ archiveId: string; deleted: number; floorSeq: number; reused: boolean }> {
  return withTenantAuditedTransaction(tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    const receipt = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives WHERE id = ${archiveId}::uuid AND tenant_id = ${tenantId}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!receipt || (receipt.status !== "sealed" && receipt.status !== "pruned")) {
      throw new Error("A durably sealed tenant archive receipt is required before pruning");
    }
    if (receipt.source !== "native") {
      throw new Error("Restored archives cannot authorize deletion of the live audit chain");
    }
    const parsed = parseStoredManifest(receipt);
    await verifyStoredArchiveChunks(tx, parsed.manifest);
    if (!parsed.durabilityAcknowledgement) {
      throw new Error("A trusted external durability acknowledgement is required before pruning");
    }
    const toSeq = Number(receipt.to_seq);
    const fromSeq = Number(receipt.from_seq);
    const policyRevision =
      receipt.retention_policy_revision == null ? null : Number(receipt.retention_policy_revision);
    if (policyRevision == null) {
      throw new Error("Manual export archives cannot authorize retention pruning");
    }
    const policy = rowsFromExecute<{ enabled: boolean; revision: number | string }>(
      await tx.execute(sql`
        SELECT enabled, revision FROM audit_retention_policies
        WHERE tenant_id = ${tenantId} LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!policy?.enabled || Number(policy.revision) !== policyRevision) {
      throw new Error("Audit retention policy changed after archive sealing; reseal required");
    }
    const head = rowsFromExecute<{ floor_seq: number | string; floor_hmac: unknown }>(
      await tx.execute(sql`
        SELECT floor_seq, floor_hmac FROM audit_chain_heads
        WHERE tenant_id = ${tenantId} LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!head) throw new Error("Audit chain head is missing; refusing to prune");
    const currentFloor = Number(head.floor_seq);
    if (receipt.status === "pruned" || currentFloor >= toSeq) {
      return { archiveId, deleted: 0, floorSeq: currentFloor, reused: true };
    }
    if (fromSeq !== currentFloor + 1) {
      throw new Error(`Archive must begin at the live retention floor ${currentFloor + 1}`);
    }
    const anchor = rowsFromExecute<{ seq: number | string; hmac: unknown }>(
      await tx.execute(sql`
        SELECT seq, hmac FROM audit_events
        WHERE tenant_id = ${tenantId} AND seq = ${toSeq} LIMIT 1
      `),
    )[0];
    if (!anchor) throw new Error("Archive floor anchor event is missing; refusing to prune");
    const manifest = parsed.manifest;
    if (bytesToHex(anchor.hmac) !== manifest.endHmac) {
      throw new Error("Archive receipt does not match the live floor anchor HMAC");
    }
    const sourceVerification = await verifyAuditChain(tenantId, {
      fromSeq,
      toSeq,
      requireHead: true,
      executor: tx as unknown as AuditReadExecutor,
    });
    if (!sourceVerification.valid || sourceVerification.count !== manifest.eventCount) {
      throw new Error("Prune source no longer matches the verified live audit chain");
    }
    await appendRequiredAudit({
      tenantId,
      actorType: context.actorId ? "user" : "system",
      actorId: context.actorId ?? null,
      action: "audit.retention.prune_authorized",
      resourceType: "audit_archive",
      resourceId: archiveId,
      metadata: {
        fromSeq,
        toSeq,
        manifestSha256: parsed.manifestSha256,
        signingKeyId: manifest.signingKeyId,
        durabilityAcknowledgementSha256: parsed.durabilityAcknowledgement.acknowledgementSha256,
        durabilityKeyId: parsed.durabilityAcknowledgement.keyId,
        retentionPolicyRevision: policyRevision,
      },
      requestId: context.requestId ?? null,
    });
    const removed = rowsFromExecute<{ seq: number | string }>(
      await tx.execute(sql`
        DELETE FROM audit_events
        WHERE tenant_id = ${tenantId} AND seq BETWEEN ${fromSeq} AND ${toSeq}
        RETURNING seq
      `),
    );
    if (removed.length !== toSeq - fromSeq + 1) {
      throw new Error("Prune source changed after archive sealing; transaction rolled back");
    }
    await tx.execute(sql`
      UPDATE audit_chain_heads
      SET floor_seq = ${toSeq}, floor_hmac = ${anchor.hmac as Uint8Array}, updated_at = now()
      WHERE tenant_id = ${tenantId}
    `);
    await tx.execute(sql`
      UPDATE audit_archives
      SET status = 'pruned', pruned_at = now(), updated_at = now()
      WHERE id = ${archiveId}::uuid AND tenant_id = ${tenantId} AND status = 'sealed'
    `);
    await appendRequiredAudit({
      tenantId,
      actorType: context.actorId ? "user" : "system",
      actorId: context.actorId ?? null,
      action: "audit.retention.prune_completed",
      resourceType: "audit_archive",
      resourceId: archiveId,
      metadata: {
        deleted: removed.length,
        floorSeq: toSeq,
        manifestSha256: parsed.manifestSha256,
        durabilityAcknowledgementSha256: parsed.durabilityAcknowledgement.acknowledgementSha256,
      },
      requestId: context.requestId ?? null,
    });
    return { archiveId, deleted: removed.length, floorSeq: toSeq, reused: false };
  });
}

export async function runTenantAuditRetention(
  tenantId: string,
  context: { actorId?: string | null; requestId?: string | null } = {},
): Promise<{
  tenantId: string;
  archiveId: string | null;
  archived: number;
  deleted: number;
  floorSeq: number;
  reused: boolean;
}> {
  const policy = await getAuditRetentionPolicy(tenantId);
  if (!policy.enabled) {
    return { tenantId, archiveId: null, archived: 0, deleted: 0, floorSeq: 0, reused: false };
  }
  const db = getDb();
  const head = rowsFromExecute<{ floor_seq: number | string; expected_seq: number | string }>(
    await db.execute(sql`
      SELECT floor_seq, expected_seq FROM audit_chain_heads WHERE tenant_id = ${tenantId} LIMIT 1
    `),
  )[0];
  if (!head) {
    return { tenantId, archiveId: null, archived: 0, deleted: 0, floorSeq: 0, reused: false };
  }
  const floorSeq = Number(head.floor_seq);
  const firstFresh = rowsFromExecute<{ seq: number | string }>(
    await db.execute(sql`
      SELECT seq FROM audit_events
      WHERE tenant_id = ${tenantId} AND seq > ${floorSeq}
        AND created_at >= now() - make_interval(days => ${policy.retentionDays})
      ORDER BY seq ASC LIMIT 1
    `),
  )[0];
  const last = rowsFromExecute<{ seq: number | string }>(
    await db.execute(sql`
      SELECT seq FROM audit_events WHERE tenant_id = ${tenantId} AND seq > ${floorSeq}
      ORDER BY seq DESC LIMIT 1
    `),
  )[0];
  if (!last) {
    return { tenantId, archiveId: null, archived: 0, deleted: 0, floorSeq, reused: false };
  }
  const eligibleTo = firstFresh ? Number(firstFresh.seq) - 1 : Number(last.seq);
  if (eligibleTo <= floorSeq) {
    return { tenantId, archiveId: null, archived: 0, deleted: 0, floorSeq, reused: false };
  }
  const toSeq = Math.min(eligibleTo, floorSeq + MAX_ARCHIVE_EVENTS_PER_RUN);
  const archive = await createAuditArchive({
    tenantId,
    fromSeq: floorSeq + 1,
    toSeq,
    chunkSize: policy.archiveChunkSize,
    retentionPolicyRevision: policy.revision,
  });
  if (!archive.durabilityAcknowledgement) {
    return {
      tenantId,
      archiveId: archive.archiveId,
      archived: toSeq - floorSeq,
      deleted: 0,
      floorSeq,
      reused: archive.reused,
    };
  }
  const pruned = await pruneSealedAuditArchive(tenantId, archive.archiveId, context);
  return {
    tenantId,
    archiveId: archive.archiveId,
    archived: toSeq - floorSeq,
    deleted: pruned.deleted,
    floorSeq: pruned.floorSeq,
    reused: archive.reused || pruned.reused,
  };
}

function verifySuppliedArchiveManifest(input: {
  tenantId: string;
  manifest: AuditArchiveManifestPayload;
  manifestSha256: string;
  signature: string;
}): { bytes: Uint8Array; trustedPublicKey: string } {
  const { manifest } = input;
  if (
    manifest.schemaVersion !== "steward.audit-archive.v1" ||
    manifest.tenantId !== input.tenantId ||
    !UUID_PATTERN.test(manifest.archiveId) ||
    !Number.isSafeInteger(manifest.fromSeq) ||
    !Number.isSafeInteger(manifest.toSeq) ||
    !Number.isSafeInteger(manifest.eventCount) ||
    manifest.fromSeq < 1 ||
    manifest.toSeq < manifest.fromSeq ||
    manifest.eventCount !== manifest.toSeq - manifest.fromSeq + 1 ||
    manifest.eventCount > MAX_ARCHIVE_EVENTS_PER_RUN ||
    typeof manifest.createdAt !== "string" ||
    !Number.isFinite(Date.parse(manifest.createdAt)) ||
    new Date(manifest.createdAt).toISOString() !== manifest.createdAt ||
    manifest.format !== "application/x-ndjson" ||
    (manifest.retentionPolicyRevision !== null &&
      (!Number.isSafeInteger(manifest.retentionPolicyRevision) ||
        manifest.retentionPolicyRevision < 1)) ||
    !Array.isArray(manifest.chunks) ||
    manifest.chunks.length < 1 ||
    manifest.chunks.length > MAX_ARCHIVE_CHUNKS ||
    !/^[0-9a-f]{64}$/.test(manifest.startPrevHash) ||
    !/^[0-9a-f]{64}$/.test(manifest.endHmac) ||
    !KEY_ID_PATTERN.test(manifest.signingKeyId)
  ) {
    throw new Error("Restored audit archive manifest is invalid");
  }
  const bytes = assertManifestTransportBounds(manifest);
  let expectedSeq = manifest.fromSeq;
  let observedEvents = 0;
  for (let index = 0; index < manifest.chunks.length; index++) {
    const chunk = manifest.chunks[index];
    if (
      !chunk ||
      chunk.index !== index ||
      chunk.file !== `chunk-${String(index).padStart(6, "0")}.jsonl` ||
      !Number.isSafeInteger(chunk.fromSeq) ||
      !Number.isSafeInteger(chunk.toSeq) ||
      !Number.isSafeInteger(chunk.eventCount) ||
      !Number.isSafeInteger(chunk.byteLength) ||
      chunk.fromSeq !== expectedSeq ||
      chunk.toSeq < chunk.fromSeq ||
      chunk.eventCount !== chunk.toSeq - chunk.fromSeq + 1 ||
      chunk.eventCount < MIN_ARCHIVE_CHUNK_SIZE ||
      chunk.eventCount > MAX_ARCHIVE_CHUNK_SIZE ||
      chunk.byteLength < 1 ||
      chunk.byteLength > MAX_ARCHIVE_CHUNK_BYTES ||
      !/^[0-9a-f]{64}$/.test(chunk.sha256)
    ) {
      throw new Error(`Restored audit archive manifest chunk ${index} is invalid`);
    }
    expectedSeq = chunk.toSeq + 1;
    observedEvents += chunk.eventCount;
  }
  if (expectedSeq !== manifest.toSeq + 1 || observedEvents !== manifest.eventCount) {
    throw new Error("Restored audit archive manifest chunk coverage is invalid");
  }
  if (sha256Hex(bytes) !== input.manifestSha256) {
    throw new Error("Restored audit archive manifest digest does not match");
  }
  const trustedKey = trustedArchiveSigningKey(manifest.signingKeyId);
  if (!verify(null, bytes, trustedKey, base64ToBytes(input.signature))) {
    throw new Error("Restored audit archive manifest signature does not verify");
  }
  return {
    bytes,
    trustedPublicKey: trustedKey.export({ format: "pem", type: "spki" }).toString(),
  };
}

export async function beginAuditArchiveRestore(input: {
  tenantId: string;
  manifest: AuditArchiveManifestPayload;
  manifestSha256: string;
  signature: string;
  actorId?: string | null;
  requestId?: string | null;
}): Promise<{ archiveId: string; reused: boolean; status: "building" | "sealed" }> {
  const verified = verifySuppliedArchiveManifest(input);
  return withTenantAuditedTransaction(input.tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    const existing = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives WHERE id = ${input.manifest.archiveId}::uuid
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (existing) {
      if (existing.tenant_id !== input.tenantId || existing.source !== "imported") {
        throw new Error("Audit archive id already belongs to another source or tenant");
      }
      if (
        existing.manifest_sha256 !== input.manifestSha256 ||
        existing.signature !== input.signature ||
        existing.signing_key_id !== input.manifest.signingKeyId
      ) {
        throw new Error("Restored audit archive identity is immutable");
      }
      if (existing.status === "sealed") {
        const parsed = parseStoredManifest(existing);
        await verifyStoredArchiveChunks(tx, parsed.manifest);
        return { archiveId: input.manifest.archiveId, reused: true, status: "sealed" };
      }
      return { archiveId: input.manifest.archiveId, reused: true, status: "building" };
    }
    await tx.execute(sql`
      INSERT INTO audit_archives
        (id, tenant_id, from_seq, to_seq, event_count, source, retention_policy_revision,
         status, manifest, manifest_sha256, signature, signing_key_id, public_key,
         created_at, updated_at)
      VALUES
        (${input.manifest.archiveId}::uuid, ${input.tenantId}, ${input.manifest.fromSeq},
         ${input.manifest.toSeq}, ${input.manifest.eventCount}, 'imported',
         ${input.manifest.retentionPolicyRevision}, 'building',
         ${JSON.stringify(input.manifest)}::jsonb, ${input.manifestSha256}, ${input.signature},
         ${input.manifest.signingKeyId}, ${verified.trustedPublicKey}, now(), now())
    `);
    await appendRequiredAudit({
      tenantId: input.tenantId,
      actorType: input.actorId ? "user" : "system",
      actorId: input.actorId ?? null,
      action: "audit.archive.restore_started",
      resourceType: "audit_archive",
      resourceId: input.manifest.archiveId,
      metadata: {
        manifestSha256: input.manifestSha256,
        eventCount: input.manifest.eventCount,
        signingKeyId: input.manifest.signingKeyId,
      },
      requestId: input.requestId ?? null,
    });
    return { archiveId: input.manifest.archiveId, reused: false, status: "building" };
  });
}

export async function putAuditArchiveRestoreChunk(input: {
  tenantId: string;
  archiveId: string;
  index: number;
  jsonl: string;
}): Promise<{ reused: boolean }> {
  if (new TextEncoder().encode(input.jsonl).length > MAX_ARCHIVE_CHUNK_BYTES) {
    throw new Error("Restored audit archive chunk exceeds the public 1 MiB limit");
  }
  return getDb().transaction(async (tx) => {
    await lockTenantAuditWriter(tx, input.tenantId);
    const row = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives
        WHERE id = ${input.archiveId}::uuid AND tenant_id = ${input.tenantId}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!row || row.source !== "imported" || !row.manifest) {
      throw new Error("Audit archive restore session not found");
    }
    verifySuppliedArchiveManifest({
      tenantId: input.tenantId,
      manifest: row.manifest as unknown as AuditArchiveManifestPayload,
      manifestSha256: String(row.manifest_sha256),
      signature: String(row.signature),
    });
    const manifest = row.manifest as unknown as AuditArchiveManifestPayload;
    const expected = manifest.chunks[input.index];
    if (!expected || expected.index !== input.index) {
      throw new Error("Restored audit archive chunk index is not in the signed manifest");
    }
    const byteLength = new TextEncoder().encode(input.jsonl).length;
    if (byteLength !== expected.byteLength || sha256Hex(input.jsonl) !== expected.sha256) {
      throw new Error("Restored audit archive chunk does not match the signed manifest");
    }
    const existing = rowsFromExecute<{ sha256: string; byte_length: number | string }>(
      await tx.execute(sql`
        SELECT sha256, byte_length FROM audit_archive_chunks
        WHERE archive_id = ${input.archiveId}::uuid AND chunk_index = ${input.index}
      `),
    )[0];
    if (existing) {
      if (existing.sha256 === expected.sha256 && Number(existing.byte_length) === byteLength) {
        return { reused: true };
      }
      throw new Error("Restored audit archive chunk is immutable");
    }
    if (row.status !== "building") {
      throw new Error("Completed audit archive restores are immutable");
    }
    await tx.execute(sql`
      INSERT INTO audit_archive_chunks
        (archive_id, chunk_index, from_seq, to_seq, event_count, sha256, byte_length, jsonl)
      VALUES
        (${input.archiveId}::uuid, ${input.index}, ${expected.fromSeq}, ${expected.toSeq},
         ${expected.eventCount}, ${expected.sha256}, ${byteLength}, ${input.jsonl})
    `);
    return { reused: false };
  });
}

export async function completeAuditArchiveRestore(input: {
  tenantId: string;
  archiveId: string;
  actorId?: string | null;
  requestId?: string | null;
}): Promise<AuditArchiveResult> {
  return withTenantAuditedTransaction(input.tenantId, async (rawTx, appendRequiredAudit) => {
    const tx = rawTx as { execute(query: ReturnType<typeof sql>): Promise<unknown> };
    const row = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives
        WHERE id = ${input.archiveId}::uuid AND tenant_id = ${input.tenantId}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!row || row.source !== "imported" || !row.manifest) {
      throw new Error("Audit archive restore session not found");
    }
    const manifest = row.manifest as unknown as AuditArchiveManifestPayload;
    verifySuppliedArchiveManifest({
      tenantId: input.tenantId,
      manifest,
      manifestSha256: String(row.manifest_sha256),
      signature: String(row.signature),
    });
    await verifyStoredArchiveChunks(tx, manifest);
    if (row.status === "sealed") {
      return { archiveId: input.archiveId, reused: true, ...parseStoredManifest(row) };
    }
    const updated = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        UPDATE audit_archives
        SET status = 'sealed', sealed_at = now(), updated_at = now()
        WHERE id = ${input.archiveId}::uuid AND tenant_id = ${input.tenantId}
          AND source = 'imported' AND status = 'building'
        RETURNING *
      `),
    )[0];
    if (!updated) throw new Error("Audit archive restore was concurrently completed");
    await appendRequiredAudit({
      tenantId: input.tenantId,
      actorType: input.actorId ? "user" : "system",
      actorId: input.actorId ?? null,
      action: "audit.archive.restore_completed",
      resourceType: "audit_archive",
      resourceId: input.archiveId,
      metadata: {
        manifestSha256: String(row.manifest_sha256),
        eventCount: manifest.eventCount,
        signingKeyId: manifest.signingKeyId,
      },
      requestId: input.requestId ?? null,
    });
    return { archiveId: input.archiveId, reused: false, ...parseStoredManifest(updated) };
  });
}

export async function listAuditArchives(
  tenantId: string,
  options: { limit?: number; before?: Date } = {},
): Promise<AuditArchiveResult[]> {
  const limit = options.limit ?? 50;
  validateInteger("limit", limit, 1, 200);
  const rows = rowsFromExecute<Record<string, unknown>>(
    await getDb().execute(
      options.before
        ? sql`
            SELECT * FROM audit_archives
            WHERE tenant_id = ${tenantId} AND status IN ('sealed', 'pruned')
              AND created_at < ${options.before.toISOString()}::timestamptz
            ORDER BY created_at DESC, id DESC LIMIT ${limit}
          `
        : sql`
            SELECT * FROM audit_archives
            WHERE tenant_id = ${tenantId} AND status IN ('sealed', 'pruned')
            ORDER BY created_at DESC, id DESC LIMIT ${limit}
          `,
    ),
  );
  return rows.map((row) => ({
    archiveId: String(row.id),
    reused: true,
    ...parseStoredManifest(row),
  }));
}

export async function getAuditArchiveManifest(
  tenantId: string,
  archiveId: string,
): Promise<SignedAuditArchiveManifest | null> {
  const row = rowsFromExecute<Record<string, unknown>>(
    await getDb().execute(sql`
      SELECT * FROM audit_archives WHERE id = ${archiveId}::uuid AND tenant_id = ${tenantId} LIMIT 1
    `),
  )[0];
  return row ? parseStoredManifest(row) : null;
}

export async function getAuditArchiveChunk(
  tenantId: string,
  archiveId: string,
  index: number,
): Promise<{ jsonl: string; sha256: string; byteLength: number } | null> {
  const row = rowsFromExecute<{ jsonl: string; sha256: string; byte_length: number | string }>(
    await getDb().execute(sql`
      SELECT c.jsonl, c.sha256, c.byte_length
      FROM audit_archive_chunks c
      JOIN audit_archives a ON a.id = c.archive_id
      WHERE c.archive_id = ${archiveId}::uuid AND c.chunk_index = ${index}
        AND a.tenant_id = ${tenantId} AND a.status IN ('sealed', 'pruned')
      LIMIT 1
    `),
  )[0];
  return row ? { jsonl: row.jsonl, sha256: row.sha256, byteLength: Number(row.byte_length) } : null;
}
