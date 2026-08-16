/** Durable, tenant-scoped signed JSONL audit archives and chain-safe pruning. */

import { createHash, createPublicKey, randomUUID, sign, verify } from "node:crypto";
import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";
import { verifyAuditChain } from "./audit";
import { parseSigningKey, publicKeyPem } from "./audit-checkpoint";

export const MIN_AUDIT_RETENTION_DAYS = 30;
export const MAX_AUDIT_RETENTION_DAYS = 3650;
export const MIN_ARCHIVE_CHUNK_SIZE = 1;
export const MAX_ARCHIVE_CHUNK_SIZE = 10_000;
export const MAX_ARCHIVE_EVENTS_PER_RUN = 50_000;

export interface AuditRetentionPolicyValue {
  tenantId: string;
  enabled: boolean;
  retentionDays: number;
  archiveChunkSize: number;
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
  if (process.env.STEWARD_DB_MODE !== "pglite" && process.env.STEWARD_PGLITE_MEMORY !== "true") {
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
  let publicKey;
  try {
    publicKey = createPublicKey(String(row.public_key));
  } catch {
    throw new Error("Audit archive receipt public key is invalid");
  }
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    !verify(null, manifestBytes, publicKey, base64ToBytes(String(row.signature)))
  ) {
    throw new Error("Audit archive receipt signature does not verify");
  }
  if (
    manifest.archiveId !== String(row.id) ||
    manifest.tenantId !== String(row.tenant_id) ||
    manifest.fromSeq !== Number(row.from_seq) ||
    manifest.toSeq !== Number(row.to_seq) ||
    manifest.eventCount !== Number(row.event_count)
  ) {
    throw new Error("Audit archive receipt identity does not match its manifest");
  }
  return {
    manifest,
    manifestSha256: String(row.manifest_sha256),
    signature: String(row.signature),
    publicKey: String(row.public_key),
    status: row.status === "pruned" ? "pruned" : "sealed",
    sealedAt: asIso(row.sealed_at as Date | string),
    prunedAt: row.pruned_at ? asIso(row.pruned_at as Date | string) : null,
  };
}

export async function getAuditRetentionPolicy(
  tenantId: string,
): Promise<AuditRetentionPolicyValue> {
  const rows = rowsFromExecute<Record<string, unknown>>(
    await getDb().execute(sql`
      SELECT tenant_id, enabled, retention_days, archive_chunk_size, updated_by, created_at, updated_at
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
  await getDb().execute(sql`
    INSERT INTO audit_retention_policies
      (tenant_id, enabled, retention_days, archive_chunk_size, updated_by, created_at, updated_at)
    VALUES
      (${input.tenantId}, ${input.enabled}, ${input.retentionDays}, ${input.archiveChunkSize},
       ${input.updatedBy}, now(), now())
    ON CONFLICT (tenant_id) DO UPDATE
      SET enabled = EXCLUDED.enabled,
          retention_days = EXCLUDED.retention_days,
          archive_chunk_size = EXCLUDED.archive_chunk_size,
          updated_by = EXCLUDED.updated_by,
          updated_at = now()
  `);
  return getAuditRetentionPolicy(input.tenantId);
}

export async function createAuditArchive(input: {
  tenantId: string;
  fromSeq: number;
  toSeq: number;
  chunkSize: number;
}): Promise<AuditArchiveResult> {
  validateInteger("fromSeq", input.fromSeq, 1, Number.MAX_SAFE_INTEGER);
  validateInteger("toSeq", input.toSeq, input.fromSeq, Number.MAX_SAFE_INTEGER);
  validateInteger("chunkSize", input.chunkSize, MIN_ARCHIVE_CHUNK_SIZE, MAX_ARCHIVE_CHUNK_SIZE);
  const eventCount = input.toSeq - input.fromSeq + 1;
  if (eventCount > MAX_ARCHIVE_EVENTS_PER_RUN) {
    throw new Error(`Archive range cannot exceed ${MAX_ARCHIVE_EVENTS_PER_RUN} events per run`);
  }
  const sourceVerification = await verifyAuditChain(input.tenantId, {
    fromSeq: input.fromSeq,
    toSeq: input.toSeq,
    requireHead: true,
  });
  if (!sourceVerification.valid || sourceVerification.count !== eventCount) {
    const brokenAt = sourceVerification.valid
      ? input.fromSeq + sourceVerification.count
      : sourceVerification.brokenAt;
    throw new Error(`Audit archive source failed HMAC verification at seq ${brokenAt}`);
  }

  return getDb().transaction(async (tx) => {
    await lockTenantAuditWriter(tx, input.tenantId);
    const existing = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives
        WHERE tenant_id = ${input.tenantId} AND from_seq = ${input.fromSeq} AND to_seq = ${input.toSeq}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (existing && (existing.status === "sealed" || existing.status === "pruned")) {
      return {
        archiveId: String(existing.id),
        reused: true,
        ...parseStoredManifest(existing),
      };
    }

    const archiveId = existing ? String(existing.id) : randomUUID();
    if (!existing) {
      await tx.execute(sql`
        INSERT INTO audit_archives
          (id, tenant_id, from_seq, to_seq, event_count, status, created_at, updated_at)
        VALUES
          (${archiveId}::uuid, ${input.tenantId}, ${input.fromSeq}, ${input.toSeq}, ${eventCount},
           'building', now(), now())
      `);
    } else {
      await tx.execute(sql`DELETE FROM audit_archive_chunks WHERE archive_id = ${archiveId}::uuid`);
    }

    const chunks: AuditArchiveChunkManifest[] = [];
    let firstRow: AuditEventRow | undefined;
    let lastRow: AuditEventRow | undefined;
    let observedCount = 0;
    for (let cursor = input.fromSeq, index = 0; cursor <= input.toSeq; index++) {
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
      firstRow ??= rows[0];
      lastRow = rows[rows.length - 1];
      observedCount += rows.length;
      const jsonl = `${rows.map(archiveLine).join("\n")}\n`;
      const chunk = {
        index,
        fromSeq: cursor,
        toSeq: chunkTo,
        eventCount: rows.length,
        sha256: sha256Hex(jsonl),
        byteLength: new TextEncoder().encode(jsonl).length,
        file: `chunk-${String(index).padStart(6, "0")}.jsonl`,
      };
      await tx.execute(sql`
        INSERT INTO audit_archive_chunks
          (archive_id, chunk_index, from_seq, to_seq, event_count, sha256, byte_length, jsonl)
        VALUES
          (${archiveId}::uuid, ${index}, ${cursor}, ${chunkTo}, ${rows.length}, ${chunk.sha256},
           ${chunk.byteLength}, ${jsonl})
      `);
      chunks.push(chunk);
      cursor = chunkTo + 1;
    }
    if (!firstRow || !lastRow || observedCount !== eventCount) {
      throw new Error("Audit archive event count changed while sealing");
    }

    const createdAt = new Date().toISOString();
    const manifest: AuditArchiveManifestPayload = {
      schemaVersion: "steward.audit-archive.v1",
      archiveId,
      tenantId: input.tenantId,
      createdAt,
      fromSeq: input.fromSeq,
      toSeq: input.toSeq,
      eventCount,
      startPrevHash: bytesToHex(firstRow.prev_hash),
      endHmac: bytesToHex(lastRow.hmac),
      format: "application/x-ndjson",
      chunks,
    };
    const manifestBytes = canonicalBytes(manifest);
    const manifestSha256 = sha256Hex(manifestBytes);
    const signingKey = parseSigningKey(process.env.STEWARD_AUDIT_SIGNING_KEY ?? "");
    const signature = bytesToBase64(sign(null, manifestBytes, signingKey));
    const publicKey = publicKeyPem(signingKey);
    await tx.execute(sql`
      UPDATE audit_archives
      SET status = 'sealed', manifest = ${JSON.stringify(manifest)}::jsonb,
          manifest_sha256 = ${manifestSha256}, signature = ${signature}, public_key = ${publicKey},
          sealed_at = now(), updated_at = now()
      WHERE id = ${archiveId}::uuid AND tenant_id = ${input.tenantId}
    `);
    const sealed = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives WHERE id = ${archiveId}::uuid AND tenant_id = ${input.tenantId}
      `),
    )[0];
    if (!sealed) throw new Error("Audit archive receipt failed to persist");
    return { archiveId, reused: false, ...parseStoredManifest(sealed) };
  });
}

export async function pruneSealedAuditArchive(
  tenantId: string,
  archiveId: string,
): Promise<{ archiveId: string; deleted: number; floorSeq: number; reused: boolean }> {
  return getDb().transaction(async (tx) => {
    await lockTenantAuditWriter(tx, tenantId);
    const receipt = rowsFromExecute<Record<string, unknown>>(
      await tx.execute(sql`
        SELECT * FROM audit_archives WHERE id = ${archiveId}::uuid AND tenant_id = ${tenantId}
        LIMIT 1 FOR UPDATE
      `),
    )[0];
    if (!receipt || (receipt.status !== "sealed" && receipt.status !== "pruned")) {
      throw new Error("A durably sealed tenant archive receipt is required before pruning");
    }
    parseStoredManifest(receipt);
    const toSeq = Number(receipt.to_seq);
    const fromSeq = Number(receipt.from_seq);
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
    const manifest = receipt.manifest as unknown as AuditArchiveManifestPayload;
    if (bytesToHex(anchor.hmac) !== manifest.endHmac) {
      throw new Error("Archive receipt does not match the live floor anchor HMAC");
    }
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
    return { archiveId, deleted: removed.length, floorSeq: toSeq, reused: false };
  });
}

export async function runTenantAuditRetention(tenantId: string): Promise<{
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
  });
  const pruned = await pruneSealedAuditArchive(tenantId, archive.archiveId);
  return {
    tenantId,
    archiveId: archive.archiveId,
    archived: toSeq - floorSeq,
    deleted: pruned.deleted,
    floorSeq: pruned.floorSeq,
    reused: archive.reused || pruned.reused,
  };
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
