/**
 * Destructive archive acknowledgement/prune races against a real PostgreSQL
 * pool. PGLite uses one connection and cannot prove row/advisory lock behavior.
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { generateKeyPairSync, sign } from "node:crypto";
import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";
import { writeAuditEvent } from "../services/audit";
import {
  type AuditArchiveDurabilityAcknowledgementPayload,
  createAuditArchive,
  pruneSealedAuditArchive,
  recordAuditArchiveDurabilityAcknowledgement,
  setAuditRetentionPolicy,
} from "../services/audit-archive";
import { parseSigningKey, publicKeyPem } from "../services/audit-checkpoint";

setDefaultTimeout(120_000);

const SKIP = !process.env.DATABASE_URL;
const SUFFIX = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
const TENANT = `audit-archive-race-${SUFFIX}`;
const SIGNING_KEY = "42".repeat(32);
const SIGNING_KEY_ID = `archive-race-${SUFFIX}`.slice(0, 64);
const ACK_KEY_ID = `durability-race-${SUFFIX}`.slice(0, 64);
const ACK_KEYS = generateKeyPairSync("ed25519");

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

function rowList<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  return ((result as { rows?: T[] }).rows ?? []) as T[];
}

async function cleanup() {
  const db = getDb();
  await db.execute(sql`DELETE FROM audit_archives WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM audit_retention_policies WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM tenants WHERE id = ${TENANT}`);
}

describe.skipIf(SKIP)("#216 audit archive destructive races (real PG)", () => {
  beforeAll(async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "7".repeat(64);
    process.env.STEWARD_AUDIT_SIGNING_KEY = SIGNING_KEY;
    process.env.STEWARD_AUDIT_SIGNING_KEY_ID = SIGNING_KEY_ID;
    process.env.STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS = JSON.stringify({
      [SIGNING_KEY_ID]: publicKeyPem(parseSigningKey(SIGNING_KEY)),
    });
    process.env.STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS = JSON.stringify({
      [ACK_KEY_ID]: ACK_KEYS.publicKey.export({ format: "pem", type: "spki" }).toString(),
    });
    await cleanup();
    await getDb().execute(sql`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES (${TENANT}, 'archive race', ${`hash-${SUFFIX}`})
    `);
    for (let index = 0; index < 3; index++) {
      await writeAuditEvent({
        tenantId: TENANT,
        actorType: "system",
        action: "archive.race.fixture",
        metadata: { index },
      });
    }
  });

  afterAll(async () => {
    if (SKIP) return;
    await cleanup();
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY_ID;
    delete process.env.STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS;
    delete process.env.STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS;
  });

  test("concurrent acknowledgement and prune calls each produce one destructive authority trail", async () => {
    const policy = await setAuditRetentionPolicy({
      tenantId: TENANT,
      enabled: true,
      retentionDays: 30,
      archiveChunkSize: 1,
      updatedBy: "race-owner",
    });
    const archive = await createAuditArchive({
      tenantId: TENANT,
      fromSeq: 1,
      toSeq: 2,
      chunkSize: 1,
      retentionPolicyRevision: policy.revision,
    });
    const payload: AuditArchiveDurabilityAcknowledgementPayload = {
      schemaVersion: "steward.audit-archive-durability.v1",
      archiveId: archive.archiveId,
      tenantId: TENANT,
      manifestSha256: archive.manifestSha256,
      durabilityUri: `s3://immutable-audit/${archive.archiveId}`,
      objectVersion: "object-lock-version-race",
      acknowledgedAt: new Date(Date.parse(archive.manifest.createdAt) + 1).toISOString(),
    };
    const signature = sign(null, Buffer.from(canonical(payload)), ACK_KEYS.privateKey).toString(
      "base64",
    );
    const acknowledge = () =>
      recordAuditArchiveDurabilityAcknowledgement({
        tenantId: TENANT,
        archiveId: archive.archiveId,
        payload,
        keyId: ACK_KEY_ID,
        signature,
      });

    const acknowledgements = await Promise.all([acknowledge(), acknowledge()]);
    expect(acknowledgements.filter((result) => !result.reused)).toHaveLength(1);
    expect(acknowledgements.filter((result) => result.reused)).toHaveLength(1);

    const prunes = await Promise.all([
      pruneSealedAuditArchive(TENANT, archive.archiveId),
      pruneSealedAuditArchive(TENANT, archive.archiveId),
    ]);
    expect(prunes.filter((result) => !result.reused && result.deleted === 2)).toHaveLength(1);
    expect(prunes.filter((result) => result.reused && result.deleted === 0)).toHaveLength(1);

    const evidence = rowList<{ action: string; count: number | string }>(
      await getDb().execute(sql`
        SELECT action, count(*)::int AS count
        FROM audit_events
        WHERE tenant_id = ${TENANT} AND action IN (
          'audit.archive.durability_acknowledged',
          'audit.retention.prune_authorized',
          'audit.retention.prune_completed'
        )
        GROUP BY action
      `),
    );
    expect(Object.fromEntries(evidence.map((row) => [row.action, Number(row.count)]))).toEqual({
      "audit.archive.durability_acknowledged": 1,
      "audit.retention.prune_authorized": 1,
      "audit.retention.prune_completed": 1,
    });
  });
});
