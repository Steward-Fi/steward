import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, sign as signBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { verifyAuditChain, writeAuditEvent } from "../services/audit";
import {
  beginAuditArchiveRestore,
  completeAuditArchiveRestore,
  createAuditArchive,
  getAuditArchiveChunk,
  getAuditArchiveManifest,
  listAuditArchives,
  pruneSealedAuditArchive,
  putAuditArchiveRestoreChunk,
  recordAuditArchiveDurabilityAcknowledgement,
  setAuditRetentionPolicy,
} from "../services/audit-archive";
import { parseSigningKey, publicKeyPem } from "../services/audit-checkpoint";

const TENANT = `audit-archive-${Date.now()}`;
const OTHER = `${TENANT}-other`;
const ARCHIVE_SIGNING_KEY = "11".repeat(32);
const ARCHIVE_SIGNING_KEY_ID = "archive-test-key-v1";
const ACK_KEY_ID = "external-archive-store-test-v1";
const ACK_KEYS = generateKeyPairSync("ed25519");
let policyRevision = 0;

describe("archive restore request boundary", () => {
  it("authenticates and MFA-gates before granting the narrow 25 MiB body exception", () => {
    const appSource = readFileSync(join(import.meta.dir, "..", "app.ts"), "utf8");
    const tenantAuthIndex = appSource.indexOf(
      "app.use(archiveRestoreChunkPath, (c, next) => tenantAuth(c, next))",
    );
    const mfaGateIndex = appSource.indexOf(
      "app.use(archiveRestoreChunkPath, auditOwnerAdminMfaGate)",
    );
    const bodyLimitIndex = appSource.indexOf('app.use("*", (c, next) =>');
    expect(tenantAuthIndex).toBeGreaterThanOrEqual(0);
    expect(mfaGateIndex).toBeGreaterThan(tenantAuthIndex);
    expect(bodyLimitIndex).toBeGreaterThan(mfaGateIndex);
    expect(appSource).toContain("maxSize: MAX_ARCHIVE_CHUNK_BYTES");
    expect(appSource).toContain("maxSize: 1024 * 1024");
  });
});

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

async function acknowledge(
  archive: Awaited<ReturnType<typeof createAuditArchive>>,
  overrides: Partial<{
    tenantId: string;
    manifestSha256: string;
    durabilityUri: string;
    objectVersion: string;
    keyId: string;
  }> = {},
) {
  const payload = {
    schemaVersion: "steward.audit-archive-durability.v1" as const,
    archiveId: archive.archiveId,
    tenantId: overrides.tenantId ?? archive.manifest.tenantId,
    manifestSha256: overrides.manifestSha256 ?? archive.manifestSha256,
    durabilityUri: overrides.durabilityUri ?? `s3://immutable-audit/${archive.archiveId}`,
    objectVersion: overrides.objectVersion ?? "object-lock-version-1",
    acknowledgedAt: new Date(Date.parse(archive.manifest.createdAt) + 1).toISOString(),
  };
  const signature = signBytes(null, Buffer.from(canonical(payload)), ACK_KEYS.privateKey).toString(
    "base64",
  );
  return recordAuditArchiveDurabilityAcknowledgement({
    tenantId: archive.manifest.tenantId,
    archiveId: archive.archiveId,
    payload,
    keyId: overrides.keyId ?? ACK_KEY_ID,
    signature,
  });
}

function rows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  return ((result as { rows?: T[] }).rows ?? []) as T[];
}

describe("durable audit retention archives", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-archive-test-hmac-key-0123456789abcdef";
    process.env.STEWARD_AUDIT_SIGNING_KEY = ARCHIVE_SIGNING_KEY;
    process.env.STEWARD_AUDIT_SIGNING_KEY_ID = ARCHIVE_SIGNING_KEY_ID;
    process.env.STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS = JSON.stringify({
      [ARCHIVE_SIGNING_KEY_ID]: publicKeyPem(parseSigningKey(ARCHIVE_SIGNING_KEY)),
    });
    process.env.STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS = JSON.stringify({
      [ACK_KEY_ID]: ACK_KEYS.publicKey.export({ format: "pem", type: "spki" }).toString(),
    });
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT, name: "Archive Tenant", apiKeyHash: "archive-hash" },
        { id: OTHER, name: "Other Tenant", apiKeyHash: "other-hash" },
      ]);
    for (let i = 1; i <= 5; i++) {
      await writeAuditEvent({
        tenantId: TENANT,
        actorType: "system",
        action: "archive.fixture",
        metadata: { i },
      });
    }
  }, 120_000);

  afterAll(async () => {
    await getDb().execute(sql`DELETE FROM audit_archives WHERE tenant_id IN (${TENANT}, ${OTHER})`);
    await getDb().delete(tenants).where(eq(tenants.id, TENANT));
    await getDb().delete(tenants).where(eq(tenants.id, OTHER));
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY_ID;
    delete process.env.STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS;
    delete process.env.STEWARD_AUDIT_ARCHIVE_ACK_TRUSTED_KEYS;
  });

  it("keeps tenant policy isolated and validates configured bounds", async () => {
    const policy = await setAuditRetentionPolicy({
      tenantId: TENANT,
      enabled: true,
      retentionDays: 90,
      archiveChunkSize: 2,
      updatedBy: "owner",
    });
    expect(policy).toMatchObject({ tenantId: TENANT, enabled: true, retentionDays: 90 });
    policyRevision = policy.revision;
    const other = await getDb().execute(
      sql`SELECT count(*)::int AS count FROM audit_retention_policies WHERE tenant_id = ${OTHER}`,
    );
    expect(Number(rows<{ count: number }>(other)[0].count)).toBe(0);
    expect(
      setAuditRetentionPolicy({
        tenantId: TENANT,
        enabled: true,
        retentionDays: 29,
        archiveChunkSize: 2,
        updatedBy: "owner",
      }),
    ).rejects.toThrow("retentionDays");
  });

  it("seals all chunks before pruning, resumes idempotently, and preserves the live chain", async () => {
    const sealed = await createAuditArchive({
      tenantId: TENANT,
      fromSeq: 1,
      toSeq: 3,
      chunkSize: 2,
      retentionPolicyRevision: policyRevision,
    });
    expect(sealed).toMatchObject({ reused: false, status: "sealed" });
    expect(sealed.manifest.chunks).toHaveLength(2);

    const before = await getDb().execute(
      sql`SELECT count(*)::int AS count FROM audit_events WHERE tenant_id = ${TENANT}`,
    );
    // Five fixtures plus atomic policy-update and archive-sealed evidence.
    expect(Number(rows<{ count: number }>(before)[0].count)).toBe(7);
    expect(await getAuditArchiveManifest(OTHER, sealed.archiveId)).toBeNull();
    expect(await getAuditArchiveChunk(OTHER, sealed.archiveId, 0)).toBeNull();

    const directory = mkdtempSync(join(tmpdir(), "steward-audit-archive-"));
    try {
      writeFileSync(join(directory, "manifest.json"), JSON.stringify(sealed));
      for (const chunk of sealed.manifest.chunks) {
        const stored = await getAuditArchiveChunk(TENANT, sealed.archiveId, chunk.index);
        writeFileSync(join(directory, chunk.file), stored?.jsonl ?? "");
      }
      const fingerprint = createHash("sha256")
        .update(createPublicKey(sealed.publicKey).export({ format: "der", type: "spki" }))
        .digest("hex");
      const verifier = spawnSync(
        "node",
        [
          "scripts/verify-audit-archive.mjs",
          join(directory, "manifest.json"),
          directory,
          "--expected-key-fingerprint",
          fingerprint,
        ],
        { cwd: join(import.meta.dir, "../../../.."), encoding: "utf8" },
      );
      expect(verifier.status).toBe(0);
      const integrityOnly = spawnSync(
        "node",
        ["scripts/verify-audit-archive.mjs", join(directory, "manifest.json"), directory],
        { cwd: join(import.meta.dir, "../../../.."), encoding: "utf8" },
      );
      expect(integrityOnly.status).toBe(0);
      expect(integrityOnly.stderr).toContain("verifies archive integrity only");
      expect(integrityOnly.stdout).toContain("PASS (integrity only");
      writeFileSync(join(directory, sealed.manifest.chunks[0].file), "tampered\n");
      const tampered = spawnSync(
        "node",
        ["scripts/verify-audit-archive.mjs", join(directory, "manifest.json"), directory],
        { cwd: join(import.meta.dir, "../../../.."), encoding: "utf8" },
      );
      expect(tampered.status).toBe(1);
      expect(tampered.stderr).toContain("does not match");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }

    const resumed = await createAuditArchive({
      tenantId: TENANT,
      fromSeq: 1,
      toSeq: 3,
      chunkSize: 2,
      retentionPolicyRevision: policyRevision,
    });
    expect(resumed).toMatchObject({ archiveId: sealed.archiveId, reused: true });

    const missingChunk = await getAuditArchiveChunk(TENANT, sealed.archiveId, 1);
    await getDb().execute(
      sql`DELETE FROM audit_archive_chunks WHERE archive_id = ${sealed.archiveId}::uuid AND chunk_index = 1`,
    );
    expect(pruneSealedAuditArchive(TENANT, sealed.archiveId)).rejects.toThrow("incomplete");
    const sourceAfterMissingChunk = await getDb().execute(
      sql`SELECT count(*)::int AS count FROM audit_events WHERE tenant_id = ${TENANT} AND seq BETWEEN 1 AND 3`,
    );
    expect(Number(rows<{ count: number }>(sourceAfterMissingChunk)[0].count)).toBe(3);
    const chunkManifest = sealed.manifest.chunks[1];
    await getDb().execute(sql`
      INSERT INTO audit_archive_chunks
        (archive_id, chunk_index, from_seq, to_seq, event_count, sha256, byte_length, jsonl)
      VALUES (${sealed.archiveId}::uuid, 1, ${chunkManifest.fromSeq}, ${chunkManifest.toSeq},
        ${chunkManifest.eventCount}, ${chunkManifest.sha256}, ${chunkManifest.byteLength},
        ${missingChunk?.jsonl ?? ""})
    `);

    expect(pruneSealedAuditArchive(TENANT, sealed.archiveId)).rejects.toThrow(
      "external durability acknowledgement",
    );
    await expect(acknowledge(sealed, { manifestSha256: "0".repeat(64) })).rejects.toThrow(
      "payload is invalid",
    );
    const acknowledged = await acknowledge(sealed);
    expect(acknowledged).toMatchObject({ reused: false });
    expect(await acknowledge(sealed)).toMatchObject({ reused: true });
    await expect(acknowledge(sealed, { objectVersion: "different-version" })).rejects.toThrow(
      "immutable",
    );

    const pruned = await pruneSealedAuditArchive(TENANT, sealed.archiveId);
    expect(pruned).toMatchObject({ deleted: 3, floorSeq: 3, reused: false });
    expect(await pruneSealedAuditArchive(TENANT, sealed.archiveId)).toMatchObject({
      deleted: 0,
      floorSeq: 3,
      reused: true,
    });
    expect(await getAuditArchiveChunk(TENANT, sealed.archiveId, 0)).not.toBeNull();
    expect(await verifyAuditChain(TENANT, { requireHead: true })).toMatchObject({
      valid: true,
    });
  });

  it("refuses deletion without a sealed receipt or across a non-contiguous floor", async () => {
    expect(pruneSealedAuditArchive(TENANT, "00000000-0000-4000-8000-000000000000")).rejects.toThrow(
      "sealed",
    );
    const later = await createAuditArchive({
      tenantId: TENANT,
      fromSeq: 5,
      toSeq: 5,
      chunkSize: 1,
      retentionPolicyRevision: policyRevision,
    });
    await expect(
      (async () =>
        getDb().execute(
          sql`UPDATE audit_archives SET signature = ${"A".repeat(86)} || '==' WHERE id = ${later.archiveId}::uuid`,
        ))(),
    ).rejects.toThrow("Failed query");
    await expect(
      (async () =>
        getDb().execute(
          sql`UPDATE audit_archives SET public_key = 'attacker' WHERE id = ${later.archiveId}::uuid`,
        ))(),
    ).rejects.toThrow("Failed query");
    await acknowledge(later);
    expect(pruneSealedAuditArchive(TENANT, later.archiveId)).rejects.toThrow(
      "live retention floor 4",
    );
    const remaining = await getDb().execute(
      sql`SELECT seq FROM audit_events WHERE tenant_id = ${TENANT} ORDER BY seq`,
    );
    expect(rows<{ seq: number | string }>(remaining).map((row) => Number(row.seq))).toContain(4);

    const updated = await setAuditRetentionPolicy({
      tenantId: TENANT,
      enabled: true,
      retentionDays: 91,
      archiveChunkSize: 2,
      updatedBy: "owner",
    });
    expect(updated.revision).toBe(policyRevision + 1);
    await expect(pruneSealedAuditArchive(TENANT, later.archiveId)).rejects.toThrow(
      "policy changed",
    );
    policyRevision = updated.revision;
  });

  it("lists tenant archives and resumes an imported restore without granting prune authority", async () => {
    const exported = await createAuditArchive({
      tenantId: TENANT,
      fromSeq: 4,
      toSeq: 4,
      chunkSize: 1,
    });
    const chunk = await getAuditArchiveChunk(TENANT, exported.archiveId, 0);
    expect(chunk).not.toBeNull();
    await getDb().execute(
      sql`DELETE FROM audit_archives WHERE id = ${exported.archiveId}::uuid AND tenant_id = ${TENANT}`,
    );

    const unsafeManifest = {
      ...exported.manifest,
      chunks: [{ ...exported.manifest.chunks[0], file: "../outside.jsonl" }],
    };
    const unsafeManifestBytes = Buffer.from(canonical(unsafeManifest));
    await expect(
      beginAuditArchiveRestore({
        tenantId: TENANT,
        manifest: unsafeManifest,
        manifestSha256: createHash("sha256").update(unsafeManifestBytes).digest("hex"),
        signature: signBytes(
          null,
          unsafeManifestBytes,
          parseSigningKey(ARCHIVE_SIGNING_KEY),
        ).toString("base64"),
      }),
    ).rejects.toThrow("manifest chunk 0 is invalid");

    const started = await beginAuditArchiveRestore({
      tenantId: TENANT,
      manifest: exported.manifest,
      manifestSha256: exported.manifestSha256,
      signature: exported.signature,
      actorId: "owner",
    });
    expect(started).toMatchObject({ reused: false, status: "building" });
    expect(
      await putAuditArchiveRestoreChunk({
        tenantId: TENANT,
        archiveId: exported.archiveId,
        index: 0,
        jsonl: chunk!.jsonl,
      }),
    ).toEqual({ reused: false });
    expect(
      await putAuditArchiveRestoreChunk({
        tenantId: TENANT,
        archiveId: exported.archiveId,
        index: 0,
        jsonl: chunk!.jsonl,
      }),
    ).toEqual({ reused: true });
    const completed = await completeAuditArchiveRestore({
      tenantId: TENANT,
      archiveId: exported.archiveId,
      actorId: "owner",
    });
    expect(completed).toMatchObject({ status: "sealed", reused: false });
    expect(await listAuditArchives(TENANT)).toContainEqual(
      expect.objectContaining({ archiveId: exported.archiveId }),
    );
    expect(await listAuditArchives(OTHER)).toEqual([]);
    expect(pruneSealedAuditArchive(TENANT, exported.archiveId)).rejects.toThrow(
      "Restored archives cannot authorize deletion",
    );
  });

  it("allows a policy revision to reseal a range that was previously exported manually", async () => {
    await writeAuditEvent({
      tenantId: OTHER,
      actorType: "system",
      action: "archive.manual.fixture",
    });
    const manual = await createAuditArchive({
      tenantId: OTHER,
      fromSeq: 1,
      toSeq: 1,
      chunkSize: 1,
    });
    const policy = await setAuditRetentionPolicy({
      tenantId: OTHER,
      enabled: true,
      retentionDays: 30,
      archiveChunkSize: 1,
      updatedBy: "owner",
    });
    const governed = await createAuditArchive({
      tenantId: OTHER,
      fromSeq: 1,
      toSeq: 1,
      chunkSize: 1,
      retentionPolicyRevision: policy.revision,
    });
    expect(governed.archiveId).not.toBe(manual.archiveId);
    expect(governed.manifest.retentionPolicyRevision).toBe(policy.revision);
  });
});
