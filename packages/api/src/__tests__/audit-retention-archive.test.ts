import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { verifyAuditChain, writeAuditEvent } from "../services/audit";
import {
  createAuditArchive,
  getAuditArchiveChunk,
  getAuditArchiveManifest,
  pruneSealedAuditArchive,
  setAuditRetentionPolicy,
} from "../services/audit-archive";

const TENANT = `audit-archive-${Date.now()}`;
const OTHER = `${TENANT}-other`;

function rows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  return ((result as { rows?: T[] }).rows ?? []) as T[];
}

describe("durable audit retention archives", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-archive-test-hmac-key-0123456789abcdef";
    process.env.STEWARD_AUDIT_SIGNING_KEY = "11".repeat(32);
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
    await getDb().execute(sql`DELETE FROM audit_archives WHERE tenant_id = ${TENANT}`);
    await getDb().delete(tenants).where(eq(tenants.id, TENANT));
    await getDb().delete(tenants).where(eq(tenants.id, OTHER));
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
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
    });
    expect(sealed).toMatchObject({ reused: false, status: "sealed" });
    expect(sealed.manifest.chunks).toHaveLength(2);

    const before = await getDb().execute(
      sql`SELECT count(*)::int AS count FROM audit_events WHERE tenant_id = ${TENANT}`,
    );
    expect(Number(rows<{ count: number }>(before)[0].count)).toBe(5);
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
    });
    expect(resumed).toMatchObject({ archiveId: sealed.archiveId, reused: true });

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
      count: 2,
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
    });
    await getDb().execute(
      sql`UPDATE audit_archives SET signature = ${"A".repeat(86)} || '==' WHERE id = ${later.archiveId}::uuid`,
    );
    expect(pruneSealedAuditArchive(TENANT, later.archiveId)).rejects.toThrow("signature");
    await getDb().execute(
      sql`UPDATE audit_archives SET signature = ${later.signature} WHERE id = ${later.archiveId}::uuid`,
    );
    expect(pruneSealedAuditArchive(TENANT, later.archiveId)).rejects.toThrow(
      "live retention floor 4",
    );
    const remaining = await getDb().execute(
      sql`SELECT seq FROM audit_events WHERE tenant_id = ${TENANT} ORDER BY seq`,
    );
    expect(rows<{ seq: number | string }>(remaining).map((row) => Number(row.seq))).toEqual([4, 5]);
  });
});
