import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID, sign } from "node:crypto";
import { signAccessToken } from "@stwd/auth";
import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import {
  type AuditArchiveManifestPayload,
  MAX_ARCHIVE_CHUNK_BYTES,
  MAX_ARCHIVE_CHUNKS,
  MAX_ARCHIVE_MANIFEST_BYTES,
} from "../services/audit-archive";
import {
  parseSigningKey,
  publicKeyPem,
  resetCheckpointSignerCache,
} from "../services/audit-checkpoint";
import type { AppVariables } from "../services/context";

setDefaultTimeout(120_000);

const TENANT = "audit-public-restore";
const OWNER = "21600000-0000-4000-8000-000000000001";
const SIGNING_KEY = "33".repeat(32);
const SIGNING_KEY_ID = "archive-public-restore-v1";
let app: Hono<{ Variables: AppVariables }>;
const ISOLATED_CHILD = "STEWARD_AUDIT_PUBLIC_RESTORE_ISOLATED_CHILD";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

function signedEnvelope(jsonl: string, byteLength = new TextEncoder().encode(jsonl).length) {
  const event = JSON.parse(jsonl) as { prevHash: string; hmac: string };
  const archiveId = randomUUID();
  const manifest: AuditArchiveManifestPayload = {
    schemaVersion: "steward.audit-archive.v1",
    archiveId,
    tenantId: TENANT,
    createdAt: new Date().toISOString(),
    fromSeq: 1,
    toSeq: 1,
    eventCount: 1,
    signingKeyId: SIGNING_KEY_ID,
    retentionPolicyRevision: null,
    startPrevHash: event.prevHash,
    endHmac: event.hmac,
    format: "application/x-ndjson",
    chunks: [
      {
        index: 0,
        fromSeq: 1,
        toSeq: 1,
        eventCount: 1,
        sha256: createHash("sha256").update(jsonl).digest("hex"),
        byteLength,
        file: "chunk-000000.jsonl",
      },
    ],
  };
  const bytes = Buffer.from(canonical(manifest));
  return {
    archiveId,
    manifest,
    manifestSha256: createHash("sha256").update(bytes).digest("hex"),
    signature: sign(null, bytes, parseSigningKey(SIGNING_KEY)).toString("base64"),
  };
}

function signedManyChunkEnvelope(chunkCount: number) {
  const archiveId = randomUUID();
  const manifest: AuditArchiveManifestPayload = {
    schemaVersion: "steward.audit-archive.v1",
    archiveId,
    tenantId: TENANT,
    createdAt: new Date().toISOString(),
    fromSeq: 1,
    toSeq: chunkCount,
    eventCount: chunkCount,
    signingKeyId: SIGNING_KEY_ID,
    retentionPolicyRevision: null,
    startPrevHash: "0".repeat(64),
    endHmac: "1".repeat(64),
    format: "application/x-ndjson",
    chunks: Array.from({ length: chunkCount }, (_, index) => ({
      index,
      fromSeq: index + 1,
      toSeq: index + 1,
      eventCount: 1,
      sha256: "a".repeat(64),
      byteLength: 1,
      file: `chunk-${String(index).padStart(6, "0")}.jsonl`,
    })),
  };
  const bytes = Buffer.from(canonical(manifest));
  return {
    archiveId,
    manifest,
    manifestSha256: createHash("sha256").update(bytes).digest("hex"),
    signature: sign(null, bytes, parseSigningKey(SIGNING_KEY)).toString("base64"),
  };
}

async function headers(contentType = "application/json") {
  const token = await signAccessToken(
    {
      address: "0x216",
      tenantId: TENANT,
      userId: OWNER,
      mfaVerifiedAt: Date.now(),
    } as never,
    "10m",
  );
  return {
    authorization: `Bearer ${token}`,
    "content-type": contentType,
    "x-steward-tenant": TENANT,
  };
}

const publicRestoreTests = process.env[ISOLATED_CHILD] === "true" ? describe : describe.skip;

publicRestoreTests("audit archive restore through the public app", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-public-restore-hmac-0123456789abcdef";
    process.env.STEWARD_AUDIT_SIGNING_KEY = SIGNING_KEY;
    process.env.STEWARD_AUDIT_SIGNING_KEY_ID = SIGNING_KEY_ID;
    process.env.STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS = JSON.stringify({
      [SIGNING_KEY_ID]: publicKeyPem(parseSigningKey(SIGNING_KEY)),
    });
    process.env.STEWARD_JWT_SECRET = "audit-public-restore-jwt-0123456789abcdef0123456789abcdef";
    process.env.STEWARD_MASTER_PASSWORD = "audit-public-restore-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: TENANT, name: "Restore", apiKeyHash: "x" });
    await getDb().insert(users).values({ id: OWNER, email: "restore-owner@example.test" });
    await getDb().insert(userTenants).values({ tenantId: TENANT, userId: OWNER, role: "owner" });
    resetCheckpointSignerCache();
    app = (await import("../app")).app as Hono<{ Variables: AppVariables }>;
  });

  afterAll(async () => {
    await closeDb();
    for (const key of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_AUDIT_HMAC_KEY",
      "STEWARD_AUDIT_SIGNING_KEY",
      "STEWARD_AUDIT_SIGNING_KEY_ID",
      "STEWARD_AUDIT_ARCHIVE_TRUSTED_SIGNING_KEYS",
      "STEWARD_JWT_SECRET",
      "STEWARD_MASTER_PASSWORD",
    ]) {
      delete process.env[key];
    }
    resetCheckpointSignerCache();
  });

  test("accepts a large bounded signed chunk and completes the restore", async () => {
    const jsonl = `${JSON.stringify({
      v: 1,
      tenantId: TENANT,
      seq: 1,
      prevHash: "0".repeat(64),
      hmac: "1".repeat(64),
      metadata: { padding: "x".repeat(900_000) },
    })}\n`;
    expect(new TextEncoder().encode(jsonl).length).toBeLessThan(MAX_ARCHIVE_CHUNK_BYTES);
    const envelope = signedEnvelope(jsonl);
    const started = await app.request("/audit/archives/restore", {
      method: "POST",
      headers: await headers(),
      body: JSON.stringify({
        manifest: envelope.manifest,
        manifestSha256: envelope.manifestSha256,
        signature: envelope.signature,
      }),
    });
    expect(started.status).toBe(201);

    const uploaded = await app.request(`/audit/archives/${envelope.archiveId}/restore/chunks/0`, {
      method: "PUT",
      headers: await headers("application/x-ndjson"),
      body: jsonl,
    });
    expect(uploaded.status).toBe(200);

    const completed = await app.request(`/audit/archives/${envelope.archiveId}/restore/complete`, {
      method: "POST",
      headers: await headers(),
      body: "{}",
    });
    expect(completed.status).toBe(200);
    expect(await completed.json()).toMatchObject({
      ok: true,
      data: { archiveId: envelope.archiveId, status: "sealed" },
    });
  });

  test("rejects a signed manifest whose chunk exceeds the public limit", async () => {
    const jsonl = `${JSON.stringify({
      v: 1,
      tenantId: TENANT,
      seq: 1,
      prevHash: "0".repeat(64),
      hmac: "2".repeat(64),
    })}\n`;
    const envelope = signedEnvelope(jsonl, MAX_ARCHIVE_CHUNK_BYTES + 1);
    const response = await app.request("/audit/archives/restore", {
      method: "POST",
      headers: await headers(),
      body: JSON.stringify({
        manifest: envelope.manifest,
        manifestSha256: envelope.manifestSha256,
        signature: envelope.signature,
      }),
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({
      ok: false,
      error: "Restored audit archive manifest chunk 0 is invalid",
    });
  });

  test("accepts the maximum transport-safe one-event chunk manifest", async () => {
    const envelope = signedManyChunkEnvelope(MAX_ARCHIVE_CHUNKS);
    const manifestBytes = new TextEncoder().encode(canonical(envelope.manifest)).length;
    const body = JSON.stringify({
      manifest: envelope.manifest,
      manifestSha256: envelope.manifestSha256,
      signature: envelope.signature,
    });
    expect(manifestBytes).toBeLessThanOrEqual(MAX_ARCHIVE_MANIFEST_BYTES);
    expect(new TextEncoder().encode(body).length).toBeLessThan(1024 * 1024);

    const response = await app.request("/audit/archives/restore", {
      method: "POST",
      headers: await headers(),
      body,
    });
    expect(response.status).toBe(201);
  });
});

if (process.env[ISOLATED_CHILD] !== "true") {
  test("runs the public restore app against isolated process globals", () => {
    const result = spawnSync(process.execPath, ["test", "--timeout", "120000", import.meta.path], {
      encoding: "utf8",
      env: { ...process.env, [ISOLATED_CHILD]: "true" },
      timeout: 120_000,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(
        `isolated public restore test failed with status ${result.status}\n${result.stdout}\n${result.stderr}`,
      );
    }
  });
}
