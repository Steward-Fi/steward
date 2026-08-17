import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditCheckpoints, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import {
  auditCheckpointAnchorDigest,
  createRfc3161TimestampQuery,
  Rfc3161TimestampSink,
  verifyRfc3161TimestampResponse,
} from "../services/audit-checkpoint-anchor";
import type { AppVariables } from "../services/context";
import { inspectGovernedRoutes } from "../services/governed-route-inventory";

const TENANT_ID = "audit-bundle-tenant";
const OTHER_TENANT_ID = "audit-bundle-other-tenant";
const EMPTY_TENANT_ID = "audit-bundle-empty-tenant";
const VERIFIER = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "..",
  "scripts",
  "verify-evidence-bundle.mjs",
);

let auditRoutesModule: Awaited<typeof import("../routes/audit")>;
let tmpDir: string;
let tsaCaPath: string;
let tsaConfigPath: string;

interface BundleEvent {
  seq: number;
  prevHash: string;
  hmac: string;
  action: string;
}
interface Bundle {
  version: number;
  tenantId: string;
  range: { from: number; to: number; includesHead: boolean };
  canonicalizationSpec: string;
  events: BundleEvent[];
  checkpoint: {
    payload: Record<string, unknown>;
    signature: string;
    publicKey: string;
    anchor?: Record<string, unknown>;
  };
  generatedAt: string;
}

function runVerifier(
  bundle: unknown,
  args: string[] = [],
): { code: number; stdout: string; stderr: string } {
  const file = join(tmpDir, `bundle-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(bundle));
  const res = spawnSync("node", [VERIFIER, file, ...args], { encoding: "utf8" });
  return { code: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

function runOpenSsl(args: string[]): void {
  const result = spawnSync("openssl", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`openssl ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
}

function setupTestTsa(): void {
  tsaCaPath = join(tmpDir, "tsa-ca.pem");
  const caKey = join(tmpDir, "tsa-ca-key.pem");
  const tsaKey = join(tmpDir, "tsa-key.pem");
  const tsaCsr = join(tmpDir, "tsa.csr");
  const tsaCert = join(tmpDir, "tsa.pem");
  const extensions = join(tmpDir, "tsa-extensions.cnf");
  const serial = join(tmpDir, "tsa-serial");
  tsaConfigPath = join(tmpDir, "tsa.cnf");

  runOpenSsl([
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    caKey,
    "-out",
    tsaCaPath,
    "-days",
    "1",
    "-subj",
    "/CN=Steward Test TSA CA",
  ]);
  runOpenSsl([
    "req",
    "-new",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    tsaKey,
    "-out",
    tsaCsr,
    "-subj",
    "/CN=Steward Test TSA",
  ]);
  writeFileSync(
    extensions,
    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n",
  );
  runOpenSsl([
    "x509",
    "-req",
    "-in",
    tsaCsr,
    "-CA",
    tsaCaPath,
    "-CAkey",
    caKey,
    "-CAcreateserial",
    "-out",
    tsaCert,
    "-days",
    "1",
    "-sha256",
    "-extfile",
    extensions,
  ]);
  writeFileSync(serial, "01\n");
  writeFileSync(
    tsaConfigPath,
    `[ tsa ]\ndefault_tsa = tsa_config1\n[ tsa_config1 ]\ndir = ${tmpDir}\nserial = ${serial}\ncrypto_device = builtin\nsigner_cert = ${tsaCert}\ncerts = ${tsaCaPath}\nsigner_key = ${tsaKey}\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n`,
  );
}

function attachTestAnchor(bundle: Bundle): void {
  const payload = bundle.checkpoint.payload;
  const ordered = Object.fromEntries(
    Object.keys(payload)
      .sort()
      .map((key) => [key, payload[key]]),
  );
  const digest = createHash("sha256").update(JSON.stringify(ordered)).digest("hex");
  const queryPath = join(tmpDir, `query-${Math.random().toString(36).slice(2)}.tsq`);
  const responsePath = `${queryPath}.tsr`;
  const nonceBytes = Uint8Array.from({ length: 16 }, (_, index) => index + 1);
  writeFileSync(queryPath, createRfc3161TimestampQuery(digest, nonceBytes));
  runOpenSsl([
    "ts",
    "-reply",
    "-config",
    tsaConfigPath,
    "-queryfile",
    queryPath,
    "-out",
    responsePath,
  ]);
  const inspected = spawnSync("openssl", ["ts", "-reply", "-in", responsePath, "-text"], {
    encoding: "utf8",
  });
  if (inspected.status !== 0) throw new Error("failed to inspect test timestamp");
  const policyOid = inspected.stdout.match(/^Policy OID:\s*([^\s]+)\s*$/m)?.[1];
  const timeText = inspected.stdout.match(/^Time stamp:\s*(.+)$/m)?.[1];
  if (!policyOid || !timeText) throw new Error("test timestamp fields missing");
  bundle.checkpoint.anchor = {
    v: 1,
    type: "rfc3161",
    sinkId: "rfc3161",
    hashAlgorithm: "sha256",
    checkpointDigest: digest,
    nonce: Buffer.from(nonceBytes).toString("hex"),
    policyOid,
    genTime: new Date(timeText).toISOString(),
    accuracyMillis: 1000,
    verifiedAt: new Date().toISOString(),
    trustAnchorSha256: createHash("sha256").update(readFileSync(tsaCaPath)).digest("hex"),
    timestampResponse: readFileSync(responsePath).toString("base64"),
  };
}

describe("audit evidence bundle endpoint + offline verifier", () => {
  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-bundle-"));
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-bundle-hmac-key-0123456789abcdef0123";
    process.env.STEWARD_MASTER_PASSWORD = "audit-bundle-master-password";
    delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
    delete process.env.STEWARD_AUDIT_RFC3161_URL;
    delete process.env.STEWARD_AUDIT_RFC3161_CA_FILE;

    // Deterministic Ed25519 signing key for the run (PKCS#8 PEM path).
    const { privateKey } = generateKeyPairSync("ed25519");
    process.env.STEWARD_AUDIT_SIGNING_KEY = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();
    resetCheckpointSignerCache();

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    auditRoutesModule = await import("../routes/audit");
    setupTestTsa();

    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Audit Bundle", apiKeyHash: "audit-bundle" },
        { id: OTHER_TENANT_ID, name: "Audit Bundle Other", apiKeyHash: "audit-bundle-other" },
        { id: EMPTY_TENANT_ID, name: "Audit Bundle Empty", apiKeyHash: "audit-bundle-empty" },
      ]);

    for (let i = 1; i <= 4; i++) {
      await writeAuditEvent({
        tenantId: TENANT_ID,
        actorType: "user",
        actorId: `user-${i}`,
        action: `wallet.action.${i}`,
        resourceType: "wallet",
        resourceId: `wallet-${i}`,
        requestId: `req-${i}`,
        metadata: { i },
      });
    }
    // A second tenant's event that must never leak into TENANT_ID's bundle.
    await writeAuditEvent({
      tenantId: OTHER_TENANT_ID,
      actorType: "user",
      action: "wallet.action.other",
      metadata: { other: true },
    });
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
    delete process.env.STEWARD_AUDIT_RFC3161_URL;
    delete process.env.STEWARD_AUDIT_RFC3161_CA_FILE;
    resetCheckpointSignerCache();
  });

  function app(tenantId = TENANT_ID) {
    const a = new Hono<{ Variables: AppVariables }>();
    a.use("*", async (c, next) => {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("tenantId", tenantId);
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    a.route("/audit", auditRoutesModule.auditRoutes);
    return a;
  }

  async function fetchBundle(query = "", tenantId = TENANT_ID): Promise<Bundle> {
    const res = await app(tenantId).request(`/audit/bundle${query}`);
    expect(res.status).toBe(200);
    return (await res.json()) as Bundle;
  }

  it("returns a well-formed bundle for the full chain", async () => {
    const bundle = await fetchBundle();
    expect(bundle.version).toBe(1);
    expect(bundle.tenantId).toBe(TENANT_ID);
    expect(bundle.events).toHaveLength(4);
    expect(bundle.events.map((e) => e.seq)).toEqual([1, 2, 3, 4]);
    expect(bundle.range.includesHead).toBe(true);
    expect(bundle.canonicalizationSpec).toContain("HMAC-SHA256");
    expect(bundle.checkpoint.publicKey).toContain("BEGIN PUBLIC KEY");
    // No anchor configuration preserves the v1 checkpoint envelope exactly;
    // there is no placeholder field and therefore no hidden network behavior.
    expect(Object.keys(bundle.checkpoint).sort()).toEqual(["payload", "publicKey", "signature"]);
    expect(bundle.checkpoint.payload.tenantId).toBe(TENANT_ID);
    expect(bundle.checkpoint.payload.seq).toBe(4);
    // Head binding: last event hmac equals signed headHmac.
    expect(bundle.events[3].hmac).toBe(bundle.checkpoint.payload.headHmac as string);
    // No cross-tenant leakage.
    expect(JSON.stringify(bundle)).not.toContain("wallet.action.other");
  });

  it("does not leak other tenants and scopes the checkpoint per tenant", async () => {
    const other = await fetchBundle("", OTHER_TENANT_ID);
    expect(other.tenantId).toBe(OTHER_TENANT_ID);
    expect(other.events).toHaveLength(1);
    expect(other.events[0].action).toBe("wallet.action.other");
    expect(other.checkpoint.payload.tenantId).toBe(OTHER_TENANT_ID);
  });

  it("supports a partial range that does not include the head", async () => {
    const bundle = await fetchBundle("?from=1&to=2");
    expect(bundle.events.map((e) => e.seq)).toEqual([1, 2]);
    expect(bundle.range.includesHead).toBe(false);
    // Checkpoint still commits to the FULL chain head (seq 4).
    expect(bundle.checkpoint.payload.seq).toBe(4);
  });

  it("persists a checkpoint row on bundle generation", async () => {
    await fetchBundle();
    const rows = await getDb()
      .select()
      .from(auditCheckpoints)
      .where(eq(auditCheckpoints.tenantId, TENANT_ID));
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows[0].signature.length).toBeGreaterThan(0);
    expect(rows[0].publicKey).toContain("BEGIN PUBLIC KEY");
  });

  it("doctor integrity requires a valid checkpoint at the current chain head", async () => {
    await fetchBundle();
    const current = await app().request("/audit/integrity");
    expect(current.status).toBe(200);
    expect(await current.json()).toMatchObject({
      ok: true,
      data: {
        valid: true,
        chainValid: true,
        checkpointPresent: true,
        checkpointValid: true,
        checkpointAtHead: true,
        checkpointSeq: 4,
        chainHeadSeq: 4,
      },
    });

    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "system",
      action: "doctor.checkpoint.stale",
      metadata: {},
    });
    const stale = await app().request("/audit/integrity");
    expect(stale.status).toBe(200);
    expect(await stale.json()).toMatchObject({
      ok: true,
      data: {
        valid: false,
        chainValid: true,
        checkpointValid: true,
        checkpointAtHead: false,
        checkpointSeq: 4,
        chainHeadSeq: 5,
      },
    });

    // Restore a current checkpoint so the remaining bundle/verifier tests run
    // against the new five-event head.
    await fetchBundle();
  });

  it("shared governed-route inventory detects an enabled legacy bypass", async () => {
    await getDb().execute(sql`
      INSERT INTO users (id, email)
      VALUES ('55555555-5555-4555-8555-555555555555', 'doctor@example.invalid')
    `);
    await getDb().execute(sql`
      INSERT INTO workspaces (id, tenant_id, key, name, environment, created_by)
      VALUES ('44444444-4444-4444-8444-444444444444', ${TENANT_ID},
        'doctor', 'Doctor', 'development', '55555555-5555-4555-8555-555555555555')
    `);
    await getDb().execute(sql`
      INSERT INTO provider_accounts
        (id, tenant_id, workspace_id, adapter_key, external_ref, display_name)
      VALUES ('66666666-6666-4666-8666-666666666666', ${TENANT_ID},
        '44444444-4444-4444-8444-444444444444', 'slack', 'doctor', 'Doctor')
    `);
    await getDb().execute(sql`
      INSERT INTO provider_operations
        (id, tenant_id, workspace_id, provider_account_id, operation_key, risk_class)
      VALUES ('33333333-3333-4333-8333-333333333333', ${TENANT_ID},
        '44444444-4444-4444-8444-444444444444',
        '66666666-6666-4666-8666-666666666666', 'doctor.test', 'read')
    `);
    await getDb().execute(sql`
      INSERT INTO secret_routes
        (tenant_id, secret_id, host_pattern, path_pattern, method, inject_as, inject_key,
         enabled, authority_mode, provider_operation_id)
      VALUES
        (${TENANT_ID}, '11111111-1111-4111-8111-111111111111', 'slack.com', '/api/*', 'POST',
         'header', 'Authorization', TRUE, 'legacy', NULL),
        (${TENANT_ID}, '22222222-2222-4222-8222-222222222222', 'slack.com', '/api/*', 'POST',
         'header', 'Authorization', TRUE, 'governed_v2',
         '33333333-3333-4333-8333-333333333333')
    `);
    const inventory = await inspectGovernedRoutes(TENANT_ID);
    expect(inventory).toMatchObject({
      governedRoutes: 1,
      nullOperationRoutes: 0,
      dualModeRoutes: 1,
      ok: false,
    });
    await getDb().execute(sql`DELETE FROM secret_routes WHERE tenant_id = ${TENANT_ID}`);
    await getDb().execute(sql`
      DELETE FROM workspaces
      WHERE id = '44444444-4444-4444-8444-444444444444'
    `);
    await getDb().execute(sql`
      DELETE FROM users WHERE id = '55555555-5555-4555-8555-555555555555'
    `);
  });

  it("PASSES the standalone offline verifier for a genuine bundle", async () => {
    const bundle = await fetchBundle();
    const { code, stdout } = runVerifier(bundle);
    expect(stdout).toContain("PASS");
    expect(code).toBe(0);
  });

  it("fails evidence generation closed when required anchoring is misconfigured", async () => {
    process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
    delete process.env.STEWARD_AUDIT_RFC3161_URL;
    try {
      const response = await app().request("/audit/bundle");
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        ok: false,
        error: "Required checkpoint anchoring failed",
      });
    } finally {
      delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
    }
  });

  it("verifies an RFC 3161 token fully offline and reports the anchored-before bound", async () => {
    const bundle = await fetchBundle();
    attachTestAnchor(bundle);
    const { code, stdout } = runVerifier(bundle, [
      "--tsa-ca",
      tsaCaPath,
      "--require-anchor",
      "--anchored-before",
      "2100-01-01T00:00:00.000Z",
    ]);
    expect(code).toBe(0);
    expect(stdout).toContain("RFC 3161 verified");
    expect(stdout).toContain("existed no later than");
    expect(stdout).toContain("not operator-proof");
  });

  it("accepts a real CMS token only after nonce, freshness, policy, signature, and path checks", async () => {
    const bundle = await fetchBundle();
    const digest = auditCheckpointAnchorDigest(bundle.checkpoint as never);
    const fakeResponse = Uint8Array.from([
      0x30,
      0x29,
      0x30,
      0x03,
      0x02,
      0x01,
      0x00,
      0x30,
      0x22,
      0x04,
      0x20,
      ...Buffer.from(digest, "hex"),
    ]);
    const fakeSink = new Rfc3161TimestampSink({
      url: "https://tsa.example.test/timestamp",
      caFile: tsaCaPath,
      fetch: async () =>
        new Response(fakeResponse, {
          status: 200,
          headers: { "content-type": "application/timestamp-reply" },
        }),
    });
    await expect(fakeSink.anchor(bundle.checkpoint as never)).rejects.toThrow(
      "trust verification failed",
    );
    let observedQuery = new Uint8Array();
    let observedResponse = new Uint8Array();
    const sink = new Rfc3161TimestampSink({
      url: "https://tsa.example.test/timestamp",
      caFile: tsaCaPath,
      fetch: async (_input, init) => {
        const queryPath = join(tmpDir, `live-query-${Math.random().toString(36).slice(2)}.tsq`);
        const responsePath = `${queryPath}.tsr`;
        observedQuery = init?.body as Uint8Array;
        writeFileSync(queryPath, observedQuery);
        runOpenSsl([
          "ts",
          "-reply",
          "-config",
          tsaConfigPath,
          "-queryfile",
          queryPath,
          "-out",
          responsePath,
        ]);
        observedResponse = readFileSync(responsePath);
        return new Response(observedResponse, {
          status: 200,
          headers: { "content-type": "application/timestamp-reply" },
        });
      },
    });
    const proof = await sink.anchor(bundle.checkpoint as never);
    expect(proof.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(proof.policyOid.length).toBeGreaterThan(0);
    expect(proof.accuracyMillis).toBe(1000);
    expect(proof.trustAnchorSha256).toBe(
      createHash("sha256").update(readFileSync(tsaCaPath)).digest("hex"),
    );
    expect(() =>
      verifyRfc3161TimestampResponse({
        query: createRfc3161TimestampQuery(proof.checkpointDigest),
        response: observedResponse,
        caFile: tsaCaPath,
        requestStartedAt: Date.now(),
        maxPastAgeMs: 300_000,
        maxFutureSkewMs: 300_000,
      }),
    ).toThrow("trust verification failed");
    expect(() =>
      verifyRfc3161TimestampResponse({
        query: observedQuery,
        response: observedResponse,
        caFile: tsaCaPath,
        requestStartedAt: Date.now() + 60 * 60_000,
        maxPastAgeMs: 0,
        maxFutureSkewMs: 0,
      }),
    ).toThrow("stale");
    // Accuracy is an uncertainty interval, not slack. Even when bare genTime
    // overlaps the window, both interval endpoints must fit the freshness
    // policy.
    const genTime = Date.parse(proof.genTime);
    expect(() =>
      verifyRfc3161TimestampResponse({
        query: observedQuery,
        response: observedResponse,
        caFile: tsaCaPath,
        requestStartedAt: genTime + 500,
        verifiedAt: genTime + 5_000,
        maxPastAgeMs: 0,
        maxFutureSkewMs: 0,
      }),
    ).toThrow("stale");
    expect(() =>
      verifyRfc3161TimestampResponse({
        query: observedQuery,
        response: observedResponse,
        caFile: tsaCaPath,
        requestStartedAt: genTime - 5_000,
        verifiedAt: genTime - 500,
        maxPastAgeMs: 10_000,
        maxFutureSkewMs: 0,
      }),
    ).toThrow("future");
  });

  it("persists the exact strictly verified proof with the signed checkpoint", async () => {
    const originalFetch = globalThis.fetch;
    process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
    process.env.STEWARD_AUDIT_RFC3161_URL = "https://tsa.example.test/timestamp";
    process.env.STEWARD_AUDIT_RFC3161_CA_FILE = tsaCaPath;
    globalThis.fetch = async (_input, init) => {
      const queryPath = join(tmpDir, `persist-query-${Math.random().toString(36).slice(2)}.tsq`);
      const responsePath = `${queryPath}.tsr`;
      writeFileSync(queryPath, init?.body as Uint8Array);
      runOpenSsl([
        "ts",
        "-reply",
        "-config",
        tsaConfigPath,
        "-queryfile",
        queryPath,
        "-out",
        responsePath,
      ]);
      return new Response(readFileSync(responsePath), {
        status: 200,
        headers: { "content-type": "application/timestamp-reply" },
      });
    };
    try {
      const bundle = await fetchBundle();
      expect(bundle.checkpoint.anchor).toBeDefined();
      const rows = await getDb()
        .select()
        .from(auditCheckpoints)
        .where(eq(auditCheckpoints.tenantId, TENANT_ID));
      const persisted = rows.find(
        (row) => row.anchorProof?.checkpointDigest === bundle.checkpoint.anchor?.checkpointDigest,
      );
      expect(persisted?.anchorProof).toEqual(bundle.checkpoint.anchor);
      expect(persisted?.anchorVerifiedAt).toBeInstanceOf(Date);
      await expect(
        (async () =>
          getDb().execute(
            sql`UPDATE audit_checkpoints SET anchor_proof = NULL WHERE id = ${persisted?.id}`,
          ))(),
      ).rejects.toThrow("Failed query");
    } finally {
      globalThis.fetch = originalFetch;
      delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
      delete process.env.STEWARD_AUDIT_RFC3161_URL;
      delete process.env.STEWARD_AUDIT_RFC3161_CA_FILE;
    }
  });

  it("persists a required proof even for an empty signed checkpoint", async () => {
    const originalFetch = globalThis.fetch;
    process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE = "required";
    process.env.STEWARD_AUDIT_RFC3161_URL = "https://tsa.example.test/timestamp";
    process.env.STEWARD_AUDIT_RFC3161_CA_FILE = tsaCaPath;
    globalThis.fetch = async (_input, init) => {
      const queryPath = join(tmpDir, `empty-query-${Math.random().toString(36).slice(2)}.tsq`);
      const responsePath = `${queryPath}.tsr`;
      writeFileSync(queryPath, init?.body as Uint8Array);
      runOpenSsl([
        "ts",
        "-reply",
        "-config",
        tsaConfigPath,
        "-queryfile",
        queryPath,
        "-out",
        responsePath,
      ]);
      return new Response(readFileSync(responsePath), {
        status: 200,
        headers: { "content-type": "application/timestamp-reply" },
      });
    };
    try {
      const bundle = await fetchBundle("", EMPTY_TENANT_ID);
      expect(bundle.events).toHaveLength(0);
      expect(bundle.checkpoint.anchor).toBeDefined();
      const rows = await getDb()
        .select()
        .from(auditCheckpoints)
        .where(eq(auditCheckpoints.tenantId, EMPTY_TENANT_ID));
      expect(rows).toHaveLength(1);
      expect(rows[0]?.anchorProof).toEqual(bundle.checkpoint.anchor);
    } finally {
      globalThis.fetch = originalFetch;
      delete process.env.STEWARD_AUDIT_CHECKPOINT_ANCHOR_MODE;
      delete process.env.STEWARD_AUDIT_RFC3161_URL;
      delete process.env.STEWARD_AUDIT_RFC3161_CA_FILE;
    }
  });

  it("fails offline anchor verification for a missing proof or wrong imprint", async () => {
    const unanchored = await fetchBundle();
    const missing = runVerifier(unanchored, ["--tsa-ca", tsaCaPath, "--require-anchor"]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("anchor is missing");

    const wrongImprint = await fetchBundle();
    attachTestAnchor(wrongImprint);
    if (wrongImprint.checkpoint.anchor) {
      wrongImprint.checkpoint.anchor.checkpointDigest = "00".repeat(32);
    }
    const invalid = runVerifier(wrongImprint, ["--tsa-ca", tsaCaPath, "--require-anchor"]);
    expect(invalid.code).toBe(1);
    expect(invalid.stderr).toContain("digest does not match");

    const wrongNonce = await fetchBundle();
    attachTestAnchor(wrongNonce);
    if (wrongNonce.checkpoint.anchor) wrongNonce.checkpoint.anchor.nonce = "ff".repeat(16);
    const nonceFailure = runVerifier(wrongNonce, ["--tsa-ca", tsaCaPath, "--require-anchor"]);
    expect(nonceFailure.code).toBe(1);
    expect(nonceFailure.stderr).toContain("nonce does not match");

    const inaccurateCutoff = await fetchBundle();
    attachTestAnchor(inaccurateCutoff);
    const anchor = inaccurateCutoff.checkpoint.anchor;
    const cutoff = new Date(Date.parse(String(anchor?.genTime)) + 500).toISOString();
    const cutoffFailure = runVerifier(inaccurateCutoff, [
      "--tsa-ca",
      tsaCaPath,
      "--require-anchor",
      "--anchored-before",
      cutoff,
    ]);
    expect(cutoffFailure.code).toBe(1);
    expect(cutoffFailure.stderr).toContain("latest accuracy bound");
  });

  it("FAILS the verifier at the right seq when an event byte is flipped", async () => {
    const bundle = await fetchBundle();
    // Flip a hex nibble in event seq=3's prevHash to break linkage there.
    const target = bundle.events[2];
    const first = target.prevHash[0] === "a" ? "b" : "a";
    target.prevHash = first + target.prevHash.slice(1);
    const { code, stderr } = runVerifier(bundle);
    expect(code).toBe(1);
    expect(stderr).toContain("FAIL");
    expect(stderr).toContain("seq 3");
  });

  it("FAILS the verifier when an event CONTENT field is altered (no HMAC key needed)", async () => {
    const bundle = await fetchBundle();
    // Change a content field (action) while leaving hmac/prevHash intact. This
    // must be caught by the signed content digest, not linkage.
    bundle.events[1].action = `${bundle.events[1].action}-tampered`;
    const { code, stderr } = runVerifier(bundle);
    expect(code).toBe(1);
    expect(stderr).toContain("content digest");
  });

  it("FAILS the verifier when the unsigned includesHead flag is flipped to hide a bad head", async () => {
    const bundle = await fetchBundle();
    // Attacker corrupts the head event's hmac AND flips the advisory flag to
    // false, hoping to skip head binding. Head inclusion is derived from the
    // SIGNED seq, so this must still FAIL.
    const last = bundle.events[bundle.events.length - 1];
    const first = last.hmac[0] === "a" ? "b" : "a";
    last.hmac = first + last.hmac.slice(1);
    bundle.range.includesHead = false;
    const { code, stderr } = runVerifier(bundle);
    expect(code).toBe(1);
    expect(stderr).toContain("FAIL");
  });

  it("FAILS the verifier when the checkpoint payload is tampered", async () => {
    const bundle = await fetchBundle();
    bundle.checkpoint.payload.expectedCount =
      (bundle.checkpoint.payload.expectedCount as number) + 1;
    const { code, stderr } = runVerifier(bundle);
    expect(code).toBe(1);
    expect(stderr).toContain("signature does not verify");
  });

  it("FAILS the verifier when the signed head no longer matches the last event", async () => {
    const bundle = await fetchBundle();
    // Corrupt the last event's hmac (keeps signature valid, breaks head binding).
    const last = bundle.events[bundle.events.length - 1];
    const first = last.hmac[0] === "a" ? "b" : "a";
    last.hmac = first + last.hmac.slice(1);
    const { code, stderr } = runVerifier(bundle);
    expect(code).toBe(1);
    // Either linkage (if it were mid-chain) or head-binding; here it's the head.
    expect(stderr).toContain("FAIL");
  });
});
