import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditCheckpoints, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import { createRfc3161TimestampQuery } from "../services/audit-checkpoint-anchor";
import type { AppVariables } from "../services/context";

const TENANT_ID = "audit-bundle-tenant";
const OTHER_TENANT_ID = "audit-bundle-other-tenant";
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
  writeFileSync(queryPath, createRfc3161TimestampQuery(digest));
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
  bundle.checkpoint.anchor = {
    v: 1,
    type: "rfc3161",
    sinkId: "rfc3161",
    hashAlgorithm: "sha256",
    checkpointDigest: digest,
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
