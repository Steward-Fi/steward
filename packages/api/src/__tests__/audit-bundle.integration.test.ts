import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditCheckpoints, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import type { AppVariables } from "../services/context";
import { inspectGovernedRoutes } from "../services/governed-route-inventory";

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
  checkpoint: { payload: Record<string, unknown>; signature: string; publicKey: string };
  generatedAt: string;
}

function runVerifier(bundle: unknown): { code: number; stdout: string; stderr: string } {
  const file = join(tmpDir, `bundle-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(bundle));
  const res = spawnSync("node", [VERIFIER, file], { encoding: "utf8" });
  return { code: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

describe("audit evidence bundle endpoint + offline verifier", () => {
  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "audit-bundle-"));
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-bundle-hmac-key-0123456789abcdef0123";
    process.env.STEWARD_MASTER_PASSWORD = "audit-bundle-master-password";

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
    const inventory = await inspectGovernedRoutes();
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
