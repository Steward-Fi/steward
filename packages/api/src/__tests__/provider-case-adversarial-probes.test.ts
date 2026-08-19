/**
 * evidence independent adversarial probes (review-gate). Two probes NOT duplicating
 * the PR's own suite:
 *
 *  P-A "byte-flip in a stored event's metadata": mutate ONE byte in a correlated
 *  event's metadata AFTER export and confirm the offline verifier FAILs on the
 *  signed content digest (proves the digest actually covers metadata, not just
 *  hmac/action). Distinct from the PR's N08 (which mutates a MANIFEST fact, not
 *  a bundle event's metadata) and N19 (synthetic-bundle field mutation).
 *
 *  P-B "manifest-omission cannot hide incompleteness": drop a REQUIRED-role
 *  event from the manifest's events[] index (leaving it in the signed bundle
 *  segment) while claiming complete. The verifier must FAIL (forged completeness)
 *  — a bad/absent event surfaces as incompleteness, never silence (spec §7.4.3 /
 *  verifier-independence item 4). Distinct from the PR's N09 (which flips
 *  terminalState) — here we keep terminalState honest and instead attack the
 *  events[] index omission + completeness claim.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signAccessToken } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import type { AppVariables } from "../services/context";
import {
  approveCase,
  createPendingCase,
  F,
  seedCaseFixture,
  wipeCase,
} from "./provider-case-fixture";

const VERIFIER = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "..",
  "scripts",
  "verify-evidence-bundle.mjs",
);
let tmpDir: string;
let realApp: Hono<{ Variables: AppVariables }>;

async function adminHeaders() {
  const token = await signAccessToken(
    {
      address: "0xadmin",
      tenantId: F.TENANT,
      userId: F.APPROVER_2,
      mfaVerifiedAt: Date.now(),
    } as never,
    "10m",
  );
  return { headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.TENANT } };
}
function runVerifier(env: unknown, args: string[] = []) {
  const file = join(tmpDir, `adv-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(env));
  const r = spawnSync("node", [VERIFIER, file, ...args], { encoding: "utf8" });
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe("evidence independent adversarial probes", () => {
  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "provider-case-adv-"));
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "0".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = "provider-case-adv-master-password";
    // Canonical JWT secret for minting the admin session token (clean-CI safe).
    process.env.STEWARD_JWT_SECRET =
      process.env.STEWARD_JWT_SECRET ||
      "provider-case-adv-jwt-secret-0123456789abcdef0123456789abcd";
    const { privateKey } = generateKeyPairSync("ed25519");
    process.env.STEWARD_AUDIT_SIGNING_KEY = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();
    resetCheckpointSignerCache();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const mod = await import("../app");
    realApp = mod.app as Hono<{ Variables: AppVariables }>;
  }, 120_000);
  afterAll(async () => {
    await closeDb();
    if (tmpDir) rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    delete process.env.STEWARD_JWT_SECRET;
    resetCheckpointSignerCache();
  });
  beforeEach(async () => {
    await wipeCase();
    await seedCaseFixture();
  });

  it("P-A: byte-flip in a bundle event's metadata → verifier FAIL (content digest)", async () => {
    const { intentId, requestHash, actionDigest } = await createPendingCase();
    await approveCase(intentId, requestHash, actionDigest);
    const env = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await adminHeaders())
      .then((r) => r.json())) as {
      bundle: { events: Array<{ metadata?: Record<string, unknown> }> };
    };
    // clean must pass
    expect(runVerifier(env).code).toBe(0);
    // flip a byte in the FIRST event's metadata.intentId (still valid JSON, but
    // no longer matches the signed content digest).
    const ev0 = env.bundle.events[0];
    ev0.metadata = {
      ...(ev0.metadata ?? {}),
      intentId: `${String(ev0.metadata?.intentId ?? intentId)}X`,
    };
    const res = runVerifier(env);
    expect(res.code).toBe(1);
    expect(res.stderr).toMatch(/content digest|tampered/i);
  });

  it("P-B: omit a required-role event from manifest.events[] while claiming complete → FAIL", async () => {
    const { intentId, requestHash, actionDigest } = await createPendingCase();
    await approveCase(intentId, requestHash, actionDigest);
    const env = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await adminHeaders())
      .then((r) => r.json())) as {
      manifest: {
        terminalState: string;
        completeness: string;
        missingRequiredRoles: string[];
        events: Array<{ seq: number; action: string; role: string; hmac: string }>;
      };
    };
    expect(runVerifier(env).code).toBe(0);
    // Attack: claim `complete` but DROP the genesis event from the manifest index
    // (it stays in the signed bundle). A required role (genesis) is now absent
    // from the manifest-referenced set; the forged-completeness guard must FAIL,
    // proving omission surfaces as incompleteness, not silence.
    env.manifest.events = env.manifest.events.filter((e) => e.role !== "genesis");
    env.manifest.completeness = "complete";
    env.manifest.missingRequiredRoles = [];
    const res = runVerifier(env);
    expect(res.code).toBe(1);
    expect(res.stderr).toMatch(/complete|genesis/i);
  });
});
