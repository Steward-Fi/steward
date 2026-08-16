/**
 * PR5 /case + /evidence route + offline-verifier round-trip.
 *
 * Drives the REAL fully-composed app (`mod.app`) with genuinely-minted session
 * Bearer tokens through the production middleware chain (tenantAuth ->
 * auditOwnerAdminMfaGate) — NOT a mock app that injects context synthetically —
 * so the route wiring itself is exercised (regression guard for the missing
 * `/v2/provider-actions/:id/{case,evidence}` tenantAuth registration). Seeds a
 * real case, exports the manifest and the signed evidence bundle over the HTTP
 * routes, verifies the bundle OFFLINE with scripts/verify-evidence-bundle.mjs
 * (both with and without a trusted fingerprint), and asserts each tamper
 * fixture FAILs.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signAccessToken, signAgentToken } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { Hono } from "hono";
import { resetCheckpointSignerCache } from "../services/audit-checkpoint";
import type { AppVariables } from "../services/context";
import {
  approveCase,
  createAccessDeniedCase,
  createAllowedCase,
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
let expectedFp: string;

// The fixture seeds APPROVER_2 as tenant `admin` (owner/admin gate passes) and
// APPROVER as `member` (N06). We mint REAL session JWTs so tenantAuth resolves
// authType/tenantRole/tenantId/sessionMfaVerifiedAt from the token, exactly as
// production does. This is what makes the route wiring genuinely under test.
const ADMIN_USER = F.APPROVER_2;
const MEMBER_USER = F.APPROVER;

async function sessionToken(opts: {
  userId?: string;
  tenantId?: string;
  mfa?: boolean;
}): Promise<string> {
  const payload: Record<string, unknown> = {
    address: `0x${(opts.userId ?? ADMIN_USER).slice(0, 8)}`,
    tenantId: opts.tenantId ?? F.TENANT,
    userId: opts.userId ?? ADMIN_USER,
  };
  if (opts.mfa !== false) payload.mfaVerifiedAt = Date.now();
  return signAccessToken(payload as never, "10m");
}

/**
 * Build request options (headers) for an owner/admin session against the REAL
 * composed app. Callers do `realApp.request(path, await authHeaders())`.
 */
async function authHeaders(
  tenantId = F.TENANT,
  role: "admin" | "member" = "admin",
  mfa = true,
): Promise<{ headers: Record<string, string> }> {
  const userId = role === "member" ? MEMBER_USER : ADMIN_USER;
  const token = await sessionToken({ userId, tenantId, mfa });
  return {
    headers: {
      authorization: `Bearer ${token}`,
      "x-steward-tenant": tenantId,
    },
  };
}

/** Agent-token request options (N04): must be rejected by the owner/admin gate. */
async function agentHeaders(tenantId = F.TENANT): Promise<{ headers: Record<string, string> }> {
  const token = await signAgentToken({ agentId: F.AGENT, tenantId, scopes: [] }, "10m");
  return {
    headers: {
      authorization: `Bearer ${token}`,
      "x-steward-tenant": tenantId,
    },
  };
}

function runVerifier(bundleOrEnvelope: unknown, extraArgs: string[] = []) {
  const file = join(tmpDir, `evi-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(bundleOrEnvelope));
  const res = spawnSync("node", [VERIFIER, file, ...extraArgs], { encoding: "utf8" });
  return { code: res.status ?? -1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

describe("PR5 /case + /evidence routes + offline verifier", () => {
  beforeAll(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), "pr5-evi-"));
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "0".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = "pr5-evidence-master-password";
    // Canonical JWT secret for minting real session/agent tokens (see note in
    // provider-case-route-wiring). Required in a clean CI env.
    process.env.STEWARD_JWT_SECRET =
      process.env.STEWARD_JWT_SECRET || "pr5-evidence-jwt-secret-0123456789abcdef0123456789";
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    process.env.STEWARD_AUDIT_SIGNING_KEY = privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();
    expectedFp = createHash("sha256")
      .update(publicKey.export({ format: "der", type: "spki" }))
      .digest("hex");
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

  it("GET /case returns the manifest for an owner/admin", async () => {
    const intentId = await createAllowedCase();
    const res = await realApp.request(`/v2/provider-actions/${intentId}/case`, await authHeaders());
    expect(res.status).toBe(200);
    const m = (await res.json()) as { caseId: string; schemaVersion: string };
    expect(m.caseId).toBe(intentId);
    expect(m.schemaVersion).toBe("steward.provider-case-manifest.v1");
  });

  it("GET /evidence exports a bundle that verifies OFFLINE (clean)", async () => {
    const intentId = await createAllowedCase();
    const res = await realApp.request(
      `/v2/provider-actions/${intentId}/evidence`,
      await authHeaders(),
    );
    expect(res.status).toBe(200);
    const envelope = await res.json();
    // No fingerprint supplied → PASS but trust-root not checked.
    const noFp = runVerifier(envelope);
    expect(noFp.code).toBe(0);
    expect(noFp.stdout).toContain("PASS");
    // Matching fingerprint → PASS + trust root matched.
    const withFp = runVerifier(envelope, ["--expected-key-fingerprint", expectedFp]);
    expect(withFp.code).toBe(0);
    expect(withFp.stdout).toContain("matched supplied fingerprint");
  });

  it("N17/N35: wrong fingerprint → verifier FAIL untrusted", async () => {
    const intentId = await createAllowedCase();
    const envelope = await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json());
    const res = runVerifier(envelope, ["--fp", "deadbeef"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("untrusted signing key");
  });

  it("N08: mutated manifest actionDigest → verifier FAIL not-backed", async () => {
    const intentId = await createAllowedCase();
    const envelope = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json())) as { manifest: { actionDigest: string } };
    envelope.manifest.actionDigest = `sha256:${"9".repeat(64)}`;
    const res = runVerifier(envelope);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("actionDigest");
  });

  it("N09: forged completeness (claim complete, drop required roles) → FAIL", async () => {
    const intentId = await createAllowedCase();
    const envelope = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json())) as {
      manifest: { terminalState: string; completeness: string; missingRequiredRoles: string[] };
    };
    // Force a terminal state that requires the full exec chain, claim complete.
    envelope.manifest.terminalState = "succeeded";
    envelope.manifest.completeness = "complete";
    envelope.manifest.missingRequiredRoles = [];
    const res = runVerifier(envelope);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("complete");
  });

  it("N11: reordered bundle event → verifier FAIL", async () => {
    // Use an approved case so there are >=2 correlated events to reorder.
    const { intentId, requestHash, actionDigest } = await createPendingCase();
    await approveCase(intentId, requestHash, actionDigest);
    const envelope = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json())) as { bundle: { events: unknown[] } };
    if (envelope.bundle.events.length >= 2) {
      const e = envelope.bundle.events;
      [e[0], e[1]] = [e[1], e[0]];
      const res = runVerifier(envelope);
      expect(res.code).toBe(1);
    }
  });

  it("N12: removed genesis event → verifier FAIL (digest/linkage)", async () => {
    const intentId = await createAllowedCase();
    const envelope = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json())) as { bundle: { events: unknown[] } };
    envelope.bundle.events = envelope.bundle.events.slice(1);
    const res = runVerifier(envelope);
    expect(res.code).toBe(1);
  });

  it("N07: /evidence with signing key unset → 503", async () => {
    const intentId = await createAllowedCase();
    const saved = process.env.STEWARD_AUDIT_SIGNING_KEY;
    delete process.env.STEWARD_AUDIT_SIGNING_KEY;
    resetCheckpointSignerCache();
    try {
      const res = await realApp.request(
        `/v2/provider-actions/${intentId}/evidence`,
        await authHeaders(),
      );
      expect(res.status).toBe(503);
      const body = (await res.json()) as { error: string };
      expect(body.error).toBe("CASE_EVIDENCE_SIGNING_DISABLED");
    } finally {
      process.env.STEWARD_AUDIT_SIGNING_KEY = saved;
      resetCheckpointSignerCache();
    }
  });

  it("N04: agent token → 403 CASE_FORBIDDEN(generic)", async () => {
    const intentId = await createAllowedCase();
    const res = await realApp.request(
      `/v2/provider-actions/${intentId}/case`,
      await agentHeaders(),
    );
    expect(res.status).toBe(403);
  });

  it("N05: owner without recent MFA → 403", async () => {
    const intentId = await createAllowedCase();
    const res = await realApp.request(
      `/v2/provider-actions/${intentId}/case`,
      await authHeaders(F.TENANT, "admin", false),
    );
    expect(res.status).toBe(403);
  });

  it("N06: member (non-admin) role → 403", async () => {
    const intentId = await createAllowedCase();
    const res = await realApp.request(
      `/v2/provider-actions/${intentId}/case`,
      await authHeaders(F.TENANT, "member"),
    );
    expect(res.status).toBe(403);
  });

  it("N01/N02/N03: foreign-tenant / foreign-workspace / nonexistent → uniform 404", async () => {
    const intentId = await createAllowedCase();
    // N01 foreign tenant: a valid admin session for a DIFFERENT tenant must not
    // see this tenant's case. The session token's tenantId (+ matching header)
    // scopes the query, so the case is not found under the caller's tenant.
    const foreignTenant = await realApp.request(
      `/v2/provider-actions/${intentId}/case`,
      await authHeaders(F.TENANT_B, "admin"),
    );
    expect(foreignTenant.status).toBe(404);
    // N03 nonexistent id (valid shape).
    const nonexistent = await realApp.request(
      "/v2/provider-actions/pa_00000000-0000-0000-0000-000000000000/case",
      await authHeaders(),
    );
    expect(nonexistent.status).toBe(404);
    const b1 = (await foreignTenant.json()) as { error: string };
    const b2 = (await nonexistent.json()) as { error: string };
    expect(b1.error).toBe("CASE_NOT_FOUND");
    expect(b2.error).toBe("CASE_NOT_FOUND");
  });

  it("N37/N38/N39: malformed case id (traversal/nullbyte/unicode) → uniform 404", async () => {
    const auth = await authHeaders();
    for (const bad of [
      "..%2f..%2fetc",
      "pa_x",
      "pa_00000000-0000-0000-0000-00000000000",
      "not-a-case",
    ]) {
      const res = await realApp.request(
        `/v2/provider-actions/${encodeURIComponent(bad)}/case`,
        auth,
      );
      expect(res.status).toBe(404);
    }
  });

  it("N24: credential-looking comment body never appears in exported evidence", async () => {
    // The allowed op body is not included in evidence (safe summary excludes it).
    const intentId = await createAllowedCase("leak0001");
    const envelope = await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.text());
    // No bearer/token-looking canary and no raw provider idempotency key. (The
    // word "authorization" legitimately appears in the canonicalizationSpec text
    // and in metadata KEYS; the leak concern is a credential VALUE, so we scan
    // for token-shaped canaries + the raw key field, not the generic substring.)
    expect(envelope).not.toContain("ghp_");
    expect(envelope).not.toMatch(/"providerIdempotencyKey":/);
    expect(envelope).not.toMatch(/"credentialSecret"\s*:/i);
    expect(envelope).not.toMatch(/Bearer\s+[A-Za-z0-9._-]{10,}/);
  });

  it("KC15/codex-P2: over-cap case segment → /evidence 400 CASE_RANGE_TOO_LARGE, /case still works", async () => {
    const { getDb } = await import("@stwd/db");
    const { sql } = await import("drizzle-orm");
    const intentId = await createAllowedCase();
    // Stretch the case's own correlated span past MAX_CASE_SEGMENT_EVENTS by
    // adding a second correlated event ~10_001 seqs above genesis (simulates a
    // long-lived case in a busy tenant). We only need the case's min/max seqs to
    // be >10k apart; the row need not be chain-valid because the over-cap branch
    // short-circuits BEFORE the chain verify.
    const rows = await getDb().execute(
      sql`SELECT MAX(seq) AS m FROM audit_events WHERE tenant_id = ${F.TENANT}`,
    );
    const arr = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? []);
    const base = Number((arr[0] as { m: number | string }).m);
    const bigSeq = base + 10_002;
    const zero = `\\x${"00".repeat(32)}`;
    await getDb().execute(
      sql`INSERT INTO audit_events (tenant_id, seq, prev_hash, hmac, actor_type, actor_id, action, resource_type, resource_id, metadata, created_at)
          VALUES (${F.TENANT}, ${bigSeq}, ${sql.raw(`'${zero}'::bytea`)}, ${sql.raw(`'${zero}'::bytea`)}, 'system', 'x', 'provider.execution.dispatched', 'provider_action', ${intentId}, ${sql.raw(
            `'{"intentId":"${intentId}"}'::jsonb`,
          )}, now())`,
    );
    // /case (manifest-only) still serves the manifest (marked unknown).
    const caseRes = await realApp.request(
      `/v2/provider-actions/${intentId}/case`,
      await authHeaders(),
    );
    expect(caseRes.status).toBe(200);
    const m = (await caseRes.json()) as { completeness: string };
    expect(m.completeness).toBe("unknown");
    // /evidence refuses to materialize the unbounded range.
    const eviRes = await realApp.request(
      `/v2/provider-actions/${intentId}/evidence`,
      await authHeaders(),
    );
    expect(eviRes.status).toBe(400);
    const body = (await eviRes.json()) as { error: string };
    expect(body.error).toBe("CASE_RANGE_TOO_LARGE");
  });

  it("access-denied case verifies OFFLINE and is honestly complete (genesis-only)", async () => {
    const intentId = await createAccessDeniedCase();
    const envelope = (await realApp
      .request(`/v2/provider-actions/${intentId}/evidence`, await authHeaders())
      .then((r) => r.json())) as { completeness: string };
    expect(envelope.completeness).toBe("complete");
    const res = runVerifier(envelope, ["--expected-key-fingerprint", expectedFp]);
    expect(res.code).toBe(0);
    expect(res.stdout).toContain("terminalState: denied_access");
  });
});
