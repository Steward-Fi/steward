/**
 * evidence real-app route-wiring regression (review-gate hardening).
 *
 * The existing evidence integration tests mount `providerCaseRoutes` on a MOCK Hono
 * app that manually injects `authType`/`tenantRole`/`tenantId`/`sessionMfaVerifiedAt`.
 * That bypasses the real middleware chain, so it cannot catch a missing
 * `tenantAuth` registration on `/v2/provider-actions/:id/{case,evidence}` in the
 * composed app. This suite drives the REAL `mountCoreIdempotencyAndRoutes(createApp())`
 * with genuinely-minted session/agent JWTs to prove:
 *   - a valid owner session with recent MFA REACHES the handler (404 CASE_NOT_FOUND
 *     for a nonexistent case, NOT a blanket 403), and
 *   - the negative-auth matrix (unauth, member role, stale MFA, agent token)
 *     is rejected with 403 through the real chain.
 *
 * Regression guard for: evidence originally forgot to wire `tenantAuth` on the case
 * subpaths (the global app.ts only wires it for /v2/workspaces|provider-accounts
 * |...), so every request 403'd and the feature was unreachable in production.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_AUDIT_HMAC_KEY = process.env.STEWARD_AUDIT_HMAC_KEY || "0".repeat(64);
process.env.STEWARD_MASTER_PASSWORD =
  process.env.STEWARD_MASTER_PASSWORD || "pr5-route-wiring-master-password";
// @stwd/auth resolves the JWT secret from STEWARD_JWT_SECRET (canonical), not
// JWT_SECRET; without it a clean CI env (no ambient secret, PGLite mode is NOT
// enough to enable the master-password fallback) throws "No JWT secret
// configured". Set the canonical var explicitly so this suite is self-contained.
process.env.STEWARD_JWT_SECRET =
  process.env.STEWARD_JWT_SECRET || "pr5-route-wiring-jwt-secret-0123456789abcdef0123456789";

import { signAccessToken, signAgentToken } from "@stwd/auth";
import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const TENANT = "default";
const CASE_ID = "pa_0123abcd-0123-0123-0123-0123456789ab".slice(0, 39);

describe("evidence case routes: real composed-app auth wiring", () => {
  let app: any;
  let ownerToken: string;
  let memberToken: string;
  let staleMfaToken: string;
  let agentToken: string;

  beforeAll(async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    await getDb()
      .insert(tenants)
      .values({ id: TENANT, name: "Evidence Wiring", apiKeyHash: "pr5-wiring" })
      .onConflictDoNothing();
    const [owner] = await getDb()
      .insert(users)
      .values({ email: "owner@pr5.io", name: "Owner" })
      .returning();
    const [member] = await getDb()
      .insert(users)
      .values({ email: "member@pr5.io", name: "Member" })
      .returning();
    await getDb()
      .insert(userTenants)
      .values([
        { userId: owner.id, tenantId: TENANT, role: "owner" },
        { userId: member.id, tenantId: TENANT, role: "member" },
      ]);

    ownerToken = await signAccessToken({
      address: "0xowner",
      tenantId: TENANT,
      userId: owner.id,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    } as any);
    memberToken = await signAccessToken({
      address: "0xmember",
      tenantId: TENANT,
      userId: member.id,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    } as any);
    staleMfaToken = await signAccessToken({
      address: "0xowner",
      tenantId: TENANT,
      userId: owner.id,
      mfaVerifiedAt: Date.now() - 10 * 60_000,
      mfaMethod: "totp",
    } as any);
    agentToken = await signAgentToken({
      agentId: "agent-pr5",
      tenantId: TENANT,
    } as any);

    const mod = await import("../app");
    app = mod.mountCoreIdempotencyAndRoutes(mod.createApp());
  }, 120_000);

  afterAll(async () => {
    // Close the PGLite client + clear the override so this file does not leak an
    // open handle into the shared bun test run (an unclosed client makes the
    // file exit 99 even with every test passing). Mirrors the teardown in
    // provider-case-evidence.integration.test.ts.
    await closeDb();
  });

  function hitCase(token?: string) {
    return app.request(
      `/v2/provider-actions/${CASE_ID}/case`,
      token ? { headers: { Authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT } } : {},
    );
  }

  it("valid owner + recent MFA REACHES handler -> 404 CASE_NOT_FOUND (not blanket 403)", async () => {
    const res = await hitCase(ownerToken);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error?: string };
    expect(body.error).toBe("CASE_NOT_FOUND");
  });

  it("unauthenticated -> 403 (gate rejects unpopulated context, fail-closed)", async () => {
    const res = await hitCase();
    expect(res.status).toBe(403);
  });

  it("member (non-admin) role -> 403 (N06)", async () => {
    const res = await hitCase(memberToken);
    expect(res.status).toBe(403);
  });

  it("stale MFA -> 403 (N05)", async () => {
    const res = await hitCase(staleMfaToken);
    expect(res.status).toBe(403);
  });

  it("agent token -> 403 (N04)", async () => {
    const res = await hitCase(agentToken);
    expect(res.status).toBe(403);
  });
});
