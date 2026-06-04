import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { revocationStore } from "@stwd/auth";
import { agents, auditEvents, closeDb, getDb, policies, sessionSigners, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `sess-signer-tenant-${Date.now()}`;
const AGENT_ID = `sess-signer-agent-${Date.now()}`;
const OTHER_AGENT_ID = `sess-signer-other-${Date.now()}`;
const POLICY_ID = `sess-signer-policy-${Date.now()}`;
const OTHER_POLICY_ID = `sess-signer-policy-other-${Date.now()}`;

type AuthMode = "tenant" | "owner" | "owner-no-mfa" | "agent";

async function makeApp(authMode: AuthMode = "tenant") {
  const { sessionSignerRoutes } = await import("../routes/session-signers");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "agent") {
      // Agent tokens are NOT tenant-level → every route must reject with 403.
      c.set("authType", "agent-token");
      c.set("agentId", AGENT_ID);
    } else if (authMode === "owner") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "sess-owner-user");
      c.set("sessionMfaVerifiedAt", Date.now());
    } else if (authMode === "owner-no-mfa") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "sess-owner-user");
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  // Mount EXACTLY as production does (app.ts) so the :agentId param resolution
  // is exercised the same way.
  app.route("/agents/:agentId/session-signers", sessionSignerRoutes);
  return app;
}

interface MintData {
  id: string;
  jti: string;
  token: string;
  label: string;
  scopes: string[];
  policyIds: string[];
  expiresAt: string;
  createdAt: string;
}

async function mint(
  app: Awaited<ReturnType<typeof makeApp>>,
  label: string,
  extra: Record<string, unknown> = {},
): Promise<MintData> {
  const res = await app.request(`/agents/${AGENT_ID}/session-signers`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ label, ...extra }),
  });
  expect(res.status).toBe(200);
  expect(res.headers.get("Cache-Control")).toBe("no-store, max-age=0");
  expect(res.headers.get("Pragma")).toBe("no-cache");
  expect(res.headers.get("Expires")).toBe("0");
  const body = (await res.json()) as { ok: boolean; data: MintData };
  expect(body.ok).toBe(true);
  return body.data;
}

describe("session signers API", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "session-signers-master-password";
    // Real (non-dev) JWT secret ≥32 chars so signAgentToken does not refuse.
    process.env.STEWARD_JWT_SECRET = "session-signers-test-jwt-secret-0123456789";
    // Real audit HMAC key (32 bytes = 64 hex chars) so the tamper-evident audit
    // chain writes succeed — exercises the session-signer audit path for real.
    process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Session Signers Tenant",
      apiKeyHash: "hash",
    });
    await getDb()
      .insert(agents)
      .values([
        {
          id: AGENT_ID,
          tenantId: TENANT_ID,
          name: "Session Signers Agent",
          walletAddress: "0x1234567890123456789012345678901234567890",
        },
        {
          id: OTHER_AGENT_ID,
          tenantId: TENANT_ID,
          name: "Other Agent",
          walletAddress: "0x0987654321098765432109876543210987654321",
        },
      ]);
    await getDb()
      .insert(policies)
      .values([
        { id: POLICY_ID, agentId: AGENT_ID, type: "spending-limit", config: {} },
        { id: OTHER_POLICY_ID, agentId: AGENT_ID, type: "approved-addresses", config: {} },
      ]);
    // Applying the full migration history against in-memory PGLite is slow
    // (~45s for 60+ migrations); give the hook ample headroom.
  }, 180_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("mints a session signer with default scope and ~24h lifetime", async () => {
    const app = await makeApp("owner");
    const data = await mint(app, "trading bot");
    expect(data.label).toBe("trading bot");
    expect(data.scopes).toEqual(["agent"]);
    expect(data.policyIds).toEqual([]);
    expect(typeof data.token).toBe("string");
    expect(data.token.length).toBeGreaterThan(0);
    expect(typeof data.jti).toBe("string");

    const ms = new Date(data.expiresAt).getTime() - Date.now();
    expect(ms).toBeGreaterThan(23 * 3600 * 1000);
    expect(ms).toBeLessThanOrEqual(24 * 3600 * 1000 + 10_000);

    // Row persisted with the same jti.
    const rows = await getDb().select().from(sessionSigners).where(eq(sessionSigners.id, data.id));
    expect(rows).toHaveLength(1);
    expect(rows[0].jti).toBe(data.jti);
    expect(rows[0].revokedAt).toBeNull();
  });

  it("mints with a valid policyId + custom scopes and clamps lifetime to 30d", async () => {
    const app = await makeApp("owner");
    const data = await mint(app, "treasury rebalancer", {
      expiresIn: "60d",
      scopes: ["agent", "api:proxy"],
      policyIds: [POLICY_ID],
    });
    expect(data.policyIds).toEqual([POLICY_ID]);
    expect(data.scopes).toContain("agent");
    expect(data.scopes).toContain("api:proxy");

    const ms = new Date(data.expiresAt).getTime() - Date.now();
    expect(ms).toBeGreaterThan(29 * 24 * 3600 * 1000);
    expect(ms).toBeLessThanOrEqual(30 * 24 * 3600 * 1000 + 10_000);
  });

  it("enforces pinned policyIds for session-signer requests", async () => {
    const mintApp = await makeApp("owner");
    const signer = await mint(mintApp, "limited signer", {
      policyIds: [POLICY_ID],
    });
    const { getScopedPolicySet, tenantAuth } = await import("../services/context");
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", tenantAuth);
    app.get("/agents/:agentId/effective-policies", async (c) => {
      const rules = await getScopedPolicySet(
        c.get("tenantId"),
        c.req.param("agentId"),
        c.get("agentPolicyIds"),
      );
      return c.json({ ids: rules.map((rule) => rule.id) });
    });

    const res = await app.request(`/agents/${AGENT_ID}/effective-policies`, {
      headers: { authorization: `Bearer ${signer.token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ids: string[] };
    expect(body.ids).toEqual([POLICY_ID]);
    expect(body.ids).not.toContain(OTHER_POLICY_ID);

    const [row] = await getDb()
      .select({ lastUsedAt: sessionSigners.lastUsedAt })
      .from(sessionSigners)
      .where(eq(sessionSigners.id, signer.id));
    expect(row.lastUsedAt).toBeInstanceOf(Date);
  });

  it("rejects a policyId that does not belong to the agent", async () => {
    const app = await makeApp("owner");
    const res = await app.request(`/agents/${AGENT_ID}/session-signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "bad-policy", policyIds: ["does-not-exist"] }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("does not belong");
  });

  it("validates label and other inputs", async () => {
    const app = await makeApp("owner");
    const cases: Array<{ name: string; body: Record<string, unknown> }> = [
      { name: "missing label", body: {} },
      { name: "blank label", body: { label: "   " } },
      { name: "label too long", body: { label: "x".repeat(129) } },
      { name: "bad expiresIn", body: { label: "ok", expiresIn: "banana" } },
      { name: "zero expiresIn", body: { label: "ok", expiresIn: "0h" } },
      { name: "invalid scope", body: { label: "ok", scopes: ["root"] } },
    ];
    for (const tc of cases) {
      const res = await app.request(`/agents/${AGENT_ID}/session-signers`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(tc.body),
      });
      expect(res.status, tc.name).toBe(400);
      const body = (await res.json()) as { ok: boolean };
      expect(body.ok, tc.name).toBe(false);
    }
  });

  it("returns 404 when minting for an agent in another tenant / unknown agent", async () => {
    const app = await makeApp("owner");
    const res = await app.request(`/agents/unknown-agent/session-signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "x" }),
    });
    expect(res.status).toBe(404);
  });

  it("lists active signers without leaking the token, and hides revoked by default", async () => {
    const app = await makeApp("owner");
    const a = await mint(app, "list-a");
    const b = await mint(app, "list-b");

    const listRes = await app.request(`/agents/${AGENT_ID}/session-signers`);
    expect(listRes.status).toBe(200);
    expect(listRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const list = (await listRes.json()) as {
      ok: boolean;
      data: Array<Record<string, unknown>>;
    };
    expect(list.ok).toBe(true);
    const ids = list.data.map((r) => r.id as string);
    expect(ids).toContain(a.id);
    expect(ids).toContain(b.id);
    // The minted JWT must never be returned on list.
    for (const row of list.data) {
      expect(row).not.toHaveProperty("token");
      expect(row).not.toHaveProperty("jti");
    }
  });

  it("revokes a signer, records the revocation, and is idempotent", async () => {
    const app = await makeApp("owner");
    const signer = await mint(app, "to-revoke");

    expect(await revocationStore.isRevoked(signer.jti)).toBe(false);

    const del = await app.request(`/agents/${AGENT_ID}/session-signers/${signer.id}`, {
      method: "DELETE",
    });
    expect(del.status).toBe(200);
    const delBody = (await del.json()) as { ok: boolean; data: { revokedAt?: string } };
    expect(delBody.ok).toBe(true);
    expect(delBody.data.revokedAt).toBeTruthy();

    // The jti is now in the revocation store → the token is rejected before expiry.
    expect(await revocationStore.isRevoked(signer.jti)).toBe(true);

    // Second revoke is idempotent.
    const del2 = await app.request(`/agents/${AGENT_ID}/session-signers/${signer.id}`, {
      method: "DELETE",
    });
    expect(del2.status).toBe(200);
    const del2Body = (await del2.json()) as { data: { alreadyRevoked?: boolean } };
    expect(del2Body.data.alreadyRevoked).toBe(true);

    // Excluded from default list, present with includeRevoked=true.
    const active = (await (await app.request(`/agents/${AGENT_ID}/session-signers`)).json()) as {
      data: Array<{ id: string }>;
    };
    expect(active.data.map((r) => r.id)).not.toContain(signer.id);

    const all = (await (
      await app.request(`/agents/${AGENT_ID}/session-signers?includeRevoked=true`)
    ).json()) as { data: Array<{ id: string }> };
    expect(all.data.map((r) => r.id)).toContain(signer.id);
  });

  it("refuses cross-agent revocation with a 404", async () => {
    const app = await makeApp("owner");
    const signer = await mint(app, "agentA-only");
    // Try to revoke agent A's signer via agent B's path.
    const del = await app.request(`/agents/${OTHER_AGENT_ID}/session-signers/${signer.id}`, {
      method: "DELETE",
    });
    expect(del.status).toBe(404);
    // And it is NOT revoked.
    expect(await revocationStore.isRevoked(signer.jti)).toBe(false);
  });

  it("repairs a missing revocation audit on retry for an already-revoked signer", async () => {
    const app = await makeApp("owner");
    const signer = await mint(app, "audit-repair");
    await getDb()
      .update(sessionSigners)
      .set({ revokedAt: new Date() })
      .where(eq(sessionSigners.id, signer.id));

    const before = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.action, "session_signer.revoked"),
          eq(auditEvents.resourceId, signer.id),
        ),
      );
    expect(before).toHaveLength(0);

    const retry = await app.request(`/agents/${AGENT_ID}/session-signers/${signer.id}`, {
      method: "DELETE",
    });
    expect(retry.status).toBe(200);
    const retryBody = (await retry.json()) as { data: { alreadyRevoked?: boolean } };
    expect(retryBody.data.alreadyRevoked).toBe(true);

    const after = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.action, "session_signer.revoked"),
          eq(auditEvents.resourceId, signer.id),
        ),
      );
    expect(after).toHaveLength(1);
  });

  it("requires owner/admin session auth and recent MFA on every route", async () => {
    const apiKeyApp = await makeApp("tenant");
    const apiKeyPost = await apiKeyApp.request(`/agents/${AGENT_ID}/session-signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "api-key-nope" }),
    });
    expect(apiKeyPost.status).toBe(403);

    const noMfaApp = await makeApp("owner-no-mfa");
    const noMfaPost = await noMfaApp.request(`/agents/${AGENT_ID}/session-signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "no-mfa-nope" }),
    });
    expect(noMfaPost.status).toBe(403);
    const noMfaBody = (await noMfaPost.json()) as { error?: string };
    expect(noMfaBody.error).toContain("requires recent MFA verification");

    const app = await makeApp("agent");
    const post = await app.request(`/agents/${AGENT_ID}/session-signers`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "nope" }),
    });
    expect(post.status).toBe(403);

    const get = await app.request(`/agents/${AGENT_ID}/session-signers`);
    expect(get.status).toBe(403);

    const del = await app.request(`/agents/${AGENT_ID}/session-signers/some-id`, {
      method: "DELETE",
    });
    expect(del.status).toBe(403);
  });
});
