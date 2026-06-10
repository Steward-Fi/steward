/**
 * REAL behavioral coverage for the trade session control-plane gates +
 * audit-actor attribution on the @stwd/api trade routes.
 *
 * The retired vault-trade-audit-gates.test.ts asserted (via source grep) only
 * that the three session routes "contain" canManageTradeSession +
 * requireRecentTradeSessionMfa, and that tradeAuditActor "contains" the
 * session-jwt→user branch. A grep cannot prove the gate FIRES, that it sits
 * ABOVE the session-manager mutation, or that the human — not a synthetic agent
 * actor — is the principal recorded in the authorization audit. This drives the
 * REAL routes against an in-memory PGLite DB + the REAL TradeSessionManager and
 * proves behaviorally:
 *
 *   - create / get / revoke each refuse a non-session principal (api-key) → 403
 *     and an owner session WITHOUT recent MFA → 403, BEFORE any session mutation
 *     (the seeded session stays active through a denied revoke).
 *   - a fully-authenticated owner+MFA create SUCCEEDS (201) and records the
 *     `trade.session.create.authorized` audit attributed to the human user
 *     (actorType "user", actorId = session userId), written BEFORE the
 *     `trade.session.created` audit — i.e. before the irreversible createSession
 *     — proving tradeAuditActor's session-jwt→user branch with execution, not a
 *     substring match.
 *
 * Nothing in the gate path is mocked. The venue wallet is seeded into
 * agentWallets exactly as the real create flow resolves it (vault.getWallet →
 * agentWallets venue row), so resolveHyperliquidWallet returns the bound wallet
 * and the create reaches the session manager for real.
 */
import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agents,
  agentPolicies,
  agentWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `trade-gate-tenant-${Date.now()}`;
const AGENT_ID = `trade-gate-agent-${Date.now()}`;
const ACTOR_ID = "trade-gate-owner";
// The agent's resolved Hyperliquid venue wallet. The create flow binds sessions
// to THIS (via vault.getWallet → agentWallets), never to caller-supplied data.
const VENUE_WALLET = "0x00000000000000000000000000000000000000aa";
// A pre-existing active session so the get/revoke gates are reachable (both
// routes load the session before gating, returning 404 if it is absent).
const SEEDED_SESSION_ID = `ses_seeded_${Date.now()}`;

setDefaultTimeout(30000);

type Posture =
  | "api-key"
  | "session-no-mfa"
  | "session-with-mfa"
  // agent's own bearer, scoped to AGENT_ID — the autonomous self-service path.
  | "agent-self"
  // agent bearer scoped to a DIFFERENT agent — must be refused.
  | "agent-other";

async function makeApp(posture: Posture) {
  const { tradeRoutes } = await import("../routes/trade");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("agentScope", undefined);
    c.set("tenantRole", "owner");
    c.set("userId", ACTOR_ID);
    if (posture === "api-key") {
      c.set("authType", "api-key");
    } else if (posture === "agent-self") {
      // agent-token scoped to AGENT_ID, no human role/MFA.
      c.set("authType", "agent-token");
      c.set("agentScope", AGENT_ID);
      c.set("tenantRole", undefined);
    } else if (posture === "agent-other") {
      c.set("authType", "agent-token");
      c.set("agentScope", `${AGENT_ID}-someone-else`);
      c.set("tenantRole", undefined);
    } else {
      c.set("authType", "session-jwt");
      if (posture === "session-with-mfa") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/v1/trade", tradeRoutes);
  return app;
}

function post(app: Awaited<ReturnType<typeof makeApp>>, path: string, body: unknown) {
  return app.request(`/v1/trade${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function errorOf(res: Response): Promise<string> {
  const body = (await res.json()) as { ok: boolean; error?: string };
  expect(body.ok).toBe(false);
  return body.error ?? "";
}

const CREATE_BODY = { agentId: AGENT_ID, venue: "hyperliquid" as const };

describe("trade session control-plane gates (real routes)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD ??= "trade-gate-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??=
      "trade-session-gates-test-audit-hmac-key-0123456789abcdef";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Trade Gate Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Trade Gate Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agentWallets).values({
      agentId: AGENT_ID,
      chainFamily: "evm",
      venue: "hyperliquid",
      address: VENUE_WALLET,
    });
    // Seed a policy so the agent-self happy-path has caps to operate within.
    // The agent-self path fails closed without a policy (tested separately).
    await getDb().insert(agentPolicies).values({
      agentId: AGENT_ID,
      tenantId: TENANT_ID,
      dailyCapUsd: "100",
      perOrderCapUsd: "50",
      leverageCap: "2",
      // Include the schema's default allowedAssets so a bare create (which
      // defaults to [BTC,ETH,BNB]) is not rejected by the asset allowlist.
      allowedAssets: ["BTC", "ETH", "BNB"],
      allowedVenues: ["hyperliquid"],
      updatedBy: ACTOR_ID,
      updatedReason: "test seed",
    });
    await getDb()
      .insert(tradeSessions)
      .values({
        id: SEEDED_SESSION_ID,
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        venue: "hyperliquid",
        walletId: VENUE_WALLET,
        status: "active",
        dailySpendUsd: "0",
        dailyCapUsd: "100",
        perOrderCapUsd: "50",
        leverageCap: "2",
        allowedAssets: ["BTC"],
        expiresAt: new Date(Date.now() + 60_000),
      });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  it("create session: refuses api-key (no owner/admin session) then owner-session-without-MFA", async () => {
    const apiKeyRes = await post(await makeApp("api-key"), "/sessions", CREATE_BODY);
    expect(apiKeyRes.status).toBe(403);
    expect(await errorOf(apiKeyRes)).toBe(
      "Forbidden: insufficient access to create a session for this agent",
    );

    const noMfaRes = await post(await makeApp("session-no-mfa"), "/sessions", CREATE_BODY);
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe(
      "Trade session management requires recent MFA verification",
    );

    // Fail-closed: neither denied create reached the session manager.
    const sessions = await getDb()
      .select({ id: tradeSessions.id })
      .from(tradeSessions)
      .where(eq(tradeSessions.agentId, AGENT_ID));
    expect(sessions.map((s) => s.id)).toEqual([SEEDED_SESSION_ID]);
  });

  it("get session: refuses api-key then owner-session-without-MFA", async () => {
    const apiKeyRes = await (await makeApp("api-key")).request(
      `/v1/trade/sessions/${SEEDED_SESSION_ID}`,
    );
    expect(apiKeyRes.status).toBe(403);
    expect(await errorOf(apiKeyRes)).toBe("Forbidden: insufficient access to this session");

    const noMfaRes = await (await makeApp("session-no-mfa")).request(
      `/v1/trade/sessions/${SEEDED_SESSION_ID}`,
    );
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe(
      "Trade session management requires recent MFA verification",
    );
  });

  it("revoke session: refuses api-key then owner-session-without-MFA, leaving the session active", async () => {
    const apiKeyRes = await post(
      await makeApp("api-key"),
      `/sessions/${SEEDED_SESSION_ID}/revoke`,
      {},
    );
    expect(apiKeyRes.status).toBe(403);
    expect(await errorOf(apiKeyRes)).toBe("Forbidden: insufficient access to revoke this session");

    const noMfaRes = await post(
      await makeApp("session-no-mfa"),
      `/sessions/${SEEDED_SESSION_ID}/revoke`,
      {},
    );
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe(
      "Trade session management requires recent MFA verification",
    );

    // The denied revokes never mutated the session — it is still active.
    const [row] = await getDb()
      .select({ status: tradeSessions.status })
      .from(tradeSessions)
      .where(eq(tradeSessions.id, SEEDED_SESSION_ID));
    expect(row.status).toBe("active");
  });

  it("create session (owner+MFA): records the authorized audit as the human user, before the create", async () => {
    const res = await post(await makeApp("session-with-mfa"), "/sessions", CREATE_BODY);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { ok?: boolean; data: { sessionId: string } };
    const newSessionId = body.data.sessionId;
    expect(newSessionId).not.toBe(SEEDED_SESSION_ID);

    // The new session is bound to the agent's resolved venue wallet (not spoofable).
    const [created] = await getDb()
      .select({ walletId: tradeSessions.walletId })
      .from(tradeSessions)
      .where(eq(tradeSessions.id, newSessionId));
    expect(created.walletId).toBe(VENUE_WALLET);

    // The authorization audit is attributed to the HUMAN session user — proving
    // tradeAuditActor's session-jwt→user branch fired (not a synthetic agent actor).
    const authorized = await getDb()
      .select({
        actorType: auditEvents.actorType,
        actorId: auditEvents.actorId,
        seq: auditEvents.seq,
      })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.action, "trade.session.create.authorized"),
          eq(auditEvents.tenantId, TENANT_ID),
        ),
      );
    expect(authorized.length).toBe(1);
    expect(authorized[0].actorType).toBe("user");
    expect(authorized[0].actorId).toBe(ACTOR_ID);

    // The success audit is also the human, and is sequenced AFTER the
    // authorization — i.e. the authorization was committed before createSession.
    const createdAudit = await getDb()
      .select({ actorType: auditEvents.actorType, seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(eq(auditEvents.action, "trade.session.created"), eq(auditEvents.tenantId, TENANT_ID)),
      );
    expect(createdAudit.length).toBe(1);
    expect(createdAudit[0].actorType).toBe("user");
    expect(authorized[0].seq).toBeLessThan(createdAudit[0].seq);
  });

  // ─── Agent self-service session path (autonomous trading) ──────────────────

  it("create session (agent-self): an agent's own bearer creates its session WITHOUT human MFA", async () => {
    const res = await post(await makeApp("agent-self"), "/sessions", CREATE_BODY);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { ok: boolean; data?: { sessionId?: string } };
    expect(body.ok).toBe(true);
    expect(typeof body.data?.sessionId).toBe("string");
  });

  it("create session (agent-other): an agent bearer CANNOT create a session for a different agent", async () => {
    // agent-other is scoped to a different agentId than the CREATE_BODY target.
    const res = await post(await makeApp("agent-other"), "/sessions", CREATE_BODY);
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe(
      "Forbidden: insufficient access to create a session for this agent",
    );
  });

  it("create session (agent-self): requested caps OVER agent policy are still rejected", async () => {
    // Seed a restrictive policy, then have the agent ask for more than it allows.
    await getDb()
      .insert(agentPolicies)
      .values({
        agentId: AGENT_ID,
        tenantId: TENANT_ID,
        dailyCapUsd: "100",
        perOrderCapUsd: "50",
        leverageCap: "2",
        allowedAssets: ["BTC"],
        allowedVenues: ["hyperliquid"],
        updatedBy: ACTOR_ID,
        updatedReason: "test seed",
      })
      .onConflictDoNothing();
    // 40_000 is within the schema max (50_000) but far over the seeded
    // agent policy dailyCap (100), so it must be rejected by the POLICY clamp,
    // not the schema. perOrderCap kept under dailyCap to avoid the ordering check.
    const res = await post(await makeApp("agent-self"), "/sessions", {
      agentId: AGENT_ID,
      venue: "hyperliquid" as const,
      dailyCap: 40_000,
      perOrderCap: 50,
    });
    expect(res.status).toBe(400);
    // The policy clamp returns a { code: "policy-violation", message } shape.
    const body = (await res.json()) as { code?: string; message?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.message).toContain("exceeds agent policy cap");
  });

  it("get session (agent-self): an agent reads its OWN session without human MFA", async () => {
    const res = await (await makeApp("agent-self")).request(
      `/v1/trade/sessions/${SEEDED_SESSION_ID}`,
    );
    expect(res.status).toBe(200);
  });

  it("create session (agent-self): an agent with NO policy is refused (fail-closed)", async () => {
    const noPolicyAgent = `${AGENT_ID}-nopolicy`;
    await getDb().insert(agents).values({
      id: noPolicyAgent,
      tenantId: TENANT_ID,
      name: "No Policy Agent",
      walletAddress: "0x0000000000000000000000000000000000000002",
    });
    await getDb().insert(agentWallets).values({
      agentId: noPolicyAgent,
      chainFamily: "evm",
      venue: "hyperliquid",
      address: "0x00000000000000000000000000000000000000bb",
    });
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "agent-token");
      c.set("agentScope", noPolicyAgent);
      c.set("tenantRole", undefined);
      await next();
    });
    const { tradeRoutes } = await import("../routes/trade");
    app.route("/v1/trade", tradeRoutes);
    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: noPolicyAgent, venue: "hyperliquid" }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { code?: string; message?: string };
    expect(body.message).toContain("no trade policy");
  });

  it("revoke session (agent-self): an agent revokes its OWN session without human MFA", async () => {
    // Seed a dedicated session so this revoke does not disturb SEEDED_SESSION_ID.
    const ownSession = `ses_agent_self_${Date.now()}`;
    await getDb()
      .insert(tradeSessions)
      .values({
        id: ownSession,
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        venue: "hyperliquid",
        walletId: VENUE_WALLET,
        status: "active",
        dailySpendUsd: "0",
        dailyCapUsd: "100",
        perOrderCapUsd: "50",
        leverageCap: "2",
        allowedAssets: ["BTC"],
        expiresAt: new Date(Date.now() + 60_000),
      });
    const res = await post(await makeApp("agent-self"), `/sessions/${ownSession}/revoke`, {});
    expect(res.status).toBe(200);
  });
});
