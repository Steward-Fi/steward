/**
 * REAL behavioral coverage for the ERC-8004 control-plane: step-up gates on the
 * registration + feedback money/identity mutations, the fail-closed feedback
 * disable, register audit-ordering, on-chain read scoping, and public-discovery
 * redaction.
 *
 * The old version of this file `readFileSync`'d routes/erc8004.ts and asserted
 * the source CONTAINED `requireTenantAdminSession` / `requireRecentAdminMfa`,
 * that an `action: "...authorized"` string appeared before an `INSERT INTO`
 * string, that `publicDiscoveryAgentRow` was referenced, etc. None of it ran the
 * routes, so a refactor that moved a gate below the mutation — or dropped the
 * discovery redaction — would still pass. This drives the REAL routes against an
 * in-memory PGLite DB and proves the behavior:
 *
 *   - register-onchain + feedback refuse a non-session principal (api-key) → 403
 *     and an owner session WITHOUT recent MFA → 403, before any DB mutation.
 *   - feedback is fail-closed DISABLED: even a fully-authenticated owner+MFA is
 *     refused 403, and the reputation aggregate is NEVER written. This is the
 *     strong invariant — the reputation cache cannot be mutated through this
 *     route at all today.
 *   - a register-onchain by owner+MFA persists a `pending` registration and
 *     commits the `erc8004.register.authorized` audit BEFORE the
 *     `erc8004.register` audit (i.e. before the INSERT), proven by audit seq.
 *   - GET /:id/onchain refuses a proxy-only agent token (lacks the "agent"
 *     read scope) and a scope-mismatched token, but allows a properly-scoped one.
 *   - public discovery surfaces only the redacted projection: a tenant-forged
 *     reputation_cache.feedback_count is NOT exposed (always 0) and the private
 *     agent_card_json never appears in the response.
 *
 * The dormant signed-feedback replay/restore machinery (gated off by
 * `signedFeedbackWritesEnabled() === false`) is unreachable at runtime, so its
 * ordering is held by a small structural backstop at the bottom — and the
 * behavioral test above proves the route stays fail-closed while it is dormant.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  agentRegistrations,
  agents,
  auditEvents,
  closeDb,
  getDb,
  reputationCache,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `erc8004-tenant-${Date.now()}`;
const AGENT_ID = `erc8004-agent-${Date.now()}`;
const AGENT_REGISTER = `erc8004-register-${Date.now()}`;
const AGENT_DISCOVERY = `erc8004-discovery-${Date.now()}`;
const ACTOR_ID = "erc8004-owner";
const DISCOVERY_TOKEN_ID = `tok-${Date.now()}`;
const DISCOVERY_SECRET = `PRIVATE-AGENT-CARD-payload-do-not-leak-${Date.now()}`;

const apiKey: Partial<AppVariables> = {
  authType: "api-key",
  tenantRole: "owner",
  userId: ACTOR_ID,
};
const sessionNoMfa: Partial<AppVariables> = {
  authType: "session-jwt",
  tenantRole: "owner",
  userId: ACTOR_ID,
};
const sessionMfa = (): Partial<AppVariables> => ({
  authType: "session-jwt",
  tenantRole: "owner",
  userId: ACTOR_ID,
  sessionMfaVerifiedAt: Date.now(),
});

async function makeApp(vars: Partial<AppVariables>) {
  const { erc8004Routes } = await import("../routes/erc8004");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (vars.authType !== undefined) c.set("authType", vars.authType);
    if (vars.tenantRole !== undefined) c.set("tenantRole", vars.tenantRole);
    if (vars.userId !== undefined) c.set("userId", vars.userId);
    if (vars.sessionMfaVerifiedAt !== undefined)
      c.set("sessionMfaVerifiedAt", vars.sessionMfaVerifiedAt);
    if (vars.agentScope !== undefined) c.set("agentScope", vars.agentScope);
    if (vars.agentScopes !== undefined) c.set("agentScopes", vars.agentScopes);
    await next();
  });
  app.route("/erc8004", erc8004Routes);
  return app;
}

async function makeDiscoveryApp() {
  const { discoveryRoutes } = await import("../routes/erc8004");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    await next();
  });
  app.route("/discovery", discoveryRoutes);
  return app;
}

function postErc(app: Awaited<ReturnType<typeof makeApp>>, path: string, body: unknown) {
  return app.request(`/erc8004${path}`, {
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

const FEEDBACK_BODY = {
  fromAddress: "0x1111111111111111111111111111111111111111",
  score: 5,
  taskId: "task-replay-1",
  chainId: 8453,
};

describe("ERC-8004 control-plane (real routes)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD ??= "erc8004-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "erc8004-audit-order-test-audit-hmac-key-0123456789ab";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "ERC-8004 Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    for (const id of [AGENT_ID, AGENT_REGISTER, AGENT_DISCOVERY]) {
      await getDb()
        .insert(agents)
        .values({
          id,
          tenantId: TENANT_ID,
          name: `ERC-8004 Agent ${id}`,
          walletAddress: "0x0000000000000000000000000000000000000abc",
        });
    }
    // A CONFIRMED registration whose private agent-card JSON carries a secret,
    // plus a forged feedback_count of 999 — public discovery must surface
    // neither.
    await getDb()
      .insert(agentRegistrations)
      .values({
        tenantId: TENANT_ID,
        agentId: AGENT_DISCOVERY,
        chainId: 8453,
        tokenId: DISCOVERY_TOKEN_ID,
        registryAddress: "0x0000000000000000000000000000000000008004",
        agentCardJson: { name: AGENT_DISCOVERY, secret: DISCOVERY_SECRET },
        status: "confirmed",
      });
    await getDb().insert(reputationCache).values({
      agentId: AGENT_DISCOVERY,
      chainId: 8453,
      tokenId: DISCOVERY_TOKEN_ID,
      scoreInternal: "5",
      feedbackCount: 999,
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  it("register-onchain: refuses api-key then owner-session-without-MFA, with no row written", async () => {
    const keyRes = await postErc(await makeApp(apiKey), `/${AGENT_ID}/register-onchain`, {
      chainId: 8453,
    });
    expect(keyRes.status).toBe(403);
    expect(await errorOf(keyRes)).toBe("ERC-8004 registration requires owner or admin session");

    const noMfaRes = await postErc(await makeApp(sessionNoMfa), `/${AGENT_ID}/register-onchain`, {
      chainId: 8453,
    });
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe("ERC-8004 registration requires recent MFA verification");

    // Fail-closed: neither denied call reached the INSERT.
    const rows = await getDb()
      .select({ id: agentRegistrations.id })
      .from(agentRegistrations)
      .where(eq(agentRegistrations.agentId, AGENT_ID));
    expect(rows.length).toBe(0);
  });

  it("feedback: refuses api-key, owner-without-MFA, and stays fail-closed disabled for owner+MFA", async () => {
    const keyRes = await postErc(await makeApp(apiKey), `/${AGENT_ID}/feedback`, FEEDBACK_BODY);
    expect(keyRes.status).toBe(403);
    expect(await errorOf(keyRes)).toBe("ERC-8004 feedback requires owner or admin session");

    const noMfaRes = await postErc(
      await makeApp(sessionNoMfa),
      `/${AGENT_ID}/feedback`,
      FEEDBACK_BODY,
    );
    expect(noMfaRes.status).toBe(403);
    expect(await errorOf(noMfaRes)).toBe("ERC-8004 feedback requires recent MFA verification");

    // Even a fully-authenticated owner+MFA is refused: signed-feedback writes are
    // disabled, so the reputation aggregate can never be mutated via this route.
    const ownerRes = await postErc(
      await makeApp(sessionMfa()),
      `/${AGENT_ID}/feedback`,
      FEEDBACK_BODY,
    );
    expect(ownerRes.status).toBe(403);
    expect(await errorOf(ownerRes)).toBe("ERC-8004 feedback writes require signed feedback proof");

    // Fail-closed proof: no reputation row and no feedback audit were ever written.
    const rep = await getDb()
      .select({ id: reputationCache.id })
      .from(reputationCache)
      .where(eq(reputationCache.agentId, AGENT_ID));
    expect(rep.length).toBe(0);
    const fb = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(and(eq(auditEvents.action, "erc8004.feedback"), eq(auditEvents.resourceId, AGENT_ID)));
    expect(fb.length).toBe(0);
  });

  it("register-onchain (owner+MFA): persists pending registration and audits authorized BEFORE the mutation", async () => {
    const res = await postErc(await makeApp(sessionMfa()), `/${AGENT_REGISTER}/register-onchain`, {
      chainId: 8453,
      capabilities: ["pay"],
      services: ["swap"],
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { status: string } };
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("pending");

    const [row] = await getDb()
      .select({ status: agentRegistrations.status })
      .from(agentRegistrations)
      .where(
        and(eq(agentRegistrations.agentId, AGENT_REGISTER), eq(agentRegistrations.chainId, 8453)),
      );
    expect(row.status).toBe("pending");

    // The authorization audit is committed before the success audit → before the
    // INSERT it brackets. Proven by the monotonic audit seq, not source order.
    const authorized = await getDb()
      .select({ seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.action, "erc8004.register.authorized"),
          eq(auditEvents.resourceId, AGENT_REGISTER),
        ),
      );
    const committed = await getDb()
      .select({ seq: auditEvents.seq })
      .from(auditEvents)
      .where(
        and(eq(auditEvents.action, "erc8004.register"), eq(auditEvents.resourceId, AGENT_REGISTER)),
      );
    expect(authorized.length).toBe(1);
    expect(committed.length).toBe(1);
    expect(authorized[0].seq).toBeLessThan(committed[0].seq);
  });

  it("on-chain read: refuses a proxy-only or scope-mismatched agent token, allows a properly-scoped one", async () => {
    // Proxy-only token: scoped to the agent but lacking the "agent" read scope.
    const proxyRes = await (
      await makeApp({ authType: "agent-token", agentScope: AGENT_ID, agentScopes: ["proxy"] })
    ).request(`/erc8004/${AGENT_ID}/onchain`);
    expect(proxyRes.status).toBe(403);
    expect(await errorOf(proxyRes)).toBe("Tenant-level agent access required");

    // Token scoped to a different agent → mismatch refused before anything else.
    const mismatchRes = await (
      await makeApp({
        authType: "agent-token",
        agentScope: "some-other-agent",
        agentScopes: ["agent"],
      })
    ).request(`/erc8004/${AGENT_ID}/onchain`);
    expect(mismatchRes.status).toBe(403);
    expect(await errorOf(mismatchRes)).toBe("Forbidden: agent scope mismatch");

    // Properly-scoped agent token reaches the read (the gate is not a blanket deny).
    const okRes = await (
      await makeApp({ authType: "agent-token", agentScope: AGENT_ID, agentScopes: ["agent"] })
    ).request(`/erc8004/${AGENT_ID}/onchain`);
    expect(okRes.status).toBe(200);
    const okBody = (await okRes.json()) as { ok: boolean; data: { reputationVerified: boolean } };
    expect(okBody.ok).toBe(true);
    // On-chain reputation is never surfaced as verified (registry not deployed).
    expect(okBody.data.reputationVerified).toBe(false);
  });

  it("public discovery: redacts agent-card JSON and never exposes a tenant-forgeable feedback count", async () => {
    const res = await (await makeDiscoveryApp()).request("/discovery/agents?chainId=8453");
    expect(res.status).toBe(200);
    const rawText = await res.text();
    // The private agent-card JSON secret must not appear anywhere in the response.
    expect(rawText).not.toContain(DISCOVERY_SECRET);
    const body = JSON.parse(rawText) as {
      ok: boolean;
      data: Array<Record<string, unknown>>;
    };
    expect(body.ok).toBe(true);
    const row = body.data.find((r) => r.token_id === DISCOVERY_TOKEN_ID);
    expect(row).toBeDefined();
    // Only the redacted public projection is present.
    expect(row?.reputation_verified).toBe(false);
    // The forged feedback_count (999 in reputation_cache) is NOT surfaced.
    expect(row?.feedback_count).toBe(0);
    expect(row?.agent_card_json).toBeUndefined();
    expect("score" in (row ?? {})).toBe(false);
  });
});

/**
 * Structural backstop for the DORMANT signed-feedback machinery. These code
 * paths are gated off at runtime (`signedFeedbackWritesEnabled()` returns false,
 * proven fail-closed by the behavioral test above), so they cannot be executed
 * to assert their ordering. The checks below ensure that — whenever signed
 * feedback is wired up — the replay key + duplicate short-circuit still precede
 * the reputation mutation, the lock is transaction-scoped, and a failed final
 * registration audit still rolls back the registration.
 */
describe("ERC-8004 dormant signed-feedback + restore machinery (structural backstop)", () => {
  const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "erc8004.ts"), "utf8");

  it("rejects replayed feedback before the reputation aggregate mutation", () => {
    const feedbackStart = routeSource.indexOf('erc8004Routes.post("/:id/feedback"');
    expect(feedbackStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("feedbackReplayKey", feedbackStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart),
    );
    expect(
      routeSource.indexOf("if (getRows(duplicateFeedback).length > 0) return true", feedbackStart),
    ).toBeLessThan(routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart));
    expect(routeSource).toContain("Feedback has already been recorded");
    expect(routeSource).toContain("taskId: z.string().trim().min(1)");
  });

  it("uses transaction-scoped feedback replay locks instead of session advisory locks", () => {
    const feedbackStart = routeSource.indexOf('erc8004Routes.post("/:id/feedback"');
    const feedbackRoute = routeSource.slice(
      feedbackStart,
      routeSource.indexOf("discoveryRoutes.get", feedbackStart),
    );
    expect(feedbackRoute).toContain("pg_advisory_xact_lock");
    expect(feedbackRoute).not.toContain("pg_advisory_lock(");
    expect(feedbackRoute).not.toContain("pg_advisory_unlock");
  });

  it("restores the previous agent registration when the final registration audit fails", () => {
    expect(routeSource).toContain("async function snapshotAgentRegistration");
    expect(routeSource).toContain("async function restoreAgentRegistration");
    const registerStart = routeSource.indexOf('erc8004Routes.post("/:id/register-onchain"');
    const registerRoute = routeSource.slice(
      registerStart,
      routeSource.indexOf('erc8004Routes.get("/:id/onchain"', registerStart),
    );
    expect(registerRoute).toContain("snapshotAgentRegistration(tenantId, agentId, chainId)");
    expect(registerRoute.indexOf('action: "erc8004.register.authorized"')).toBeLessThan(
      registerRoute.indexOf("INSERT INTO agent_registrations"),
    );
    expect(registerRoute).toContain(
      "restoreAgentRegistration(tenantId, agentId, chainId, previousRegistration)",
    );
  });
});
