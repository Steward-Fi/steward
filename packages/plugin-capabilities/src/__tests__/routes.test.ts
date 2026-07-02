/**
 * routes.test.ts - operator/tenant-auth CRUD route behavior + auth gates.
 *
 * mounts the capability + grant router (and the agent-scoped router) onto a bare
 * hono app with an injected test context and a test middleware that stamps the
 * per-request auth variables (tenantId, authType, tenantRole, sessionMfaVerifiedAt).
 * proves: the MFA/admin gate on every mutating route (the same bar the core
 * /secrets CRUD enforces), the create->grant->revoke->delete happy path with no
 * orphaned enabled routes, validation rejections surfaced as 400, secret values
 * never returned (there are none to return - only ids + routing metadata).
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import type { AppVariables } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import { createAgentCapabilityRoutes, createCapabilityRoutes } from "../routes";
import {
  enabledRouteCount,
  ensureAgent,
  ensureSecret,
  ensureTenant,
  type Harness,
  makeHarness,
  totalRouteCount,
} from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let tenantId: string;
let secretId: string;

/** a minimal injected context: the routes use db + safeJsonParse + writeAuditEvent. */
function buildCtx(db: unknown): StewardAppContext {
  return {
    db,
    // note (any is intentional): unused-by-routes ctx members are stubbed.
    vault: {} as any,
    // note (any is intentional): unused-by-routes ctx members are stubbed.
    policyEngine: {} as any,
    // note (any is intentional): unused-by-routes ctx members are stubbed.
    priceOracle: {} as any,
    async ensureAgentForTenant() {
      return undefined;
    },
    async getPolicySet() {
      return [];
    },
    async safeJsonParse<T>(c: { req: { json(): Promise<unknown> } }): Promise<T | null> {
      try {
        return (await c.req.json()) as T;
      } catch {
        return null;
      }
    },
    isValidAnyAddress() {
      return false;
    },
    async writeAuditEvent() {
      /* no-op audit sink for tests */
    },
    async getAgentTokenStatus() {
      return null;
    },
    getRedisClient() {
      return null;
    },
    async requireAgentJwt() {},
    async operatorAuth() {},
    async tenantAuth() {},
    // note (any is intentional): the test ctx satisfies the used subset.
  } as any;
}

type AuthOpts = {
  authType?: string;
  role?: string;
  mfa?: boolean;
};

/** build an app whose test middleware stamps the auth variables per request. */
function buildApp(db: unknown, auth: AuthOpts): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    if (auth.authType) c.set("authType", auth.authType as never);
    if (auth.role) c.set("tenantRole", auth.role as never);
    if (auth.mfa) c.set("sessionMfaVerifiedAt", Date.now() as never);
    await next();
  });
  const ctx = buildCtx(db);
  app.route("/capabilities", createCapabilityRoutes(ctx));
  app.route("/agents", createAgentCapabilityRoutes(ctx));
  return app;
}

/** an authorized (owner + recent MFA) app. */
function authedApp(db: unknown) {
  return buildApp(db, { authType: "session-jwt", role: "owner", mfa: true });
}

const GH_BODY = {
  name: "github.pr.comment",
  host: "api.github.com",
  pathPattern: "/repos/acme/widgets/issues/1/comments",
  method: "POST",
  injectKey: "authorization",
  injectFormat: "Bearer {value}",
};

beforeEach(async () => {
  harness = await makeHarness();
  tenantId = `tenant-${crypto.randomUUID()}`;
  await ensureTenant(harness.db, tenantId);
  secretId = await ensureSecret(harness.db, tenantId, "github-pat");
});

afterEach(async () => {
  await harness?.close();
  harness = null;
});

async function createCap(
  app: Hono<{ Variables: AppVariables }>,
  overrides: Record<string, unknown> = {},
) {
  return app.request("/capabilities", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ secretId, ...GH_BODY, ...overrides }),
  });
}

describe("auth gates (same bar as core /secrets CRUD)", () => {
  test("POST /capabilities without a session is 403", async () => {
    const app = buildApp(harness!.db, {}); // no auth
    const res = await createCap(app);
    expect(res.status).toBe(403);
  });

  test("POST /capabilities as a non-admin session is 403", async () => {
    const app = buildApp(harness!.db, { authType: "session-jwt", role: "member", mfa: true });
    const res = await createCap(app);
    expect(res.status).toBe(403);
  });

  test("POST /capabilities as admin WITHOUT recent MFA is 403", async () => {
    const app = buildApp(harness!.db, { authType: "session-jwt", role: "owner", mfa: false });
    const res = await createCap(app);
    expect(res.status).toBe(403);
  });

  test("GET /agents/:id/capabilities without a session is 403", async () => {
    const app = buildApp(harness!.db, {});
    const res = await app.request("/agents/agent-a/capabilities");
    expect(res.status).toBe(403);
  });
});

describe("capability CRUD happy path (authorized)", () => {
  test("create -> read -> list -> grant -> revoke -> delete, no orphaned routes", async () => {
    const app = authedApp(harness!.db);
    await ensureAgent(harness!.db, tenantId, "agent-a");

    // create
    const created = await createCap(app);
    expect(created.status).toBe(201);
    const capId = (await created.json()).data.id as string;

    // read
    const read = await app.request(`/capabilities/${capId}`);
    expect(read.status).toBe(200);
    const readBody = await read.json();
    expect(readBody.data.name).toBe("github.pr.comment");
    // never leaks a secret VALUE (only the id + routing metadata)
    expect(JSON.stringify(readBody)).not.toContain("Bearer sk");
    expect(readBody.data.secretId).toBe(secretId);

    // list
    const list = await app.request("/capabilities");
    expect((await list.json()).data).toHaveLength(1);

    // grant
    const grantRes = await app.request(`/capabilities/${capId}/grants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "agent-a" }),
    });
    expect(grantRes.status).toBe(201);
    const grantId = (await grantRes.json()).data.id as string;
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(1);

    // agent-scoped usable listing shows it
    const usable = await app.request("/agents/agent-a/capabilities");
    expect((await usable.json()).data).toHaveLength(1);

    // revoke -> route gone
    const revoke = await app.request(`/capabilities/grants/${grantId}`, { method: "DELETE" });
    expect(revoke.status).toBe(200);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);

    // delete
    const del = await app.request(`/capabilities/${capId}`, { method: "DELETE" });
    expect(del.status).toBe(200);
    expect(await app.request(`/capabilities/${capId}`).then((r) => r.status)).toBe(404);
  });

  test("duplicate name -> 409", async () => {
    const app = authedApp(harness!.db);
    expect((await createCap(app)).status).toBe(201);
    expect((await createCap(app)).status).toBe(409);
  });

  test("invalid github spec -> 400 (strict host)", async () => {
    const app = authedApp(harness!.db);
    const res = await createCap(app, { pathPattern: "/repos" });
    expect(res.status).toBe(400);
  });

  test("off-allowlist host -> 400", async () => {
    const app = authedApp(harness!.db);
    const res = await createCap(app, { host: "evil.example.com", pathPattern: "/v1/x" });
    expect(res.status).toBe(400);
  });

  test("bad capability name -> 400", async () => {
    const app = authedApp(harness!.db);
    const res = await createCap(app, { name: "Bad Name!" });
    expect(res.status).toBe(400);
  });

  test("unknown secretId -> 400 (secret must exist for the tenant)", async () => {
    const app = authedApp(harness!.db);
    const res = await createCap(app, { secretId: crypto.randomUUID() });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/secret not found or not usable/i);
  });

  test("foreign-tenant secretId -> 400 (no cross-tenant secret reference)", async () => {
    const otherTenant = `tenant-other-${crypto.randomUUID()}`;
    await ensureTenant(harness!.db, otherTenant);
    const foreignSecret = await ensureSecret(harness!.db, otherTenant, "foreign-pat");
    const app = authedApp(harness!.db);
    const res = await createCap(app, { secretId: foreignSecret });
    expect(res.status).toBe(400);
  });
});

describe("grant + patch route behaviors (authorized)", () => {
  test("grant to unknown agent -> 404", async () => {
    const app = authedApp(harness!.db);
    const capId = (await (await createCap(app)).json()).data.id as string;
    const res = await app.request(`/capabilities/${capId}/grants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "ghost" }),
    });
    expect(res.status).toBe(404);
    expect(await totalRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("duplicate grant -> 409", async () => {
    const app = authedApp(harness!.db);
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const capId = (await (await createCap(app)).json()).data.id as string;
    const body = JSON.stringify({ agentId: "agent-a" });
    const h = { "content-type": "application/json" };
    expect(
      (await app.request(`/capabilities/${capId}/grants`, { method: "POST", headers: h, body }))
        .status,
    ).toBe(201);
    expect(
      (await app.request(`/capabilities/${capId}/grants`, { method: "POST", headers: h, body }))
        .status,
    ).toBe(409);
  });

  test("PATCH disable -> paired routes disabled (no orphans)", async () => {
    const app = authedApp(harness!.db);
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const capId = (await (await createCap(app)).json()).data.id as string;
    await app.request(`/capabilities/${capId}/grants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "agent-a" }),
    });
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(1);

    const patch = await app.request(`/capabilities/${capId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: false }),
    });
    expect(patch.status).toBe(200);
    expect(await enabledRouteCount(harness!.db, tenantId)).toBe(0);
  });

  test("PATCH widening a github path to a wildcard -> 400 (no widen-by-patch)", async () => {
    const app = authedApp(harness!.db);
    const capId = (await (await createCap(app)).json()).data.id as string;
    const patch = await app.request(`/capabilities/${capId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pathPattern: "/repos/acme/*" }),
    });
    expect(patch.status).toBe(400);
  });

  test("grant with a past expiresAt -> 400", async () => {
    const app = authedApp(harness!.db);
    await ensureAgent(harness!.db, tenantId, "agent-a");
    const capId = (await (await createCap(app)).json()).data.id as string;
    const res = await app.request(`/capabilities/${capId}/grants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId: "agent-a",
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      }),
    });
    expect(res.status).toBe(400);
  });
});
