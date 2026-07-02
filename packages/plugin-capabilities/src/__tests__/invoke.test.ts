/**
 * invoke.test.ts - unit coverage for the agent-facing invoke route's DECISION
 * layer (the default-deny + effect resolution + audit/rate machinery), isolated
 * from the proxy forward (which the e2e proves end-to-end with a real proxy).
 *
 * mounts createInvokeRoutes onto a bare hono app with a test middleware that
 * stamps the agent-token context (tenantId + agentScope, as requireAgentJwt
 * would) and an injected context whose db is a real PGLite carrying the core +
 * plugin schema, whose getPolicySet returns a per-test policy set, and whose
 * safeJsonParse mirrors the core. proves:
 *   - default-deny: no governing capability-intent rule => 403.
 *   - matched allow (passes) but proxy env absent => 503 (the decision AUTHORIZED
 *     the forward; the forward failed closed on missing proxy config) - this is
 *     how we assert "matched-allow proceeded" without a live proxy.
 *   - matched deny => 403.
 *   - matched require-approval => 202 + an invocation row with decision=approval.
 *   - wrong argEquals on an allow rule => 403 (constraint fail).
 *   - maxCallsPerHour=1 => the SECOND invoke is denied (count computed from the
 *     invocations table).
 *   - agent auth required (no agentScope => 401).
 *   - ungranted / expired / revoked / disabled capability => 403 (no-usable-grant).
 *   - every attempt records exactly one invocation row with its decision.
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { eq } from "@stwd/db";
import type { AppVariables, PolicyRule } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import { createInvokeRoutes } from "../invoke";
import { capabilityInvocations } from "../schema";
import { CapabilityStore } from "../store";
import { ensureAgent, ensureSecret, ensureTenant, type Harness, makeHarness } from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let tenantId: string;
let agentId: string;
let secretId: string;

// the policy set the injected getPolicySet returns for the current test.
let currentPolicySet: PolicyRule[] = [];

/** a capability-intent rule of the given effect governing `github.pr.comment`. */
function capRule(
  id: string,
  effect: "allow" | "deny" | "require-approval",
  constraints?: Record<string, unknown>,
  capabilities: string[] = ["github.pr.comment"],
): PolicyRule {
  return {
    id,
    // capability-intent is a contributed type (not in the core union); the DB
    // stores it as a string. cast for the test fixture.
    type: "capability-intent" as unknown as PolicyRule["type"],
    enabled: true,
    config: { capabilities, effect, ...(constraints ? { constraints } : {}) },
  };
}

function buildCtx(db: unknown): StewardAppContext {
  return {
    db,
    vault: {} as never,
    policyEngine: {} as never,
    priceOracle: {} as never,
    async ensureAgentForTenant() {
      return undefined;
    },
    async getPolicySet() {
      return currentPolicySet;
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
    async writeAuditEvent() {},
    async getAgentTokenStatus() {
      return null;
    },
    getRedisClient() {
      return null;
    },
    async requireAgentJwt() {},
    async operatorAuth() {},
    async tenantAuth() {},
  } as unknown as StewardAppContext;
}

interface AuthOpts {
  agent?: boolean;
}

/** mount the invoke router behind a test mw that stamps the agent-token context. */
function buildApp(db: unknown, auth: AuthOpts): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    if (auth.agent) {
      c.set("tenantId", tenantId);
      c.set("agentScope", agentId);
      c.set("authType", "agent-token" as never);
    }
    await next();
  });
  app.route("/capabilities", createInvokeRoutes(buildCtx(db)));
  return app;
}

/** create an enabled capability + an active grant for the agent. returns cap id. */
async function seedCapabilityWithGrant(opts?: {
  enabled?: boolean;
  expiresAt?: Date | null;
  revoke?: boolean;
}): Promise<string> {
  const db = harness!.db;
  const store = new CapabilityStore(db);
  const cap = await store.createCapability({
    tenantId,
    name: "github.pr.comment",
    spec: {
      secretId,
      host: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    },
    constraints: {},
    enabled: opts?.enabled ?? true,
  });
  const result = await store.createGrant({
    tenantId,
    capabilityId: cap.id,
    agentId,
    expiresAt: opts?.expiresAt ?? null,
  });
  if (opts?.revoke && result) {
    await store.revokeGrant(tenantId, result.grant.id);
  }
  return cap.id;
}

async function invocationRows(capabilityId: string | null) {
  const db = harness!.db;
  const rows = await db
    .select()
    .from(capabilityInvocations)
    .where(eq(capabilityInvocations.agentId, agentId));
  return capabilityId === null
    ? rows
    : rows.filter((r: { capabilityId: string | null }) => r.capabilityId === capabilityId);
}

function invokeReq(body?: unknown) {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
}

beforeEach(async () => {
  harness = await makeHarness();
  tenantId = `tenant-inv-${crypto.randomUUID()}`;
  agentId = `agent-inv-${crypto.randomUUID()}`;
  await ensureTenant(harness.db, tenantId);
  await ensureAgent(harness.db, tenantId, agentId);
  secretId = await ensureSecret(harness.db, tenantId, "gh-pat");
  currentPolicySet = [];
  // ensure the proxy env is ABSENT by default (so allow => 503 unless a test opts in).
  delete process.env.STEWARD_PROXY_URL;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS;
});

afterEach(async () => {
  await harness?.close();
  harness = null;
  delete process.env.STEWARD_PROXY_URL;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS;
});

describe("invoke: agent auth", () => {
  test("no agent context => 401", async () => {
    const app = buildApp(harness!.db, { agent: false });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(401);
  });
});

describe("invoke: grant resolution (fail-closed)", () => {
  test("unknown capability => 403, records a deny with null capability", async () => {
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/does.not.exist/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    const rows = await invocationRows(null);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("deny");
    expect(rows[0].capabilityId).toBeNull();
  });

  test("disabled capability => 403", async () => {
    await seedCapabilityWithGrant({ enabled: false });
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("expired grant => 403", async () => {
    await seedCapabilityWithGrant({ expiresAt: new Date(Date.now() - 60_000) });
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("revoked grant => 403", async () => {
    await seedCapabilityWithGrant({ revoke: true });
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });
});

describe("invoke: default-deny + effects", () => {
  test("no governing capability-intent rule => 403 (default-deny)", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = []; // engine passes vacuously; invoke layer denies.
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("deny");
  });

  test("a DISABLED allow rule does NOT authorize => 403 (revoke-by-disable is honored)", async () => {
    const capId = await seedCapabilityWithGrant();
    // an allow rule that WOULD authorize, but disabled. the engine skips it and
    // the authoritative loop must too (fail-closed): access is revoked.
    currentPolicySet = [{ ...capRule("r1", "allow"), enabled: false }];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
  });

  test("a rule that governs a DIFFERENT capability does not authorize => 403", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow", undefined, ["github.other.thing"])];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("matched deny => 403", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "deny")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
  });

  test("matched require-approval => 202 + approvalId + invocation(decision=approval)", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "require-approval")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: boolean;
      data: { approvalId: string; status: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("pending");
    expect(body.data.approvalId).toBeTruthy();
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("approval");
    expect(rows[0].id).toBe(body.data.approvalId);
  });

  test("matched allow that PASSES but proxy env absent => 503 (authorized, forward failed closed)", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: { x: 1 } }),
    );
    expect(res.status).toBe(503);
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("error");
  });
});

describe("invoke: body parsing", () => {
  test("malformed JSON body => 400 (not silently coerced to {})", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{ not valid json",
    });
    expect(res.status).toBe(400);
  });

  test("empty body is allowed (no args) => authorized, proxy-env-absent 503", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    // no body at all.
    const res = await app.request("/capabilities/github.pr.comment/invoke", { method: "POST" });
    expect(res.status).toBe(503);
  });

  test("a JSON array body => 400 (must be an object)", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "[1,2,3]",
    });
    expect(res.status).toBe(400);
  });
});

describe("invoke: allow-rule constraints", () => {
  test("argEquals mismatch => 403", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow", { argEquals: { repo: "acme/app" } })];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ args: { repo: "evil/app" } }),
    );
    expect(res.status).toBe(403);
  });

  test("argEquals match but proxy env absent => 503 (constraint passed, authorized)", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow", { argEquals: { repo: "acme/app" } })];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ args: { repo: "acme/app" } }),
    );
    expect(res.status).toBe(503);
  });
});

describe("invoke: rate limit (count from invocations table)", () => {
  test("maxCallsPerHour=1 => second invoke denied", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = [capRule("r1", "allow", { maxCallsPerHour: 1 })];
    const app = buildApp(harness!.db, { agent: true });

    // first invoke: count=0 < 1 => authorized, forward fails closed (503, records error).
    const first = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(first.status).toBe(503);

    // second invoke: count=1 (the recorded error attempt) >= 1 => the rate
    // constraint denies the allow rule => default-deny => 403.
    const second = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(second.status).toBe(403);

    const rows = await invocationRows(capId);
    expect(rows.length).toBe(2);
    expect(rows.filter((r) => r.decision === "error").length).toBe(1);
    expect(rows.filter((r) => r.decision === "deny").length).toBe(1);
  });
});
