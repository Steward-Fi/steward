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
import {
  ensureAgent,
  ensureGovernedRoute,
  ensureSecret,
  ensureTenant,
  type Harness,
  makeHarness,
} from "./_harness";

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
    async requireCapabilityAgentJwt() {},
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

  // CANONICAL PRECEDENCE (master-plan §5.3) end-to-end through the invoke route.
  // These directly guard the fixed allow-over-approval bug: a matching passing
  // allow must NEVER shadow an applicable require-approval.

  test("REGRESSION allow + require-approval on same capability => 202 (approval NOT shadowed by allow)", async () => {
    const capId = await seedCapabilityWithGrant();
    // an allow rule (would authorize) AND a require-approval rule on the same
    // capability. old code let the passing allow short-circuit to allow (503).
    currentPolicySet = [
      capRule("allow-rule", "allow", undefined, ["github.*"]),
      capRule("approval-rule", "require-approval"),
    ];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(202);
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("approval");
  });

  test("REGRESSION holds regardless of rule order (approval listed first) => 202", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [
      capRule("approval-rule", "require-approval"),
      capRule("allow-rule", "allow", undefined, ["github.*"]),
    ];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(202);
  });

  test("deny + approval on same capability => 403 (deny wins, never softened to approval)", async () => {
    const capId = await seedCapabilityWithGrant();
    currentPolicySet = [capRule("approval-rule", "require-approval"), capRule("deny-rule", "deny")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
  });

  test("deny + allow on same capability => 403 (deny wins over allow)", async () => {
    await seedCapabilityWithGrant();
    currentPolicySet = [
      capRule("allow-rule", "allow", undefined, ["github.*"]),
      capRule("deny-rule", "deny"),
    ];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("malformed rule config alongside a passing allow => 403 (fail closed)", async () => {
    await seedCapabilityWithGrant();
    const malformed = capRule("bad-rule", "allow", undefined, ["github.*"]);
    // inject an unknown config key => parseConfig fails closed => hard deny.
    (malformed.config as Record<string, unknown>).bogus = true;
    currentPolicySet = [capRule("allow-rule", "allow", undefined, ["github.*"]), malformed];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("FINDING 1: config null => 403 (hard deny, NOT 500) even beside a passing allow", async () => {
    // `rule.config` is opaque jsonb and can be null at runtime. The old
    // parseConfig did `Object.keys(raw)` unguarded => TypeError => HTTP 500.
    // It must now fail closed as a 403, never a 500.
    const nullCfg: PolicyRule = {
      id: "null-cfg",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      config: null as unknown as Record<string, unknown>,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("allow-rule", "allow", undefined, ["github.*"]), nullCfg];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  for (const [label, badConfig] of [
    ["string", "not-an-object"],
    ["number", 42],
    ["array", ["github.*"]],
  ] as const) {
    test(`FINDING 1: config ${label} => 403 (hard deny, NOT 500)`, async () => {
      const badCfg: PolicyRule = {
        id: `bad-${label}`,
        type: "capability-intent" as unknown as PolicyRule["type"],
        enabled: true,
        config: badConfig as unknown as Record<string, unknown>,
      };
      await seedCapabilityWithGrant();
      currentPolicySet = [badCfg];
      const app = buildApp(harness!.db, { agent: true });
      const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
      expect(res.status).toBe(403);
    });
  }

  test("FINDING 2: malformed rule SCOPED ELSEWHERE + valid allow => 503 (authorized, NOT bricked to 403)", async () => {
    // A malformed rule scoped (valid selector) to a DIFFERENT capability must not
    // brick this invoke. The valid github allow authorizes => proxy-env-absent
    // 503, proving the decision was ALLOW (not the malformed-elsewhere hard-deny).
    const malformedElsewhere: PolicyRule = {
      id: "malformed-elsewhere",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      config: { capabilities: ["gitlab.*"], effect: "allow", bogus: true } as unknown as Record<
        string,
        unknown
      >,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [
      capRule("allow-rule", "allow", undefined, ["github.*"]),
      malformedElsewhere,
    ];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: { x: 1 } }),
    );
    expect(res.status).toBe(503);
  });

  test("FINDING 2: malformed rule with UNRECOVERABLE selector + valid allow for another cap => 403 (fail closed on ambiguous scope)", async () => {
    const unrecoverable: PolicyRule = {
      id: "unrecoverable",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      // misspelled `capabilities` => selector unrecoverable => ambiguous scope.
      config: { capabilties: ["gitlab.*"], effect: "deny" } as unknown as Record<string, unknown>,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("allow-rule", "allow", undefined, ["github.*"]), unrecoverable];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  test("REGRESSION malformed rule that does NOT govern (misspelled `capabilities`) is NOT dropped => 403", async () => {
    // This is the fail-OPEN path codex flagged: a malformed rule whose broken
    // config would make a raw governing-match filter return false (here the
    // `capabilities` key is misspelled `capabilties`, so there is no valid
    // capabilities list to match on). The composer must still parse it and
    // hard-deny — it must NOT be silently filtered out before composition, even
    // when a sibling allow matches the invoked capability.
    const malformed: PolicyRule = {
      id: "typo-rule",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      // NOTE: `capabilties` (typo) + no valid `capabilities` array => parseConfig
      // fails closed. A raw `Array.isArray(cfg.capabilities)` governing filter
      // would drop this rule entirely.
      config: { capabilties: ["github.*"], effect: "deny" } as unknown as Record<string, unknown>,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("allow-rule", "allow", undefined, ["github.*"]), malformed];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
  });

  // ROUND-2 P0: a GOVERNING capability-intent rule whose evaluation throws a
  // value whose toString/valueOf/Symbol.toPrimitive all throw used to escape the
  // composer's catch (which did `String(err)`) as a raw exception => HTTP 500 at
  // this invoke boundary. It must now fail closed as a 403, NEVER a 500, even
  // beside a passing allow. The `constraints` getter throws the hostile value
  // during parseConfig, reproducing an evaluator throw on the governing rule.
  test("P0: governing rule throws an UNPRINTABLE value => 403 (hard deny, NOT 500), even beside a passing allow", async () => {
    const hostile = {
      toString() {
        throw new Error("toString throws");
      },
      valueOf() {
        throw new Error("valueOf throws");
      },
      [Symbol.toPrimitive]() {
        throw new Error("toPrimitive throws");
      },
    };
    const hostileConfig: Record<string, unknown> = {
      capabilities: ["github.pr.comment"],
      effect: "allow",
    };
    Object.defineProperty(hostileConfig, "constraints", {
      enumerable: true,
      configurable: true,
      get() {
        throw hostile;
      },
    });
    const hostileRule: PolicyRule = {
      id: "hostile-throw",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      config: hostileConfig as unknown as Record<string, unknown>,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [capRule("allow-rule", "allow", undefined, ["github.*"]), hostileRule];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    // Must NOT be a 500 (the pre-fix escape).
    expect(res.status).not.toBe(500);
  });

  test("P0: governing rule throws a Proxy(Error) with a throwing `.message` getter => 403, NOT 500", async () => {
    const hostile = new Proxy(new Error("real"), {
      get(_t, prop) {
        if (prop === "message") throw new Error("hostile message getter");
        if (prop === "toString" || prop === Symbol.toPrimitive || prop === "valueOf") {
          return () => {
            throw new Error("hostile coercion");
          };
        }
        return undefined;
      },
    });
    const hostileConfig: Record<string, unknown> = {
      capabilities: ["github.pr.comment"],
      effect: "allow",
    };
    Object.defineProperty(hostileConfig, "constraints", {
      enumerable: true,
      configurable: true,
      get() {
        throw hostile;
      },
    });
    const hostileRule: PolicyRule = {
      id: "hostile-proxy",
      type: "capability-intent" as unknown as PolicyRule["type"],
      enabled: true,
      config: hostileConfig as unknown as Record<string, unknown>,
    };
    await seedCapabilityWithGrant();
    currentPolicySet = [hostileRule];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request("/capabilities/github.pr.comment/invoke", invokeReq({}));
    expect(res.status).toBe(403);
    expect(res.status).not.toBe(500);
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

// ─────────────────────────────────────────────────────────────────────────────
// PR4 governed-route plugin gate (spec §5.2, X1, P03/P04). A governed_v2 route/
// operation must NOT be invokable through the capability alias or the OpenAI-
// compat adapter: the plugin's URLSearchParams path (G4) cannot faithfully
// represent a governed action's duplicate-query semantics, and governed actions
// must go through /v2/provider-actions (PR2), never a minted proxy token. When
// the resolved capability maps to a governed route, the plugin denies with
// GOVERNED_ROUTE_PLUGIN_DENIED (403) and never mints a proxy token — even when
// the policy ALLOWS and the proxy env is present.
// ─────────────────────────────────────────────────────────────────────────────
describe("invoke: PR4 governed-route plugin gate (§5.2, X1)", () => {
  // The gate fires AFTER authorization (so we prove it blocks an otherwise-
  // allowed forward) but BEFORE any proxy mint. Set the proxy env so, absent the
  // gate, an allowed rule would have proceeded to a mint/forward (=> not 403).
  function withProxyEnv() {
    process.env.STEWARD_PROXY_URL = "https://proxy.local";
    process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = "x".repeat(48);
  }

  test("P03/P04: allow rule + governed route matching the cap => 403 GOVERNED_ROUTE_PLUGIN_DENIED, no proxy mint", async () => {
    const capId = await seedCapabilityWithGrant();
    // A governed route that matches the seeded cap (api.github.com, POST,
    // /repos/acme/app/issues/1/comments).
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "POST",
    });
    currentPolicySet = [capRule("r1", "allow")];
    withProxyEnv();
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("GOVERNED_ROUTE_PLUGIN_DENIED");
    // Exactly one invocation row, a deny (never an error/forward attempt).
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("deny");
  });

  test("a governed route with a WILDCARD path (/*) still denies the cap (broad match fails closed)", async () => {
    const capId = await seedCapabilityWithGrant();
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/*",
      method: "*",
    });
    currentPolicySet = [capRule("r1", "allow")];
    withProxyEnv();
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GOVERNED_ROUTE_PLUGIN_DENIED");
    expect((await invocationRows(capId)).length).toBe(1);
  });

  test("a wildcard-host governed route (*.github.com) matches api.github.com and denies", async () => {
    await seedCapabilityWithGrant();
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "*.github.com",
      pathPattern: "/*",
      method: "POST",
    });
    currentPolicySet = [capRule("r1", "allow")];
    withProxyEnv();
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toBe("GOVERNED_ROUTE_PLUGIN_DENIED");
  });

  test("a governed route for a DIFFERENT host does NOT block the cap (gate is scoped)", async () => {
    await seedCapabilityWithGrant();
    // Governed route on a different host: must NOT deny this cap.
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.gitlab.com",
      pathPattern: "/*",
      method: "POST",
    });
    currentPolicySet = [capRule("r1", "allow")];
    // NO proxy env => an allowed, non-governed cap falls through to the forward
    // which fails closed on missing proxy config (503), proving the gate did NOT
    // fire (a governed-denied path would be 403).
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(503);
  });

  test("a governed route for a DIFFERENT method does NOT block the cap (gate honors method)", async () => {
    await seedCapabilityWithGrant();
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "GET", // cap is POST
    });
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    // Non-matching governed route => gate does not fire => allowed, forward fails
    // closed on absent proxy env (503).
    expect(res.status).toBe(503);
  });

  test("a LEGACY route matching the cap does NOT trigger the governed gate", async () => {
    await seedCapabilityWithGrant();
    // A legacy route matching the cap host/path — the gate only fires for
    // governed_v2, so this must fall through (503 on absent proxy env).
    await harness!.db.execute(
      // legacy route (default authority_mode); insert directly.
      (await import("drizzle-orm")).sql`INSERT INTO secret_routes
              (tenant_id, agent_id, secret_id, host_pattern, path_pattern, method, inject_as, inject_key)
            VALUES (${tenantId}, ${agentId}, ${secretId}, 'api.github.com',
                    '/repos/acme/app/issues/1/comments', 'POST', 'header', 'authorization')`,
    );
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(503);
  });

  test("a DENY policy still wins over the governed gate (deny is evaluated first)", async () => {
    await seedCapabilityWithGrant();
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/*",
      method: "POST",
    });
    currentPolicySet = [capRule("r1", "deny")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    // Policy deny is resolved before the governed gate; either way it's a 403,
    // but the error is the policy deny, not the governed-plugin code.
    expect(res.status).toBe(403);
  });

  test("a DISABLED governed route does NOT block the cap (codex P2: unselectable route must not gate)", async () => {
    await seedCapabilityWithGrant();
    const routeId = await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "POST",
    });
    // Disable the route: the proxy would never select it, so the plugin gate must
    // ignore it (falls through to the forward => 503 on absent proxy env, NOT a
    // 403 governed denial).
    const { sql } = await import("drizzle-orm");
    await harness!.db.execute(sql`UPDATE secret_routes SET enabled = false WHERE id = ${routeId}`);
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(503);
  });

  test("a governed route backed by a DELETED secret does NOT block the cap (codex P2)", async () => {
    await seedCapabilityWithGrant();
    await ensureGovernedRoute(harness!.db, tenantId, agentId, secretId, {
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "POST",
    });
    // Soft-delete the backing secret: findMatchingRoute's active-secret join would
    // drop this route, so the plugin gate must too (=> 503, not 403).
    const { sql } = await import("drizzle-orm");
    await harness!.db.execute(sql`UPDATE secrets SET deleted_at = now() WHERE id = ${secretId}`);
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildApp(harness!.db, { agent: true });
    const res = await app.request(
      "/capabilities/github.pr.comment/invoke",
      invokeReq({ body: {} }),
    );
    expect(res.status).toBe(503);
  });
});
