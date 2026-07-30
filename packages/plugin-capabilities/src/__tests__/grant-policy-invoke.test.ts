/**
 * grant-policy-invoke.test.ts — the per-GRANT policy layer on the invoke path
 * (C1), proven at the enforcement point (the mounted invoke route over a real
 * PGLite with the plugin migrations applied).
 *
 * proves BIDIRECTIONALLY (each rule blocks what it should AND allows what it
 * should) at the HTTP boundary:
 *   - migration/default: a grant created WITHOUT a policy carries the explicit
 *     permissive default and behaves exactly as before (allow-through to the
 *     tenant layer),
 *   - rate: N-per-window blocks the (N+1)th invoke, allows up to N,
 *   - amount: per-invoke cap denies; approval threshold => 202 with a pending
 *     row that RESERVES amountMicros; window cap denies when the rolling sum
 *     would be exceeded,
 *   - venue: method allowlist blocks a non-listed method,
 *   - time: notAfter in the past denies,
 *   - approval.always: 202 even though the tenant layer allows,
 *   - malformed policy on the grant: fail-closed 403 (never ignored),
 *   - strict mode flag: a NULL policy denies iff STEWARD_GRANT_POLICY_STRICT,
 *   - layering: a grant-policy deny wins over a tenant allow; a tenant deny
 *     wins over a grant allow (the grant layer can only narrow),
 *   - audit: every terminal outcome records the verdict rule + reason (+ amount).
 */

import { afterEach, beforeEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { eq } from "@stwd/db";
import type { AppVariables, PolicyRule } from "@stwd/shared";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import { createInvokeRoutes } from "../invoke";
import { capabilityGrants, capabilityInvocations } from "../schema";
import { CapabilityStore } from "../store";
import { ensureAgent, ensureSecret, ensureTenant, type Harness, makeHarness } from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
let tenantId: string;
let agentId: string;
let secretId: string;
let currentPolicySet: PolicyRule[] = [];

/** a tenant-layer capability-intent rule governing github.pr.comment. */
function capRule(
  id: string,
  effect: "allow" | "deny" | "require-approval",
  capabilities: string[] = ["github.pr.comment"],
): PolicyRule {
  return {
    id,
    type: "capability-intent" as unknown as PolicyRule["type"],
    enabled: true,
    config: { capabilities, effect },
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

function buildApp(db: unknown): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent-token" as never);
    await next();
  });
  app.route("/capabilities", createInvokeRoutes(buildCtx(db)));
  return app;
}

/** create an enabled capability + an active grant (optionally with a policy).
 *  returns { capId, grantId }. */
async function seedGrant(
  policy?: Record<string, unknown>,
): Promise<{ capId: string; grantId: string }> {
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
    enabled: true,
  });
  const result = await store.createGrant({
    tenantId,
    capabilityId: cap.id,
    agentId,
    expiresAt: null,
    policy,
  });
  return { capId: cap.id, grantId: result!.grant.id };
}

/** write a raw policy value onto the grant, bypassing route validation (models
 *  a malformed/legacy row: the invoke path must still fail closed). */
async function setRawGrantPolicy(grantId: string, policy: unknown): Promise<void> {
  await harness!.db
    .update(capabilityGrants)
    .set({ policy })
    .where(eq(capabilityGrants.id, grantId));
}

async function invocationRows(capId: string) {
  const rows = await harness!.db
    .select()
    .from(capabilityInvocations)
    .where(eq(capabilityInvocations.agentId, agentId));
  return rows.filter((r: { capabilityId: string | null }) => r.capabilityId === capId);
}

function invoke(app: Hono<{ Variables: AppVariables }>, body?: unknown) {
  return app.request("/capabilities/github.pr.comment/invoke", {
    method: "POST",
    headers: { "content-type": "application/json" },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
}

beforeEach(async () => {
  harness = await makeHarness();
  tenantId = `tenant-gp-${crypto.randomUUID()}`;
  agentId = `agent-gp-${crypto.randomUUID()}`;
  await ensureTenant(harness.db, tenantId);
  await ensureAgent(harness.db, tenantId, agentId);
  secretId = await ensureSecret(harness.db, tenantId, "gh-pat");
  // tenant layer allows by default so the tests isolate the GRANT layer.
  currentPolicySet = [capRule("tenant-allow", "allow")];
  delete process.env.STEWARD_PROXY_URL;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS;
  delete process.env.STEWARD_GRANT_POLICY_STRICT;
});

afterEach(async () => {
  await harness?.close();
  harness = null;
  delete process.env.STEWARD_PROXY_URL;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS;
  delete process.env.STEWARD_GRANT_POLICY_STRICT;
});

// NOTE: proxy env is ABSENT in these tests, so a fully-authorized invoke
// terminates 503 "capability delegation unavailable" — that status is the
// proof BOTH policy layers ALLOWED (the decision reached proxy delegation).
const AUTHORIZED = 503;

describe("grant policy: migration default + compatibility", () => {
  test("a grant created WITHOUT a policy carries the explicit permissive default", async () => {
    const { grantId } = await seedGrant();
    const [row] = await harness!.db
      .select()
      .from(capabilityGrants)
      .where(eq(capabilityGrants.id, grantId));
    expect(row.policy).toEqual({ version: 1, class: "plain-secret" });
  });

  test("the default policy allows through to the tenant layer (pre-policy behavior)", async () => {
    const { capId } = await seedGrant();
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(AUTHORIZED);
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("error"); // 503 delegation-unavailable row
  });
});

describe("grant policy: rate limit", () => {
  test("allows up to N then blocks the (N+1)th, auditing the rule", async () => {
    const { capId } = await seedGrant({
      version: 1,
      class: "plain-secret",
      rate: { maxInvokes: 2, windowSeconds: 3600 },
    });
    const app = buildApp(harness!.db);
    expect((await invoke(app, {})).status).toBe(AUTHORIZED);
    expect((await invoke(app, {})).status).toBe(AUTHORIZED);
    const third = await invoke(app, {});
    expect(third.status).toBe(403);
    const body = (await third.json()) as { error: string };
    expect(body.error).toContain("rate limit exceeded");
    const rows = await invocationRows(capId);
    const denyRow = rows.find((r: { decision: string }) => r.decision === "deny");
    expect(denyRow.verdictRule).toBe("grant-policy:rate.limit");
    expect(denyRow.verdictReason).toContain("rate limit exceeded");
  });
});

describe("grant policy: amount limits", () => {
  const valuePolicy = {
    version: 1,
    class: "value-bearing",
    amount: {
      argField: "amountMicros",
      perInvokeMaxMicros: 10_000_000,
      window: { maxMicros: 15_000_000, windowSeconds: 3600 },
      approvalOverMicros: 5_000_000,
    },
  };

  test("small amount under every bound => authorized, amount audited", async () => {
    const { capId } = await seedGrant(valuePolicy);
    const app = buildApp(harness!.db);
    const res = await invoke(app, { args: { amountMicros: 1_000_000 } });
    expect(res.status).toBe(AUTHORIZED);
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(Number(rows[0].amountMicros)).toBe(1_000_000);
  });

  test("over the per-invoke cap => 403, never softened to approval", async () => {
    const { capId } = await seedGrant(valuePolicy);
    const app = buildApp(harness!.db);
    const res = await invoke(app, { args: { amountMicros: 10_000_001 } });
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
    expect(rows[0].verdictRule).toBe("grant-policy:amount.perInvokeMax");
  });

  test("over the approval threshold (under hard cap) => 202 pending, amount reserved", async () => {
    const { capId } = await seedGrant(valuePolicy);
    const app = buildApp(harness!.db);
    const res = await invoke(app, { args: { amountMicros: 6_000_000 } });
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: boolean;
      data: { approvalId: string; status: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.status).toBe("pending");
    const rows = await invocationRows(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("approval");
    expect(rows[0].verdictRule).toBe("grant-policy:amount.approvalOver");
    expect(Number(rows[0].amountMicros)).toBe(6_000_000);
  });

  test("rolling window cap: pending approval spend counts, breach denies", async () => {
    const { capId } = await seedGrant(valuePolicy);
    const app = buildApp(harness!.db);
    // 6M -> 202 (reserves 6M in the window). 4M -> authorized (sum 10M). a
    // further 6M would make 16M > 15M => deny on the window cap.
    expect((await invoke(app, { args: { amountMicros: 6_000_000 } })).status).toBe(202);
    expect((await invoke(app, { args: { amountMicros: 4_000_000 } })).status).toBe(AUTHORIZED);
    const third = await invoke(app, { args: { amountMicros: 6_000_000 } });
    expect(third.status).toBe(403);
    const rows = await invocationRows(capId);
    const denyRow = rows.find((r: { decision: string }) => r.decision === "deny");
    expect(denyRow.verdictRule).toBe("grant-policy:amount.windowMax");
  });

  test("missing amount arg on a value-bearing grant => 403 (unreadable value)", async () => {
    const { capId } = await seedGrant(valuePolicy);
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].verdictRule).toBe("grant-policy:amount.arg");
  });
});

describe("grant policy: venue + time", () => {
  test("method allowlist blocks the capability's method", async () => {
    const { capId } = await seedGrant({
      version: 1,
      class: "plain-secret",
      venue: { methods: ["GET"] },
    });
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].verdictRule).toBe("grant-policy:venue.method");
  });

  test("matching venue allowlist passes through", async () => {
    await seedGrant({
      version: 1,
      class: "plain-secret",
      venue: { hosts: ["api.github.com"], methods: ["POST"], pathPrefixes: ["/repos/acme"] },
    });
    const app = buildApp(harness!.db);
    expect((await invoke(app, {})).status).toBe(AUTHORIZED);
  });

  test("notAfter in the past denies; in the future allows", async () => {
    const { capId } = await seedGrant({
      version: 1,
      class: "plain-secret",
      time: { notAfter: "2020-01-01T00:00:00Z" },
    });
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].verdictRule).toBe("grant-policy:time.notAfter");

    // future notAfter allows (fresh grant on a new capability name is not
    // needed: replace the policy in place).
    const [grantRow] = await harness!.db
      .select()
      .from(capabilityGrants)
      .where(eq(capabilityGrants.capabilityId, capId));
    await setRawGrantPolicy(grantRow.id, {
      version: 1,
      class: "plain-secret",
      time: { notAfter: "2999-01-01T00:00:00Z" },
    });
    expect((await invoke(app, {})).status).toBe(AUTHORIZED);
  });
});

describe("grant policy: approval.always + layering", () => {
  test("approval.always => 202 even though the tenant layer allows", async () => {
    const { capId } = await seedGrant({
      version: 1,
      class: "plain-secret",
      approval: { always: true },
    });
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(202);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("approval");
    expect(rows[0].verdictRule).toBe("grant-policy:approval.always");
  });

  test("a tenant-layer DENY wins over a grant-layer allow (grant only narrows)", async () => {
    const { capId } = await seedGrant(); // permissive default grant policy
    currentPolicySet = [capRule("tenant-deny", "deny")];
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
    expect(rows[0].verdictRule).toBe("capability-intent:hard_deny");
  });

  test("a tenant-layer DENY wins over a grant-layer approval (deny is never softened)", async () => {
    const { capId } = await seedGrant({
      version: 1,
      class: "plain-secret",
      approval: { always: true },
    });
    currentPolicySet = [capRule("tenant-deny", "deny")];
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
  });

  test("a tenant-layer require-approval still 202s when the grant layer allows", async () => {
    const { capId } = await seedGrant();
    currentPolicySet = [capRule("tenant-approve", "require-approval")];
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(202);
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("approval");
    expect(rows[0].verdictRule).toBe("capability-intent:approval_required");
  });
});

describe("grant policy: malformed + strict mode (fail-closed)", () => {
  test("a malformed policy on the grant => 403, audited, never ignored", async () => {
    const { capId, grantId } = await seedGrant();
    await setRawGrantPolicy(grantId, { version: 1, class: "plain-secret", raet: {} });
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("unknown key");
    const rows = await invocationRows(capId);
    expect(rows[0].decision).toBe("deny");
    expect(rows[0].verdictRule).toBe("grant-policy:malformed");
  });

  test("a value-bearing policy whose amount block was stripped => 403", async () => {
    const { grantId } = await seedGrant();
    await setRawGrantPolicy(grantId, { version: 1, class: "value-bearing" });
    const app = buildApp(harness!.db);
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("requires an `amount` block");
  });

  test("NULL policy: compatibility mode allows (audited), strict mode denies", async () => {
    const { capId, grantId } = await seedGrant();
    await setRawGrantPolicy(grantId, null);

    const app = buildApp(harness!.db);
    // compatibility (flag off): explicit permissive verdict.
    expect((await invoke(app, {})).status).toBe(AUTHORIZED);
    let rows = await invocationRows(capId);
    expect(rows[0].verdictRule).toBe("grant-policy:no-policy.permissive");

    // strict mode: fail closed.
    process.env.STEWARD_GRANT_POLICY_STRICT = "true";
    const res = await invoke(app, {});
    expect(res.status).toBe(403);
    rows = await invocationRows(capId);
    const denyRow = rows.find((r: { decision: string }) => r.decision === "deny");
    expect(denyRow.verdictRule).toBe("grant-policy:no-policy.strict");
  });
});
