/**
 * invoke-e2e.test.ts - the FULL arc, end to end, in-process:
 *
 *   agent -> invoke route -> policy default-deny -> @stwd/proxy-client ->
 *   REAL @stwd/proxy (auth + route-match + decrypt + inject + scrub) -> stub upstream
 *
 * we DO NOT hit real GitHub. the proxy's outbound forwarder is replaced via the
 * shipped `__setForwardProxyRequestForTests` hook (same pattern as the #149
 * proxy-client e2e), so we assert:
 *   1. an ALLOWED invoke forwards to the proxy with the seeded PAT injected as the
 *      upstream Authorization header, and the PAT is NEVER visible to the agent
 *      caller (the agent only ever sent the invoke body; the plugin minted the
 *      api:proxy token server-side; the credential lives only on the OUTBOUND
 *      proxy->upstream request). an invocation row (decision=allow) is recorded.
 *   2. a wrong argEquals value => 403 (never forwards).
 *   3. an ungranted capability => 403.
 *   4. a require-approval capability => 202 + queued (invocation decision=approval).
 *   5. maxCallsPerHour=1 => the second invoke is denied.
 *
 * the invoke route builds its own StewardProxyClient using globalThis.fetch; we
 * override globalThis.fetch for the test to dispatch the proxy URL into the
 * in-process proxy Hono app (so the ENTIRE shipping client + proxy codepath runs,
 * only the network is stubbed).
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import { fileURLToPath } from "node:url";
import { agents, closeDb, eq, getDb, runPluginMigrations, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { AppVariables, PolicyRule } from "@stwd/shared";
import { SecretVault } from "@stwd/vault";
import { migrate as pgliteMigrate } from "drizzle-orm/pglite/migrator";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import { createInvokeRoutes } from "../invoke";
import { capabilityInvocations } from "../schema";
import { CapabilityStore } from "../store";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "cap-invoke-e2e-master-password";
const SIGNING_SECRET = "cap-invoke-e2e-signing-secret-with-enough-bytes";
const FAKE_PAT = "ghp_test_e2e_do_not_use_0123456789abcdef";
const PROXY_URL = "https://proxy.cap-e2e.test";
const MIGRATIONS_FOLDER = fileURLToPath(new URL("../../drizzle", import.meta.url));

let authMiddleware: typeof import("@stwd/proxy/src/middleware/auth")["authMiddleware"];
let handleProxy: typeof import("@stwd/proxy/src/handlers/proxy")["handleProxy"];
let setForwardProxyRequestForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setForwardProxyRequestForTests"];
let setResolveProxyHostForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setResolveProxyHostForTests"];

interface ForwardedCapture {
  url: string;
  method: string;
  headers: Headers;
}
let lastForwarded: ForwardedCapture | null = null;
let proxyApp: Hono | null = null;
const realFetch = globalThis.fetch;

// the policy set the injected getPolicySet returns for the current test.
let currentPolicySet: PolicyRule[] = [];

function capRule(
  id: string,
  effect: "allow" | "deny" | "require-approval",
  constraints?: Record<string, unknown>,
): PolicyRule {
  return {
    id,
    type: "capability-intent" as unknown as PolicyRule["type"],
    enabled: true,
    config: {
      capabilities: ["github.pr.comment"],
      effect,
      ...(constraints ? { constraints } : {}),
    },
  };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "cap-invoke-e2e-jwt-secret-with-enough-bytes-0123456789";
  process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
  process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = SIGNING_SECRET;
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.github.com";
  // the invoke route reads these to build its proxy client (fail-closed if absent).
  process.env.STEWARD_PROXY_URL = PROXY_URL;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  // apply the plugin's own migrations (capabilities + grants + invocations).
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder: MIGRATIONS_FOLDER },
    { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
  );

  ({ authMiddleware } = await import("@stwd/proxy/src/middleware/auth"));
  ({
    handleProxy,
    __setForwardProxyRequestForTests: setForwardProxyRequestForTests,
    __setResolveProxyHostForTests: setResolveProxyHostForTests,
  } = await import("@stwd/proxy/src/handlers/proxy"));

  // deterministic public ip so route-match -> decrypt -> inject -> forward runs
  // with no external network (mirrors the #149 e2e).
  setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  setForwardProxyRequestForTests(async (url, method, headers) => {
    lastForwarded = { url: url.toString(), method, headers };
    return new Response(JSON.stringify({ id: 12345, body: "ok" }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });

  // real proxy app, in-process.
  proxyApp = new Hono();
  proxyApp.use("*", authMiddleware);
  proxyApp.all("*", handleProxy);

  // override globalThis.fetch: route the proxy URL into the in-process proxy app;
  // everything else uses the real fetch.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith(PROXY_URL) && proxyApp) {
      const path = url.slice(PROXY_URL.length) || "/";
      return proxyApp.request(path, init as RequestInit);
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
  delete process.env.STEWARD_PROXY_URL;
});

let tenantId: string;
let agentId: string;

async function seedTenantAgent(): Promise<void> {
  tenantId = `tenant-cap-e2e-${crypto.randomUUID()}`;
  agentId = `agent-cap-e2e-${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"2".repeat(40)}` });
}

/** create the secret (real, encrypts the PAT), the capability, and the grant. */
async function seedCapability(): Promise<string> {
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "gh-pat", FAKE_PAT);
  const store = new CapabilityStore(getDb());
  const cap = await store.createCapability({
    tenantId,
    name: "github.pr.comment",
    spec: {
      secretId: secret.id,
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
  await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });
  return cap.id;
}

function buildCtx(): StewardAppContext {
  return {
    db: getDb(),
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

/** the invoke app (test mw stamps the agent-token context). */
function buildInvokeApp(): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent-token" as never);
    await next();
  });
  app.route("/capabilities", createInvokeRoutes(buildCtx()));
  return app;
}

async function agentInvocations(capabilityId: string) {
  const rows = await getDb()
    .select()
    .from(capabilityInvocations)
    .where(eq(capabilityInvocations.agentId, agentId));
  return rows.filter((r: { capabilityId: string | null }) => r.capabilityId === capabilityId);
}

beforeEach(async () => {
  await seedTenantAgent();
  currentPolicySet = [];
  lastForwarded = null;
});

describe("invoke e2e: full arc through the real proxy", () => {
  it("allowed invoke forwards with the PAT injected, never visible to the agent, records allow", async () => {
    const capId = await seedCapability();
    currentPolicySet = [capRule("r1", "allow", { argEquals: { repo: "acme/app" } })];
    const app = buildInvokeApp();

    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ args: { repo: "acme/app" }, body: { body: "LGTM" } }),
    });

    // upstream 201 passed through.
    expect(res.status).toBe(201);
    const passthrough = await res.text();
    // the passthrough body never contains the PAT.
    expect(passthrough).not.toContain(FAKE_PAT);

    // the proxy forwarded to the real upstream URL with the PAT injected.
    expect(lastForwarded).not.toBeNull();
    expect(lastForwarded?.url).toBe("https://api.github.com/repos/acme/app/issues/1/comments");
    expect(lastForwarded?.headers.get("authorization")).toBe(`Bearer ${FAKE_PAT}`);

    // the agent-facing request/response never carried the PAT.
    const rows = await agentInvocations(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("allow");
  });

  it("wrong argEquals => 403, never forwards", async () => {
    await seedCapability();
    currentPolicySet = [capRule("r1", "allow", { argEquals: { repo: "acme/app" } })];
    const app = buildInvokeApp();
    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ args: { repo: "evil/app" }, body: { body: "x" } }),
    });
    expect(res.status).toBe(403);
    expect(lastForwarded).toBeNull();
  });

  it("ungranted capability => 403", async () => {
    // seed a capability but NO grant for this agent.
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "gh-pat2", FAKE_PAT);
    const store = new CapabilityStore(getDb());
    await store.createCapability({
      tenantId,
      name: "github.pr.comment",
      spec: {
        secretId: secret.id,
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
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildInvokeApp();
    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(403);
    expect(lastForwarded).toBeNull();
  });

  it("require-approval capability => 202 + queued", async () => {
    const capId = await seedCapability();
    currentPolicySet = [capRule("r1", "require-approval")];
    const app = buildInvokeApp();
    const res = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: boolean;
      data: { approvalId: string; status: string };
    };
    expect(body.data.status).toBe("pending");
    const rows = await agentInvocations(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("approval");
    expect(lastForwarded).toBeNull();
  });

  it("maxCallsPerHour=1 => second invoke denied", async () => {
    const capId = await seedCapability();
    currentPolicySet = [capRule("r1", "allow", { maxCallsPerHour: 1 })];
    const app = buildInvokeApp();

    const first = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { body: "one" } }),
    });
    // first invoke: count 0 < 1 => forwards (upstream 201).
    expect(first.status).toBe(201);

    const second = await app.request("/capabilities/github.pr.comment/invoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { body: "two" } }),
    });
    // second invoke: count 1 >= 1 => rate constraint denies the allow => 403.
    expect(second.status).toBe(403);

    const rows = await agentInvocations(capId);
    expect(rows.filter((r) => r.decision === "allow").length).toBe(1);
    expect(rows.filter((r) => r.decision === "deny").length).toBe(1);
  });
});
