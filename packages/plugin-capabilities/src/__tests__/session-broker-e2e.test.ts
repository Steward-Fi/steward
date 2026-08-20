/**
 * session-broker-e2e.test.ts - the session-broker integration arc, in-process:
 *
 *   agent -> invoke route -> policy default-deny -> @stwd/proxy-client ->
 *   REAL @stwd/proxy (auth + route-match + decrypt + inject + scrub) -> stub broker
 *
 * This is the runbook's executable proof (steward#157). It mirrors invoke-e2e.test.ts
 * but models a SESSION BROKER capability (`broker.session.render`) instead of the
 * GitHub example, and asserts the properties the runbook promises:
 *
 *   1. an ALLOWED POST invoke forwards to the broker with the stored broker token
 *      injected as `Authorization: Bearer <token>`, returns the broker's JSON body
 *      passthrough, the token is NEVER visible to the agent caller, and an
 *      invocation row (decision=allow) is recorded.
 *   2. a FAT base64 body (a rendered-screenshot-shaped payload) passes through
 *      intact and under the 25 MiB response cap.
 *   3. deny-by-default: an ungranted capability => 403, never forwards.
 *   4. an explicit `effect: "deny"` policy rule => 403, never forwards.
 *   5. an ALLOWED signed GET reaches a real broker-shaped list endpoint with
 *      query parameters, replay-bound idempotency, bearer injection, no body,
 *      no credential reflection, and a durable allow audit.
 *
 * The SSRF guard is prod defense with NO disable flag, so the broker cannot be a
 * localhost mock. We use the shipped in-process test hooks
 * (`__setResolveProxyHostForTests` + `__setForwardProxyRequestForTests`) plus a
 * public-DNS-shaped hostname (`broker.cap-e2e.test`, which passes the string-level
 * host guard) — exactly the escape hatch the shipped invoke-e2e uses.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, setDefaultTimeout } from "bun:test";
import { fileURLToPath } from "node:url";
import { signAgentToken } from "@stwd/auth";
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

const MASTER_PASSWORD = "broker-e2e-master-password-with-enough-bytes";
const SIGNING_SECRET = "broker-e2e-signing-secret-with-enough-bytes-0123";
// a scoped broker token — the credential the broker expects in Authorization.
const BROKER_TOKEN = "brk_live_e2e_do_not_use_0123456789abcdef";
const PROXY_URL = "https://proxy.broker-e2e.test";
// public-DNS-shaped host: passes the proxy's string-level SSRF guard (has a dot,
// not localhost/.local/.internal, in the allowlist below). The DNS-level guard is
// short-circuited by __setResolveProxyHostForTests to a fixed public IP.
const BROKER_HOST = "broker.cap-e2e.test";
const CAP_NAME = "broker.session.render";
const BROKER_READ_PATH = "/api/otter/items";
const MIGRATIONS_FOLDER = fileURLToPath(new URL("../../drizzle", import.meta.url));
const TEST_KDF_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TEST_ENV_KEYS = [
  "NODE_ENV",
  "STEWARD_KDF_SALT",
  "REDIS_REQUIRED",
  "STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL",
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE",
  "STEWARD_PROXY_REQUEST_SIGNING_SECRET",
  "STEWARD_PROXY_ALLOWED_HOSTS",
  "STEWARD_SECRET_ROUTE_ALLOWED_HOSTS",
  "STEWARD_PROXY_DEV_MODE",
  "STEWARD_PROXY_URL",
] as const;
const originalEnv = new Map<(typeof TEST_ENV_KEYS)[number], string | undefined>();

let authMiddleware: typeof import("@stwd/proxy/src/middleware/auth")["authMiddleware"];
let handleProxy: typeof import("@stwd/proxy/src/handlers/proxy")["handleProxy"];
let setForwardProxyRequestForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setForwardProxyRequestForTests"];
let setResolveProxyHostForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setResolveProxyHostForTests"];
let setCheckProxyRateLimitForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setCheckProxyRateLimitForTests"];
let resetProxyHandlerTestHooksForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__resetProxyHandlerTestHooksForTests"];

interface ForwardedCapture {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}
let lastForwarded: ForwardedCapture | null = null;
let forwardCount = 0;
interface ProxyRequestCapture {
  path: string;
  method: string;
  headers: Headers;
  body: BodyInit | null;
}
let lastProxyRequest: ProxyRequestCapture | null = null;
// the broker's next response body (a test may seed a fat body).
let brokerResponseBody: string = JSON.stringify({ ok: true, rendered: "small" });
let proxyApp: Hono | null = null;
let proxyRateLimitChecks = 0;
let lastProxyRequestHeaders: Headers | null = null;
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
      capabilities: [CAP_NAME],
      effect,
      ...(constraints ? { constraints } : {}),
    },
  };
}

beforeAll(async () => {
  for (const key of TEST_ENV_KEYS) originalEnv.set(key, process.env[key]);
  process.env.NODE_ENV = "test";
  process.env.STEWARD_KDF_SALT = TEST_KDF_SALT;
  process.env.REDIS_REQUIRED = "false";
  process.env.STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL = "false";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "broker-e2e-jwt-secret-with-enough-bytes-0123456789ab";
  // The in-process proxy intentionally uses its explicit dev-only replay/rate
  // stores. Production remains fail-closed on shared Redis.
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
  process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = SIGNING_SECRET;
  // the broker host must be in the proxy allowlist (SSRF layer 1) AND the
  // secret-route host allowlist (so a credential may be injected on it).
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = BROKER_HOST;
  process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = BROKER_HOST;
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  process.env.STEWARD_PROXY_URL = PROXY_URL;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder: MIGRATIONS_FOLDER },
    { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
  );

  ({ authMiddleware } = await import("@stwd/proxy/src/middleware/auth"));
  ({
    handleProxy,
    __setForwardProxyRequestForTests: setForwardProxyRequestForTests,
    __setResolveProxyHostForTests: setResolveProxyHostForTests,
    __setCheckProxyRateLimitForTests: setCheckProxyRateLimitForTests,
    __resetProxyHandlerTestHooksForTests: resetProxyHandlerTestHooksForTests,
  } = await import("@stwd/proxy/src/handlers/proxy"));

  // deterministic public ip so the DNS-level SSRF guard passes with no network.
  setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  setCheckProxyRateLimitForTests(async () => {
    proxyRateLimitChecks += 1;
    return { allowed: true, resetMs: 0 };
  });
  // the stub broker: capture the forwarded request (to assert the injected token +
  // that the agent body reached the broker), return the seeded JSON body. The
  // forwarder signature is (url, method, headers, body: ReadableStream|null,
  // records); we drain the stream to a string to assert body passthrough.
  setForwardProxyRequestForTests(async (url, method, headers, body) => {
    forwardCount += 1;
    let capturedBody: string | null = null;
    if (body != null) {
      capturedBody = await new Response(body as ReadableStream<Uint8Array>).text();
    }
    lastForwarded = { url: url.toString(), method, headers, body: capturedBody };
    return new Response(brokerResponseBody, {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });

  proxyApp = new Hono();
  proxyApp.use("*", authMiddleware);
  proxyApp.all("*", handleProxy);

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith(PROXY_URL) && proxyApp) {
      const path = url.slice(PROXY_URL.length) || "/";
      lastProxyRequestHeaders = new Headers(init?.headers);
      lastProxyRequest = {
        path,
        method: (init?.method ?? "GET").toUpperCase(),
        headers: new Headers(init?.headers),
        body: init?.body ?? null,
      };
      return proxyApp.request(path, init as RequestInit);
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  try {
    resetProxyHandlerTestHooksForTests?.();
  } finally {
    try {
      await closeDb().catch(() => {});
    } finally {
      for (const key of TEST_ENV_KEYS) {
        const original = originalEnv.get(key);
        if (original === undefined) delete process.env[key];
        else process.env[key] = original;
      }
      originalEnv.clear();
    }
  }
});

let tenantId: string;
let agentId: string;

async function seedTenantAgent(): Promise<void> {
  tenantId = `tenant-broker-e2e-${crypto.randomUUID()}`;
  agentId = `agent-broker-e2e-${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"3".repeat(40)}` });
}

/**
 * Seed the broker capability + a grant for the agent. POST render calls use the
 * default `/render`; GET read calls can select a broker-native list path.
 */
async function seedBrokerCapability(
  method: "POST" | "GET" = "POST",
  pathPattern = "/render",
): Promise<string> {
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "session-broker-token", BROKER_TOKEN);
  const store = new CapabilityStore(getDb());
  const cap = await store.createCapability({
    tenantId,
    name: CAP_NAME,
    spec: {
      secretId: secret.id,
      host: BROKER_HOST,
      pathPattern,
      method,
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
    async requireCapabilityAgentJwt() {},
    async operatorAuth() {},
    async tenantAuth() {},
  } as unknown as StewardAppContext;
}

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
  proxyRateLimitChecks = 0;
  lastProxyRequestHeaders = null;
  lastProxyRequest = null;
  forwardCount = 0;
  brokerResponseBody = JSON.stringify({ ok: true, rendered: "small" });
});

describe("session-broker e2e: full arc through the real proxy", () => {
  it("pins hermetic test security settings independently of the ambient environment", () => {
    expect(process.env.NODE_ENV).toBe("test");
    expect(process.env.STEWARD_KDF_SALT).toBe(TEST_KDF_SALT);
    expect(process.env.REDIS_REQUIRED).toBe("false");
    expect(process.env.STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL).toBe("false");
  });

  it("keeps unsigned proxy requests fail-closed in production despite dev mode", async () => {
    const token = await signAgentToken({ agentId, tenantId, scopes: ["api:proxy"] }, "5m");
    process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "false";
    process.env.NODE_ENV = "production";
    try {
      const response = await proxyApp!.request(`/proxy/${BROKER_HOST}/render`, {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({
        ok: false,
        error: "X-Steward-Signature header required",
      });
      expect(lastForwarded).toBeNull();
    } finally {
      process.env.NODE_ENV = "test";
      process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
    }
  });

  it("allowed POST invoke injects the broker token, passes the JSON body through, token never seen by agent, records allow", async () => {
    const capId = await seedBrokerCapability("POST");
    currentPolicySet = [capRule("r1", "allow", { argEquals: { sessionId: "sess_123" } })];
    const app = buildInvokeApp();

    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        args: { sessionId: "sess_123" },
        body: { url: "https://example.com/dashboard", format: "png" },
      }),
    });

    // broker 200 passed through verbatim.
    expect(res.status).toBe(200);
    expect(proxyRateLimitChecks).toBe(1);
    expect(lastProxyRequestHeaders?.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(lastProxyRequestHeaders?.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
    const passthrough = await res.text();
    const parsed = JSON.parse(passthrough) as { ok: boolean; rendered: string };
    expect(parsed.ok).toBe(true);
    // the broker token NEVER appears in the agent-facing passthrough.
    expect(passthrough).not.toContain(BROKER_TOKEN);

    // the proxy forwarded to the real broker URL with the token injected + the
    // agent's request body carried through.
    expect(lastForwarded).not.toBeNull();
    expect(lastForwarded?.method).toBe("POST");
    expect(lastForwarded?.url).toBe(`https://${BROKER_HOST}/render`);
    expect(lastForwarded?.headers.get("authorization")).toBe(`Bearer ${BROKER_TOKEN}`);
    expect(lastForwarded?.body ?? "").toContain("example.com/dashboard");

    // one durable allow audit row.
    const rows = await agentInvocations(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("allow");
  });

  it("fat base64 body passes through intact and under the 25 MiB cap", async () => {
    const capId = await seedBrokerCapability("POST");
    // ~1.5 MiB of base64 (a rendered-screenshot-shaped payload). Well under the
    // 25 MiB cap; asserts the buffered passthrough handles a fat body.
    const fatB64 = Buffer.alloc(1_500_000, 0x41).toString("base64");
    brokerResponseBody = JSON.stringify({ ok: true, format: "png", data: fatB64 });
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildInvokeApp();

    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { url: "https://example.com", format: "png" } }),
    });

    expect(res.status).toBe(200);
    expect(proxyRateLimitChecks).toBe(1);
    const passthrough = await res.text();
    const parsed = JSON.parse(passthrough) as { ok: boolean; data: string };
    // the fat body survived the round trip byte-for-byte.
    expect(parsed.data).toBe(fatB64);
    expect(parsed.data.length).toBeGreaterThan(1_000_000);
    // and still no token leak in a large body (the reflection scan holds).
    expect(passthrough).not.toContain(BROKER_TOKEN);

    const rows = await agentInvocations(capId);
    expect(rows.filter((r) => r.decision === "allow").length).toBe(1);
  });

  it("deny-by-default: ungranted capability => 403, never forwards", async () => {
    // seed a capability + secret but NO grant for this agent.
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "session-broker-token-2", BROKER_TOKEN);
    const store = new CapabilityStore(getDb());
    await store.createCapability({
      tenantId,
      name: CAP_NAME,
      spec: {
        secretId: secret.id,
        host: BROKER_HOST,
        pathPattern: "/render",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      },
      constraints: {},
      enabled: true,
    });
    // even with an allow policy present, the missing grant => deny.
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildInvokeApp();
    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { url: "https://example.com" } }),
    });
    expect(res.status).toBe(403);
    // no credential was ever attached because we never reached the proxy.
    expect(lastForwarded).toBeNull();
  });

  it("explicit deny policy => 403, never forwards", async () => {
    const capId = await seedBrokerCapability("POST");
    // grant is present, but a matched deny rule short-circuits.
    currentPolicySet = [capRule("r1", "deny")];
    const app = buildInvokeApp();
    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { url: "https://example.com" } }),
    });
    expect(res.status).toBe(403);
    expect(lastForwarded).toBeNull();

    const rows = await agentInvocations(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("deny");
  });

  it("signed GET reaches a broker-native read endpoint with query, bearer injection, replay binding, and no body", async () => {
    const capId = await seedBrokerCapability("GET", BROKER_READ_PATH);
    currentPolicySet = [
      capRule("r1", "allow", {
        argEquals: { account: "primary", limit: "10", cursor: "next-page" },
      }),
    ];
    brokerResponseBody = JSON.stringify({ items: [{ id: "otter-note-1" }] });
    const app = buildInvokeApp();

    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        args: { account: "primary" },
        query: { account: "primary", limit: "10", cursor: "next-page" },
      }),
    });

    expect(res.status).toBe(200);
    const passthrough = await res.text();
    expect(JSON.parse(passthrough)).toEqual({ items: [{ id: "otter-note-1" }] });
    expect(passthrough).not.toContain(BROKER_TOKEN);

    expect(lastForwarded).not.toBeNull();
    expect(lastForwarded?.method).toBe("GET");
    expect(lastForwarded?.url).toBe(
      `https://${BROKER_HOST}${BROKER_READ_PATH}?account=primary&limit=10&cursor=next-page`,
    );
    expect(lastForwarded?.headers.get("authorization")).toBe(`Bearer ${BROKER_TOKEN}`);
    expect(lastForwarded?.body).toBeNull();
    expect(forwardCount).toBe(1);

    // Replay the exact signed client request: same signature, timestamp, and
    // generated idempotency key. The real proxy must reject it before the
    // broker forwarder runs a second time.
    expect(lastProxyRequest).not.toBeNull();
    expect(lastProxyRequest?.headers.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);
    expect(lastProxyRequest?.headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    const replay = await proxyApp!.request(lastProxyRequest!.path, {
      method: lastProxyRequest!.method,
      headers: new Headers(lastProxyRequest!.headers),
      body: lastProxyRequest!.body,
    });
    expect(replay.status).toBe(409);
    expect(forwardCount).toBe(1);

    const rows = await agentInvocations(capId);
    expect(rows.length).toBe(1);
    expect(rows[0].decision).toBe("allow");
  });
});
