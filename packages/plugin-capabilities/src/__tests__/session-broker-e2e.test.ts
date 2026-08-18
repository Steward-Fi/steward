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
 *   5. the GET-signed limitation: a GET capability does NOT forward a request
 *      body (the invoke path omits it for GET/HEAD), which is why the runbook
 *      says "use POST for body-carrying broker calls".
 *
 * The SSRF guard is prod defense with NO disable flag, so the broker cannot be a
 * localhost mock. We use the shipped in-process test hooks
 * (`__setResolveProxyHostForTests` + `__setForwardProxyRequestForTests`) plus a
 * public-DNS-shaped hostname (`broker.cap-e2e.test`, which passes the string-level
 * host guard) — exactly the escape hatch the shipped invoke-e2e uses.
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
const MIGRATIONS_FOLDER = fileURLToPath(new URL("../../drizzle", import.meta.url));

let authMiddleware: typeof import("@stwd/proxy/src/middleware/auth")["authMiddleware"];
let handleProxy: typeof import("@stwd/proxy/src/handlers/proxy")["handleProxy"];
let setForwardProxyRequestForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setForwardProxyRequestForTests"];
let setResolveProxyHostForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setResolveProxyHostForTests"];
let setCheckProxyRateLimitForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setCheckProxyRateLimitForTests"];

interface ForwardedCapture {
  url: string;
  method: string;
  headers: Headers;
  body: string | null;
}
let lastForwarded: ForwardedCapture | null = null;
// the broker's next response body (a test may seed a fat body).
let brokerResponseBody: string = JSON.stringify({ ok: true, rendered: "small" });
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
      capabilities: [CAP_NAME],
      effect,
      ...(constraints ? { constraints } : {}),
    },
  };
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "broker-e2e-jwt-secret-with-enough-bytes-0123456789ab";
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
  } = await import("@stwd/proxy/src/handlers/proxy"));

  // deterministic public ip so the DNS-level SSRF guard passes with no network.
  setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  // This suite verifies capability policy and broker credential handling. Keep
  // the proxy gateway's independent host limiter deterministic so requests in
  // earlier cases cannot consume a later case's allowance.
  setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
  // the stub broker: capture the forwarded request (to assert the injected token +
  // that the agent body reached the broker), return the seeded JSON body. The
  // forwarder signature is (url, method, headers, body: ReadableStream|null,
  // records); we drain the stream to a string to assert body passthrough.
  setForwardProxyRequestForTests(async (url, method, headers, body) => {
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
  delete process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS;
  delete process.env.STEWARD_PROXY_DEV_MODE;
  delete process.env.STEWARD_PROXY_URL;
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
 * Seed the broker capability + a grant for the agent. `method` defaults to POST
 * (the runbook's recommended verb); the GET-limitation test overrides it.
 */
async function seedBrokerCapability(method: "POST" | "GET" = "POST"): Promise<string> {
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "session-broker-token", BROKER_TOKEN);
  const store = new CapabilityStore(getDb());
  const cap = await store.createCapability({
    tenantId,
    name: CAP_NAME,
    spec: {
      secretId: secret.id,
      host: BROKER_HOST,
      pathPattern: "/render",
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
  brokerResponseBody = JSON.stringify({ ok: true, rendered: "small" });
});

describe("session-broker e2e: full arc through the real proxy", () => {
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

  it("documents the GET-signed limitation: a signed GET capability invoke is BLOCKED (400) under production request-signing", async () => {
    // The runbook's honest caveat, proven. TWO things conspire against a GET
    // capability when the proxy runs with request signing enabled (production,
    // STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE=true, set in beforeAll):
    //
    //   1. the invoke path computes
    //        hasBody = method !== "GET" && method !== "HEAD" && body !== undefined,
    //      so a GET capability NEVER forwards a request body -- a broker needing a
    //      render payload in the body could not receive it via GET anyway.
    //   2. MORE IMPORTANTLY: the proxy requires an `Idempotency-Key` header for
    //      ANY *signed* request -- including safe/GET methods (proxy.ts
    //      claimUnsafeProxyRequest: `signedRequest` forces the key even for
    //      SAFE_PROXY_METHODS). But StewardProxyClient does NOT auto-attach an
    //      idempotency key on GET, and the invoke path supplies none. So a signed
    //      GET capability invoke fails CLOSED with a 400 before it ever forwards.
    //
    // Net: under production request-signing, a GET capability is not usable for a
    // credential-injected broker call. USE POST (which carries the body AND gets
    // an auto-attached idempotency key). This test pins that behavior so a future
    // change that silently "fixes" GET must update the runbook.
    await seedBrokerCapability("GET");
    currentPolicySet = [capRule("r1", "allow")];
    const app = buildInvokeApp();

    const res = await app.request(`/capabilities/${CAP_NAME}/invoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ body: { url: "https://example.com/dashboard", format: "png" } }),
    });

    // policy authorized the invoke, but the proxy rejected the signed GET for the
    // missing idempotency key. The invoke path forwards the upstream/proxy status
    // verbatim. The request NEVER reached the broker.
    expect(res.status).toBe(400);
    const bodyText = await res.text();
    expect(bodyText).toContain("Idempotency-Key");
    // the broker was never called: no credential was ever attached/forwarded.
    expect(lastForwarded).toBeNull();
  });
});
