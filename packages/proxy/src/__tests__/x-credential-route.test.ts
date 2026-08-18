/**
 * X narrow credential-route integration test (#195 workstream C, proxy plane).
 *
 * Full flow, no real network: an X OAuth access token is stored in the vault, a
 * narrow secret_route is created for a single X API endpoint, and a proxied
 * agent request is verified to carry the token upstream as `Authorization:
 * Bearer <token>` while the agent's own JWT never contained it. Byte-level proof
 * that the governed X `x.tweet.create` request reaches the wire as the exact
 * canonical bytes (method POST, path /2/tweets, JSON body). Mirrors the github
 * credential-route test posture exactly (same seam, same allowlist model).
 *
 * This proves the CURRENT-version credential resolution at execution: the proxy
 * resolves the route -> its secret id -> decrypts the current version. The
 * authority-plane version-DRIFT guard (a refresh between approval and execution
 * bumping credential_version => APPROVAL_CREDENTIAL_STALE) lives in the api
 * package and is proven in provider-x-governed-e2e.test.ts.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-x-route-master";
// A recognizable X OAuth2 access token shape; asserted never to leak back.
const X_ACCESS_TOKEN = "x-oauth2-access-EXAMPLEtokenVALUEdeadbeef1234567890";

let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];
let proxyMod: typeof import("../handlers/proxy");

// Captures the outbound request the proxy would have sent upstream.
let captured: {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
} | null = null;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-x-route-jwt-secret-with-enough-bytes-here-ok";
  // Soft development posture (unsigned requests, in-process replay store) —
  // explicit opt-in since SEC-175.
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  // api.x.com ships in the default allowlists (secret-route + proxy alias) as of
  // workstream C, so no STEWARD_*_ALLOWED_HOSTS env is needed for the happy path.

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("../middleware/auth"));
  proxyMod = await import("../handlers/proxy");
  ({ handleProxy } = proxyMod);

  // Pin DNS to a public address so the SSRF guard passes without a real lookup.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "104.244.42.65", family: 4 }]);
  // Stub the final forward so nothing hits the network; capture what would ship.
  proxyMod.__setForwardProxyRequestForTests(async (url, method, headers, body) => {
    const headerObj: Record<string, string> = {};
    headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });
    // body is the outbound ReadableStream<Uint8Array> | null; drain it so the
    // test can byte-match the canonical request bytes that reach the wire.
    let bodyText: string | null = null;
    if (body) {
      const chunks: Uint8Array[] = [];
      const reader = body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      bodyText = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
    }
    captured = { url: url.toString(), method, headers: headerObj, body: bodyText };
    return new Response(JSON.stringify({ data: { id: "1799999999", text: "ok" } }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_DEV_MODE;
});

function buildApp() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.all("*", handleProxy);
  return app;
}

async function ensureTenant(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

async function ensureAgent(tenantId: string, agentId: string) {
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"1".repeat(40)}` })
    .onConflictDoNothing();
}

describe("x narrow credential route (integration)", () => {
  it("injects the X access token upstream on POST /2/tweets; agent request never carries it", async () => {
    captured = null;
    const tenantId = `tenant-x-${crypto.randomUUID()}`;
    const agentId = `agent-x-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "x-oauth", X_ACCESS_TOKEN);
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");

    // The exact canonical body the X adapter would emit for x.tweet.create.
    const canonicalBody = JSON.stringify({ text: "gm from a governed agent" });
    const res = await buildApp().request("/x/2/tweets", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body: canonicalBody,
    });

    expect(res.status).toBe(201);
    expect(captured).not.toBeNull();
    // The proxy resolved the /x alias to api.x.com.
    expect(captured?.url).toBe("https://api.x.com/2/tweets");
    expect(captured?.method).toBe("POST");
    // Exact canonical bytes reach the wire, unmodified.
    expect(captured?.body).toBe(canonicalBody);
    // The X token was injected upstream as a Bearer credential.
    expect(captured?.headers.authorization).toBe(`Bearer ${X_ACCESS_TOKEN}`);
    // The agent's own JWT is replaced — the token is never something the agent
    // supplied, and the agent's JWT never leaks upstream.
    expect(captured?.headers.authorization).not.toContain(token);
    // The raw token is never returned to the agent in the response body.
    const text = await res.text();
    expect(text).not.toContain(X_ACCESS_TOKEN);
  });

  it("unwraps an OAuth-connect envelope without forwarding its refresh token", async () => {
    captured = null;
    const tenantId = `tenant-x-envelope-${crypto.randomUUID()}`;
    const agentId = `agent-x-envelope-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const refreshCanary = "x-refresh-token-MUST-NOT-CROSS-PROXY";
    const envelope = JSON.stringify({
      schemaVersion: "steward.provider-x.credential.v1",
      accessToken: X_ACCESS_TOKEN,
      refreshToken: refreshCanary,
      scopesGranted: ["tweet.read", "tweet.write", "offline.access"],
      xUserId: "12345",
      xUsername: "steward",
      obtainedAt: new Date().toISOString(),
      expiresAt: null,
    });
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "x-oauth-envelope", envelope);
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const res = await buildApp().request("/x/2/tweets", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body: JSON.stringify({ text: "safe envelope extraction" }),
    });

    expect(res.status).toBe(201);
    expect(captured?.headers.authorization).toBe(`Bearer ${X_ACCESS_TOKEN}`);
    expect(JSON.stringify(captured)).not.toContain(refreshCanary);
    expect(await res.text()).not.toContain(refreshCanary);
  });

  it("MUTATION: a route/endpoint mismatch fails closed; the Bearer is NEVER injected or leaked", async () => {
    // A route for /2/users/me must NOT inject on a POST /2/tweets request: the
    // credential is pinned to one exact endpoint+verb. With only that route
    // configured, the non-matching /2/tweets call has no credential route and the
    // proxy fails CLOSED (403) rather than forwarding an un-credentialed call.
    // Either way the X token must never be injected or leak into the outbound
    // request or the response.
    captured = null;
    const tenantId = `tenant-x-mm-${crypto.randomUUID()}`;
    const agentId = `agent-x-mm-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "x-oauth-2", X_ACCESS_TOKEN);
    // Route bound to the READ endpoint only.
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.x.com",
      pathPattern: "/2/users/me",
      method: "GET",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const res = await buildApp().request("/x/2/tweets", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body: JSON.stringify({ text: "should not carry the X token" }),
    });

    // Fail-closed: no credential route matches this exact endpoint+verb, so the
    // proxy denies rather than forwarding an un-credentialed call.
    expect(res.status).toBe(403);
    // The X token was never injected into any outbound request...
    if (captured) {
      expect(captured.headers.authorization).not.toBe(`Bearer ${X_ACCESS_TOKEN}`);
      expect(captured.headers.authorization ?? "").not.toContain(X_ACCESS_TOKEN);
      expect(captured.body ?? "").not.toContain(X_ACCESS_TOKEN);
    }
    // ...and never leaks into the response body.
    const text = await res.text();
    expect(text).not.toContain(X_ACCESS_TOKEN);
  });

  it("rejects a single-segment X route (POST /) at create time", async () => {
    const tenantId = `tenant-x-bad-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "x-oauth-3", X_ACCESS_TOKEN);

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.x.com",
        pathPattern: "/",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      }),
    ).rejects.toThrow(/at least 2 segments/);
  });

  it("rejects a wildcard X path (/2/*) at create time", async () => {
    const tenantId = `tenant-x-wild-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "x-oauth-wild", X_ACCESS_TOKEN);

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.x.com",
        pathPattern: "/2/*",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      }),
    ).rejects.toThrow(/exact path \(no "\*" wildcards\)/);
  });
});
