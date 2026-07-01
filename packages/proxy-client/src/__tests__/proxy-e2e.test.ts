/**
 * End-to-end proof: real @stwd/proxy-client -> proxy auth -> route match ->
 * decrypt -> inject -> scrub, on the EXISTING OpenAI alias (zero new hosts).
 *
 * We DO NOT hit real OpenAI. The proxy's outbound forwarder is replaced via the
 * built-in `__setForwardProxyRequestForTests` hook, so we can:
 *   - assert the proxy injected the seeded (fake) OpenAI key as the
 *     Authorization header on the OUTBOUND request,
 *   - assert the AGENT-side request never carried the secret,
 *   - assert a clean upstream response passes through and never contains it,
 *   - assert that if the upstream DID reflect the secret, the proxy's scrubbing
 *     blocks it (502) so the credential never reaches the agent.
 *
 * The client is the REAL StewardProxyClient. Its outbound fetch is routed into
 * the in-process Hono app so every real header (Bearer, X-Steward-Signature,
 * X-Steward-Request-Timestamp, Idempotency-Key) is computed by the shipping
 * client code, then verified by the shipping proxy middleware.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { PROXY_SCOPE } from "@stwd/proxy/src/config";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { StewardProxyClient } from "../index";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-client-e2e-master-password";
const SIGNING_SECRET = "proxy-client-e2e-signing-secret-with-enough-bytes";
const FAKE_OPENAI_KEY = "sk-test-e2e-do-not-use-0123456789abcdef";

let authMiddleware: typeof import("@stwd/proxy/src/middleware/auth")["authMiddleware"];
let handleProxy: typeof import("@stwd/proxy/src/handlers/proxy")["handleProxy"];
let setForwardProxyRequestForTests: typeof import("@stwd/proxy/src/handlers/proxy")["__setForwardProxyRequestForTests"];

// Capture what the proxy tried to forward upstream.
interface ForwardedCapture {
  url: string;
  method: string;
  headers: Headers;
}
let lastForwarded: ForwardedCapture | null = null;
// Controls whether the stubbed upstream reflects the secret back (leak sim).
let reflectSecretInResponse = false;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-client-e2e-jwt-secret-with-enough-bytes";
  // Force the production-grade request-signature requirement so the e2e also
  // exercises the client's HMAC signer against the proxy verifier.
  process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
  process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = SIGNING_SECRET;
  // api.openai.com is already in the direct-proxy + secret-route default
  // allowlists, but set it explicitly for hermeticity.
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.openai.com";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("@stwd/proxy/src/middleware/auth"));
  ({ handleProxy, __setForwardProxyRequestForTests: setForwardProxyRequestForTests } = await import(
    "@stwd/proxy/src/handlers/proxy"
  ));

  // Replace the real outbound forwarder. Assert-friendly stub: capture the
  // outbound (already credential-injected) request and synthesize a response.
  setForwardProxyRequestForTests(async (url, method, headers) => {
    lastForwarded = { url: url.toString(), method, headers };
    const payload = reflectSecretInResponse
      ? { echoedAuthorization: headers.get("authorization") }
      : { id: "chatcmpl-test", object: "chat.completion", choices: [] };
    return new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  });
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
  delete process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
});

function buildProxyApp() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.all("*", handleProxy);
  return app;
}

/**
 * Route the real client's outbound fetch into the in-process Hono app. This
 * keeps the entire shipping client codepath (header + signature computation)
 * while dispatching to the shipping proxy code instead of the network.
 */
function makeAppFetch(app: ReturnType<typeof buildProxyApp>): {
  fetch: typeof fetch;
  agentRequests: Array<{ url: string; method: string; headers: Headers; body: string | null }>;
} {
  const agentRequests: Array<{
    url: string;
    method: string;
    headers: Headers;
    body: string | null;
  }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const path = new URL(url).pathname + new URL(url).search;
    const bodyStr = typeof init?.body === "string" ? init.body : null;
    agentRequests.push({
      url,
      method: (init?.method ?? "GET").toUpperCase(),
      headers: new Headers(init?.headers),
      body: bodyStr,
    });
    return app.request(path, init as RequestInit);
  }) as typeof fetch;
  return { fetch: fetchImpl, agentRequests };
}

async function seedTenantAgentSecretRoute() {
  const tenantId = `tenant-e2e-${crypto.randomUUID()}`;
  const agentId = `agent-e2e-${crypto.randomUUID()}`;

  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"1".repeat(40)}` });

  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "openai", FAKE_OPENAI_KEY);
  // Specific host + path + method: avoids broad-route gating, api.openai.com is
  // in the default secret-route allowlist.
  await vault.createRoute(tenantId, secret.id, {
    agentId,
    hostPattern: "api.openai.com",
    pathPattern: "/v1/chat/*",
    method: "POST",
    injectAs: "header",
    injectKey: "authorization",
    injectFormat: "Bearer {value}",
  });

  return { tenantId, agentId };
}

describe("proxy-client e2e: injection + scrub on the openai alias", () => {
  it("injects the seeded secret upstream, never exposes it to the agent, passes clean responses", async () => {
    lastForwarded = null;
    reflectSecretInResponse = false;
    const { tenantId, agentId } = await seedTenantAgentSecretRoute();

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");

    const app = buildProxyApp();
    const { fetch, agentRequests } = makeAppFetch(app);

    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.e2e.test",
      token,
      signingSecret: SIGNING_SECRET,
      tenantId,
      agentId,
      requireHttps: true,
      fetch,
    });

    const requestBody = JSON.stringify({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hello from the e2e test" }],
    });

    const res = await client.fetch("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestBody,
    });

    // 1. The proxy accepted the signed, idempotency-keyed request and forwarded.
    expect(res.status).toBe(200);
    expect(lastForwarded).not.toBeNull();

    // 2. The proxy injected the decrypted secret as the Authorization header on
    //    the OUTBOUND (upstream) request.
    expect(lastForwarded?.url).toBe("https://api.openai.com/v1/chat/completions");
    expect(lastForwarded?.headers.get("authorization")).toBe(`Bearer ${FAKE_OPENAI_KEY}`);

    // 3. The AGENT-side request never carried the secret in any header or body.
    expect(agentRequests.length).toBe(1);
    const agentReq = agentRequests[0];
    expect(agentReq.headers.get("authorization")).toBe(`Bearer ${token}`);
    expect(agentReq.headers.get("authorization")).not.toContain(FAKE_OPENAI_KEY);
    for (const [, value] of agentReq.headers.entries()) {
      expect(value).not.toContain(FAKE_OPENAI_KEY);
    }
    expect(agentReq.body ?? "").not.toContain(FAKE_OPENAI_KEY);

    // 3b. The real client attached the proof-of-possession signature +
    //     idempotency key that the proxy required.
    expect(agentReq.headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(agentReq.headers.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
    expect(agentReq.headers.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);

    // 4. The response returned to the agent never contains the secret.
    const responseText = await res.text();
    expect(responseText).not.toContain(FAKE_OPENAI_KEY);
  });

  it("blocks the response (502) if the upstream reflects the injected secret", async () => {
    lastForwarded = null;
    reflectSecretInResponse = true;
    const { tenantId, agentId } = await seedTenantAgentSecretRoute();

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");

    const app = buildProxyApp();
    const { fetch } = makeAppFetch(app);

    const client = new StewardProxyClient({
      proxyUrl: "https://proxy.e2e.test",
      token,
      signingSecret: SIGNING_SECRET,
      tenantId,
      agentId,
      requireHttps: true,
      fetch,
    });

    const res = await client.fetch("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: [] }),
    });

    // Proxy detected the reflected credential and refused to pass it through.
    expect(res.status).toBe(502);
    const body = await res.text();
    expect(body).not.toContain(FAKE_OPENAI_KEY);
    expect(body).toContain("reflected injected credential");
  });

  it("rejects an unsigned request when signing is required (proves the guard is live)", async () => {
    const { tenantId, agentId } = await seedTenantAgentSecretRoute();
    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");
    const app = buildProxyApp();

    // Bypass the client and hit the app directly WITHOUT a signature.
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: [] }),
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("X-Steward-Signature");
  });
});
