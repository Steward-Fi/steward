/**
 * GitHub narrow credential-route integration test.
 *
 * Full flow, no real network: a fine-grained PAT is stored in the vault, a
 * narrow route is created for a single GitHub REST endpoint, and a proxied
 * agent request is verified to carry the PAT upstream while the agent's own
 * request never contained it. Also asserts the create-time narrowness guards
 * (single-segment path, missing explicit method) and the host allowlist.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { SecretVault } from "@stwd/vault";
import { Hono } from "hono";
import { PROXY_SCOPE } from "../config";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "proxy-github-route-master";
const FINE_GRAINED_PAT = "github_pat_11ABCDEFG_examplefinegrainedtokenvalue";

let authMiddleware: typeof import("../middleware/auth")["authMiddleware"];
let handleProxy: typeof import("../handlers/proxy")["handleProxy"];
let proxyMod: typeof import("../handlers/proxy");

// Captures the outbound request the proxy would have sent upstream.
let captured: { url: string; method: string; headers: Record<string, string> } | null = null;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "proxy-github-route-jwt-secret-with-enough-bytes-here";
  // api.github.com ships in the default allowlists (secret-route + proxy alias),
  // so no STEWARD_*_ALLOWED_HOSTS env is needed for the happy path.

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ authMiddleware } = await import("../middleware/auth"));
  proxyMod = await import("../handlers/proxy");
  ({ handleProxy } = proxyMod);

  // Pin DNS to a public address so the SSRF guard passes without a real lookup.
  proxyMod.__setResolveProxyHostForTests(async () => [{ address: "140.82.112.6", family: 4 }]);
  // Stub the final forward so nothing hits the network; capture what would ship.
  proxyMod.__setForwardProxyRequestForTests(async (url, method, headers) => {
    const headerObj: Record<string, string> = {};
    headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });
    captured = { url: url.toString(), method, headers: headerObj };
    return new Response(JSON.stringify({ ok: true }), {
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

describe("github narrow credential route (integration)", () => {
  it("injects the fine-grained PAT upstream; the agent request never carries it", async () => {
    captured = null;
    const tenantId = `tenant-gh-${crypto.randomUUID()}`;
    const agentId = `agent-gh-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);

    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "github-pat", FINE_GRAINED_PAT);
    await vault.createRoute(tenantId, secret.id, {
      agentId,
      hostPattern: "api.github.com",
      pathPattern: "/repos/acme/widgets/issues/1/comments",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    });

    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", PROXY_SCOPE] }, "1h");

    const agentBody = JSON.stringify({ body: "hello from agent" });
    const res = await buildApp().request("/github/repos/acme/widgets/issues/1/comments", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body: agentBody,
    });

    expect(res.status).toBe(200);
    expect(captured).not.toBeNull();
    // The proxy resolved the /github alias to api.github.com.
    expect(captured?.url).toBe("https://api.github.com/repos/acme/widgets/issues/1/comments");
    expect(captured?.method).toBe("POST");
    // The PAT was injected upstream as a Bearer credential.
    expect(captured?.headers.authorization).toBe(`Bearer ${FINE_GRAINED_PAT}`);
    // Crucially, the agent's own bearer token (its JWT) is replaced — the PAT is
    // never something the agent supplied, and the agent's JWT never leaks upstream.
    expect(captured?.headers.authorization).not.toContain(token);
    // The raw PAT is never returned to the agent in the response body.
    const text = await res.text();
    expect(text).not.toContain(FINE_GRAINED_PAT);
  });

  it("rejects a single-segment github route (GET /) at create time", async () => {
    const tenantId = `tenant-gh-bad-path-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "github-pat-2", FINE_GRAINED_PAT);

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.github.com",
        pathPattern: "/",
        method: "GET",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      }),
    ).rejects.toThrow(/at least 2 segments/);
  });

  it("rejects a github route without an explicit method at create time", async () => {
    process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES = "true";
    const tenantId = `tenant-gh-no-method-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "github-pat-3", FINE_GRAINED_PAT);

    try {
      await expect(
        vault.createRoute(tenantId, secret.id, {
          agentId,
          hostPattern: "api.github.com",
          pathPattern: "/repos/acme/widgets",
          method: "*",
          injectAs: "header",
          injectKey: "authorization",
          injectFormat: "Bearer {value}",
        }),
      ).rejects.toThrow(/must specify an explicit HTTP method/);
    } finally {
      delete process.env.STEWARD_ALLOW_BROAD_SECRET_ROUTES;
    }
  });

  it("rejects a non-allowlisted host at create time", async () => {
    const tenantId = `tenant-evil-${crypto.randomUUID()}`;
    const agentId = `agent-${crypto.randomUUID()}`;
    await ensureTenant(tenantId);
    await ensureAgent(tenantId, agentId);
    const vault = new SecretVault(MASTER_PASSWORD);
    const secret = await vault.createSecret(tenantId, "evil-secret", "sk-evil");

    await expect(
      vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.evil.com",
        pathPattern: "/repos/acme/widgets",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
        injectFormat: "Bearer {value}",
      }),
    ).rejects.toThrow(/not in the secret route allowlist/);
  });
});
