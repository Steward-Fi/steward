/**
 * agent-client-e2e.test.ts — sovereign-custody happy-path E2E.
 *
 * Drives the REAL @stwd/sdk AgentClient against a REAL, in-process Steward API
 * surface — the actual A1 route handlers (agent-enroll + manifest/issuance +
 * broker invoke), the real @stwd/auth crypto, a real pglite DB with a seeded
 * p256 agent_signer, and the real @stwd/proxy forward path (only the outbound
 * network is stubbed). No mock server: the client talks to the shipping handlers.
 *
 * The full sovereign-custody arc, keypair-only:
 *   1. operator step (once): register the agent's PUBLIC p256 key in agent_signers.
 *   2. agent boots holding ONLY the matching PRIVATE key (AgentKeypair).
 *   3. AgentClient.enroll()  → challenge/response → short-lived agent token.
 *   4. AgentClient.manifest() → the agent's granted capabilities.
 *   5. AgentClient.issue()   → token-mode: short-lived scoped token (github).
 *   6. AgentClient.invoke()  → broker-mode: Steward performs the call, credential
 *      injected server-side, agent gets only the scrubbed upstream body.
 *
 * The PAT is NEVER visible to the agent: it is sealed in the vault, injected by
 * the proxy onto the OUTBOUND request, and the client only ever sent the invoke
 * body. We assert exactly that.
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { fileURLToPath } from "node:url";
import { generateP256KeyPair, signAgentToken } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  agentSigners,
  agents,
  closeDb,
  getDb,
  runPluginMigrations,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { CapabilityStore } from "@stwd/plugin-capabilities";
import { AgentClient, AgentKeypair } from "@stwd/sdk";
import type { AppVariables } from "@stwd/shared";
import { SecretVault } from "@stwd/vault";
import { migrate as pgliteMigrate } from "drizzle-orm/pglite/migrator";
import { Hono } from "hono";

setDefaultTimeout(30000);

const MASTER_PASSWORD = "a3-agent-client-e2e-master-password-32chars";
const SIGNING_SECRET = "a3-agent-client-e2e-signing-secret-32bytes-min";
const FAKE_PAT = "ghp_a3_e2e_do_not_use_0123456789abcdef";
const AUDIT_HMAC_KEY = "a3-agent-client-e2e-audit-hmac-key-with-enough-bytes";
const PROXY_URL = "https://proxy.a3-e2e.test";
const CAP_MIGRATIONS = fileURLToPath(
  new URL("../../../plugin-capabilities/drizzle", import.meta.url),
);
const TEST_ENV_KEYS = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_JWT_SECRET",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE",
  "STEWARD_PROXY_REQUEST_SIGNING_SECRET",
  "STEWARD_PROXY_ALLOWED_HOSTS",
  "STEWARD_PROXY_DEV_MODE",
  "STEWARD_PROXY_URL",
] as const;

let keypair: Awaited<ReturnType<typeof generateP256KeyPair>>;
let tenantId: string;
let agentId: string;
let capName: string;

let forwarded: { url: string; auth: string | null; bodyText: string | null } | null = null;
let proxyRequest: { headers: Headers; bodyText: string | null } | null = null;
let proxyApp: Hono | null = null;
const realFetch = globalThis.fetch;
let originalEnv = new Map<string, string | undefined>();
let resetProxyHandlerTestHooksForTests: (() => void) | undefined;

// Real A1 route factories + agent-jwt middleware.
let agentEnrollRoutes: Hono<{ Variables: AppVariables }>;
let apiApp: Hono<{ Variables: AppVariables }>;

async function buildStewardAppContext() {
  const { getDb: gdb } = await import("@stwd/db");
  const { verifyToken } = await import("@stwd/auth");
  // A permissive agent-jwt middleware: verify the bearer agent token and stamp
  // the tenant + agent scope, exactly what the real manifest/invoke handlers read.
  const requireAgentJwt = async (
    c: {
      req: { header(name: string): string | undefined };
      set(k: string, v: unknown): void;
      json(b: unknown, s: number): Response;
    },
    next: () => Promise<void>,
  ) => {
    const auth = c.req.header("authorization") ?? "";
    const m = auth.match(/^Bearer (.+)$/);
    if (!m) return c.json({ ok: false, error: "agent authentication required" }, 401);
    try {
      const payload = await verifyToken(m[1]);
      if (!payload.agentId || !payload.tenantId) {
        return c.json({ ok: false, error: "agent authentication required" }, 401);
      }
      c.set("tenantId", payload.tenantId);
      c.set("agentScope", payload.agentId);
      c.set("agentScopes", payload.scopes ?? ["agent"]);
      c.set("authType", "agent-token");
    } catch {
      return c.json({ ok: false, error: "agent authentication required" }, 401);
    }
    await next();
  };

  return {
    db: gdb(),
    async safeJsonParse<T>(c: { req: { json(): Promise<unknown> } }): Promise<T | null> {
      try {
        return (await c.req.json()) as T;
      } catch {
        return null;
      }
    },
    async getPolicySet() {
      // allow the capability intent (broker invoke) through to the proxy.
      return [
        {
          id: "allow-gh",
          type: "capability-intent",
          enabled: true,
          config: { capabilities: [capName], effect: "allow" },
        },
      ];
    },
    async writeAuditEvent() {},
    async getAgentTokenStatus() {
      return null;
    },
    getRedisClient() {
      return null;
    },
    requireAgentJwt,
    async operatorAuth() {},
    async tenantAuth(_c: unknown, next: () => Promise<void>) {
      await next();
    },
  } as unknown as Parameters<typeof import("@stwd/plugin-capabilities").createManifestRoutes>[0] & {
    requireAgentJwt: typeof requireAgentJwt;
  };
}

beforeAll(async () => {
  originalEnv = new Map(TEST_ENV_KEYS.map((key) => [key, process.env[key]]));
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = MASTER_PASSWORD;
  process.env.STEWARD_JWT_SECRET = "a3-agent-client-e2e-jwt-secret-with-enough-bytes-0123456789";
  process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_HMAC_KEY;
  __resetAuditHmacKeyCacheForTests();
  process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
  process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = SIGNING_SECRET;
  process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.github.com";
  process.env.STEWARD_PROXY_DEV_MODE = "true";
  process.env.STEWARD_PROXY_URL = PROXY_URL;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder: CAP_MIGRATIONS },
    { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
  );

  // ── real proxy, outbound network stubbed ────────────────────────────────────
  const { authMiddleware } = await import("@stwd/proxy/src/middleware/auth");
  const {
    handleProxy,
    __setForwardProxyRequestForTests: setForward,
    __setResolveProxyHostForTests: setResolveHost,
    __setCheckProxyRateLimitForTests: setCheckProxyRateLimitForTests,
    __resetProxyHandlerTestHooksForTests: resetProxyHooks,
  } = await import("@stwd/proxy/src/handlers/proxy");
  resetProxyHandlerTestHooksForTests = resetProxyHooks;
  setResolveHost(async () => [{ address: "93.184.216.34", family: 4 }]);
  setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
  setForward(async (url, method, headers, body) => {
    const bodyText = body ? await new Response(body).text() : null;
    forwarded = {
      url: url.toString(),
      auth: headers.get("authorization"),
      bodyText,
    };
    return new Response(JSON.stringify({ id: 999, body: "commented" }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  });
  proxyApp = new Hono();
  proxyApp.use("*", authMiddleware);
  proxyApp.all("*", handleProxy);

  // ── the API app: real enroll + manifest + invoke routes ─────────────────────
  ({ agentEnrollRoutes } = await import("../routes/agent-enroll"));
  const { createManifestRoutes, createInvokeRoutes } = await import("@stwd/plugin-capabilities");
  const ctx = await buildStewardAppContext();
  apiApp = new Hono<{ Variables: AppVariables }>();
  apiApp.route("/agent-enroll", agentEnrollRoutes);
  // agent-jwt gate for the agent-facing capability surface.
  apiApp.use("/capabilities/manifest", (c, next) => ctx.requireAgentJwt(c as never, next));
  apiApp.use("/capabilities/manifest/*", (c, next) => ctx.requireAgentJwt(c as never, next));
  apiApp.use("/capabilities/:name/invoke", (c, next) => ctx.requireAgentJwt(c as never, next));
  apiApp.route("/capabilities", createManifestRoutes(ctx));
  apiApp.route("/capabilities", createInvokeRoutes(ctx));

  // ── seed: tenant, agent, p256 signer (OPERATOR STEP), capability + grant ─────
  tenantId = `t-a3-${crypto.randomUUID()}`;
  agentId = `a-a3-${crypto.randomUUID()}`;
  capName = "github.pr.comment";
  keypair = await generateP256KeyPair();

  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `h-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"3".repeat(40)}` });
  // OPERATOR STEP: register only the PUBLIC key. No token is ever minted by hand.
  await getDb().insert(agentSigners).values({
    tenantId,
    agentId,
    signerType: "service",
    subjectType: "agent",
    subjectId: agentId,
    keyType: "p256",
    publicKey: keypair.publicKeySpkiBase64,
    status: "active",
  });

  // seal the PAT + declare a broker capability with a manifest identifier + grant.
  const vault = new SecretVault(MASTER_PASSWORD);
  const secret = await vault.createSecret(tenantId, "gh-pat", FAKE_PAT);
  const store = new CapabilityStore(getDb());
  const cap = await store.createCapability({
    tenantId,
    name: capName,
    spec: {
      secretId: secret.id,
      host: "api.github.com",
      pathPattern: "/repos/acme/app/issues/1/comments",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
      injectFormat: "Bearer {value}",
    },
    // discord ⇒ broker mode (A1 PROVIDER-MODES): issue returns a delegation, and
    // the invoke path brokers the call — the honest broker story end to end.
    constraints: { manifest: "discord:bot-token:soliza" },
    enabled: true,
  });
  await store.createGrant({ tenantId, capabilityId: cap.id, agentId, expiresAt: null });

  // route the client's fetch: /agent-enroll + /capabilities → apiApp; proxy → proxyApp.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith("http://localhost")) {
      const path = url.slice("http://localhost".length) || "/";
      return apiApp.request(path, init as RequestInit);
    }
    if (url.startsWith(PROXY_URL) && proxyApp) {
      const path = url.slice(PROXY_URL.length) || "/";
      proxyRequest = {
        headers: new Headers(init?.headers),
        bodyText: typeof init?.body === "string" ? init.body : null,
      };
      return proxyApp.request(path, init as RequestInit);
    }
    return realFetch(input as RequestInfo, init);
  }) as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  resetProxyHandlerTestHooksForTests?.();
  await closeDb().catch(() => {});
  for (const key of TEST_ENV_KEYS) {
    const original = originalEnv.get(key);
    if (original === undefined) delete process.env[key];
    else process.env[key] = original;
  }
  __resetAuditHmacKeyCacheForTests();
  originalEnv.clear();
});

describe("A3 agent-client E2E (real API, seeded p256 signer)", () => {
  it("keeps the proxy fail-closed for unsigned agent requests", async () => {
    const token = await signAgentToken({ agentId, tenantId, scopes: ["agent", "api:proxy"] }, "5m");
    const response = await proxyApp!.request(
      "/proxy/api.github.com/repos/acme/app/issues/1/comments",
      { headers: { authorization: `Bearer ${token}` } },
    );

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      ok: false,
      error: "X-Steward-Signature header required",
    });
  });

  it("boots keypair-only and runs enroll → manifest → issue → invoke", async () => {
    forwarded = null;
    proxyRequest = null;
    // The agent holds ONLY its private key (imported non-extractable).
    const kp = await AgentKeypair.fromPkcs8Base64(await exportPkcs8Base64(keypair.privateKey));
    const client = new AgentClient({
      baseUrl: "http://localhost",
      agentId,
      keypair: kp,
      renewJitterMs: 0,
    });

    // 3. enroll (challenge/response against the REAL enroll route + REAL verify).
    const enrolled = await client.enroll();
    expect(enrolled.tenantId).toBe(tenantId);
    expect(enrolled.scopes).toContain("agent");
    expect(client.isEnrolled()).toBe(true);

    // 4. manifest (real manifest route + real DB projection).
    const manifest = await client.manifest();
    expect(manifest.map((m) => m.manifest)).toContain("discord:bot-token:soliza");

    // 5. issue — discord is broker mode: returns a delegation, NOT a token.
    const cap = await client.issue("discord:bot-token:soliza");
    expect(cap.mode).toBe("broker");
    if (cap.mode !== "broker") throw new Error("expected broker mode for discord");
    expect(cap.delegation.capabilityName).toBe(capName);

    // 6. invoke (broker path through the REAL proxy). The PAT is injected
    //    server-side; the agent only ever sent the body.
    const res = await client.invoke(capName, {
      body: { body: "LGTM from Soliza" },
    });
    expect(res.status).toBe("ok");
    if (res.status !== "ok") throw new Error("expected ok invoke");
    expect(res.data).toMatchObject({ id: 999 });

    // the credential reached the UPSTREAM (proxy→github), never the agent.
    expect(forwarded).not.toBeNull();
    expect(forwarded!.auth).toBe(`Bearer ${FAKE_PAT}`);
    expect(forwarded!.bodyText).not.toContain(FAKE_PAT);
    // The API→proxy leg really is signed; dev-mode test plumbing must not make
    // this happy path vacuous by allowing an unsigned request through.
    expect(proxyRequest).not.toBeNull();
    expect(proxyRequest!.headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(proxyRequest!.headers.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
    expect(proxyRequest!.bodyText).not.toContain(FAKE_PAT);
    // the agent-visible response body never contains the PAT.
    expect(JSON.stringify(res.data)).not.toContain(FAKE_PAT);
    expect(JSON.stringify(res.data)).not.toContain("ghp_");
    expect(JSON.stringify(res.data)).not.toContain(AUDIT_HMAC_KEY);

    client.stopRenewalLoop();
  });
});

/** Export a private CryptoKey as base64 PKCS#8 (the operator-side file format the
 * AgentKeypair loader consumes). Used only to bridge the test's generated key. */
async function exportPkcs8Base64(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
  let bin = "";
  for (let i = 0; i < pkcs8.length; i += 1) bin += String.fromCharCode(pkcs8[i]);
  return btoa(bin);
}
