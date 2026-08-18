import { signAgentToken } from "@stwd/auth";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { authMiddleware } from "@stwd/proxy/src/middleware/auth";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { StewardService } from "../services/StewardService.js";
import type { StewardPluginConfig } from "../types.js";

const SIGNING_SECRET = "eliza-plugin-proxy-signing-secret-with-enough-bytes";
const JWT_SECRET = "eliza-plugin-proxy-jwt-secret-with-enough-bytes";
const PROXY_URL = "https://proxy.eliza-plugin.test";
const PROXY_TEST_ENV_KEYS = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_JWT_SECRET",
  "STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE",
  "STEWARD_PROXY_REQUEST_SIGNING_SECRET",
  "STEWARD_PROXY_DEV_MODE",
] as const;
const savedProxyTestEnv = new Map<string, string | undefined>();

let tenantId: string;
let agentId: string;
let token: string;
let proxyApp: Hono;
let lastProxyRequest: Request | null = null;
const realFetch = globalThis.fetch;

function configuredService(overrides: Partial<StewardPluginConfig> = {}): StewardService {
  const pluginConfig: StewardPluginConfig = {
    apiUrl: "https://api.steward.test",
    proxyUrl: PROXY_URL,
    proxyRequestSigningSecret: SIGNING_SECRET,
    bearerToken: token,
    tenantId,
    agentId,
    autoRegister: false,
    fallbackLocal: false,
    ...overrides,
  };
  const service = new StewardService({} as never);
  Object.assign(service, { client: {}, pluginConfig, _connected: true });
  return service;
}

beforeAll(async () => {
  for (const key of PROXY_TEST_ENV_KEYS) savedProxyTestEnv.set(key, process.env[key]);
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_JWT_SECRET = JWT_SECRET;
  process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
  process.env.STEWARD_PROXY_REQUEST_SIGNING_SECRET = SIGNING_SECRET;
  delete process.env.STEWARD_PROXY_DEV_MODE;

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());

  tenantId = `tenant-eliza-signing-${crypto.randomUUID()}`;
  agentId = `agent-eliza-signing-${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` });
  await getDb()
    .insert(agents)
    .values({ id: agentId, tenantId, name: agentId, walletAddress: `0x${"4".repeat(40)}` });
  token = await signAgentToken({ agentId, tenantId, scopes: ["agent", "api:proxy"] }, "1h");

  proxyApp = new Hono();
  proxyApp.use("*", authMiddleware);
  proxyApp.all("*", (c) => c.json({ ok: true, path: c.req.path }));

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (!url.startsWith(PROXY_URL)) return realFetch(input as RequestInfo, init);
    const path = url.slice(PROXY_URL.length) || "/";
    lastProxyRequest = new Request(url, init);
    return proxyApp.request(path, init as RequestInit);
  }) as typeof fetch;
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  await closeDb().catch(() => {});
  for (const key of PROXY_TEST_ENV_KEYS) {
    const value = savedProxyTestEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe("Eliza plugin proxy request signing", () => {
  it("sends governed proxy calls through the canonical client and real proxy verifier", async () => {
    lastProxyRequest = null;
    const result = await configuredService().callGovernedApi({
      url: "https://api.example.com/v1/items?limit=2",
      method: "POST",
      body: { name: "signed-by-eliza" },
    });

    expect(result.status).toBe(200);
    expect(lastProxyRequest).not.toBeNull();
    expect(lastProxyRequest?.headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
    expect(lastProxyRequest?.headers.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
    expect(lastProxyRequest?.headers.get("idempotency-key")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("rejects the same request when signature headers are dropped", async () => {
    const body = JSON.stringify({ name: "unsigned" });
    const response = await proxyApp.request("/proxy/api.example.com/v1/items", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body,
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({
      ok: false,
      error: "X-Steward-Signature header required",
    });
  });

  it("fails closed before fetch when signing is enforced but no secret is configured", async () => {
    lastProxyRequest = null;
    const service = configuredService({ proxyRequestSigningSecret: undefined });

    await expect(
      service.callGovernedApi({ url: "https://api.example.com/v1/items" }),
    ).rejects.toThrow("STEWARD_PROXY_REQUEST_SIGNING_SECRET is required");
    expect(lastProxyRequest).toBeNull();
  });

  it("signs whenever a secret is configured, even with enforcement disabled", async () => {
    delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
    try {
      lastProxyRequest = null;
      // configuredService() includes proxyRequestSigningSecret — dev-mode must
      // not downgrade this deployment to unsigned proxy calls (SEC-171).
      const result = await configuredService().callGovernedApi({
        url: "https://api.example.com/v1/items",
      });

      expect(result.status).toBe(200);
      expect(lastProxyRequest?.headers.get("x-steward-signature")).toMatch(/^v1=[0-9a-f]{64}$/);
      expect(lastProxyRequest?.headers.get("x-steward-request-timestamp")).toMatch(/^\d+$/);
    } finally {
      process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
    }
  });

  it("allows unsigned proxy operation only with the explicit dev-mode opt-in (SEC-175)", async () => {
    delete process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE;
    try {
      // Enforcement off but no dev-mode opt-in: the proxy fails closed rather
      // than silently accepting an unsigned call.
      lastProxyRequest = null;
      const denied = await configuredService({
        proxyRequestSigningSecret: undefined,
      }).callGovernedApi({ url: "https://api.example.com/v1/items" });
      expect(denied.status).toBe(401);

      // Local/dev unsigned operation remains available via explicit opt-in.
      process.env.STEWARD_PROXY_DEV_MODE = "true";
      try {
        lastProxyRequest = null;
        const result = await configuredService({
          proxyRequestSigningSecret: undefined,
        }).callGovernedApi({ url: "https://api.example.com/v1/items" });

        expect(result.status).toBe(200);
        expect(lastProxyRequest?.headers.get("x-steward-signature")).toBeNull();
      } finally {
        delete process.env.STEWARD_PROXY_DEV_MODE;
      }
    } finally {
      process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE = "true";
    }
  });
});
