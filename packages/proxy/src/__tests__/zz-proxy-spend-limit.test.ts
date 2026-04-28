import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";

let spendResult: any = {
  allowed: true,
  configured: true,
  period: "day",
  limit: 1,
  spent: 0,
  remaining: 1,
};
let fetchCalls = 0;
const audits: any[] = [];
const originalFetch = globalThis.fetch;

const route = {
  id: "route-1",
  tenantId: "tenant-1",
  secretId: "secret-1",
  hostPattern: "example.com",
  pathPattern: "/*",
  method: "*",
  injectAs: "header",
  injectKey: "x-api-key",
  injectFormat: "Bearer {value}",
  priority: 0,
  enabled: true,
  createdAt: new Date(),
};

mock.module("drizzle-orm", () => ({
  and: (...args: unknown[]) => args,
  desc: (arg: unknown) => arg,
  eq: (...args: unknown[]) => args,
}));

mock.module("@stwd/db", () => {
  const secretRoutes = {
    tenantId: "tenantId",
    enabled: "enabled",
    priority: "priority",
  };
  const secrets = { id: "id" };
  const policies = {
    agentId: "agentId",
    type: "type",
    enabled: "enabled",
    config: "config",
  };
  const proxyAuditLog = {};
  return {
    and: (...args: unknown[]) => args,
    desc: (arg: unknown) => arg,
    eq: (...args: unknown[]) => args,
    getSql: () => null,
    secretRoutes,
    secrets,
    policies,
    proxyAuditLog,
    getDb: () => ({
      select: () => ({
        from: (table: unknown) => ({
          where: () => {
            if (table === secretRoutes) {
              return { orderBy: async () => [route] };
            }
            return {
              limit: async () => [
                {
                  id: "secret-1",
                  ciphertext: "ciphertext",
                  iv: "iv",
                  authTag: "tag",
                  salt: "salt",
                },
              ],
            };
          },
        }),
      }),
      insert: () => ({
        values: async (entry: any) => {
          audits.push(entry);
        },
      }),
    }),
  };
});

mock.module("@stwd/vault", () => ({
  KeyStore: class {
    decrypt() {
      return "test-secret";
    }
  },
}));

function makeContext(path = "/proxy/example.com/v1/echo") {
  const headers = new Headers({ authorization: "Bearer steward-token" });
  return {
    req: {
      path,
      method: "GET",
      raw: new Request(`https://proxy.test${path}`, { headers }),
    },
    get(key: string) {
      if (key === "agentId") return "agent-1";
      if (key === "tenantId") return "tenant-1";
      return undefined;
    },
    header() {},
    json(body: unknown, status: number) {
      return Response.json(body, { status });
    },
  } as any;
}

describe("proxy spend-limit enforcement", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  beforeEach(() => {
    process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
    spendResult = {
      allowed: true,
      configured: true,
      period: "day",
      limit: 1,
      spent: 0,
      remaining: 1,
    };
    fetchCalls = 0;
    audits.length = 0;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      expect(new Headers(init?.headers).get("x-api-key")).toBe("Bearer test-secret");
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }) as typeof fetch;
  });

  test("agent under spend limit proceeds to upstream", async () => {
    const { handleProxy, __setCheckProxySpendLimitForTests } = await import("../handlers/proxy");
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());

    expect(res.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  test("agent over daily budget returns 402 and does not call upstream", async () => {
    spendResult = {
      allowed: false,
      configured: true,
      period: "day",
      limit: 0.1,
      spent: 0.12,
      remaining: 0,
      reason: "Daily proxy spend limit exceeded for example.com: spent $0.1200 of $0.1000",
    };
    const { handleProxy, __setCheckProxySpendLimitForTests } = await import("../handlers/proxy");
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(402);
    expect(fetchCalls).toBe(0);
    expect(body).toEqual({
      ok: false,
      error: "Daily proxy spend limit exceeded for example.com: spent $0.1200 of $0.1000",
      limit: {
        type: "spend",
        period: "day",
        limitUsd: 0.1,
        spentUsd: 0.12,
        remainingUsd: 0,
      },
    });
    expect(audits[0]).toMatchObject({
      agentId: "agent-1",
      tenantId: "tenant-1",
      targetHost: "example.com",
      statusCode: 402,
      reason: "Daily proxy spend limit exceeded for example.com: spent $0.1200 of $0.1000",
    });
  });

  test("Redis down with REDIS_REQUIRED=false allows when spend check is permissive", async () => {
    const { handleProxy, __setCheckProxySpendLimitForTests } = await import("../handlers/proxy");
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());

    expect(res.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  test("Redis down with REDIS_REQUIRED=true fails closed when spend check denies", async () => {
    spendResult = {
      allowed: false,
      configured: true,
      period: "day",
      limit: 1,
      spent: 0,
      remaining: 0,
      reason: "Redis unavailable; spend-limit enforcement is required",
    };
    const { handleProxy, __setCheckProxySpendLimitForTests } = await import("../handlers/proxy");
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(402);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Redis unavailable");
  });
});
