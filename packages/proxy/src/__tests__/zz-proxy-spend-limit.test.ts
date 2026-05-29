import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

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
const proxySource = readFileSync(join(import.meta.dir, "..", "handlers", "proxy.ts"), "utf8");

const route = {
  id: "route-1",
  tenantId: "tenant-1",
  secretId: "secret-1",
  agentId: "agent-1",
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

// Drizzle helpers stubbed as no-op argument-collectors. The real ones
// build SQL AST nodes which the rest of this test would have to mock
// around. proxy.ts also imports `gt`, `or`, `isNull` (for the active-
// secrets join), so we expose them too.
const noopFn = (...args: unknown[]) => args;
mock.module("drizzle-orm", () => ({
  and: noopFn,
  desc: (arg: unknown) => arg,
  eq: noopFn,
  gt: noopFn,
  gte: noopFn,
  inArray: noopFn,
  isNotNull: noopFn,
  isNull: noopFn,
  lt: noopFn,
  lte: noopFn,
  or: noopFn,
  sql: noopFn,
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
    and: noopFn,
    desc: (arg: unknown) => arg,
    eq: noopFn,
    gt: noopFn,
    gte: noopFn,
    inArray: noopFn,
    isNotNull: noopFn,
    isNull: noopFn,
    lt: noopFn,
    lte: noopFn,
    or: noopFn,
    getSql: () => null,
    secretRoutes,
    secrets,
    policies,
    proxyAuditLog,
    getDb: () => ({
      select: () => ({
        from: (table: unknown) => ({
          // findMatchingRoute now joins secret_routes against active
          // secrets (deletedAt IS NULL, expiresAt > now) before the
          // tenant/enabled filter. Mirror that chain so a matching
          // {route} still surfaces regardless of join semantics.
          innerJoin: () => ({
            where: () => ({
              orderBy: async () => [{ route }],
            }),
          }),
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
  // proxy.ts now decrypts secrets via SecretVault.decryptSecret so it
  // can centralize the lifecycle checks (deleted/expired). Stub the
  // class with a matching shape that returns the same plaintext the
  // spend-limit assertions already expect.
  SecretVault: class {
    async decryptSecret() {
      return "test-secret";
    }
  },
}));

function makeContext(
  path = "/proxy/example.com/v1/echo",
  options: { method?: string; headers?: Record<string, string>; body?: string } = {},
) {
  const method = options.method ?? "GET";
  const headers = new Headers({ authorization: "Bearer steward-token", ...options.headers });
  const init: RequestInit = { method, headers };
  if (method !== "GET" && method !== "HEAD" && options.body !== undefined) {
    init.body = options.body;
  }
  return {
    req: {
      path,
      method,
      raw: new Request(`https://proxy.test${path}`, init),
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

async function loadProxy() {
  const mod = await import("../handlers/proxy");
  mod.__setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  mod.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
  mod.__setForwardProxyRequestForTests(
    async (url: URL, method: string, headers: Headers, body: ReadableStream<Uint8Array> | null) =>
      fetch(url.toString(), {
        method,
        headers,
        body: method !== "GET" && method !== "HEAD" ? body : undefined,
        redirect: "manual",
        // @ts-expect-error Bun supports duplex for streaming request bodies.
        duplex: "half",
      }),
  );
  return mod;
}

describe("proxy spend-limit enforcement", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.STEWARD_PROXY_ALLOWED_HOSTS;
  });

  beforeEach(() => {
    process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
    process.env.STEWARD_PROXY_ALLOWED_HOSTS = "example.com";
    route.injectAs = "header";
    route.injectKey = "x-api-key";
    route.injectFormat = "Bearer {value}";
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
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());

    expect(res.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  test("strips spoofable forwarding headers before calling upstream", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      const headers = new Headers(init?.headers);
      expect(headers.get("x-api-key")).toBe("Bearer test-secret");
      expect(headers.get("forwarded")).toBeNull();
      expect(headers.get("x-forwarded-for")).toBeNull();
      expect(headers.get("x-forwarded-host")).toBeNull();
      expect(headers.get("x-forwarded-proto")).toBeNull();
      expect(headers.get("x-real-ip")).toBeNull();
      expect(headers.get("cookie")).toBeNull();
      expect(headers.get("x-steward-key")).toBeNull();
      expect(headers.get("x-steward-platform-key")).toBeNull();
      expect(headers.get("x-steward-signature")).toBeNull();
      expect(headers.get("x-http-method-override")).toBeNull();
      expect(headers.get("x-method-override")).toBeNull();
      expect(headers.get("x-original-url")).toBeNull();
      expect(headers.get("x-rewrite-url")).toBeNull();
      expect(headers.get("idempotency-key")).toBeNull();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(
      makeContext("/proxy/example.com/v1/echo", {
        headers: {
          Forwarded: "for=127.0.0.1;host=internal.example.com;proto=https",
          "X-Forwarded-For": "127.0.0.1",
          "X-Forwarded-Host": "internal.example.com",
          "X-Forwarded-Proto": "https",
          "X-Real-IP": "127.0.0.1",
          Cookie: "steward_session=victim",
          "X-Steward-Key": "tenant-key",
          "X-Steward-Platform-Key": "platform-key",
          "X-Steward-Signature": "signature",
          "X-HTTP-Method-Override": "DELETE",
          "X-Method-Override": "PATCH",
          "X-Original-URL": "/v1/admin/delete-all",
          "X-Rewrite-URL": "/v1/admin/delete-all",
          "Idempotency-Key": "upstream-collision-key",
        },
      }),
    );

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
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
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
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());

    expect(res.status).toBe(200);
    expect(fetchCalls).toBe(1);
  });

  test("rate-limit denials are audited and do not call upstream", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxyRateLimitForTests, __setCheckProxySpendLimitForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    __setCheckProxyRateLimitForTests(async () => ({ allowed: false, resetMs: 2000 }));

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(429);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Rate limit exceeded");
    expect(audits[0]).toMatchObject({
      agentId: "agent-1",
      tenantId: "tenant-1",
      targetHost: "example.com",
      statusCode: 429,
      reason: "proxy-rate-limit-exceeded",
    });
  });

  test("blocks spend-limited proxy requests for hosts without metering", async () => {
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(402);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("no metering strategy");
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
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(402);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Redis unavailable");
  });

  test("query-injected secrets fail closed before forwarding", async () => {
    spendResult.configured = false;
    route.injectAs = "query";
    route.injectKey = "api_key";
    route.injectFormat = "{value}";
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo?api_key=test-secret");
      return new Response(JSON.stringify({ ok: true }), {
        status: 201,
        headers: {
          "content-type": "application/json",
          location: "https://example.com/resource?api_key=test-secret",
          "content-location": "https://example.com/resource?api_key=test-secret",
          link: '<https://example.com/resource?api_key=test-secret>; rel="self"',
          refresh: "0; url=https://example.com/resource?api_key=test-secret",
        },
      });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Query credential injection is disabled");
  });

  test("blocks injected credentials reflected in opaque response bodies", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      return new Response(new TextEncoder().encode("raw bytes: Bearer test-secret"), {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
      });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(fetchCalls).toBe(1);
    expect(body.error).toContain("reflected injected credential");
    expect(audits).toContainEqual(
      expect.objectContaining({
        targetHost: "example.com",
        statusCode: 502,
        reason: "credential-reflected-in-response-body",
      }),
    );
  });

  test("blocks injected credentials split across opaque response chunks", async () => {
    spendResult.configured = false;
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("raw bytes: Bearer "));
        controller.enqueue(new TextEncoder().encode("test-secret"));
        controller.close();
      },
    });
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      return new Response(stream, {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
      });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(fetchCalls).toBe(1);
    expect(body.error).toContain("reflected injected credential");
    expect(audits).toContainEqual(
      expect.objectContaining({
        targetHost: "example.com",
        statusCode: 502,
        reason: "credential-reflected-in-response-body",
      }),
    );
  });

  test("blocks streaming responses after injecting a credential", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      return new Response("data: Bearer test-secret\n\n", {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(fetchCalls).toBe(1);
    expect(body.error).toContain("Streaming response blocked");
    expect(audits).toContainEqual(
      expect.objectContaining({
        targetHost: "example.com",
        statusCode: 502,
        reason: "credential-streaming-response-blocked",
      }),
    );
  });

  test("blocks allowed hosts that resolve to private or reserved addresses", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests, __setResolveProxyHostForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    __setResolveProxyHostForTests(async () => [{ address: "169.254.169.254", family: 4 }]);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("private or reserved address");
    expect(audits[0]).toMatchObject({
      agentId: "agent-1",
      tenantId: "tenant-1",
      targetHost: "example.com",
      statusCode: 403,
      reason: "target-resolves-private",
    });
  });

  test("blocks IPv4-mapped IPv6 hex DNS answers that resolve to private addresses", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests, __setResolveProxyHostForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    __setResolveProxyHostForTests(async () => [{ address: "::ffff:7f00:1", family: 6 }]);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("private or reserved address");
    expect(audits[0]).toMatchObject({
      agentId: "agent-1",
      tenantId: "tenant-1",
      targetHost: "example.com",
      statusCode: 403,
      reason: "target-resolves-private",
    });
  });

  test("blocks NAT64 and 6to4 DNS answers that embed private IPv4 addresses", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests, __setResolveProxyHostForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    for (const address of ["64:ff9b::a9fe:a9fe", "64:ff9b:1::a9fe:a9fe", "2002:7f00:1::"]) {
      audits.length = 0;
      __setResolveProxyHostForTests(async () => [{ address, family: 6 }]);

      const res = await handleProxy(makeContext());
      const body = await res.json();

      expect(res.status).toBe(403);
      expect(fetchCalls).toBe(0);
      expect(body.error).toContain("private or reserved address");
      expect(audits[0]).toMatchObject({
        targetHost: "example.com",
        statusCode: 403,
        reason: "target-resolves-private",
      });
    }
  });

  test("blocks Teredo and documentation IPv6 DNS answers", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests, __setResolveProxyHostForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    for (const address of ["2001::", "2001:db8::1"]) {
      audits.length = 0;
      __setResolveProxyHostForTests(async () => [{ address, family: 6 }]);

      const res = await handleProxy(makeContext());
      const body = await res.json();

      expect(res.status).toBe(403);
      expect(fetchCalls).toBe(0);
      expect(body.error).toContain("private or reserved address");
      expect(audits[0]).toMatchObject({
        targetHost: "example.com",
        statusCode: 403,
        reason: "target-resolves-private",
      });
    }
  });

  test("blocks deprecated IPv6 site-local DNS answers", async () => {
    spendResult.configured = false;
    const { handleProxy, __setCheckProxySpendLimitForTests, __setResolveProxyHostForTests } =
      await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    __setResolveProxyHostForTests(async () => [{ address: "fec0::1", family: 6 }]);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(403);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("private or reserved address");
    expect(audits[0]).toMatchObject({
      targetHost: "example.com",
      statusCode: 403,
      reason: "target-resolves-private",
    });
  });

  test("requires idempotency keys for mutating proxy requests", async () => {
    spendResult.configured = false;
    const { handleProxy, __clearProxyReplayClaimsForTests, __setCheckProxySpendLimitForTests } =
      await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext("/proxy/example.com/v1/echo", { method: "POST" }));
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Idempotency-Key");
  });

  test("blocks replay of mutating proxy requests with the same idempotency key", async () => {
    spendResult.configured = false;
    const { handleProxy, __clearProxyReplayClaimsForTests, __setCheckProxySpendLimitForTests } =
      await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      expect(new Headers(init?.headers).get("x-api-key")).toBe("Bearer test-secret");
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const first = await handleProxy(
      makeContext("/proxy/example.com/v1/echo", {
        method: "POST",
        headers: { "Idempotency-Key": "replay-key-1" },
        body: JSON.stringify({ op: "create" }),
      }),
    );
    const second = await handleProxy(
      makeContext("/proxy/example.com/v1/echo", {
        method: "POST",
        headers: { "Idempotency-Key": "replay-key-1" },
        body: JSON.stringify({ op: "create" }),
      }),
    );

    expect(first.status).toBe(200);
    expect(second.status).toBe(409);
    expect(fetchCalls).toBe(1);
    expect(((await second.json()) as { error: string }).error).toContain("already forwarded");
  });

  test("uses Redis-backed idempotency claims when Redis is available", () => {
    expect(proxySource).toContain("isProxyRedisAvailable()");
    expect(proxySource).toContain("getRedis().set");
    expect(proxySource).toContain('"PX"');
    expect(proxySource).toContain('"NX"');
    expect(proxySource).toContain("Shared proxy idempotency store unavailable");
  });

  test("forwards through a vetted DNS-bound transport instead of platform fetch", () => {
    expect(proxySource).toContain("function lookupFromVettedRecords");
    expect(proxySource).toContain("lookup: lookupFromVettedRecords(records)");
    expect(proxySource).toContain("forwardProxyRequestForHandler");
    expect(proxySource).not.toContain("response = await fetch(outboundUrl.toString()");
  });
});
