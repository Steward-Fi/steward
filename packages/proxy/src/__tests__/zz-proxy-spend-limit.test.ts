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
let secretPlaintext = "test-secret";
// When set, the security-required pre-forward audit insert throws so we can
// exercise the fail-closed (503) path. recordRequiredAudit rethrows, unlike
// best-effort recordAudit.
let failRequiredAudit = false;
const originalFetch = globalThis.fetch;

const route = {
  id: "route-1",
  tenantId: "tenant-1",
  secretId: "secret-1",
  agentId: "agent-1",
  hostPattern: "example.com",
  pathPattern: "/*",
  method: "*",
  injectAs: "header",
  injectionStrategy: "header",
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
  relations: noopFn,
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
  const providerAccounts = { id: "id" };
  const providerOperations = { id: "id" };
  const workspaces = { id: "id" };
  const policies = {
    agentId: "agentId",
    type: "type",
    enabled: "enabled",
    config: "config",
  };
  const proxyAuditLog = {};
  const pendingProxyRequests = {
    id: "id",
    tenantId: "tenantId",
    agentId: "agentId",
    status: "status",
    expiresAt: "expiresAt",
  };
  const agents = { id: "id", tenantId: "tenantId" };
  const tenants = { id: "id" };
  return {
    sql: noopFn,
    relations: noopFn,
    pendingProxyRequests,
    agents,
    tenants,
    closeDb: async () => {},
    createDb: () => ({}),
    getDatabaseUrl: () => "postgres://mock",
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
    providerAccounts,
    providerOperations,
    workspaces,
    policies,
    proxyAuditLog,
    // Table/function stubs for modules outside this suite's scope (provider
    // authority, google/slack credential lifecycles, audit chain). bun
    // validates named imports against this mock namespace at link time, so
    // every name any transitively-loaded module imports must exist here.
    approvalQueue: { id: "id" },
    auditEvents: { id: "id" },
    executionAuthorizationNonces: { id: "id" },
    intents: { id: "id" },
    providerActionBindings: { id: "id" },
    providerGoogleCredentialLifecycles: { id: "id" },
    users: { id: "id" },
    withTenantAuditedTransaction: async (
      _tenantId: unknown,
      fn: (tx: unknown, appendRequiredAudit: (event: unknown) => Promise<void>) => Promise<unknown>,
    ) => fn({}, async () => {}),
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
          // The required pre-forward audit is written with the
          // "credential-proxy-authorized" reason (status 102). Throwing here
          // models an audit-store outage on the security-critical write.
          if (failRequiredAudit && entry?.reason === "credential-proxy-authorized") {
            throw new Error("audit store offline");
          }
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
      return secretPlaintext;
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
    delete process.env.STEWARD_PROXY_DEV_MODE;
  });

  beforeEach(() => {
    process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
    process.env.STEWARD_PROXY_ALLOWED_HOSTS = "example.com";
    // These tests exercise handler logic under the soft development posture
    // (in-process replay store, no Redis). SEC-175 made that posture an
    // explicit opt-in, so set the flag here.
    process.env.STEWARD_PROXY_DEV_MODE = "true";
    route.injectAs = "header";
    route.injectKey = "x-api-key";
    route.injectFormat = "Bearer {value}";
    secretPlaintext = "test-secret";
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
    failRequiredAudit = false;
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
    expect(res.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(res.headers.get("Pragma")).toBe("no-cache");
    expect(res.headers.get("Expires")).toBe("0");
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
      // SEC-097: alternate client-IP headers must not be relayed upstream.
      expect(headers.get("x-client-ip")).toBeNull();
      expect(headers.get("cf-connecting-ip")).toBeNull();
      expect(headers.get("true-client-ip")).toBeNull();
      expect(headers.get("fastly-client-ip")).toBeNull();
      expect(headers.get("x-cluster-client-ip")).toBeNull();
      expect(headers.get("x-original-forwarded-for")).toBeNull();
      // SEC-099: request-signing window metadata is internal to the proxy.
      expect(headers.get("x-steward-request-timestamp")).toBeNull();
      expect(headers.get("x-steward-request-expires-at")).toBeNull();
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
          "X-Client-IP": "127.0.0.1",
          "CF-Connecting-IP": "127.0.0.1",
          "True-Client-IP": "127.0.0.1",
          "Fastly-Client-IP": "127.0.0.1",
          "X-Cluster-Client-IP": "127.0.0.1",
          "X-Original-Forwarded-For": "127.0.0.1",
          "X-Steward-Request-Timestamp": "1700000000",
          "X-Steward-Request-Expires-At": "1700000300",
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

  test("strips upstream Set-Cookie so agents never receive credential-derived sessions (SEC-098)", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (url: string | URL | Request, _init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "set-cookie": "provider_session=abc123; HttpOnly; Path=/",
        },
      });
    }) as typeof fetch;
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());

    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(fetchCalls).toBe(1);
  });

  test("unknown injectAs fails closed with 400 and never reaches upstream (SEC-176)", async () => {
    spendResult.configured = false;
    route.injectAs = "carrier-pigeon";
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = (await res.json()) as { error?: string };

    expect(res.status).toBe(400);
    expect(body.error).toContain("Invalid credential injection configuration");
    expect(fetchCalls).toBe(0);
    expect(audits.some((entry) => entry?.reason === "credential-injection-failed")).toBe(true);
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

  test("blocks raw secret reflected in opaque response bodies when injectFormat adds a prefix", async () => {
    spendResult.configured = false;
    route.injectFormat = "Bearer {value}";
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response(new TextEncoder().encode("upstream error: invalid api key test-secret"), {
        status: 401,
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

  for (const [label, declaredLength] of [
    ["missing Content-Length", undefined],
    ["lying small Content-Length", "1"],
  ] as const) {
    test(`bounds credential response inspection with ${label}`, async () => {
      spendResult.configured = false;
      let cancelled = false;
      globalThis.fetch = (async () => {
        fetchCalls++;
        let chunks = 0;
        const stream = new ReadableStream<Uint8Array>({
          pull(controller) {
            chunks += 1;
            controller.enqueue(new Uint8Array(64 * 1024));
            if (chunks >= 40) controller.close();
          },
          cancel() {
            cancelled = true;
          },
        });
        const headers = new Headers({ "content-type": "application/octet-stream" });
        if (declaredLength !== undefined) headers.set("content-length", declaredLength);
        return new Response(stream, { status: 200, headers });
      }) as typeof fetch;

      const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
      __setCheckProxySpendLimitForTests(async () => spendResult);

      const response = await handleProxy(makeContext());
      const body = await response.text();
      expect(response.status).toBe(502);
      expect(body).toContain("could not be inspected safely");
      expect(body).not.toContain("test-secret");
      expect(cancelled).toBe(true);
      expect(audits).toContainEqual(
        expect.objectContaining({
          targetHost: "example.com",
          statusCode: 502,
          reason: "credential-response-inspection-failed",
        }),
      );
    });
  }

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

    for (const address of [
      "64:ff9b::a9fe:a9fe",
      "64:ff9b:1::a9fe:a9fe",
      // RFC 8215 local-use /48: the embedded IPv4 position is operator-defined,
      // so a non-zero fourth word must not bypass the public-address boundary.
      "64:ff9b:1:1::808:808",
      // Exercise the final address in the reserved /48 so the guard cannot
      // accidentally regress to a narrower implementation-defined subnet.
      "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
      "2002:7f00:1::",
    ]) {
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

  test("preserves a successful upstream response when replay completion persistence fails", async () => {
    spendResult.configured = false;
    const {
      __clearProxyReplayClaimsForTests,
      __setCheckProxySpendLimitForTests,
      createProxyHandler,
      handleProxy,
    } = await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    const diagnosticCalls: unknown[][] = [];
    const originalConsoleError = console.error;
    console.error = (...args: unknown[]) => diagnosticCalls.push(args);
    let completionAttempts = 0;
    const request = () =>
      makeContext("/proxy/example.com/v1/echo", {
        method: "POST",
        headers: { "Idempotency-Key": "completion-failure-success" },
        body: JSON.stringify({ op: "create" }),
      });

    try {
      const handler = createProxyHandler({
        completeReplayClaim: async () => {
          completionAttempts++;
          throw new Error("Bearer completion-secret-must-not-be-logged");
        },
      });
      const first = await handler(request());
      const retry = await handleProxy(request());

      expect(first.status).toBe(200);
      expect(await first.text()).toBe(JSON.stringify({ ok: true }));
      expect(retry.status).toBe(409);
      expect(((await retry.json()) as { error: string }).error).toContain("already processing");
      expect(fetchCalls).toBe(1);
      expect(completionAttempts).toBe(1);
      expect(JSON.stringify(diagnosticCalls)).toContain(
        "Failed to persist post-forward idempotency completion",
      );
      expect(JSON.stringify(diagnosticCalls)).not.toContain("completion-secret-must-not-be-logged");
    } finally {
      console.error = originalConsoleError;
    }
  });

  test("keeps a single winner while replay completion is still unresolved", async () => {
    spendResult.configured = false;
    const {
      __clearProxyReplayClaimsForTests,
      __setCheckProxySpendLimitForTests,
      createProxyHandler,
      handleProxy,
    } = await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    let completionStarted!: () => void;
    const completionStartedPromise = new Promise<void>((resolve) => {
      completionStarted = resolve;
    });
    let rejectCompletion!: (reason: Error) => void;
    const completionBarrier = new Promise<void>((_resolve, reject) => {
      rejectCompletion = reject;
    });
    const diagnosticCalls: unknown[][] = [];
    const originalConsoleError = console.error;
    console.error = (...args: unknown[]) => diagnosticCalls.push(args);
    const request = () =>
      makeContext("/proxy/example.com/v1/echo", {
        method: "POST",
        headers: { "Idempotency-Key": "completion-in-flight-single-winner" },
        body: JSON.stringify({ op: "create" }),
      });

    try {
      const handler = createProxyHandler({
        completeReplayClaim: async () => {
          completionStarted();
          await completionBarrier;
        },
      });
      const firstPromise = handler(request());
      await completionStartedPromise;

      const concurrentRetry = await handleProxy(request());
      expect(concurrentRetry.status).toBe(409);
      expect(((await concurrentRetry.json()) as { error: string }).error).toContain(
        "already processing",
      );
      expect(fetchCalls).toBe(1);

      rejectCompletion(new Error("Bearer concurrent-completion-secret-must-not-be-logged"));
      const first = await firstPromise;
      expect(first.status).toBe(200);
      expect(await first.text()).toBe(JSON.stringify({ ok: true }));
      expect(fetchCalls).toBe(1);
      expect(JSON.stringify(diagnosticCalls)).not.toContain(
        "concurrent-completion-secret-must-not-be-logged",
      );
    } finally {
      console.error = originalConsoleError;
      // Avoid an unhandled rejection if an assertion above fails before the
      // request awaiting the completion barrier can observe it.
      rejectCompletion(new Error("test cleanup"));
      await completionBarrier.catch(() => undefined);
    }
  });

  test("preserves a sanitized upstream failure when replay completion persistence fails", async () => {
    spendResult.configured = false;
    const {
      __clearProxyReplayClaimsForTests,
      __setCheckProxySpendLimitForTests,
      createProxyHandler,
      handleProxy,
    } = await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    globalThis.fetch = (async () => {
      fetchCalls++;
      throw new Error("Bearer upstream-secret-must-not-be-logged");
    }) as typeof fetch;
    const diagnosticCalls: unknown[][] = [];
    const originalConsoleError = console.error;
    console.error = (...args: unknown[]) => diagnosticCalls.push(args);
    let completionAttempts = 0;
    const request = () =>
      makeContext("/proxy/example.com/v1/echo", {
        method: "POST",
        headers: { "Idempotency-Key": "completion-failure-upstream" },
        body: JSON.stringify({ op: "create" }),
      });

    try {
      const handler = createProxyHandler({
        completeReplayClaim: async () => {
          completionAttempts++;
          throw new Error("Bearer completion-secret-must-not-be-logged");
        },
      });
      const first = await handler(request());
      const retry = await handleProxy(request());

      expect(first.status).toBe(502);
      expect(await first.json()).toEqual({ ok: false, error: "Upstream request failed" });
      expect(retry.status).toBe(409);
      expect(((await retry.json()) as { error: string }).error).toContain("already processing");
      expect(fetchCalls).toBe(1);
      expect(completionAttempts).toBe(1);
      const diagnostics = JSON.stringify(diagnosticCalls);
      expect(diagnostics).toContain("Failed to persist post-forward idempotency completion");
      expect(diagnostics).not.toContain("upstream-secret-must-not-be-logged");
      expect(diagnostics).not.toContain("completion-secret-must-not-be-logged");
    } finally {
      console.error = originalConsoleError;
    }
  });

  test("blocks injected credentials reflected in upstream response headers", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      // Upstream echoes the injected credential back in a response header.
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "x-echoed-auth": "Bearer test-secret",
        },
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
        reason: "credential-reflected-in-response-header",
      }),
    );
  });

  test("blocks raw secret reflected in upstream response headers when injectFormat adds a prefix", async () => {
    spendResult.configured = false;
    route.injectFormat = "Bearer {value}";
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      return new Response(JSON.stringify({ ok: false }), {
        status: 401,
        headers: {
          "content-type": "application/json",
          "x-error": "invalid api key test-secret",
        },
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
        reason: "credential-reflected-in-response-header",
      }),
    );
  });

  test("blocks percent-encoded injected credentials reflected in upstream response headers", async () => {
    spendResult.configured = false;
    secretPlaintext = "sk/a+b=";
    route.injectFormat = "Bearer {value}";
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      expect(new Headers(init?.headers).get("x-api-key")).toBe("Bearer sk/a+b=");
      return new Response(JSON.stringify({ ok: false }), {
        status: 401,
        headers: {
          "content-type": "application/json",
          "x-error": `invalid ${encodeURIComponent("Bearer sk/a+b=")}`,
        },
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
        reason: "credential-reflected-in-response-header",
      }),
    );
  });

  test("requests identity encoding and blocks encoded credential-bearing responses", async () => {
    spendResult.configured = false;
    globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(new Headers(init?.headers).get("accept-encoding")).toBe("identity");
      return new Response(new TextEncoder().encode("compressed bytes"), {
        status: 200,
        headers: {
          "content-type": "application/octet-stream",
          "content-encoding": "gzip",
        },
      });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(502);
    expect(fetchCalls).toBe(1);
    expect(body.error).toContain("Encoded response blocked");
    expect(audits).toContainEqual(
      expect.objectContaining({
        targetHost: "example.com",
        statusCode: 502,
        reason: "credential-encoded-response-blocked",
      }),
    );
  });

  test("blocks percent-encoded raw secrets reflected in opaque response bodies", async () => {
    spendResult.configured = false;
    secretPlaintext = "sk/a+b=";
    globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      expect(new Headers(init?.headers).get("x-api-key")).toBe("Bearer sk/a+b=");
      return new Response(`upstream error: ${encodeURIComponent("sk/a+b=")}`, {
        status: 401,
        headers: { "content-type": "text/plain" },
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

  test("fails closed with 503 when the required pre-forward audit cannot be persisted", async () => {
    spendResult.configured = false;
    // Force the security-required pre-forward audit write to throw.
    // recordRequiredAudit rethrows (unlike best-effort recordAudit), so
    // handleProxy must abort before decrypting/forwarding any credential.
    failRequiredAudit = true;
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(503);
    // Credential was never decrypted or forwarded: upstream untouched.
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Proxy audit logging unavailable");
  });

  test("rejects CRLF-injecting credential header formats before forwarding", async () => {
    spendResult.configured = false;
    // A malicious/misconfigured route format that smuggles a CRLF must be
    // rejected by injectCredential, surfacing 400 and never reaching upstream.
    route.injectAs = "header";
    route.injectKey = "x-api-key";
    route.injectFormat = "Bearer {value}\r\nX-Injected: evil";
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    const { handleProxy, __setCheckProxySpendLimitForTests } = await loadProxy();
    __setCheckProxySpendLimitForTests(async () => spendResult);

    const res = await handleProxy(makeContext());
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Invalid credential injection configuration");
    expect(audits).toContainEqual(
      expect.objectContaining({
        targetHost: "example.com",
        statusCode: 400,
        reason: "credential-injection-failed",
      }),
    );
  });

  test("caps in-flight proxy requests per agent and fails the overflow with 429", async () => {
    spendResult.configured = false;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    // First request hangs inside the upstream call, holding its slot.
    globalThis.fetch = (async (url: string | URL | Request) => {
      fetchCalls++;
      expect(String(url)).toBe("https://example.com/v1/echo");
      await gate;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const mod = await loadProxy();
    mod.__setCheckProxySpendLimitForTests(async () => spendResult);
    // Squeeze the per-agent cap to 1 so the second concurrent request overflows.
    mod.__setProxyInFlightCapsForTests({ perAgent: 1 });

    try {
      const first = mod.handleProxy(makeContext());
      // Yield so the first request acquires its slot and parks on `gate`.
      await new Promise((resolve) => setTimeout(resolve, 10));

      const second = await mod.handleProxy(makeContext());
      const body = await second.json();

      expect(second.status).toBe(429);
      expect(body.error).toContain("Too many in-flight proxy requests for agent");

      release();
      const firstRes = await first;
      expect(firstRes.status).toBe(200);
      // Drain the streamed body so the slot is released for later tests.
      await firstRes.text();
    } finally {
      release();
      // Restore the production default so later tests are unaffected.
      mod.__setProxyInFlightCapsForTests({ perAgent: 50 });
    }
  });

  test("requires an idempotency key for signed safe (GET) proxy requests", async () => {
    spendResult.configured = false;
    const { handleProxy, __clearProxyReplayClaimsForTests, __setCheckProxySpendLimitForTests } =
      await loadProxy();
    __clearProxyReplayClaimsForTests();
    __setCheckProxySpendLimitForTests(async () => spendResult);
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response("{}", { status: 200 });
    }) as typeof fetch;

    // A GET is normally replay-safe, but once it carries a proof-of-possession
    // signature it must still present an Idempotency-Key (replay binding).
    const res = await handleProxy(
      makeContext("/proxy/example.com/v1/echo", {
        method: "GET",
        headers: { "X-Steward-Signature": "v1=deadbeef" },
      }),
    );
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(fetchCalls).toBe(0);
    expect(body.error).toContain("Idempotency-Key");
    expect(body.error).toContain("signed proxy requests");
  });
});
