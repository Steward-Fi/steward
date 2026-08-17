import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { StewardAuth } from "../auth.ts";

/**
 * SEC-018 regression tests: when `authProxyUrl` is configured, the long-lived
 * refresh token must never touch JS-readable storage. Sign-in deposits it with
 * the same-origin proxy (HttpOnly cookie), and refresh/revoke/tenant-switch
 * calls go to the proxy without a token in the request body.
 */

class TestStorage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

type CapturedRequest = {
  method: string;
  path: string;
  headers: IncomingMessage["headers"];
  bodyJson: Record<string, unknown> | undefined;
};

function fakeJwt(payload: Record<string, unknown> = {}): string {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(
    JSON.stringify({
      exp: Math.floor(Date.now() / 1000) + 3600,
      address: "0x1234",
      tenantId: "test-tenant",
      userId: "user-1",
      email: "test@example.com",
      ...payload,
    }),
  );
  return `${header}.${body}.fake-sig`;
}

async function readRequestBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

type ResponsePayload = { status?: number; json?: unknown };

async function startServer(
  handler: (request: CapturedRequest) => Promise<ResponsePayload> | ResponsePayload,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer(async (req, res) => {
    const bodyText = await readRequestBody(req);
    const response = await handler({
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers: req.headers,
      bodyJson: bodyText.length > 0 ? (JSON.parse(bodyText) as Record<string, unknown>) : undefined,
    });
    res.writeHead(response.status ?? 200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(response.json ?? { ok: true }));
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => (error ? reject(error) : resolve()));
  });

  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

const TEST_USER = {
  id: "user-1",
  email: "test@example.com",
  walletAddress: "0x1234",
  walletChain: "evm",
};

describe("StewardAuth authProxyUrl (SEC-018: HttpOnly refresh-token custody)", () => {
  let storage: TestStorage;
  let requests: CapturedRequest[];
  let server: { baseUrl: string; close: () => Promise<void> } | null = null;
  let proxyDepositFails: boolean;

  beforeEach(async () => {
    storage = new TestStorage();
    requests = [];
    proxyDepositFails = false;
    server = await startServer((req) => {
      requests.push(req);
      if (req.path === "/auth/email/verify") {
        return {
          json: { ok: true, token: fakeJwt(), refreshToken: "rt-secret-1", user: TEST_USER },
        };
      }
      if (req.path === "/proxy/session" && req.method === "POST") {
        if (proxyDepositFails) {
          return { status: 500, json: { ok: false, error: "proxy down" } };
        }
        return { json: { ok: true } };
      }
      if (req.path === "/proxy/session" && req.method === "DELETE") {
        return { json: { ok: true } };
      }
      if (req.path === "/proxy/refresh") {
        return { json: { ok: true, token: fakeJwt({ userId: "user-2" }), expiresIn: 900 } };
      }
      if (req.path === "/proxy/revoke") {
        return { json: { ok: true } };
      }
      return { status: 404, json: { ok: false, error: "not found" } };
    });
  });

  afterEach(async () => {
    storage.clear();
    await server?.close();
    server = null;
  });

  function proxyRequests(path: string, method?: string): CapturedRequest[] {
    return requests.filter((r) => r.path === path && (!method || r.method === method));
  }

  test("sign-in deposits the refresh token with the proxy, never with JS storage", async () => {
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });

    await auth.verifyEmailCallback("magic-token", "test@example.com");

    const deposits = proxyRequests("/proxy/session", "POST");
    expect(deposits).toHaveLength(1);
    expect(deposits[0].bodyJson).toEqual({ refreshToken: "rt-secret-1" });
    expect(deposits[0].headers["x-steward-auth-proxy"]).toBe("1");

    expect(storage.getItem("steward_session_token")).toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
    expect(storage.getItem("steward_refresh_token")).toBeNull();
  });

  test("sign-in fails closed when the refresh-token deposit fails", async () => {
    proxyDepositFails = true;
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });

    await expect(auth.verifyEmailCallback("magic-token", "test@example.com")).rejects.toThrow(
      /secure the refresh token/i,
    );
    // The refresh token must not fall back to JS-readable storage.
    expect(storage.getItem("steward_refresh_token")).toBeNull();
  });

  test("refreshSession calls the proxy without a JS-held token", async () => {
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });
    storage.setItem("steward_session_token", fakeJwt());

    const session = await auth.refreshSession();

    expect(session?.userId).toBe("user-2");
    const refreshes = proxyRequests("/proxy/refresh", "POST");
    expect(refreshes).toHaveLength(1);
    // No refresh token is ever sent from JS — the proxy injects the cookie.
    expect(refreshes[0].bodyJson).toEqual({});
    expect(refreshes[0].headers["x-steward-auth-proxy"]).toBe("1");
    // The API's direct /auth/refresh endpoint is never called.
    expect(proxyRequests("/auth/refresh")).toHaveLength(0);
  });

  test("a 401 from the proxy refresh signs out and clears the proxy cookie", async () => {
    server?.close();
    server = await startServer((req) => {
      requests.push(req);
      if (req.path === "/proxy/refresh") {
        return { status: 401, json: { ok: false, error: "Invalid or expired refresh token" } };
      }
      return { json: { ok: true } };
    });
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });
    storage.setItem("steward_session_token", fakeJwt());

    const session = await auth.refreshSession();

    expect(session).toBeNull();
    expect(storage.getItem("steward_session_token")).toBeNull();
    // signOut fires a best-effort cookie clear at the proxy.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(proxyRequests("/proxy/session", "DELETE").length).toBeGreaterThanOrEqual(1);
  });

  test("switchTenant forwards only the tenantId to the proxy refresh", async () => {
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });
    storage.setItem("steward_session_token", fakeJwt());

    const session = await auth.switchTenant("tenant-2");

    expect(session?.userId).toBe("user-2");
    const refreshes = proxyRequests("/proxy/refresh", "POST");
    expect(refreshes).toHaveLength(1);
    expect(refreshes[0].bodyJson).toEqual({ tenantId: "tenant-2" });
  });

  test("revokeSession revokes via the proxy and clears local state", async () => {
    const auth = new StewardAuth({
      baseUrl: server!.baseUrl,
      storage,
      authProxyUrl: `${server!.baseUrl}/proxy`,
    });
    storage.setItem("steward_session_token", fakeJwt());

    await auth.revokeSession();

    expect(proxyRequests("/proxy/revoke", "POST")).toHaveLength(1);
    expect(storage.getItem("steward_session_token")).toBeNull();
  });

  test("without authProxyUrl the refresh token still goes to storage (default unchanged)", async () => {
    const auth = new StewardAuth({ baseUrl: server!.baseUrl, storage });

    await auth.verifyEmailCallback("magic-token", "test@example.com");

    expect(storage.getItem("steward_refresh_token")).toBe("rt-secret-1");
    expect(proxyRequests("/proxy/session")).toHaveLength(0);
  });
});
