import { describe, expect, test } from "bun:test";
import {
  AUTH_PROXY_HEADER,
  buildExpiredRefreshCookie,
  buildRefreshCookie,
  forwardToApi,
  hasProxyHeader,
  isHttpsRequest,
  normalizeAccessToken,
  normalizeRefreshToken,
  proxyJson,
  readBoundedJsonObject,
  readRefreshCookie,
} from "@/lib/auth-proxy";

/**
 * SEC-018 regression tests for the same-origin auth proxy helpers. The cookie
 * contract (HttpOnly + SameSite=Strict + Path scoping) is what keeps the
 * refresh token out of reach of page JavaScript.
 */

function req(init: { url?: string; headers?: Record<string, string> } = {}): Request {
  return new Request(init.url ?? "https://app.example.test/api/auth/session", {
    method: "POST",
    headers: init.headers,
  });
}

describe("auth proxy cookie contract (SEC-018)", () => {
  test("refresh cookie is host-bound, HttpOnly, SameSite=Strict, and Secure on https", () => {
    const cookie = buildRefreshCookie("token-123", true);
    expect(cookie).toContain("__Host-steward_rt=token-123");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Max-Age=");
  });

  test("refresh cookie omits Secure on plain http (local e2e/dev origin)", () => {
    const cookie = buildRefreshCookie("token-123", false);
    expect(cookie).toContain("steward_rt=token-123");
    expect(cookie).toContain("Path=/api/auth");
    expect(cookie).not.toContain("Secure");
    expect(cookie).toContain("HttpOnly");
  });

  test("refresh cookie value is URL-encoded", () => {
    const cookie = buildRefreshCookie("tok%en/with=special;chars", true);
    expect(cookie).toContain(
      `__Host-steward_rt=${encodeURIComponent("tok%en/with=special;chars")}`,
    );
    expect(cookie).not.toContain("tok%en/with=special;chars;");
  });

  test("expired cookie clears the value with Max-Age=0", () => {
    const cookie = buildExpiredRefreshCookie(true);
    expect(cookie).toContain("__Host-steward_rt=");
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("HttpOnly");
  });

  test("readRefreshCookie round-trips a written token", () => {
    const token = "refresh-token-abc.123";
    const request = req({
      headers: { cookie: `other=1; __Host-steward_rt=${encodeURIComponent(token)}; theme=dark` },
    });
    expect(readRefreshCookie(request)).toBe(token);
  });

  test("readRefreshCookie returns null when missing, empty, or malformed", () => {
    expect(readRefreshCookie(req())).toBeNull();
    expect(readRefreshCookie(req({ headers: { cookie: "other=1" } }))).toBeNull();
    expect(readRefreshCookie(req({ headers: { cookie: "__Host-steward_rt=" } }))).toBeNull();
    expect(
      readRefreshCookie(req({ headers: { cookie: "__Host-steward_rt=%E0%A4%A" } })),
    ).toBeNull();
    expect(
      readRefreshCookie(req({ headers: { cookie: `__Host-steward_rt=${"x".repeat(9000)}` } })),
    ).toBeNull();
  });

  test("production ignores a sibling-domain legacy cookie shadow", () => {
    expect(
      readRefreshCookie(
        req({ headers: { cookie: "steward_rt=attacker; __Host-steward_rt=trusted" } }),
      ),
    ).toBe("trusted");
    expect(readRefreshCookie(req({ headers: { cookie: "steward_rt=attacker" } }))).toBeNull();
  });
});

describe("auth proxy CSRF/header checks (SEC-018)", () => {
  test("hasProxyHeader accepts only the exact SDK header value", () => {
    expect(hasProxyHeader(req({ headers: { [AUTH_PROXY_HEADER]: "1" } }))).toBe(true);
    expect(hasProxyHeader(req())).toBe(false);
    expect(hasProxyHeader(req({ headers: { [AUTH_PROXY_HEADER]: "true" } }))).toBe(false);
  });

  test("isHttpsRequest reflects the request URL protocol", () => {
    expect(isHttpsRequest(req({ url: "https://app.example.test/x" }))).toBe(true);
    expect(isHttpsRequest(req({ url: "http://localhost:3499/x" }))).toBe(false);
  });

  test("proxyJson is never cacheable", async () => {
    const response = proxyJson({ ok: true });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(response.headers.get("Content-Type")).toBe("application/json");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await response.json()).toEqual({ ok: true });
  });

  test("bounded JSON parsing rejects oversized, encoded, and non-object bodies", async () => {
    const request = (body: string, headers: Record<string, string> = {}) =>
      new Request("https://app.example.test/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body,
      });
    await expect(
      readBoundedJsonObject(request(`{"padding":"${"x".repeat(17000)}"}`)),
    ).rejects.toThrow("too large");
    await expect(readBoundedJsonObject(request("[]"))).rejects.toThrow("must be an object");
    await expect(
      readBoundedJsonObject(request("{}", { "Content-Encoding": "gzip" })),
    ).rejects.toThrow("Encoded");
    await expect(
      readBoundedJsonObject(request("{}", { "Content-Type": "text/plain" })),
    ).rejects.toThrow("Content-Type");
  });

  test("normalizeRefreshToken rejects non-strings and oversized values", () => {
    expect(normalizeRefreshToken("token")).toBe("token");
    expect(normalizeRefreshToken(undefined)).toBeNull();
    expect(normalizeRefreshToken(123)).toBeNull();
    expect(normalizeRefreshToken("")).toBeNull();
    expect(normalizeRefreshToken("x".repeat(9000))).toBeNull();
  });

  test("normalizeAccessToken accepts only bounded compact JWTs and rejects credential reflection", () => {
    expect(normalizeAccessToken("header.payload.signature")).toBe("header.payload.signature");
    expect(normalizeAccessToken("refresh-token")).toBeNull();
    expect(
      normalizeAccessToken("header.payload.signature", ["header.payload.signature"]),
    ).toBeNull();
    expect(normalizeAccessToken("x".repeat(9000))).toBeNull();
  });
});

describe("forwardToApi (SEC-018)", () => {
  test("posts JSON to the configured Steward API and parses the response", async () => {
    const { createServer } = await import("node:http");
    const server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, echo: JSON.parse(body), path: req.url }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : 0;

    // Point the shared API URL module at the test server.
    process.env.NEXT_PUBLIC_STEWARD_API_URL = `http://127.0.0.1:${port}`;
    try {
      const { forwardToApi: forward } = await import("@/lib/auth-proxy");
      const result = await forward("/auth/refresh", { refreshToken: "rt-1" });
      expect(result.status).toBe(200);
      expect(result.json?.ok).toBe(true);
      expect((result.json?.echo as { refreshToken?: string })?.refreshToken).toBe("rt-1");
    } finally {
      delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
      server.close();
    }
  });

  test("does not replay a refresh-token POST across an upstream redirect", async () => {
    const { createServer } = await import("node:http");
    let redirectedRequests = 0;
    const receiver = createServer((_req, res) => {
      redirectedRequests += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
    const receiverAddress = receiver.address();
    const receiverPort =
      typeof receiverAddress === "object" && receiverAddress ? receiverAddress.port : 0;

    const redirector = createServer((_req, res) => {
      res.writeHead(307, { Location: `http://127.0.0.1:${receiverPort}/capture` });
      res.end();
    });
    await new Promise<void>((resolve) => redirector.listen(0, "127.0.0.1", resolve));
    const redirectorAddress = redirector.address();
    const redirectorPort =
      typeof redirectorAddress === "object" && redirectorAddress ? redirectorAddress.port : 0;

    process.env.NEXT_PUBLIC_STEWARD_API_URL = `http://127.0.0.1:${redirectorPort}`;
    try {
      const { forwardToApi: forward } = await import("@/lib/auth-proxy");
      await expect(
        forward("/auth/refresh", { refreshToken: "rt-must-not-leak" }),
      ).rejects.toThrow();
      expect(redirectedRequests).toBe(0);
    } finally {
      delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
      await Promise.all([
        new Promise<void>((resolve) => redirector.close(() => resolve())),
        new Promise<void>((resolve) => receiver.close(() => resolve())),
      ]);
    }
  });

  test("rejects credential-bearing and plaintext production API destinations", async () => {
    const mutableEnv = process.env as Record<string, string | undefined>;
    const originalNodeEnv = mutableEnv.NODE_ENV;
    try {
      mutableEnv.NEXT_PUBLIC_STEWARD_API_URL = "https://user:password@api.example.test";
      await expect(forwardToApi("/auth/revoke", { refreshToken: "secret" })).rejects.toThrow(
        "credential-free",
      );
      mutableEnv.NODE_ENV = "production";
      mutableEnv.NEXT_PUBLIC_STEWARD_API_URL = "http://api.example.test";
      await expect(forwardToApi("/auth/revoke", { refreshToken: "secret" })).rejects.toThrow(
        "HTTPS",
      );
    } finally {
      delete mutableEnv.NEXT_PUBLIC_STEWARD_API_URL;
      if (originalNodeEnv === undefined) delete mutableEnv.NODE_ENV;
      else mutableEnv.NODE_ENV = originalNodeEnv;
    }
  });
});
