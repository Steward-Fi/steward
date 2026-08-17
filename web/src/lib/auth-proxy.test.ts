import { describe, expect, test } from "bun:test";
import {
  AUTH_PROXY_HEADER,
  buildExpiredRefreshCookie,
  buildRefreshCookie,
  hasProxyHeader,
  isHttpsRequest,
  normalizeRefreshToken,
  proxyJson,
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
  test("refresh cookie is HttpOnly, SameSite=Strict, path-scoped, and Secure on https", () => {
    const cookie = buildRefreshCookie("token-123", true);
    expect(cookie).toContain("steward_rt=token-123");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Path=/api/auth");
    expect(cookie).toContain("Secure");
    expect(cookie).toContain("Max-Age=");
  });

  test("refresh cookie omits Secure on plain http (local e2e/dev origin)", () => {
    const cookie = buildRefreshCookie("token-123", false);
    expect(cookie).not.toContain("Secure");
    expect(cookie).toContain("HttpOnly");
  });

  test("refresh cookie value is URL-encoded", () => {
    const cookie = buildRefreshCookie("tok%en/with=special;chars", true);
    expect(cookie).toContain(`steward_rt=${encodeURIComponent("tok%en/with=special;chars")}`);
    expect(cookie).not.toContain("tok%en/with=special;chars;");
  });

  test("expired cookie clears the value with Max-Age=0", () => {
    const cookie = buildExpiredRefreshCookie(true);
    expect(cookie).toContain("steward_rt=");
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("HttpOnly");
  });

  test("readRefreshCookie round-trips a written token", () => {
    const token = "refresh-token-abc.123";
    const request = req({
      headers: { cookie: `other=1; steward_rt=${encodeURIComponent(token)}; theme=dark` },
    });
    expect(readRefreshCookie(request)).toBe(token);
  });

  test("readRefreshCookie returns null when missing, empty, or malformed", () => {
    expect(readRefreshCookie(req())).toBeNull();
    expect(readRefreshCookie(req({ headers: { cookie: "other=1" } }))).toBeNull();
    expect(readRefreshCookie(req({ headers: { cookie: "steward_rt=" } }))).toBeNull();
    expect(readRefreshCookie(req({ headers: { cookie: "steward_rt=%E0%A4%A" } }))).toBeNull();
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
    expect(await response.json()).toEqual({ ok: true });
  });

  test("normalizeRefreshToken rejects non-strings and oversized values", () => {
    expect(normalizeRefreshToken("token")).toBe("token");
    expect(normalizeRefreshToken(undefined)).toBeNull();
    expect(normalizeRefreshToken(123)).toBeNull();
    expect(normalizeRefreshToken("")).toBeNull();
    expect(normalizeRefreshToken("x".repeat(9000))).toBeNull();
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
});
