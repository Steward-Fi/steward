import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { AUTH_PROXY_HEADER } from "@/lib/auth-proxy";
import { POST as refreshPOST } from "./refresh/route";
import { POST as revokePOST } from "./revoke/route";
import { DELETE as sessionDELETE, POST as sessionPOST } from "./session/route";

/**
 * SEC-018 regression tests for the same-origin auth proxy route handlers.
 * These routes are the only code path allowed to touch the refresh token:
 * it arrives over the request body once (deposit), then lives exclusively in
 * an HttpOnly cookie that JS cannot read.
 */

const PROXY_HEADERS = { [AUTH_PROXY_HEADER]: "1", "Content-Type": "application/json" };

function postJson(url: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(url, {
    method: "POST",
    headers: { ...PROXY_HEADERS, ...headers },
    body: JSON.stringify(body),
  });
}

describe("auth proxy route handlers (SEC-018)", () => {
  describe("POST /api/auth/session (deposit)", () => {
    test("rejects calls without the proxy header", async () => {
      const res = await sessionPOST(
        new Request("https://app.example.test/api/auth/session", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refreshToken: "rt" }),
        }),
      );
      expect(res.status).toBe(403);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });

    test("stores the token in an HttpOnly SameSite=Strict cookie", async () => {
      const res = await sessionPOST(
        postJson("https://app.example.test/api/auth/session", { refreshToken: "rt-secret" }),
      );
      expect(res.status).toBe(200);
      const cookie = res.headers.get("Set-Cookie") ?? "";
      expect(cookie).toContain("steward_rt=rt-secret");
      expect(cookie).toContain("HttpOnly");
      expect(cookie).toContain("SameSite=Strict");
      expect(cookie).toContain("Secure");
      expect(res.headers.get("Cache-Control")).toBe("no-store");
    });

    test("rejects a missing refresh token", async () => {
      const res = await sessionPOST(
        postJson("https://app.example.test/api/auth/session", { refreshToken: "" }),
      );
      expect(res.status).toBe(400);
      expect(res.headers.get("Set-Cookie")).toBeNull();
    });
  });

  describe("DELETE /api/auth/session (sign-out)", () => {
    test("expires the cookie", async () => {
      const res = await sessionDELETE(
        new Request("https://app.example.test/api/auth/session", {
          method: "DELETE",
          headers: PROXY_HEADERS,
        }),
      );
      expect(res.status).toBe(200);
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    test("rejects calls without the proxy header", async () => {
      const res = await sessionDELETE(
        new Request("https://app.example.test/api/auth/session", { method: "DELETE" }),
      );
      expect(res.status).toBe(403);
    });
  });

  describe("POST /api/auth/refresh + /api/auth/revoke (upstream forwarding)", () => {
    let upstream: ReturnType<typeof createServer> | null = null;
    let upstreamRequests: Array<{ path: string; body: Record<string, unknown> }>;
    let upstreamStatus: number;

    beforeEach(async () => {
      upstreamRequests = [];
      upstreamStatus = 200;
      upstream = createServer((req: IncomingMessage, res) => {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => {
          upstreamRequests.push({ path: req.url ?? "/", body: JSON.parse(body || "{}") });
          res.writeHead(upstreamStatus, { "Content-Type": "application/json" });
          res.end(
            upstreamStatus === 200
              ? JSON.stringify({
                  ok: true,
                  token: "new-access-jwt",
                  refreshToken: "rotated-rt",
                  expiresIn: 900,
                })
              : JSON.stringify({ ok: false, error: "Invalid or expired refresh token" }),
          );
        });
      });
      await new Promise<void>((resolve) => upstream!.listen(0, "127.0.0.1", resolve));
      const { port } = upstream!.address() as AddressInfo;
      process.env.NEXT_PUBLIC_STEWARD_API_URL = `http://127.0.0.1:${port}`;
    });

    afterEach(async () => {
      delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
      await new Promise<void>((resolve) => upstream?.close(() => resolve()));
      upstream = null;
    });

    test("refresh rejects calls without the proxy header", async () => {
      const res = await refreshPOST(
        new Request("https://app.example.test/api/auth/refresh", {
          method: "POST",
          headers: { cookie: "steward_rt=rt-secret" },
        }),
      );
      expect(res.status).toBe(403);
      expect(upstreamRequests).toHaveLength(0);
    });

    test("refresh without a cookie fails closed with an expired cookie", async () => {
      const res = await refreshPOST(postJson("https://app.example.test/api/auth/refresh", {}));
      expect(res.status).toBe(401);
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
      expect(upstreamRequests).toHaveLength(0);
    });

    test("refresh forwards the cookie token and strips the rotated token from the body", async () => {
      const res = await refreshPOST(
        postJson(
          "https://app.example.test/api/auth/refresh",
          {},
          { cookie: "steward_rt=rt-secret" },
        ),
      );
      expect(res.status).toBe(200);

      // The API received exactly the cookie-held token.
      expect(upstreamRequests).toHaveLength(1);
      expect(upstreamRequests[0].path).toBe("/auth/refresh");
      expect(upstreamRequests[0].body).toEqual({ refreshToken: "rt-secret" });

      // The browser gets the access token but NEVER the rotated refresh token.
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.token).toBe("new-access-jwt");
      expect(body.refreshToken).toBeUndefined();

      // The rotated token goes straight into the HttpOnly cookie.
      const cookie = res.headers.get("Set-Cookie") ?? "";
      expect(cookie).toContain("steward_rt=rotated-rt");
      expect(cookie).toContain("HttpOnly");
    });

    test("refresh forwards tenantId for tenant switching", async () => {
      const res = await refreshPOST(
        postJson(
          "https://app.example.test/api/auth/refresh",
          { tenantId: "tenant-2" },
          { cookie: "steward_rt=rt-secret" },
        ),
      );
      expect(res.status).toBe(200);
      expect(upstreamRequests[0].body).toEqual({ refreshToken: "rt-secret", tenantId: "tenant-2" });
    });

    test("a 401 from the API clears the cookie so the client signs out", async () => {
      upstreamStatus = 401;
      const res = await refreshPOST(
        postJson("https://app.example.test/api/auth/refresh", {}, { cookie: "steward_rt=stale" }),
      );
      expect(res.status).toBe(401);
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    test("revoke forwards the cookie token and always clears the cookie", async () => {
      const res = await revokePOST(
        postJson("https://app.example.test/api/auth/revoke", {}, { cookie: "steward_rt=rt-9" }),
      );
      expect(res.status).toBe(200);
      expect(upstreamRequests).toHaveLength(1);
      expect(upstreamRequests[0].path).toBe("/auth/revoke");
      expect(upstreamRequests[0].body).toEqual({ refreshToken: "rt-9" });
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });

    test("revoke without a cookie clears state without calling upstream", async () => {
      const res = await revokePOST(postJson("https://app.example.test/api/auth/revoke", {}));
      expect(res.status).toBe(200);
      expect(upstreamRequests).toHaveLength(0);
      expect(res.headers.get("Set-Cookie")).toContain("Max-Age=0");
    });
  });
});
