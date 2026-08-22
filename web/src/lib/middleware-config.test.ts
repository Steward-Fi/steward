import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server";
import { NextRequest } from "next/server";
import { config, middleware } from "../middleware";

const EXPECTED_SECURITY_HEADERS = {
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
} as const;

function matchesMiddleware(pathname: string): boolean {
  return unstable_doesMiddlewareMatch({ config, url: `https://steward.test${pathname}` });
}

function configuredHeaders(allowInsecureHttp: boolean) {
  const webRoot = join(import.meta.dir, "..", "..");
  const { E2E_ALLOW_INSECURE_HTTP: _ignored, ...cleanEnv } = process.env;
  const result = Bun.spawnSync({
    cmd: [
      process.execPath,
      "--eval",
      'const { default: config } = await import("./next.config.ts"); console.log(JSON.stringify(await config.headers?.()));',
    ],
    cwd: webRoot,
    env: allowInsecureHttp ? { ...cleanEnv, E2E_ALLOW_INSECURE_HTTP: "true" } : cleanEnv,
    stderr: "pipe",
    stdout: "pipe",
  });
  expect(result.exitCode, result.stderr.toString()).toBe(0);
  return JSON.parse(result.stdout.toString()) as Array<{
    source: string;
    headers: Array<{ key: string; value: string }>;
  }>;
}

describe("middleware security contract", () => {
  test("sets response headers and replaces attacker-controlled nonce inputs", () => {
    const previousApiUrl = process.env.NEXT_PUBLIC_STEWARD_API_URL;
    process.env.NEXT_PUBLIC_STEWARD_API_URL = "https://api.steward.test";
    try {
      const response = middleware(
        new NextRequest("https://steward.test/dashboard", {
          headers: { "x-nonce": "attacker-controlled", "content-security-policy": "default-src *" },
        }),
      );
      for (const [key, value] of Object.entries(EXPECTED_SECURITY_HEADERS)) {
        expect(response.headers.get(key)).toBe(value);
      }
      const csp = response.headers.get("Content-Security-Policy");
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("upgrade-insecure-requests");
      const nonce = csp?.match(/'nonce-([^']+)'/)?.[1];
      if (!nonce) throw new Error("middleware did not emit a nonce-bound CSP");
      expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
      expect(nonce).not.toBe("attacker-controlled");
      expect(response.headers.get("x-middleware-request-x-nonce")).toBe(nonce);
      expect(response.headers.get("x-middleware-request-content-security-policy")).toBe(csp);
    } finally {
      if (previousApiUrl === undefined) delete process.env.NEXT_PUBLIC_STEWARD_API_URL;
      else process.env.NEXT_PUBLIC_STEWARD_API_URL = previousApiUrl;
    }
  });
});

describe("exported middleware matcher", () => {
  test.each([
    "/api",
    "/api/auth/refresh",
    "/api/anything",
    "/_next/static/chunk.js",
    "/_next/image",
    "/favicon.ico",
    "/icon-192.png",
    "/apple-touch-icon.png",
    "/site.webmanifest",
  ])("excludes %s", (pathname) => expect(matchesMiddleware(pathname)).toBe(false));
  test.each(["/api-keys", "/dashboard", "/login"])("covers %s", (pathname) => {
    expect(matchesMiddleware(pathname)).toBe(true);
  });
  test.each([
    "/apiary",
    "/_next/staticity",
    "/_next/images",
    "/favicon.icoevil",
    "/faviconXico",
    "/icon-192.png/page",
    "/icon-192Xpng",
    "/icon-512.png-extra",
    "/apple-touch-icon.png.bak",
    "/siteXwebmanifest",
  ])("does not exempt hostile prefix/suffix path %s", (pathname) => {
    expect(matchesMiddleware(pathname)).toBe(true);
  });
  test("skips router prefetches through the exported missing-header rules", () => {
    expect(
      unstable_doesMiddlewareMatch({
        config,
        url: "https://steward.test/dashboard",
        headers: { purpose: "prefetch" },
      }),
    ).toBe(false);
  });
});

describe("next.config static security headers", () => {
  test("matches the middleware header posture by default", () => {
    const entries = configuredHeaders(false);
    expect(entries).toHaveLength(1);
    expect(entries[0]?.source).toBe("/:path*");
    expect(
      Object.fromEntries(entries[0]?.headers.map(({ key, value }) => [key, value]) ?? []),
    ).toEqual(EXPECTED_SECURITY_HEADERS);
  });
  test("only omits HSTS under the explicit e2e insecure-HTTP opt-out", () => {
    const entries = configuredHeaders(true);
    const actual = Object.fromEntries(
      entries[0]?.headers.map(({ key, value }) => [key, value]) ?? [],
    );
    const { "Strict-Transport-Security": _hsts, ...expected } = EXPECTED_SECURITY_HEADERS;
    expect(actual).toEqual(expected);
  });
});
