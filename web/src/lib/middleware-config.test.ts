// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { NextRequest } from "next/server";
import nextConfig from "../../next.config";
import { config, middleware } from "../middleware";

/**
 * SEC-155/SEC-156: middleware matcher anchoring + cross-origin isolation
 * headers. Source-level assertions mirror the repo's existing web test style
 * (see components/providers.test.ts).
 */
describe("middleware matcher anchoring (SEC-155)", () => {
  const pattern = config.matcher[0].source;

  test("the api exclusion is anchored to api/ only", () => {
    expect(pattern).toContain("(?!api/|");
    expect(pattern).not.toContain("(?!api|");
  });

  test("api routes are excluded but api-prefixed pages are not", () => {
    // The matcher source "/((?!api/|_next/static|...).*)" maps to a regex over
    // the full pathname: leading slash, then a segment not starting with an
    // excluded prefix.
    const regex = new RegExp(`^${pattern}$`);
    expect(regex.test("/api/auth/refresh")).toBe(false);
    expect(regex.test("/api/anything")).toBe(false);
    expect(regex.test("/api-keys")).toBe(true);
    expect(regex.test("/dashboard")).toBe(true);
    expect(regex.test("/login")).toBe(true);
    expect(regex.test("/_next/static/chunk.js")).toBe(false);
  });
});

describe("cross-origin isolation headers (SEC-156)", () => {
  test("middleware response preserves OAuth popups and restricts resource embedding", () => {
    const response = middleware(new NextRequest("https://steward.example/dashboard"));
    expect(response.headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin-allow-popups");
    expect(response.headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
  });

  test("static-asset responses mirror the middleware policy", async () => {
    const rules = await nextConfig.headers();
    const headers = new Map(rules[0].headers.map(({ key, value }) => [key, value]));
    expect(headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin-allow-popups");
    expect(headers.get("Cross-Origin-Resource-Policy")).toBe("same-origin");
  });
});
