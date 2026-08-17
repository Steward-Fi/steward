// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const middlewareSource = readFileSync(join(import.meta.dir, "..", "middleware.ts"), "utf8");
const nextConfigSource = readFileSync(join(import.meta.dir, "..", "..", "next.config.ts"), "utf8");
const providersSource = readFileSync(
  join(import.meta.dir, "..", "components", "providers.tsx"),
  "utf8",
);

/**
 * SEC-155/SEC-156: middleware matcher anchoring + cross-origin isolation
 * headers. Source-level assertions mirror the repo's existing web test style
 * (see components/providers.test.ts).
 */
describe("middleware matcher anchoring (SEC-155)", () => {
  const matcherMatch = middlewareSource.match(/source:\s*\n?\s*"([^"]+)"/);
  const pattern = matcherMatch?.[1] ?? "";

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
  test("middleware sets COOP same-origin-allow-popups (keeps OAuth popup opener)", () => {
    expect(middlewareSource).toContain(
      '["Cross-Origin-Opener-Policy", "same-origin-allow-popups"]',
    );
    // Must NOT be plain same-origin — that severs window.opener for the OAuth
    // popup flow once the popup navigates cross-origin.
    expect(middlewareSource).not.toContain('["Cross-Origin-Opener-Policy", "same-origin"]');
  });

  test("middleware sets CORP same-origin", () => {
    expect(middlewareSource).toContain('"Cross-Origin-Resource-Policy"');
    expect(middlewareSource).toContain('"same-origin"');
  });

  test("static-asset headers in next.config.ts mirror COOP/CORP", () => {
    expect(nextConfigSource).toContain('"Cross-Origin-Opener-Policy"');
    expect(nextConfigSource).toContain('"Cross-Origin-Resource-Policy"');
  });

  test("no stale web/vercel.json CSP references remain", () => {
    expect(providersSource).not.toContain("vercel.json");
  });
});
