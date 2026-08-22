import { expect, test } from "@playwright/test";

const COOP = "same-origin-allow-popups";
const CORP = "same-origin";

function values(headers: Array<{ name: string; value: string }>, name: string): string[] {
  return headers
    .filter((header) => header.name.toLowerCase() === name.toLowerCase())
    .map((header) => header.value);
}

test("production server applies middleware only to intended HTML routes", async ({ request }) => {
  for (const path of ["/api-keys", "/dashboard", "/login"]) {
    const response = await request.get(path);
    expect(response.status(), path).toBeLessThan(500);
    expect(response.headers()["content-security-policy"], path).toContain("nonce-");
    expect(values(response.headersArray(), "cross-origin-opener-policy"), path).toEqual([COOP]);
    expect(values(response.headersArray(), "cross-origin-resource-policy"), path).toEqual([CORP]);
  }

  const api = await request.get("/api/auth/session");
  expect(api.status()).toBeLessThan(500);
  expect(api.headers()["content-security-policy"]).toBeUndefined();
  expect(values(api.headersArray(), "cross-origin-opener-policy")).toEqual([COOP]);
  expect(values(api.headersArray(), "cross-origin-resource-policy")).toEqual([CORP]);
});

test("production static/image/favicon paths have exact non-conflicting isolation headers", async ({
  request,
}) => {
  const login = await request.get("/login");
  const html = await login.text();
  const staticAsset = html.match(/(?:src|href)="([^"]*\/_next\/static\/[^"]+)"/)?.[1];
  expect(staticAsset).toBeTruthy();

  const paths = [
    staticAsset!,
    "/favicon.ico",
    "/icon-192.png",
    "/_next/image?url=%2Flogo.png&w=64&q=75",
  ];
  for (const path of paths) {
    const response = await request.get(path);
    expect(response.status(), path).toBeLessThan(500);
    const csp = response.headers()["content-security-policy"];
    if (path.startsWith("/_next/image")) {
      // Next's image optimizer adds its own fixed sandbox CSP. It must not be
      // confused with the nonce-bearing page middleware CSP.
      expect(csp).toBe("script-src 'none'; frame-src 'none'; sandbox;");
    } else {
      expect(csp, path).toBeUndefined();
    }
    expect(values(response.headersArray(), "cross-origin-opener-policy"), path).toEqual([COOP]);
    expect(values(response.headersArray(), "cross-origin-resource-policy"), path).toEqual([CORP]);
  }
});
