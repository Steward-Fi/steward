import { expect, test } from "@playwright/test";

const COOP = "same-origin-allow-popups";
const CORP = "same-origin";

// This file verifies the policy itself. The shared trust-UX suite retains its
// historical bypass, but these contexts must let Chromium enforce the CSP.
test.use({ bypassCSP: false });

function values(headers: Array<{ name: string; value: string }>, name: string): string[] {
  return headers
    .filter((header) => header.name.toLowerCase() === name.toLowerCase())
    .map((header) => header.value);
}

function nonceFromCsp(csp: string): string {
  const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
  expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
  return nonce!;
}

function executableScriptNonces(html: string): Array<string | undefined> {
  return [...html.matchAll(/<script\b([^>]*)>/gi)]
    .filter(([, attributes]) => !/\btype=["']application\/(?:ld\+json|json)["']/i.test(attributes))
    .map(([, attributes]) => attributes.match(/\bnonce=["']([^"']+)["']/i)?.[1]);
}

test("production server applies middleware only to intended HTML routes", async ({ request }) => {
  for (const path of ["/api-keys", "/dashboard", "/login"]) {
    const response = await request.get(path, {
      headers: { "content-security-policy": "default-src *", "x-nonce": "attacker-controlled" },
    });
    expect(response.status(), path).toBe(200);
    const csp = response.headers()["content-security-policy"];
    expect(csp, path).toContain("nonce-");
    expect(csp, path).not.toContain("attacker-controlled");
    expect(values(response.headersArray(), "cross-origin-opener-policy"), path).toEqual([COOP]);
    expect(values(response.headersArray(), "cross-origin-resource-policy"), path).toEqual([CORP]);
    const nonce = nonceFromCsp(csp);
    const scriptNonces = executableScriptNonces(await response.text());
    expect(scriptNonces.length, `${path} executable Next scripts`).toBeGreaterThan(0);
    expect(new Set(scriptNonces), `${path} rendered script nonces`).toEqual(new Set([nonce]));
  }

  const api = await request.post("/api/auth/session", { data: {} });
  expect(api.status()).toBe(403);
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

test("browser hydrates under CSP and enforces exact inline-script nonce binding", async ({
  page,
}) => {
  await page.goto("/api-keys");
  await expect(page.getByRole("heading", { name: "API keys" })).toBeVisible();
  await page.waitForFunction(() =>
    Array.isArray((window as typeof window & { __next_f?: unknown[] }).__next_f),
  );

  const nonce = await page
    .locator("script[nonce]")
    .first()
    .evaluate((script) => script.nonce);
  expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);

  async function appendInlineScript(key: string, candidateNonce?: string): Promise<boolean> {
    return page.evaluate(
      ({ candidateNonce, key }) => {
        const target = window as typeof window & Record<string, unknown>;
        delete target[key];
        const script = document.createElement("script");
        if (candidateNonce !== undefined) script.nonce = candidateNonce;
        script.textContent = `window[${JSON.stringify(key)}] = true`;
        document.head.append(script);
        script.remove();
        return target[key] === true;
      },
      { candidateNonce, key },
    );
  }

  expect(await appendInlineScript("__stewardMissingNonce")).toBe(false);
  expect(await appendInlineScript("__stewardMismatchedNonce", `${nonce}-attacker`)).toBe(false);
  expect(await appendInlineScript("__stewardExactNonce", nonce)).toBe(true);

  // A Next Link must perform client-side navigation after hydration. A full
  // document navigation would discard this in-memory sentinel.
  await page.evaluate(() => {
    (
      window as typeof window & { __stewardNavigationSentinel?: string }
    ).__stewardNavigationSentinel = "preserved";
  });
  await Promise.all([
    page.waitForURL("**/dashboard/secrets"),
    page.getByRole("link", { name: "Manage governed credentials" }).click(),
  ]);
  expect(
    await page.evaluate(
      () =>
        (window as typeof window & { __stewardNavigationSentinel?: string })
          .__stewardNavigationSentinel,
    ),
  ).toBe("preserved");
});
