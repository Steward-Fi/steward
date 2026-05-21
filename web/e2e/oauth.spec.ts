import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";
const FAKE_OAUTH = process.env.E2E_FAKE_OAUTH_URL ?? "http://localhost:5599";

/**
 * Drives the OAuth authorization-code flow end-to-end against the fake
 * provider server. The fake provider issues a `code`; Steward exchanges it
 * with the fake `/token` endpoint, fetches the profile, mints a JWT, and
 * redirects to the configured redirect_uri.
 */
async function runOAuthFlow(
  request: import("@playwright/test").APIRequestContext,
  provider: "google" | "discord",
  loginHint: string,
): Promise<{ status: number; location: string | null }> {
  // 1. Hit Steward's /authorize. It redirects to the fake provider with state.
  const redirectUri = `${WEB}/auth/oauth/${provider}/callback`;
  const authorizeUrl = `${API}/auth/oauth/${provider}/authorize?redirect_uri=${encodeURIComponent(
    redirectUri,
  )}`;
  const stewardAuthRes = await request.get(authorizeUrl, { maxRedirects: 0 });
  expect([302, 303]).toContain(stewardAuthRes.status());
  const fakeAuthorize = stewardAuthRes.headers().location;
  expect(fakeAuthorize).toContain(`${FAKE_OAUTH}/${provider}/authorize`);

  // 2. Follow the redirect to the fake provider, asking it to mint a profile
  //    matching our login_hint. The fake redirects back to Steward's callback
  //    with a code + state.
  const fakeUrl = new URL(fakeAuthorize!);
  fakeUrl.searchParams.set("login_hint", loginHint);
  const fakeRes = await request.get(fakeUrl.toString(), { maxRedirects: 0 });
  expect([302, 303]).toContain(fakeRes.status());
  const stewardCallback = fakeRes.headers().location;
  expect(stewardCallback).toContain(`${API}/auth/oauth/${provider}/callback`);

  // 3. Hit Steward's /callback. Steward exchanges the code with the fake
  //    /token + /userinfo and redirects to redirect_uri with token(s).
  const callbackRes = await request.get(stewardCallback!, { maxRedirects: 0 });
  return {
    status: callbackRes.status(),
    location: callbackRes.headers().location ?? null,
  };
}

test.describe("OAuth — Google + Discord against fake provider", () => {
  for (const provider of ["google", "discord"] as const) {
    test(`${provider}: full authorization-code flow mints a session`, async ({ request }) => {
      const email = `${provider}-user-${Date.now()}@example.test`;
      const { status, location } = await runOAuthFlow(request, provider, email);
      expect([302, 303]).toContain(status);
      expect(location).toBeTruthy();
      const cb = new URL(location!);
      // The flow ends back at the web app with either ?code= (nonce-exchange)
      // or ?token=&refreshToken= (legacy). Either is acceptable here.
      const hasCode = cb.searchParams.get("code");
      const hasToken = cb.searchParams.get("token");
      expect(hasCode || hasToken).toBeTruthy();
    });
  }

  test("OAuth state is rejected on tamper (invalid state → 4xx)", async ({ request }) => {
    // Manually craft a callback with garbage state — Steward should reject.
    const res = await request.get(
      `${API}/auth/oauth/google/callback?code=abc&state=not-a-real-state`,
      { maxRedirects: 0 },
    );
    expect(res.status()).toBeGreaterThanOrEqual(400);
    expect(res.status()).toBeLessThan(500);
  });
});
