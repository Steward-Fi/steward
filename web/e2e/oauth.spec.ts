import { createHash, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";
const FAKE_OAUTH = process.env.E2E_FAKE_OAUTH_URL ?? "http://localhost:5599";

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Steward's authorize endpoint requires PKCE for response_type=code (the secure
 * default). The SDK generates this pair in the browser; here we replicate it so
 * the raw HTTP flow speaks the same protocol. Only the S256 challenge is needed
 * on /authorize — the verifier would be used at /oauth/exchange, which this
 * flow stops short of (it asserts the callback redirects back with a code).
 */
function pkcePair(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(32));
  return {
    verifier,
    challenge: base64url(createHash("sha256").update(verifier).digest()),
  };
}

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
): Promise<{
  status: number;
  location: string | null;
  redirectUri: string;
  codeVerifier: string;
}> {
  // 1. Hit Steward's /authorize. It redirects to the fake provider with state.
  const redirectUri = `${WEB}/auth/oauth/${provider}/callback`;
  const pkce = pkcePair();
  const appState = randomBytes(16).toString("hex");
  const authorizeUrl =
    `${API}/auth/oauth/${provider}/authorize?redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&code_challenge=${encodeURIComponent(pkce.challenge)}&code_challenge_method=S256` +
    `&state=${encodeURIComponent(appState)}`;
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
    redirectUri,
    codeVerifier: pkce.verifier,
  };
}

test.describe("OAuth — Google + Discord against fake provider", () => {
  for (const provider of ["google", "discord"] as const) {
    test(`${provider}: full authorization-code + PKCE exchange mints a session`, async ({
      request,
    }) => {
      // Globally unique per run: the 3 engines share one API instance with
      // persistent state, and OAuth identities are keyed by the provider account
      // id (derived from this email). A non-unique email would relink an existing
      // account and (correctly) 403. Date.now() + random guarantees uniqueness.
      const email = `${provider}-user-${Date.now()}-${randomBytes(6).toString("hex")}@example.test`;
      const { status, location, redirectUri, codeVerifier } = await runOAuthFlow(
        request,
        provider,
        email,
      );
      expect([302, 303]).toContain(status);
      expect(location).toBeTruthy();
      const cb = new URL(location!);
      // The nonce-exchange path returns the one-time code in the URL *fragment*
      // (`#code=...`, via setRedirectFragment) to keep it out of query logs /
      // Referer; the legacy path uses `?token=`. Check the fragment first, then
      // fall back to query params, accepting either code or token.
      const frag = new URLSearchParams(cb.hash.replace(/^#/, ""));
      const code = frag.get("code") ?? cb.searchParams.get("code");
      const state = frag.get("state") ?? cb.searchParams.get("state");
      expect(code).toBeTruthy();
      expect(state).toBeTruthy();
      expect(frag.get("token") ?? cb.searchParams.get("token")).toBeNull();
      expect(frag.get("refreshToken") ?? cb.searchParams.get("refreshToken")).toBeNull();

      const exchangeRes = await request.post(`${API}/auth/oauth/${provider}/token`, {
        data: { code, redirectUri, state, codeVerifier },
      });
      expect(exchangeRes.status()).toBe(200);
      const exchange = (await exchangeRes.json()) as {
        ok: boolean;
        token: string;
        refreshToken: string;
        user: { email: string };
      };
      expect(exchange.ok).toBe(true);
      expect(exchange.token.split(".")).toHaveLength(3);
      expect(exchange.refreshToken).toBeTruthy();
      expect(exchange.user.email).toBe(email);

      const replay = await request.post(`${API}/auth/oauth/${provider}/token`, {
        data: { code, redirectUri, state, codeVerifier },
      });
      expect(replay.status()).toBeGreaterThanOrEqual(400);
      expect(replay.status()).toBeLessThan(500);
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
