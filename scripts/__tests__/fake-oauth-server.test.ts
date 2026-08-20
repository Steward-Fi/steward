import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { OAuthClient } from "../../packages/auth/src/oauth";
import { clearFakeOAuthState, setFakeOAuthUser, startFakeOAuthServer } from "../fake-oauth-server";

describe("fake-oauth-server", () => {
  let server: ReturnType<typeof startFakeOAuthServer>;
  let prevAllowInsecure: string | undefined;

  beforeAll(() => {
    // OAuthClient rejects non-https provider URLs unless this opt-in is set
    // (same flag web/e2e/global-setup.ts uses); the stub serves http://127.0.0.1.
    prevAllowInsecure = process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS;
    process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS = "true";
    server = startFakeOAuthServer(0);
  });
  afterAll(async () => {
    await server.stop();
    if (prevAllowInsecure === undefined) {
      delete process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS;
    } else {
      process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS = prevAllowInsecure;
    }
  });
  afterEach(() => clearFakeOAuthState());

  it("authorize → token → userinfo round-trip works with OAuthClient", async () => {
    setFakeOAuthUser("google", {
      id: "user-1",
      email: "alice@example.com",
      name: "Alice",
      verified_email: true,
    });

    const client = new OAuthClient({
      clientId: "test-client",
      clientSecret: "test-secret",
      authorizationUrl: `${server.origin}/google/authorize`,
      tokenUrl: `${server.origin}/google/token`,
      userInfoUrl: `${server.origin}/google/userinfo`,
      scopes: ["openid", "email", "profile"],
    });

    const redirectUri = "http://localhost:3999/auth/oauth/google/callback";
    const { url } = client.generateAuthUrl("state-xyz", redirectUri);

    // Follow the authorize redirect by hand — fetch with `redirect: manual`
    // so we can read the Location header that carries the issued code.
    const authRes = await fetch(url, { redirect: "manual" });
    expect([302, 303]).toContain(authRes.status);
    const location = authRes.headers.get("location");
    expect(location).toBeTruthy();
    const cb = new URL(location!);
    const code = cb.searchParams.get("code");
    expect(cb.searchParams.get("state")).toBe("state-xyz");
    expect(code).toBeTruthy();

    const tokenRes = await client.exchangeCode(code!, redirectUri);
    expect(tokenRes.access_token).toMatch(/^[a-f0-9]{48}$/);

    const profile = await client.getUserInfo(tokenRes.access_token);
    expect(profile.email).toBe("alice@example.com");
    expect(profile.id).toBe("user-1");
    expect(profile.name).toBe("Alice");
  });

  it("rejects redirect_uri mismatch at token exchange", async () => {
    const authRes = await fetch(
      `${server.origin}/discord/authorize?redirect_uri=http://localhost:1/cb&state=s&client_id=x&response_type=code&scope=identify`,
      { redirect: "manual" },
    );
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    // Exercise the stub directly: OAuthClient intentionally sanitizes
    // provider error bodies ("Token exchange failed (400)"), so the
    // redirect_uri enforcement is asserted at the server boundary.
    const tokenRes = await fetch(`${server.origin}/discord/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "x",
        client_secret: "y",
        code,
        redirect_uri: "http://localhost:1/different-cb",
      }).toString(),
    });
    expect(tokenRes.status).toBe(400);
    const body = (await tokenRes.json()) as { error: string };
    expect(body.error).toBe("redirect_uri mismatch");
  });

  it("login_hint mints a deterministic profile", async () => {
    const url = `${server.origin}/google/authorize?redirect_uri=http://localhost:1/cb&state=s&login_hint=bob%40example.com&client_id=x&response_type=code&scope=openid`;
    const authRes = await fetch(url, { redirect: "manual" });
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;

    const tokenRes = await fetch(`${server.origin}/google/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: "x",
        client_secret: "y",
        code,
        redirect_uri: "http://localhost:1/cb",
      }).toString(),
    });
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const profileRes = await fetch(`${server.origin}/google/userinfo`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const profile = (await profileRes.json()) as { email: string };
    expect(profile.email).toBe("bob@example.com");
  });

  it("binds loopback only (SEC-128) — an auth-bypass stub must not listen on all interfaces", () => {
    // Bun.serve({ port }) defaults to 0.0.0.0, so bind the
    // accept-any-credential / mint-any-identity provider to the network.
    const source = readFileSync(new URL("../fake-oauth-server.ts", import.meta.url), "utf8");
    expect(source).toContain('hostname: "127.0.0.1"');
  });
});
