import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import { OAuthClient } from "../../packages/auth/src/oauth";
import { clearFakeOAuthState, setFakeOAuthUser, startFakeOAuthServer } from "../fake-oauth-server";

describe("fake-oauth-server", () => {
  let server: ReturnType<typeof startFakeOAuthServer>;

  beforeAll(() => {
    server = startFakeOAuthServer(0);
  });
  afterAll(async () => {
    await server.stop();
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
    const client = new OAuthClient({
      clientId: "x",
      clientSecret: "y",
      authorizationUrl: `${server.origin}/discord/authorize`,
      tokenUrl: `${server.origin}/discord/token`,
      userInfoUrl: `${server.origin}/discord/userinfo`,
      scopes: ["identify", "email"],
    });
    const { url } = client.generateAuthUrl("st", "http://localhost:1/cb");
    const authRes = await fetch(url, { redirect: "manual" });
    const code = new URL(authRes.headers.get("location")!).searchParams.get("code")!;
    await expect(client.exchangeCode(code, "http://localhost:1/different-cb")).rejects.toThrow(
      /redirect_uri/,
    );
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
});
