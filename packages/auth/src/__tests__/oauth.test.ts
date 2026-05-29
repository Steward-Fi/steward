import { describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { getEnabledProviders, getProviderConfig, isBuiltInProvider, OAuthClient } from "../oauth";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function verifyPkceChallenge(verifier: string, challenge: string): boolean {
  const expected = createHash("sha256").update(verifier).digest().toString("base64url");
  return expected === challenge;
}

function asFetchMock(impl: (...args: any[]) => Promise<Response>): typeof fetch {
  return impl as unknown as typeof fetch;
}

// ─── isBuiltInProvider ───────────────────────────────────────────────────────

describe("isBuiltInProvider", () => {
  it("returns true for supported OAuth provider ids", () => {
    for (const provider of [
      "google",
      "discord",
      "twitter",
      "github",
      "linkedin",
      "spotify",
      "twitch",
      "instagram",
      "line",
    ]) {
      expect(isBuiltInProvider(provider)).toBe(true);
    }
  });

  it("returns false for unknown providers", () => {
    expect(isBuiltInProvider("facebook")).toBe(false);
    expect(isBuiltInProvider("")).toBe(false);
  });

  it("returns true for configured custom providers", () => {
    const original = process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = JSON.stringify([
      {
        id: "acme",
        clientId: "cid",
        clientSecret: "secret",
        authorizationUrl: "https://idp.example.com/auth",
        tokenUrl: "https://idp.example.com/token",
        userInfoUrl: "https://idp.example.com/userinfo",
        scopes: ["openid"],
      },
    ]);
    expect(isBuiltInProvider("custom:acme")).toBe(true);
    expect(isBuiltInProvider("acme")).toBe(true);
    if (original === undefined) {
      delete process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    } else {
      process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = original;
    }
  });
});

// ─── getEnabledProviders ─────────────────────────────────────────────────────

describe("getEnabledProviders", () => {
  it("returns empty array when no provider env vars are set", () => {
    const orig = {
      GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
      GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
      DISCORD_CLIENT_ID: process.env.DISCORD_CLIENT_ID,
      DISCORD_CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET,
      TWITTER_CLIENT_ID: process.env.TWITTER_CLIENT_ID,
      TWITTER_CLIENT_SECRET: process.env.TWITTER_CLIENT_SECRET,
      GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID,
      GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
      LINKEDIN_CLIENT_ID: process.env.LINKEDIN_CLIENT_ID,
      LINKEDIN_CLIENT_SECRET: process.env.LINKEDIN_CLIENT_SECRET,
      SPOTIFY_CLIENT_ID: process.env.SPOTIFY_CLIENT_ID,
      SPOTIFY_CLIENT_SECRET: process.env.SPOTIFY_CLIENT_SECRET,
      TWITCH_CLIENT_ID: process.env.TWITCH_CLIENT_ID,
      TWITCH_CLIENT_SECRET: process.env.TWITCH_CLIENT_SECRET,
      INSTAGRAM_CLIENT_ID: process.env.INSTAGRAM_CLIENT_ID,
      INSTAGRAM_CLIENT_SECRET: process.env.INSTAGRAM_CLIENT_SECRET,
      LINE_CLIENT_ID: process.env.LINE_CLIENT_ID,
      LINE_CLIENT_SECRET: process.env.LINE_CLIENT_SECRET,
      STEWARD_CUSTOM_OAUTH_PROVIDERS: process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS,
    };
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.DISCORD_CLIENT_ID;
    delete process.env.DISCORD_CLIENT_SECRET;
    delete process.env.TWITTER_CLIENT_ID;
    delete process.env.TWITTER_CLIENT_SECRET;
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    delete process.env.LINKEDIN_CLIENT_ID;
    delete process.env.LINKEDIN_CLIENT_SECRET;
    delete process.env.SPOTIFY_CLIENT_ID;
    delete process.env.SPOTIFY_CLIENT_SECRET;
    delete process.env.TWITCH_CLIENT_ID;
    delete process.env.TWITCH_CLIENT_SECRET;
    delete process.env.INSTAGRAM_CLIENT_ID;
    delete process.env.INSTAGRAM_CLIENT_SECRET;
    delete process.env.LINE_CLIENT_ID;
    delete process.env.LINE_CLIENT_SECRET;
    delete process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    expect(getEnabledProviders()).toEqual([]);
    Object.assign(process.env, orig);
  });

  it("includes google when both google vars are set", () => {
    process.env.GOOGLE_CLIENT_ID = "gid";
    process.env.GOOGLE_CLIENT_SECRET = "gsecret";
    delete process.env.DISCORD_CLIENT_ID;
    delete process.env.DISCORD_CLIENT_SECRET;
    delete process.env.TWITTER_CLIENT_ID;
    delete process.env.TWITTER_CLIENT_SECRET;
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    expect(getEnabledProviders()).toContain("google");
    expect(getEnabledProviders()).not.toContain("discord");
    expect(getEnabledProviders()).not.toContain("twitter");
    expect(getEnabledProviders()).not.toContain("github");
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
  });

  it("does not include google if only one var is set", () => {
    process.env.GOOGLE_CLIENT_ID = "gid";
    delete process.env.GOOGLE_CLIENT_SECRET;
    expect(getEnabledProviders()).not.toContain("google");
    delete process.env.GOOGLE_CLIENT_ID;
  });
});

// ─── getProviderConfig ───────────────────────────────────────────────────────

describe("getProviderConfig", () => {
  it("throws for unknown providers", () => {
    expect(() => getProviderConfig("facebook")).toThrow("Unknown OAuth provider");
  });

  it("throws when google env vars are missing", () => {
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    expect(() => getProviderConfig("google")).toThrow("Google OAuth not configured");
  });

  it("throws when discord env vars are missing", () => {
    delete process.env.DISCORD_CLIENT_ID;
    delete process.env.DISCORD_CLIENT_SECRET;
    expect(() => getProviderConfig("discord")).toThrow("Discord OAuth not configured");
  });

  it("throws when twitter env vars are missing", () => {
    delete process.env.TWITTER_CLIENT_ID;
    delete process.env.TWITTER_CLIENT_SECRET;
    expect(() => getProviderConfig("twitter")).toThrow("Twitter OAuth not configured");
  });

  it("throws when github env vars are missing", () => {
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    expect(() => getProviderConfig("github")).toThrow("GitHub OAuth not configured");
  });

  it("returns config with requiresPkce=true for Twitter", () => {
    process.env.TWITTER_CLIENT_ID = "tid";
    process.env.TWITTER_CLIENT_SECRET = "tsecret";
    const config = getProviderConfig("twitter");
    expect(config.requiresPkce).toBe(true);
    delete process.env.TWITTER_CLIENT_ID;
    delete process.env.TWITTER_CLIENT_SECRET;
  });

  it("returns config without requiresPkce for Google and Discord", () => {
    process.env.GOOGLE_CLIENT_ID = "gid";
    process.env.GOOGLE_CLIENT_SECRET = "gsecret";
    process.env.DISCORD_CLIENT_ID = "did";
    process.env.DISCORD_CLIENT_SECRET = "dsecret";
    expect(getProviderConfig("google").requiresPkce).toBeFalsy();
    expect(getProviderConfig("discord").requiresPkce).toBeFalsy();
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.DISCORD_CLIENT_ID;
    delete process.env.DISCORD_CLIENT_SECRET;
  });

  it("returns config with GitHub email fallback endpoint", () => {
    process.env.GITHUB_CLIENT_ID = "ghid";
    process.env.GITHUB_CLIENT_SECRET = "ghsecret";
    const config = getProviderConfig("github");
    expect(config.emailUrl).toBe("https://api.github.com/user/emails");
    expect(config.scopes).toEqual(["read:user", "user:email"]);
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
  });

  it("returns configs for additional OAuth-style social providers", () => {
    for (const provider of ["linkedin", "spotify", "twitch", "instagram", "line"]) {
      const prefix = provider.toUpperCase();
      process.env[`${prefix}_CLIENT_ID`] = `${provider}-id`;
      process.env[`${prefix}_CLIENT_SECRET`] = `${provider}-secret`;
      const config = getProviderConfig(provider);
      expect(config.clientId).toBe(`${provider}-id`);
      expect(config.authorizationUrl).toStartWith("https://");
      expect(config.tokenUrl).toStartWith("https://");
      expect(config.userInfoUrl).toStartWith("https://");
      delete process.env[`${prefix}_CLIENT_ID`];
      delete process.env[`${prefix}_CLIENT_SECRET`];
    }
  });

  it("loads custom OAuth2 provider configs with PKCE and profile mapping", () => {
    const original = process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = JSON.stringify([
      {
        id: "custom-acme",
        clientId: "custom-id",
        clientSecret: "custom-secret",
        authorizationUrl: "https://idp.example.com/auth",
        tokenUrl: "https://idp.example.com/token",
        userInfoUrl: "https://idp.example.com/userinfo",
        scopes: ["openid", "profile"],
        requiresPkce: true,
        profileMap: {
          id: "identity.id",
          email: "identity.email",
          name: "profile.displayName",
        },
      },
    ]);
    const config = getProviderConfig("custom:custom-acme");
    expect(config).toMatchObject({
      clientId: "custom-id",
      requiresPkce: true,
      scopes: ["openid", "profile"],
    });
    expect(getEnabledProviders()).toContain("custom:custom-acme");
    if (original === undefined) {
      delete process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    } else {
      process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = original;
    }
  });

  it("rejects insecure custom OAuth2 provider URLs", () => {
    const original = process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = JSON.stringify([
      {
        id: "bad",
        clientId: "custom-id",
        clientSecret: "custom-secret",
        authorizationUrl: "http://idp.example.com/auth",
        tokenUrl: "https://idp.example.com/token",
        userInfoUrl: "https://idp.example.com/userinfo",
        scopes: ["openid"],
      },
    ]);
    expect(() => getProviderConfig("custom:bad")).toThrow("authorizationUrl must be an https URL");
    if (original === undefined) {
      delete process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    } else {
      process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = original;
    }
  });

  it("rejects insecure custom OAuth2 email fallback URLs", () => {
    const original = process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = JSON.stringify([
      {
        id: "bad-email",
        clientId: "custom-id",
        clientSecret: "custom-secret",
        authorizationUrl: "https://idp.example.com/auth",
        tokenUrl: "https://idp.example.com/token",
        userInfoUrl: "https://idp.example.com/userinfo",
        emailUrl: "http://169.254.169.254/latest/meta-data",
        scopes: ["openid", "email"],
      },
    ]);
    expect(() => getProviderConfig("custom:bad-email")).toThrow(
      "emailUrl must be an https URL",
    );
    if (original === undefined) {
      delete process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS;
    } else {
      process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS = original;
    }
  });
});

// ─── OAuthClient.generateAuthUrl ─────────────────────────────────────────────

describe("OAuthClient.generateAuthUrl", () => {
  const googleConfig = {
    clientId: "google-client-id",
    clientSecret: "google-secret",
    authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
    scopes: ["openid", "email", "profile"],
  };

  const twitterConfig = {
    clientId: "twitter-client-id",
    clientSecret: "twitter-secret",
    authorizationUrl: "https://x.com/i/oauth2/authorize",
    tokenUrl: "https://api.x.com/2/oauth2/token",
    userInfoUrl: "https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url",
    scopes: ["tweet.read", "users.read", "offline.access"],
    requiresPkce: true,
  };

  it("generates a well-formed URL for non-PKCE providers", () => {
    const client = new OAuthClient(googleConfig);
    const { url, codeVerifier } = client.generateAuthUrl("state123", "https://app.com/callback");
    expect(url).toContain("accounts.google.com");
    expect(url).toContain("state=state123");
    expect(url).toContain("redirect_uri=");
    expect(url).toContain("response_type=code");
    expect(url).toContain("scope=openid+email+profile");
    expect(codeVerifier).toBeUndefined();
  });

  it("does NOT include code_challenge params for non-PKCE providers", () => {
    const client = new OAuthClient(googleConfig);
    const { url } = client.generateAuthUrl("state123", "https://app.com/callback");
    expect(url).not.toContain("code_challenge");
  });

  it("generates PKCE params for Twitter", () => {
    const client = new OAuthClient(twitterConfig);
    const { url, codeVerifier } = client.generateAuthUrl("state456", "https://app.com/callback");
    expect(url).toContain("code_challenge_method=S256");
    expect(url).toContain("code_challenge=");
    expect(typeof codeVerifier).toBe("string");
    expect(codeVerifier?.length).toBeGreaterThan(20);
  });

  it("PKCE code_challenge is the SHA-256 hash of the verifier (S256)", () => {
    const client = new OAuthClient(twitterConfig);
    const { url, codeVerifier } = client.generateAuthUrl("state456", "https://app.com/callback");
    const params = new URLSearchParams(new URL(url).search);
    const challenge = params.get("code_challenge")!;
    expect(verifyPkceChallenge(codeVerifier!, challenge)).toBe(true);
  });

  it("generates unique codeVerifiers on each call", () => {
    const client = new OAuthClient(twitterConfig);
    const { codeVerifier: v1 } = client.generateAuthUrl("s1", "https://app.com/cb");
    const { codeVerifier: v2 } = client.generateAuthUrl("s2", "https://app.com/cb");
    expect(v1).not.toBe(v2);
  });

  it("rejects insecure provider endpoints by default", () => {
    expect(
      () =>
        new OAuthClient({
          clientId: "c",
          clientSecret: "s",
          authorizationUrl: "https://example.com/auth",
          tokenUrl: "https://example.com/token",
          userInfoUrl: "http://127.0.0.1/userinfo",
          scopes: [],
        }),
    ).toThrow("userInfoUrl must be an https URL");
  });

  it("allows insecure provider endpoints only with the explicit non-production test flag", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    const previousAllow = process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS;
    process.env.NODE_ENV = "test";
    process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS = "true";
    try {
      expect(
        () =>
          new OAuthClient({
            clientId: "c",
            clientSecret: "s",
            authorizationUrl: "http://127.0.0.1/auth",
            tokenUrl: "http://127.0.0.1/token",
            userInfoUrl: "http://127.0.0.1/userinfo",
            scopes: [],
          }),
      ).not.toThrow();
    } finally {
      if (previousNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = previousNodeEnv;
      }
      if (previousAllow === undefined) {
        delete process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS;
      } else {
        process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS = previousAllow;
      }
    }
  });
});

// ─── OAuthClient.exchangeCode ─────────────────────────────────────────────────

describe("OAuthClient.exchangeCode", () => {
  const pkceConfig = {
    clientId: "client",
    clientSecret: "secret",
    authorizationUrl: "https://example.com/auth",
    tokenUrl: "https://example.com/token",
    userInfoUrl: "https://example.com/userinfo",
    scopes: ["read"],
    requiresPkce: true,
  };

  it("throws if codeVerifier is missing for a PKCE provider", async () => {
    const client = new OAuthClient(pkceConfig);
    await expect(client.exchangeCode("auth-code", "https://app.com/cb")).rejects.toThrow(
      "codeVerifier is required",
    );
  });

  it("includes code_verifier in the token request body for PKCE providers", async () => {
    let capturedBody = "";
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(async (_url: string | URL | Request, init?: RequestInit) => {
      capturedBody = init?.body?.toString() ?? "";
      return new Response(JSON.stringify({ access_token: "tok", token_type: "Bearer" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const client = new OAuthClient(pkceConfig);
    await client.exchangeCode("auth-code", "https://app.com/cb", "my-verifier");
    expect(capturedBody).toContain("code_verifier=my-verifier");
    globalThis.fetch = originalFetch;
  });

  it("throws on non-200 token response", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response("invalid_client", {
          status: 401,
          headers: { "Content-Type": "text/plain" },
        }),
    );
    const client = new OAuthClient({ ...pkceConfig, requiresPkce: false });
    await expect(client.exchangeCode("code", "https://app.com/cb")).rejects.toThrow(
      "Token exchange failed (401)",
    );
    globalThis.fetch = originalFetch;
  });
});

// ─── OAuthClient.getUserInfo — Twitter response normalization ─────────────────

describe("OAuthClient.getUserInfo — provider response normalization", () => {
  function makeClient() {
    return new OAuthClient({
      clientId: "c",
      clientSecret: "s",
      authorizationUrl: "https://example.com/auth",
      tokenUrl: "https://example.com/token",
      userInfoUrl: "https://example.com/userinfo",
      scopes: [],
    });
  }

  it("parses flat Google/Discord response shape", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(
          JSON.stringify({
            id: "google-user-id",
            email: "user@gmail.com",
            name: "Test User",
            picture: "https://lh3.googleusercontent.com/a/photo",
            verified_email: true,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    const client = makeClient();
    const info = await client.getUserInfo("tok");
    expect(info.id).toBe("google-user-id");
    expect(info.email).toBe("user@gmail.com");
    expect(info.name).toBe("Test User");
    expect(info.verified_email).toBe(true);
    globalThis.fetch = originalFetch;
  });

  it("parses Twitter's nested data envelope — no email", async () => {
    // Twitter v2 wraps user data inside { data: { id, name, username } }
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(
          JSON.stringify({
            data: {
              id: "twitter-user-id",
              name: "Test Twitter User",
              username: "testuser",
              profile_image_url: "https://pbs.twimg.com/profile.jpg",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    const client = makeClient();
    const info = await client.getUserInfo("tok");
    expect(info.id).toBe("twitter-user-id");
    expect(info.name).toBe("Test Twitter User");
    expect(info.picture).toBe("https://pbs.twimg.com/profile.jpg");
    // Critical: Twitter returns no email — must be empty string
    expect(info.email).toBe("");
    globalThis.fetch = originalFetch;
  });

  it("falls back to username as name when name field absent (Twitter)", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(JSON.stringify({ data: { id: "tid", username: "handle" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const client = makeClient();
    const info = await client.getUserInfo("tok");
    expect(info.name).toBe("handle");
    globalThis.fetch = originalFetch;
  });

  it("fetches GitHub email from /user/emails when /user email is empty", async () => {
    const originalFetch = globalThis.fetch;
    let callCount = 0;
    globalThis.fetch = asFetchMock(async (input) => {
      const url = String(input);
      callCount += 1;
      if (url.endsWith("/userinfo")) {
        return new Response(
          JSON.stringify({
            id: "gh-123",
            login: "octocat",
            name: "The Octocat",
            avatar_url: "https://github.com/images/error/octocat_happy.gif",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify([
          { email: "secondary@example.com", primary: false, verified: true },
          { email: "primary@example.com", primary: true, verified: true },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new OAuthClient({
      clientId: "c",
      clientSecret: "s",
      authorizationUrl: "https://example.com/auth",
      tokenUrl: "https://example.com/token",
      userInfoUrl: "https://example.com/userinfo",
      emailUrl: "https://example.com/emails",
      scopes: [],
    });
    const info = await client.getUserInfo("tok");
    expect(callCount).toBe(2);
    expect(info.id).toBe("gh-123");
    expect(info.email).toBe("primary@example.com");
    expect(info.picture).toBe("https://github.com/images/error/octocat_happy.gif");
    expect(info.verified_email).toBe(true);
    globalThis.fetch = originalFetch;
  });

  it("maps custom provider profile fields including nested array paths", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(
          JSON.stringify({
            identity: { id: "custom-user", email: "custom@example.com" },
            profile: {
              displayName: "Custom User",
              photos: [{ url: "https://cdn.example.com/avatar.png" }],
            },
            flags: { verified: true },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    const client = new OAuthClient({
      clientId: "c",
      clientSecret: "s",
      authorizationUrl: "https://example.com/auth",
      tokenUrl: "https://example.com/token",
      userInfoUrl: "https://example.com/userinfo",
      scopes: [],
      profileMap: {
        id: "identity.id",
        email: "identity.email",
        name: "profile.displayName",
        picture: "profile.photos.0.url",
        emailVerified: "flags.verified",
      },
    });
    const info = await client.getUserInfo("tok");
    expect(info).toEqual({
      id: "custom-user",
      email: "custom@example.com",
      name: "Custom User",
      picture: "https://cdn.example.com/avatar.png",
      verified_email: true,
    });
    globalThis.fetch = originalFetch;
  });

  it("throws on non-200 userinfo response", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response("Unauthorized", {
          status: 401,
          headers: { "Content-Type": "text/plain" },
        }),
    );
    const client = makeClient();
    await expect(client.getUserInfo("bad-token")).rejects.toThrow("getUserInfo failed (401)");
    globalThis.fetch = originalFetch;
  });
});
