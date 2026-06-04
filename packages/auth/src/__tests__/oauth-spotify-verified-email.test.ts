import { describe, expect, it } from "bun:test";
import { getProviderConfig, OAuthClient } from "../oauth";

// Regression test for issue #103 (Spotify OAuth fails closed with 403).
//
// Spotify's /v1/me returns a real, confirmed account email but NO per-response
// verification flag, and the provider config has no emailUrl fallback. Before
// the fix, getUserInfo() therefore reported verified_email=false, and the
// account-takeover gate in provisionOAuthUser() rejected every Spotify login
// with 403 "Provider email must be verified before OAuth sign-in is allowed".
//
// The fix adds an `assertsEmailVerified` provider flag (set on Spotify) that
// marks a non-empty returned email as verified.

function asFetchMock(impl: (...args: any[]) => Promise<Response>): typeof fetch {
  return impl as unknown as typeof fetch;
}

function spotifyClient() {
  return new OAuthClient({
    clientId: "spotify-id",
    clientSecret: "spotify-secret",
    authorizationUrl: "https://accounts.spotify.com/authorize",
    tokenUrl: "https://accounts.spotify.com/api/token",
    userInfoUrl: "https://api.spotify.com/v1/me",
    scopes: ["user-read-email"],
    assertsEmailVerified: true,
    profileMap: {
      id: "id",
      email: "email",
      name: "display_name",
      picture: "images.0.url",
    },
  });
}

describe("Spotify OAuth verified-email (issue #103)", () => {
  it("built-in Spotify config asserts the returned email is verified", () => {
    process.env.SPOTIFY_CLIENT_ID = "spotify-id";
    process.env.SPOTIFY_CLIENT_SECRET = "spotify-secret";
    const config = getProviderConfig("spotify");
    expect(config.assertsEmailVerified).toBe(true);
    delete process.env.SPOTIFY_CLIENT_ID;
    delete process.env.SPOTIFY_CLIENT_SECRET;
  });

  it("marks verified_email=true for a real Spotify email with no verification flag", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(
          JSON.stringify({
            id: "spotify-user-id",
            display_name: "Spotify User",
            email: "user@example.com",
            images: [{ url: "https://i.scdn.co/image/avatar" }],
            // Note: Spotify returns NO verified/email_verified field.
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    const info = await spotifyClient().getUserInfo("tok");
    expect(info.id).toBe("spotify-user-id");
    expect(info.email).toBe("user@example.com");
    expect(info.name).toBe("Spotify User");
    // The fix: a confirmed-by-construction email is trusted as verified.
    expect(info.verified_email).toBe(true);
    globalThis.fetch = originalFetch;
  });

  it("does NOT fabricate verification when the provider returns no email", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = asFetchMock(
      async () =>
        new Response(JSON.stringify({ id: "spotify-user-id", display_name: "No Email" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const info = await spotifyClient().getUserInfo("tok");
    expect(info.email).toBe("");
    // No email => nothing to trust; the gate must still see verified_email=false.
    expect(info.verified_email).toBe(false);
    globalThis.fetch = originalFetch;
  });
});
