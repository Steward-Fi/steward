import { afterEach, describe, expect, it } from "bun:test";
import { GOOGLE_GOLDEN_VECTORS } from "@stwd/shared";
import {
  __setGoogleRefreshFetcherForTests,
  extractProviderCredentialForHost,
  resolveProviderCredentialForHost,
} from "../handlers/proxy";

const originalFetch = globalThis.fetch;

afterEach(() => {
  __setGoogleRefreshFetcherForTests(null);
  delete process.env.GOOGLE_PROVIDER_CLIENT_ID;
  delete process.env.GOOGLE_PROVIDER_CLIENT_SECRET;
  globalThis.fetch = originalFetch;
});

describe("Google OAuth credential envelope", () => {
  it("imports the shared canonical corpus used by the API", () => {
    expect(GOOGLE_GOLDEN_VECTORS.map((v) => v.id)).toEqual(["GGV-01", "GGV-02"]);
  });
  it("injects only access token and never the refresh canary", () => {
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-canary",
      refreshToken: "refresh-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(extractProviderCredentialForHost("gmail.googleapis.com", value)).toBe("access-canary");
    expect(extractProviderCredentialForHost("gmail.googleapis.com", value)).not.toContain(
      "refresh-canary",
    );
  });
  it("never forwards a Google credential envelope to a non-Google host", () => {
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-canary",
      refreshToken: "refresh-canary",
    });
    expect(() => extractProviderCredentialForHost("api.openai.com", value)).toThrow(
      "Google OAuth credential used for a non-Google host",
    );
  });
  it("fails closed for malformed/wrong-schema envelopes", () => {
    expect(() =>
      extractProviderCredentialForHost("www.googleapis.com", "refresh-canary"),
    ).toThrow();
    expect(() =>
      extractProviderCredentialForHost("www.googleapis.com", JSON.stringify({ accessToken: "x" })),
    ).toThrow();
  });

  it("mints a fresh access token from the server-held refresh token when the cached token is near expiry", async () => {
    process.env.GOOGLE_PROVIDER_CLIENT_ID = "google-provider-client";
    process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "google-provider-secret";
    let refreshTokenSeen: string | null = null;
    __setGoogleRefreshFetcherForTests(async ({ refreshToken, allowedScopes }) => {
      refreshTokenSeen = refreshToken;
      expect(allowedScopes).toEqual([
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.send",
      ]);
      return {
        revoked: false,
        accessToken: "access-fresh-from-refresh",
        scopes: [...allowedScopes],
        expiresIn: 3600,
      };
    });
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-expiring",
      refreshToken: "refresh-server-held-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 1_000).toISOString(),
    });
    const token = await resolveProviderCredentialForHost("gmail.googleapis.com", value);
    expect(token).toBe("access-fresh-from-refresh");
    expect(token).not.toContain("refresh-server-held-canary");
    expect(refreshTokenSeen).toBe("refresh-server-held-canary");
  });

  it("fails closed when dispatch-time refresh rotates the Google refresh token", async () => {
    process.env.GOOGLE_PROVIDER_CLIENT_ID = "google-provider-client";
    process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "google-provider-secret";
    __setGoogleRefreshFetcherForTests(async () => ({
      revoked: false,
      accessToken: "access-fresh-from-refresh",
      refreshToken: "rotated-refresh-token",
      scopes: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      expiresIn: 3600,
    }));
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-expiring",
      refreshToken: "refresh-server-held-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 1_000).toISOString(),
    });
    await expect(resolveProviderCredentialForHost("gmail.googleapis.com", value)).rejects.toThrow(
      "Google refresh rotated the credential during governed dispatch",
    );
  });

  it("fails closed when dispatch-time refresh returns a still-near-expiry access token", async () => {
    process.env.GOOGLE_PROVIDER_CLIENT_ID = "google-provider-client";
    process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "google-provider-secret";
    __setGoogleRefreshFetcherForTests(async () => ({
      revoked: false,
      accessToken: "access-too-short-lived",
      scopes: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      expiresIn: 299,
    }));
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-expiring",
      refreshToken: "refresh-server-held-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 1_000).toISOString(),
    });
    await expect(resolveProviderCredentialForHost("gmail.googleapis.com", value)).rejects.toThrow(
      "Google refresh returned an access token that expires too soon",
    );
  });

  it("fails closed when dispatch-time refresh broadens granted scopes", async () => {
    process.env.GOOGLE_PROVIDER_CLIENT_ID = "google-provider-client";
    process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "google-provider-secret";
    __setGoogleRefreshFetcherForTests(async () => ({
      revoked: false,
      accessToken: "access-broadened",
      scopes: [
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/calendar.events",
      ],
      expiresIn: 3600,
    }));
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-expiring",
      refreshToken: "refresh-server-held-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 1_000).toISOString(),
    });
    await expect(resolveProviderCredentialForHost("gmail.googleapis.com", value)).rejects.toThrow(
      "Google refresh returned invalid scopes",
    );
  });

  it("uses the default Google refresh transport with redirect=error and form-encoded credentials", async () => {
    process.env.GOOGLE_PROVIDER_CLIENT_ID = "google-provider-client";
    process.env.GOOGLE_PROVIDER_CLIENT_SECRET = "google-provider-secret";
    let seenUrl: string | null = null;
    let seenInit: RequestInit | null = null;
    globalThis.fetch = (async (input, init) => {
      seenUrl = String(input);
      seenInit = init ?? null;
      return new Response(
        JSON.stringify({
          access_token: "access-fresh-from-upstream",
          scope: "openid email https://www.googleapis.com/auth/gmail.send",
          expires_in: 3600,
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    }) as typeof fetch;
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-expiring",
      refreshToken: "refresh-server-held-canary",
      scopesGranted: ["openid", "email", "https://www.googleapis.com/auth/gmail.send"],
      googleUserId: "google-user-123",
      googleEmail: "approver@example.com",
      obtainedAt: new Date(Date.now() - 30_000).toISOString(),
      expiresAt: new Date(Date.now() + 1_000).toISOString(),
    });
    await expect(resolveProviderCredentialForHost("gmail.googleapis.com", value)).resolves.toBe(
      "access-fresh-from-upstream",
    );
    expect(seenUrl).toBe("https://oauth2.googleapis.com/token");
    expect(seenInit?.redirect).toBe("error");
    expect(seenInit?.method).toBe("POST");
    expect(seenInit?.headers).toMatchObject({
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    });
    expect(String(seenInit?.body)).toContain("grant_type=refresh_token");
    expect(String(seenInit?.body)).toContain("refresh_token=refresh-server-held-canary");
    expect(String(seenInit?.body)).toContain("client_id=google-provider-client");
    expect(String(seenInit?.body)).toContain("client_secret=google-provider-secret");
  });
});
