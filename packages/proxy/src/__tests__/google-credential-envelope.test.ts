import { describe, expect, it } from "bun:test";
import { GOOGLE_GOLDEN_VECTORS } from "@stwd/shared";
import { extractProviderCredentialForHost } from "../handlers/proxy";

describe("Google OAuth credential envelope", () => {
  it("imports the shared canonical corpus used by the API", () => {
    expect(GOOGLE_GOLDEN_VECTORS.map((v) => v.id)).toEqual(["GGV-01", "GGV-02"]);
  });
  it("injects only access token and never the refresh canary", () => {
    const value = JSON.stringify({
      schemaVersion: "steward.provider-google.credential.v1",
      accessToken: "access-canary",
      refreshToken: "refresh-canary",
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
});

describe("X OAuth credential envelope", () => {
  const value = JSON.stringify({
    schemaVersion: "steward.provider-x.credential.v1",
    accessToken: "x-access-canary",
    refreshToken: "x-refresh-canary",
  });

  it("injects only the X access token and never the refresh token", () => {
    expect(extractProviderCredentialForHost("api.x.com", value)).toBe("x-access-canary");
    expect(extractProviderCredentialForHost("api.x.com", value)).not.toContain("x-refresh-canary");
  });

  it("never forwards an X envelope to another host", () => {
    expect(() => extractProviderCredentialForHost("api.openai.com", value)).toThrow(
      "X OAuth credential used for a non-X host",
    );
  });

  it("fails closed for malformed X envelopes while preserving legacy raw tokens", () => {
    expect(() =>
      extractProviderCredentialForHost(
        "api.x.com",
        JSON.stringify({ schemaVersion: "steward.provider-x.credential.v1" }),
      ),
    ).toThrow("invalid X OAuth credential envelope");
    expect(() =>
      extractProviderCredentialForHost("api.x.com", JSON.stringify({ accessToken: "x" })),
    ).toThrow("invalid X OAuth credential envelope");
    expect(extractProviderCredentialForHost("api.x.com", "legacy-raw-x-access-token")).toBe(
      "legacy-raw-x-access-token",
    );
  });
});
