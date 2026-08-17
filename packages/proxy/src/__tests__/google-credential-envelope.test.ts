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
  it("fails closed for malformed/wrong-schema envelopes", () => {
    expect(() =>
      extractProviderCredentialForHost("www.googleapis.com", "refresh-canary"),
    ).toThrow();
    expect(() =>
      extractProviderCredentialForHost("www.googleapis.com", JSON.stringify({ accessToken: "x" })),
    ).toThrow();
  });
});
