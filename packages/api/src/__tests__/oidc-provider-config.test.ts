import { describe, expect, it } from "bun:test";
import { normalizeOidcProviders } from "../services/oidc-provider-config";

const validProvider = {
  id: "enterprise",
  issuer: "https://idp.example.com",
  audience: ["steward-api"],
  jwksUri: "https://idp.example.com/.well-known/jwks.json",
  clientId: "steward-client",
  authorizationUrl: "https://idp.example.com/authorize",
  tokenUrl: "https://idp.example.com/token",
};

describe("OIDC provider public destination validation", () => {
  it("uses the fail-closed classifier for every configured endpoint", () => {
    const unsafeEndpoints = [
      "https://[::127.0.0.1]/endpoint",
      "https://[::ffff:0:127.0.0.1]/endpoint",
      "https://192.0.2.1/endpoint",
      "https://[100::1]/endpoint",
      "https://[3fff::1]/endpoint",
      "https://user:secret@idp.example.com/endpoint",
      "https://idp/endpoint",
      "https://idp.home.arpa/endpoint",
      "https://idp.test/endpoint",
    ];

    for (const field of ["issuer", "jwksUri", "authorizationUrl", "tokenUrl"] as const) {
      for (const endpoint of unsafeEndpoints) {
        const result = normalizeOidcProviders([{ ...validProvider, [field]: endpoint }]);
        expect(result, `${field}: ${endpoint}`).toBe(
          `${field} for provider enterprise must be a public https URL`,
        );
      }
    }
  });

  it("retains ordinary public HTTPS provider endpoints", () => {
    const result = normalizeOidcProviders([validProvider]);
    expect(Array.isArray(result)).toBe(true);
    expect(Array.isArray(result) ? result[0] : null).toMatchObject(validProvider);
  });
});
