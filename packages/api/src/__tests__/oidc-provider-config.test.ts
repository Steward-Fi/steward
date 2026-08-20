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

  it("rejects issuer query and fragment components", () => {
    for (const issuer of [
      "https://idp.example.com?tenant=attacker",
      "https://idp.example.com#issuer",
    ]) {
      const result = normalizeOidcProviders([{ ...validProvider, issuer }]);
      expect(result, issuer).toBe("issuer for provider enterprise must be a public https URL");
    }
  });

  it("allows clientId-only direct-token providers for azp binding", () => {
    const result = normalizeOidcProviders([
      {
        id: validProvider.id,
        issuer: validProvider.issuer,
        audience: validProvider.audience,
        jwksUri: validProvider.jwksUri,
        clientId: validProvider.clientId,
      },
    ]);
    expect(Array.isArray(result)).toBe(true);
    expect(Array.isArray(result) ? result[0]?.clientId : undefined).toBe(validProvider.clientId);
  });

  it("rejects legacy symmetric or unknown token algorithms", () => {
    for (const allowedAlgs of [["HS256"], ["RS256", "none"]]) {
      const result = normalizeOidcProviders([{ ...validProvider, allowedAlgs }]);
      expect(result).toBe("allowedAlgs for provider enterprise may only include RS256 or ES256");
    }
  });

  it("defaults allowJitProvisioning to OFF when the field is omitted (SEC-151)", () => {
    const result = normalizeOidcProviders([validProvider]);
    expect(Array.isArray(result)).toBe(true);
    if (!Array.isArray(result)) return;
    // Auto-creating user accounts for any holder of a valid IdP token must be
    // an explicit tenant opt-in — an omitted field must never normalize to on.
    expect(result[0]?.allowJitProvisioning).toBe(false);
  });

  it("honors an explicit allowJitProvisioning opt-in", () => {
    const result = normalizeOidcProviders([{ ...validProvider, allowJitProvisioning: true }]);
    expect(Array.isArray(result)).toBe(true);
    if (!Array.isArray(result)) return;
    expect(result[0]?.allowJitProvisioning).toBe(true);
  });
});
