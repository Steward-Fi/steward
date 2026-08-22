import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { buildSamlServiceProviderUrls, normalizeSamlSsoUpdate } from "../services/saml-sso-config";

const ROOT = join(import.meta.dir, "../../../..");
const CERT = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUE2hhcGUtc3Rld2FyZC1zYW1sLXRlc3QtY2VydGlmaWNh
dGUwDQYJKoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN0ZXdh
cmQgVGVzdDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0dXJlMB4XDTI2
MDEwMTAwMDAwMFoXDTM2MDEwMTAwMDAwMFowSDELMAkGA1UEBhMCVVMxEjAQBgNV
BAoMCVN0ZXdhcmQgVGVzdDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0
dXJlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AQIDAQAB
-----END CERTIFICATE-----`;

// Assert the composed SAML DDL contract across
// the full set of migration files rather than hard-coded filenames.
function allMigrations(): string {
  const dir = join(ROOT, "packages/db/drizzle");
  return readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .map((f) => readFileSync(join(dir, f), "utf-8"))
    .join("\n");
}

describe("tenant SAML SSO config foundation", () => {
  it("normalizes public IdP config and pins generated SP URLs to APP_URL", () => {
    process.env.APP_URL = "https://api.example.com/";
    const result = normalizeSamlSsoUpdate("tenant-saml", {
      enabled: true,
      idpEntityId: "https://idp.example.com/saml",
      idpSsoUrl: "https://idp.example.com/sso",
      idpCertPems: [CERT],
      emailAttribute: "email",
      groupsAttribute: "groups",
      groupRoleMappings: [{ group: "Engineering", role: "developer" }],
      allowJitProvisioning: true,
    });

    expect(result).toEqual(
      expect.objectContaining({
        tenantId: "tenant-saml",
        enabled: true,
        status: "active",
        spEntityId: "https://api.example.com/auth/saml/tenant-saml/metadata",
        acsUrl: "https://api.example.com/auth/saml/tenant-saml/acs",
        allowJitProvisioning: true,
        groupRoleMappings: [{ group: "Engineering", role: "developer" }],
        jitDefaultRole: "viewer",
      }),
    );
    expect(buildSamlServiceProviderUrls("tenant-saml").metadataUrl).toBe(
      "https://api.example.com/auth/saml/tenant-saml/metadata",
    );
    delete process.env.APP_URL;
  });

  it("rejects unsafe IdP URLs and private key material", () => {
    expect(
      normalizeSamlSsoUpdate("tenant-saml", {
        idpEntityId: "https://idp.example.com/saml",
        idpSsoUrl: "https://127.0.0.1/sso",
        idpCertPems: [CERT],
      }),
    ).toBe("idpSsoUrl must be a public https URL");

    expect(
      normalizeSamlSsoUpdate("tenant-saml", {
        idpEntityId: "https://idp.example.com/saml",
        idpSsoUrl: "https://idp.example.com/sso",
        idpCertPems: ["-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"],
      }),
    ).toBe("IdP certificate must not contain private key material");

    expect(
      normalizeSamlSsoUpdate("tenant-saml", {
        idpEntityId: "https://idp.example.com/saml",
        idpSsoUrl: "https://idp.example.com/sso",
        idpCertPems: [CERT],
        groupRoleMappings: [{ group: "Owners", role: "owner" }],
      }),
    ).toBe("groupRoleMappings role must be admin, developer, billing, viewer, or member");
  });

  it("retains the immutable SAML schema constraints across composed migrations", () => {
    const migration = allMigrations();

    expect(migration).toContain("\"jit_default_role\" varchar(32) NOT NULL DEFAULT 'viewer'");
    expect(migration).toContain('"tenant_saml_sso_configs_viewer_jit_role_check"');
    expect(migration).toContain('cardinality("idp_cert_pems") BETWEEN 1 AND 5');
    expect(migration).toContain('"group_role_mappings" jsonb');
    expect(migration).toContain("jsonb_typeof(\"group_role_mappings\") = 'array'");
  });
});
