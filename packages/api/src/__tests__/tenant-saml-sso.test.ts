import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
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

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
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

  it("adds MFA-gated tenant routes, audit rollback, metadata, login, and ACS guardrails", () => {
    const tenantConfigSource = read("packages/api/src/routes/tenant-config.ts");
    const authSource = read("packages/api/src/routes/auth.ts");
    const migration = read("packages/db/drizzle/0050_tenant_saml_sso_configs.sql");

    expect(tenantConfigSource).toContain('tenantConfigRoutes.get("/:id/saml-sso"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.put("/:id/saml-sso"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.delete("/:id/saml-sso"');
    expect(tenantConfigSource).toContain('requireRecentTenantAdminMfa(c, "SAML SSO config');
    expect(tenantConfigSource).toContain("tenant.saml_sso.update.authorized");
    expect(tenantConfigSource).toContain("restoreTenantSamlSsoConfig");

    expect(authSource).toContain('auth.get("/saml/:tenantId/metadata"');
    expect(authSource).toContain('auth.get("/saml/:tenantId/login"');
    expect(authSource).toContain('auth.post("/saml/:tenantId/acs"');
    expect(authSource).toContain("application/samlmetadata+xml");
    expect(authSource).toContain('WantAssertionsSigned="true"');
    expect(authSource).toContain("verifySamlAcsResponse");
    expect(authSource).toContain("isVerifiedSsoEmailDomainForTenant");
    expect(authSource).toContain("recordSamlAssertionReplay");
    expect(authSource).toContain("resolveSamlMappedRole(config, groups)");

    expect(migration).toContain("\"jit_default_role\" varchar(32) NOT NULL DEFAULT 'viewer'");
    expect(migration).toContain('"tenant_saml_sso_configs_viewer_jit_role_check"');
    expect(migration).toContain('cardinality("idp_cert_pems") BETWEEN 1 AND 5');
    expect(read("packages/db/drizzle/0053_saml_group_role_mappings.sql")).toContain(
      '"group_role_mappings" jsonb NOT NULL DEFAULT',
    );
  });
});
