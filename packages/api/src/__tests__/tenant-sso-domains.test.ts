import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("tenant SSO domain hardening", () => {
  it("requires DNS TXT proof before a tenant SSO domain can become discoverable", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");
    const verifyStart = source.indexOf('tenantConfigRoutes.post("/:id/sso-domains/:domain/verify"');
    expect(verifyStart).toBeGreaterThanOrEqual(0);
    const verifyEnd = source.indexOf("\ntenantConfigRoutes.", verifyStart + 1);
    const verifyRoute = source.slice(verifyStart, verifyEnd === -1 ? undefined : verifyEnd);

    expect(source).toContain('import { resolveTxt } from "node:dns/promises"');
    expect(source).toContain("async function hasSsoDomainVerificationTxt");
    expect(source).toContain('resolveTxt(`_steward-sso.${domain}`)');
    expect(verifyRoute).toContain("previousDomain.verificationToken");
    expect(verifyRoute).toContain("hasSsoDomainVerificationTxt(domain, previousDomain.verificationToken)");
    expect(verifyRoute).toContain('action: "tenant.sso_domain.verify.authorized"');
    expect(verifyRoute.indexOf('action: "tenant.sso_domain.verify.authorized"')).toBeLessThan(
      verifyRoute.indexOf(".update(tenantSsoDomains)"),
    );
  });

  it("rolls back SSO domain control-plane mutations when final audits fail", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");
    expect(source).toContain("async function snapshotTenantSsoDomain");
    expect(source).toContain("async function restoreTenantSsoDomain");

    for (const [marker, authorizedAction, finalAction] of [
      [
        'tenantConfigRoutes.post("/:id/sso-domains"',
        'action: "tenant.sso_domain.upsert.authorized"',
        'action: "tenant.sso_domain.upsert"',
      ],
      [
        'tenantConfigRoutes.post("/:id/sso-domains/:domain/verify"',
        'action: "tenant.sso_domain.verify.authorized"',
        'action: "tenant.sso_domain.verify"',
      ],
      [
        'tenantConfigRoutes.delete("/:id/sso-domains/:domain"',
        'action: "tenant.sso_domain.delete.authorized"',
        'action: "tenant.sso_domain.delete"',
      ],
    ] as const) {
      const start = source.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = source.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = source.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain(authorizedAction);
      expect(route).toContain("const previousDomain = await snapshotTenantSsoDomain");
      expect(route).toContain("try {");
      expect(route).toContain(finalAction);
      expect(route).toContain("await restoreTenantSsoDomain(tenantId, domain, previousDomain)");
    }
  });

  it("does not let two tenants verify the same SSO discovery domain", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");
    const auth = read("packages/api/src/routes/auth.ts");
    const verifyStart = source.indexOf('tenantConfigRoutes.post("/:id/sso-domains/:domain/verify"');
    const verifyEnd = source.indexOf("\ntenantConfigRoutes.", verifyStart + 1);
    const verifyRoute = source.slice(verifyStart, verifyEnd === -1 ? undefined : verifyEnd);

    expect(verifyRoute).toContain("existingVerifiedDomain");
    expect(verifyRoute).toContain("existingVerifiedDomain.tenantId !== tenantId");
    expect(verifyRoute).toContain("SSO domain is already verified by another tenant");
    expect(auth).toContain(".limit(2)");
    expect(auth).toContain("rows.length === 1");
  });

  it("enforces SSO-required domains against email and built-in OAuth login", () => {
    const auth = read("packages/api/src/routes/auth.ts");

    expect(auth).toContain("async function isSsoRequiredForEmailDomain");
    expect(auth).toContain("async function requireNonSsoEmailLoginAllowed");
    expect(auth).toContain("Email login is disabled because this email domain requires SSO");
    expect(auth).toContain("OAuth login is disabled because this email domain requires SSO");
    expect(auth).toContain('authMethod: "oidc"');
  });
});
