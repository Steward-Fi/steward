import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const authSource = readFileSync(join(apiRoot, "routes", "auth.ts"), "utf8");
const discoverySource = readFileSync(join(apiRoot, "routes", "discovery.ts"), "utf8");

describe("identity issuer hardening", () => {
  it("does not mint identity tokens with a request Host-derived issuer", () => {
    const routeStart = authSource.indexOf('auth.get("/identity-token"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    expect(authSource.indexOf("createIdentityToken(claims)", routeStart)).toBeGreaterThan(
      routeStart,
    );
    expect(authSource).toContain("function tenantIdentityJwtIssuer");
    expect(authSource).toContain("tenantIdentityJwtIssuer(claims.tenantId)");
    expect(authSource.indexOf("new URL(c.req.url).origin", routeStart)).toBe(-1);
  });

  it("requires a canonical identity discovery base URL in production", () => {
    expect(discoverySource).toContain("STEWARD_IDENTITY_JWT_ISSUER");
    expect(discoverySource).toContain("APP_URL");
    expect(discoverySource).toContain('process.env.NODE_ENV === "production"');
    expect(discoverySource).toContain(
      "STEWARD_IDENTITY_JWT_ISSUER or APP_URL is required for identity discovery",
    );
  });
});
