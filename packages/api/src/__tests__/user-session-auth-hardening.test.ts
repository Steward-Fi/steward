import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const userRouteSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");

describe("user session auth hardening", () => {
  it("uses the shared session verifier instead of accepting arbitrary signed JWTs", () => {
    expect(userRouteSource).toContain("verifySessionToken(token)");
    expect(userRouteSource).not.toContain("verifyToken(token)");
    expect(userRouteSource).not.toContain("assertTokenNotRevoked(verified");
  });

  it("rejects legacy address-only sessions on user routes", () => {
    expect(userRouteSource).toContain("const userId = payload.userId as string | undefined");
    expect(userRouteSource).toContain('error: "Session token missing userId claim"');
    expect(userRouteSource).not.toContain("payload.address as string | undefined");
    expect(userRouteSource).toContain("not raw wallet addresses");
  });

  it("does not let tenant switching renew access-token lifetime or registered claims", () => {
    const switchStart = userRouteSource.indexOf('user.post("/me/tenants/switch"');
    expect(switchStart).toBeGreaterThanOrEqual(0);
    const switchRoute = userRouteSource.slice(
      switchStart,
      userRouteSource.indexOf('user.post("/me/tenants/:tenantId/join"', switchStart),
    );
    expect(switchRoute).toContain(
      "const remainingSeconds = Math.floor(session.exp - Date.now() / 1000)",
    );
    expect(switchRoute).toContain("`${remainingSeconds}s`");
    for (const claim of ["exp", "iat", "nbf", "jti", "iss", "aud"]) {
      expect(switchRoute).toContain(`${claim}: _${claim}`);
    }
  });

  it("requires recent MFA before minting a tenant-scoped switch token", () => {
    const switchStart = userRouteSource.indexOf('user.post("/me/tenants/switch"');
    expect(switchStart).toBeGreaterThanOrEqual(0);
    const switchRoute = userRouteSource.slice(
      switchStart,
      userRouteSource.indexOf('user.post("/me/tenants/:tenantId/join"', switchStart),
    );
    expect(switchRoute).toContain("hasRecentMfaStepUp(session)");
    expect(switchRoute).toContain("Tenant switching requires a recent MFA step-up session");
    expect(switchRoute.indexOf("hasRecentMfaStepUp(session)")).toBeLessThan(
      switchRoute.indexOf("createSessionToken("),
    );
    expect(switchRoute).toContain("mfaVerifiedAt: _mfaVerifiedAt");
    expect(switchRoute).toContain("mfaMethod: _mfaMethod");
  });

  it("marks user API-key and tenant-switch token responses as non-cacheable", () => {
    const createStart = userRouteSource.indexOf('user.post("/me/tenants"');
    const switchStart = userRouteSource.indexOf('user.post("/me/tenants/switch"');
    expect(createStart).toBeGreaterThanOrEqual(0);
    expect(switchStart).toBeGreaterThan(createStart);
    const createRoute = userRouteSource.slice(createStart, switchStart);
    const switchRoute = userRouteSource.slice(
      switchStart,
      userRouteSource.indexOf('user.post("/me/tenants/:tenantId/join"', switchStart),
    );

    expect(createRoute.indexOf("setNoStoreHeaders(c)")).toBeLessThan(
      createRoute.indexOf("apiKey: apiKeyPair.key"),
    );
    expect(switchRoute.indexOf("setNoStoreHeaders(c)")).toBeLessThan(switchRoute.indexOf("token,"));
  });

  it("requires personal user sessions for global personal user routes", () => {
    expect(userRouteSource).toContain("function requirePersonalUserSession");
    expect(userRouteSource).toContain("session.tenantId === personalTenantId(userId)");
    for (const route of [
      'user.get("/me"',
      'user.get("/me/accounts"',
      'user.delete("/me/accounts/:provider/:providerAccountId"',
      'user.get("/me/wallet"',
      'user.post("/me/wallet"',
      'user.post("/me/wallet/sign"',
      'user.get("/me/wallet/history"',
      'user.post("/me/wallet/sign-message"',
      'user.post("/me/wallet/export"',
      'user.get("/me/tenants"',
      'user.post("/me/tenants"',
      'user.post("/me/tenants/switch"',
    ]) {
      const routeStart = userRouteSource.indexOf(route);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const routeBody = userRouteSource.slice(routeStart, routeStart + 400);
      expect(routeBody).toContain("requirePersonalUserSession(c)");
    }
  });
});
