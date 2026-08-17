// @ts-nocheck
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const providersSource = readFileSync(join(import.meta.dir, "providers.tsx"), "utf8");
const apiSource = readFileSync(join(import.meta.dir, "..", "lib", "api.ts"), "utf8");

describe("AuthTokenSync security invariants", () => {
  test("syncs the legacy API client from the current session token", () => {
    expect(providersSource).toContain("const sessionToken = auth.session?.token ?? null");
    expect(providersSource).toContain("const token = sessionToken ?? auth.getToken()");
    expect(providersSource).toContain(
      "[auth.isAuthenticated, auth.getToken, auth.activeTenantId, sessionToken]",
    );
  });

  test("clears the legacy API client when the user signs out", () => {
    expect(apiSource).toContain("export function clearAuthToken()");
    expect(providersSource).toContain("clearAuthToken()");
  });

  test("SEC-018: refresh token custody is the same-origin HttpOnly cookie proxy", () => {
    // The SDK is configured to deposit/refresh via the BFF routes, so the
    // long-lived refresh token never lands in JS-readable storage.
    expect(providersSource).toContain('authProxyUrl: "/api/auth"');
    expect(providersSource).toContain("removeLegacyRefreshToken");
    // The old "deferred hardening" comment must not come back.
    expect(providersSource).not.toContain("RECOMMENDED FUTURE HARDENING");
  });
});
