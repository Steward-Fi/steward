import { describe, expect, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const { StewardMfaChallenge } = await import("../components/StewardMfaChallenge.js");
const { StewardMfaSettings } = await import("../components/StewardMfaSettings.js");
const { StewardAuthContext } = await import("../provider.js");

type AuthCtx = React.ContextType<typeof StewardAuthContext>;

function authCtx(): NonNullable<AuthCtx> {
  return {
    isAuthenticated: true,
    isLoading: false,
    user: { id: "user-1", email: "u@example.com" },
    session: { token: "token", address: "0x1234", tenantId: "tenant-1" },
    providers: null,
    isProvidersLoading: false,
    signOut: () => {},
    getToken: () => "token",
    signInWithPasskey: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    addPasskey: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    signInWithEmail: async () => ({ ok: true, expiresAt: new Date().toISOString() }),
    verifyEmailCallback: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    signInWithSIWE: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    signInWithSolana: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    signInWithOAuth: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    getTotpStatus: async () => ({ ok: true, enabled: false, pending: false }),
    enrollTotp: async () => ({
      ok: true,
      secret: "secret",
      otpauthUri: "otpauth://totp/x",
      expiresAt: new Date().toISOString(),
    }),
    verifyTotp: async () => ({ ok: true, enabled: true, recoveryCodes: ["ABCDE-FGHJK"] }),
    completeTotpMfa: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    completeRecoveryCodeMfa: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    getRecoveryCodeStatus: async () => ({ ok: true, enabled: false, remaining: 0 }),
    regenerateRecoveryCodes: async () => ({ ok: true, recoveryCodes: ["ABCDE-FGHJK"] }),
    unenrollTotp: async () => ({ ok: true }),
    getSmsMfaStatus: async () => ({ ok: true, enabled: false, pending: false }),
    enrollSmsMfa: async () => ({ ok: true, phone: "***0123", expiresAt: new Date().toISOString() }),
    verifySmsMfa: async () => ({ ok: true, enabled: true, phone: "***0123" }),
    sendSmsMfaCode: async () => ({
      ok: true,
      phone: "***0123",
      expiresAt: new Date().toISOString(),
    }),
    completeSmsMfa: async () => ({
      token: "token",
      refreshToken: "refresh",
      expiresIn: 900,
      user: { id: "user-1", email: "u@example.com" },
    }),
    unenrollSmsMfa: async () => ({ ok: true }),
    activeTenantId: "tenant-1",
    tenants: null,
    isTenantsLoading: false,
    listTenants: async () => [],
    switchTenant: async () => true,
    joinTenant: async () => ({ tenantId: "tenant-1", name: "Tenant", role: "owner" }),
    leaveTenant: async () => {},
  };
}

function wrap(node: React.ReactNode) {
  return React.createElement(StewardAuthContext.Provider, { value: authCtx() }, node);
}

describe("<StewardMfaChallenge />", () => {
  test("renders TOTP verification with recovery-code toggle", () => {
    const html = renderToString(
      wrap(
        React.createElement(StewardMfaChallenge, {
          challenge: {
            type: "totp",
            challengeId: "challenge-1",
            expiresAt: "2026-05-25T12:00:00.000Z",
          },
        }),
      ),
    );
    expect(html).toContain("multi-factor verification");
    expect(html).toContain("totp code");
    expect(html).toContain("use recovery code");
  });

  test("renders SMS verification without recovery-code toggle", () => {
    const html = renderToString(
      wrap(
        React.createElement(StewardMfaChallenge, {
          challenge: {
            type: "sms",
            challengeId: "challenge-2",
            expiresAt: "2026-05-25T12:00:00.000Z",
          },
        }),
      ),
    );
    expect(html).toContain("sms code");
    expect(html).not.toContain("use recovery code");
  });
});

describe("<StewardMfaSettings />", () => {
  test("renders MFA management sections", () => {
    const html = renderToString(wrap(React.createElement(StewardMfaSettings, {})));
    expect(html).toContain("multi-factor authentication");
    expect(html).toContain("authenticator app");
    expect(html).toContain("sms");
    expect(html).toContain("recovery codes");
  });
});
