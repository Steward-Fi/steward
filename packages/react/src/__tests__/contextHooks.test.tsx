/**
 * Tests for the two context-access hooks: useAuth() and useSteward().
 *
 * Both throw a descriptive error when used outside their provider, and both
 * return the context value when wrapped. We exercise the throw path by
 * rendering a probe component without a provider (renderToString surfaces the
 * thrown error), and the happy path by wrapping the probe in the relevant
 * context provider and capturing the value the hook returns.
 */

import { describe, expect, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const { useAuth } = await import("../hooks/useAuth.js");
const { useSteward } = await import("../hooks/useSteward.js");
const { StewardAuthContext } = await import("../provider.js");

// useSteward reads the *non-exported* StewardContext via useStewardContext().
// Since we can't import that context directly, we drive the happy path of
// useSteward only through <StewardProvider>-equivalent wrapping is not
// possible here without the real provider tree; instead we assert the throw
// path (no provider) which is the branch with real guard logic. The happy
// path for the steward context is covered indirectly by the hook tests that
// mock ../provider.js.

function AuthProbe({ sink }: { sink: (v: unknown) => void }) {
  const value = useAuth();
  sink(value);
  return null;
}

function StewardProbe() {
  useSteward();
  return null;
}

describe("useAuth()", () => {
  test("throws a helpful error when no StewardAuthContext provider is present", () => {
    expect(() => renderToString(React.createElement(AuthProbe, { sink: () => {} }))).toThrow(
      /useAuth must be used within a <StewardProvider> with an `auth` prop/,
    );
  });

  test("returns the auth context value when wrapped", () => {
    let captured: unknown = null;
    const authValue = {
      isAuthenticated: true,
      isLoading: false,
      user: { id: "u1", email: "u@x.io" },
      session: null,
      providers: null,
      isProvidersLoading: false,
      signOut: () => {},
      getToken: () => "tok",
      signInWithPasskey: async () => ({}),
      signInWithEmail: async () => ({}),
      verifyEmailCallback: async () => ({}),
      signInWithSIWE: async () => ({}),
      signInWithOAuth: async () => ({}),
      activeTenantId: null,
      tenants: null,
      isTenantsLoading: false,
      listTenants: async () => [],
      switchTenant: async () => false,
      joinTenant: async () => ({}),
      leaveTenant: async () => {},
    };
    renderToString(
      React.createElement(
        StewardAuthContext.Provider,
        { value: authValue as unknown as React.ContextType<typeof StewardAuthContext> },
        React.createElement(AuthProbe, {
          sink: (v) => {
            captured = v;
          },
        }),
      ),
    );
    expect(captured).toBe(authValue as unknown);
    expect((captured as typeof authValue).getToken()).toBe("tok");
  });
});

describe("useSteward()", () => {
  test("throws when used outside a <StewardProvider>", () => {
    expect(() => renderToString(React.createElement(StewardProbe))).toThrow(
      /useStewardContext must be used within a <StewardProvider>/,
    );
  });
});
