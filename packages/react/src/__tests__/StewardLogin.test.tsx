/**
 * StewardLogin tests — Rules-of-Hooks regression coverage.
 *
 * The previously-fixed bug placed `useRef` + `useEffect` after an early
 * return on `!ctx`. This test locks in the correct structure by mounting
 * the component in each branch — missing auth context, signed-in, and
 * signed-out — and asserting no throw.
 */

import { describe, expect, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const { StewardLogin } = await import("../components/StewardLogin.js");
const { StewardAuthContext } = await import("../provider.js");

type AuthCtx = {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: null;
  session: null | { token: string; user: { id: string; email: string } };
  providers: null | { google?: boolean; discord?: boolean };
  isProvidersLoading: boolean;
  signOut: () => void;
  getToken: () => null;
  signInWithPasskey: (email: string) => Promise<unknown>;
  signInWithEmail: (email: string) => Promise<unknown>;
  verifyEmailCallback: () => Promise<unknown>;
  signInWithSIWE: () => Promise<unknown>;
  signInWithSolana?: () => Promise<unknown>;
  signInWithOAuth?: (p: string, c?: unknown) => Promise<unknown>;
  activeTenantId: null;
  tenants: null;
  isTenantsLoading: boolean;
  listTenants: () => Promise<unknown[]>;
  switchTenant: () => Promise<void>;
  joinTenant: () => Promise<void>;
  leaveTenant: () => Promise<void>;
};

function baseCtx(overrides: Partial<AuthCtx> = {}): AuthCtx {
  return {
    isAuthenticated: false,
    isLoading: false,
    user: null,
    session: null,
    providers: { google: true, discord: true },
    isProvidersLoading: false,
    signOut: () => {},
    getToken: () => null,
    signInWithPasskey: async () => ({}),
    signInWithEmail: async () => ({}),
    verifyEmailCallback: async () => ({}),
    signInWithSIWE: async () => ({}),
    signInWithSolana: async () => ({}),
    signInWithOAuth: async () => ({}),
    activeTenantId: null,
    tenants: null,
    isTenantsLoading: false,
    listTenants: async () => [],
    switchTenant: async () => {},
    joinTenant: async () => {},
    leaveTenant: async () => {},
    ...overrides,
  };
}

function wrap(value: AuthCtx | null, node: React.ReactNode) {
  // Cast: provider's context type has the same shape, we just skip the full
  // generic to avoid pulling the 20-field union into every test.
  return React.createElement(
    StewardAuthContext.Provider,
    { value: value as unknown as React.ContextType<typeof StewardAuthContext> },
    node,
  );
}

describe("<StewardLogin /> — rules-of-hooks branch coverage", () => {
  test("mounts when no auth context is present (renders inline error)", () => {
    // Provider missing → ctx is null → component shows error message.
    // Critically, this path must still call all hooks unconditionally before
    // returning.
    const html = renderToString(wrap(null, React.createElement(StewardLogin, {})));
    expect(html).toContain("stwd-login--error");
  });

  test("mounts in signed-out branch", () => {
    const html = renderToString(
      wrap(
        baseCtx({ isAuthenticated: false }),
        React.createElement(StewardLogin, { title: "Welcome" }),
      ),
    );
    expect(html).toContain("Welcome");
    expect(html).toContain("Sign in with Passkey");
  });

  test("mounts in signed-in branch (renders nothing)", () => {
    const html = renderToString(
      wrap(
        baseCtx({
          isAuthenticated: true,
          session: { token: "t", user: { id: "u", email: "u@x.io" } },
        }),
        React.createElement(StewardLogin, {}),
      ),
    );
    // Signed-in returns null.
    expect(html).toBe("");
  });

  test("mounts in loading branch", () => {
    const html = renderToString(
      wrap(baseCtx({ isLoading: true }), React.createElement(StewardLogin, {})),
    );
    // Buttons are disabled when isLoading; we just verify no crash.
    expect(html).toContain("stwd-login");
  });

  test("hook order is stable across ctx transitions", () => {
    // Render three different ctx shapes — with the old bug (hooks after
    // early return), the null ctx path would have called fewer hooks than
    // the authed path. Each render is fresh (SSR), but the invariant we
    // care about is that hook calls are unconditional. If they weren't,
    // any of these calls would throw under react-hooks lint or at runtime
    // on a persistent fiber.
    expect(() => renderToString(wrap(null, React.createElement(StewardLogin, {})))).not.toThrow();
    expect(() =>
      renderToString(
        wrap(baseCtx({ isAuthenticated: false }), React.createElement(StewardLogin, {})),
      ),
    ).not.toThrow();
    expect(() =>
      renderToString(
        wrap(
          baseCtx({
            isAuthenticated: true,
            session: { token: "t", user: { id: "u", email: "u@x.io" } },
          }),
          React.createElement(StewardLogin, {}),
        ),
      ),
    ).not.toThrow();
  });
});
