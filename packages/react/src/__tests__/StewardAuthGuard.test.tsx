/**
 * <StewardAuthGuard /> branch coverage.
 *
 * Guard renders one of three trees based on the auth context:
 *   - isLoading           → loadingFallback (or default spinner)
 *   - !isAuthenticated    → fallback (or default <StewardLogin />)
 *   - authenticated       → children
 *
 * We wrap the guard in the real StewardAuthContext.Provider (same approach as
 * StewardLogin.test.tsx) and assert on SSR HTML. The default-unauthenticated
 * branch renders <StewardLogin />, which needs the wallet-panel registry; we
 * pass an explicit `fallback` to keep these tests focused on the guard's own
 * branching and avoid coupling to StewardLogin internals.
 */

import { describe, expect, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const { StewardAuthGuard } = await import("../components/StewardAuthGuard.js");
const { StewardAuthContext } = await import("../provider.js");

function ctx(overrides: Record<string, unknown>): any {
  return {
    isAuthenticated: false,
    isLoading: false,
    user: null,
    session: null,
    providers: null,
    isProvidersLoading: false,
    signOut: () => {},
    getToken: () => null,
    activeTenantId: null,
    tenants: null,
    isTenantsLoading: false,
    ...overrides,
  };
}

function wrap(value: unknown, node: React.ReactNode) {
  return React.createElement(
    StewardAuthContext.Provider,
    { value: value as React.ContextType<typeof StewardAuthContext> },
    node,
  );
}

const child = React.createElement("div", { "data-testid": "protected" }, "secret");

describe("<StewardAuthGuard /> branch coverage", () => {
  test("loading branch renders the default spinner", () => {
    const html = renderToString(
      wrap(ctx({ isLoading: true }), React.createElement(StewardAuthGuard, {}, child)),
    );
    expect(html).toContain("stwd-auth-guard__loading");
    expect(html).toContain("Loading");
    expect(html).not.toContain("secret");
  });

  test("loading branch renders a custom loadingFallback when provided", () => {
    const html = renderToString(
      wrap(
        ctx({ isLoading: true }),
        React.createElement(
          StewardAuthGuard,
          { loadingFallback: React.createElement("p", {}, "please wait") },
          child,
        ),
      ),
    );
    expect(html).toContain("please wait");
    expect(html).not.toContain("Loading…");
  });

  test("unauthenticated branch renders a custom fallback", () => {
    const html = renderToString(
      wrap(
        ctx({ isAuthenticated: false, isLoading: false }),
        React.createElement(
          StewardAuthGuard,
          { fallback: React.createElement("p", {}, "log in please") },
          child,
        ),
      ),
    );
    expect(html).toContain("stwd-auth-guard");
    expect(html).toContain("log in please");
    expect(html).not.toContain("secret");
  });

  test("authenticated branch renders the children", () => {
    const html = renderToString(
      wrap(
        ctx({ isAuthenticated: true, isLoading: false }),
        React.createElement(StewardAuthGuard, {}, child),
      ),
    );
    expect(html).toContain("secret");
    expect(html).not.toContain("stwd-auth-guard__loading");
  });
});
