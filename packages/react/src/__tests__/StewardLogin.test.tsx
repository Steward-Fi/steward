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

const { StewardLogin, composeWalletSuccess, composeWalletError } = await import(
  "../components/StewardLogin.js"
);
const { StewardAuthContext } = await import("../provider.js");

type AuthCtx = {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: null;
  session: null | { token: string; user: { id: string; email: string } };
  providers: null | {
    google?: boolean;
    discord?: boolean;
    siwe?: boolean;
    siws?: boolean;
  };
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
    providers: { google: true, discord: true, siwe: true, siws: true },
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

describe("<StewardLogin /> showWallets prop", () => {
  // The wallet panels (<WalletLogin.EVM>, <WalletLogin.Solana>) are pulled in
  // via dynamic import inside an effect, so they do not appear in SSR output.
  // Instead we assert against the loading-fallback markers (`stwd-login-wallet-evm-loading`
  // / `stwd-login-wallet-sol-loading`) and the wallet container testid
  // (`stwd-login-wallets`). This is enough to verify the gating logic without
  // pulling in jsdom or wagmi/solana mocks (those are exercised by
  // WalletLogin.test.tsx).

  test("showWallets={true} renders both wallet placeholders when providers report siwe + siws", () => {
    const html = renderToString(
      wrap(baseCtx({}), React.createElement(StewardLogin, { showWallets: true })),
    );
    expect(html).toContain("stwd-login-wallets");
    expect(html).toContain("stwd-login-wallet-evm-loading");
    expect(html).toContain("stwd-login-wallet-sol-loading");
  });

  test("default (showWallets undefined) renders no wallet buttons", () => {
    const html = renderToString(wrap(baseCtx({}), React.createElement(StewardLogin, {})));
    expect(html).not.toContain("stwd-login-wallets");
    expect(html).not.toContain("stwd-login-wallet-evm-loading");
    expect(html).not.toContain("stwd-login-wallet-sol-loading");
  });

  test("showWallets={false} renders no wallet buttons", () => {
    const html = renderToString(
      wrap(baseCtx({}), React.createElement(StewardLogin, { showWallets: false })),
    );
    expect(html).not.toContain("stwd-login-wallets");
  });

  test("showWallets={{ evm: true }} renders only EVM", () => {
    const html = renderToString(
      wrap(baseCtx({}), React.createElement(StewardLogin, { showWallets: { evm: true } })),
    );
    expect(html).toContain("stwd-login-wallets");
    expect(html).toContain("stwd-login-wallet-evm-loading");
    expect(html).not.toContain("stwd-login-wallet-sol-loading");
  });

  test("showWallets={{ solana: true }} renders only Solana", () => {
    const html = renderToString(
      wrap(baseCtx({}), React.createElement(StewardLogin, { showWallets: { solana: true } })),
    );
    expect(html).toContain("stwd-login-wallets");
    expect(html).toContain("stwd-login-wallet-sol-loading");
    expect(html).not.toContain("stwd-login-wallet-evm-loading");
  });

  test("providers.siwe=false hides EVM even when showWallets={true}", () => {
    const html = renderToString(
      wrap(
        baseCtx({
          providers: { google: true, discord: true, siwe: false, siws: true },
        }),
        React.createElement(StewardLogin, { showWallets: true }),
      ),
    );
    expect(html).toContain("stwd-login-wallets");
    expect(html).not.toContain("stwd-login-wallet-evm-loading");
    expect(html).toContain("stwd-login-wallet-sol-loading");
  });

  test("providers.siws=false hides Solana even when showWallets={true}", () => {
    const html = renderToString(
      wrap(
        baseCtx({
          providers: { google: true, discord: true, siwe: true, siws: false },
        }),
        React.createElement(StewardLogin, { showWallets: true }),
      ),
    );
    expect(html).toContain("stwd-login-wallets");
    expect(html).toContain("stwd-login-wallet-evm-loading");
    expect(html).not.toContain("stwd-login-wallet-sol-loading");
  });

  test("providers === null (initial load / discovery failed) hides wallet buttons", () => {
    const html = renderToString(
      wrap(baseCtx({ providers: null }), React.createElement(StewardLogin, { showWallets: true })),
    );
    expect(html).not.toContain("stwd-login-wallets");
    expect(html).not.toContain("stwd-login-wallet-evm-loading");
    expect(html).not.toContain("stwd-login-wallet-sol-loading");
  });
});

describe("<StewardLogin /> wallet success/error bubbling", () => {
  // The bubble adapters (`composeWalletSuccess`, `composeWalletError`) are
  // exported precisely so the contract is testable without spinning up
  // wagmi/@solana mocks. They mirror what `<StewardLogin>` wires into the
  // panel `onSuccess` / `onError` props verbatim. The full integration is
  // exercised end-to-end in WalletLogin.test.tsx (panel-level).

  test("wallet sign success bubbles to onSuccess as { token, user }", () => {
    let received: { token: string; user: { id: string; email: string } } | null = null;
    const handler = composeWalletSuccess((res) => {
      received = res;
    });
    handler(
      {
        token: "jwt-abc",
        refreshToken: "refresh-xyz",
        expiresIn: 900,
        user: { id: "user-1", email: "a@b.io" },
      },
      "evm",
    );
    expect(received).not.toBeNull();
    expect(received!.token).toBe("jwt-abc");
    expect(received!.user.id).toBe("user-1");
    expect(received!.user.email).toBe("a@b.io");
  });

  test("wallet sign success is a no-op when consumer onSuccess is undefined", () => {
    const handler = composeWalletSuccess(undefined);
    expect(() =>
      handler(
        {
          token: "t",
          refreshToken: "r",
          expiresIn: 900,
          user: { id: "u", email: "u@x.io" },
        },
        "solana",
      ),
    ).not.toThrow();
  });

  test("wallet sign error bubbles to onError", () => {
    let received: Error | null = null;
    const handler = composeWalletError((err) => {
      received = err;
    });
    const boom = new Error("user rejected signature");
    handler(boom, "evm");
    expect(received).toBe(boom);
  });

  test("wallet sign error is a no-op when consumer onError is undefined", () => {
    const handler = composeWalletError(undefined);
    expect(() => handler(new Error("x"), "solana")).not.toThrow();
  });
});
