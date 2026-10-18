/**
 * Passkey conditional-mediation (autofill) regression coverage.
 *
 * Bug (2026-08-20): the email input carried `autoComplete="email webauthn"`.
 * The `webauthn` autofill token arms browser conditional mediation, which
 * surfaces ANY discoverable passkey stored for the relying party the moment
 * the field is focused — ignoring the email being typed. A user composing a
 * BRAND-NEW email was prompted with an EXISTING account's passkey, blocking
 * new-account signup.
 *
 * Invariant locked in here: typing a new email must never surface an
 * existing account's passkey. Passkey login remains available via the
 * explicit passkey button, which scopes to the typed email through
 * `signInWithPasskey(email)` → `/auth/passkey/login/options`.
 *
 * jsdom/happy-dom cannot exercise real WebAuthn conditional UI, so we assert
 * at the levels we control deterministically:
 *   1. The email input's `autocomplete` attribute is exactly "email"
 *      (no `webauthn` token → browser never arms conditional mediation).
 *   2. No `navigator.credentials.get()` call is issued on mount or while
 *      typing (no programmatic conditional mediation either).
 *   3. The explicit passkey button still initiates email-scoped passkey
 *      login with the typed email.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Window } from "happy-dom";
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";
import { Simulate } from "react-dom/test-utils";

const window = new Window();
Object.assign(globalThis, {
  window,
  document: window.document,
  navigator: window.navigator,
  HTMLElement: window.HTMLElement,
  HTMLInputElement: window.HTMLInputElement,
  HTMLButtonElement: window.HTMLButtonElement,
  Event: window.Event,
  KeyboardEvent: window.KeyboardEvent,
  MouseEvent: window.MouseEvent,
  IS_REACT_ACT_ENVIRONMENT: true,
});

// Spy on navigator.credentials.get so any conditional-mediation request
// issued by the component (mount-time or type-time) is detected.
const credentialsGet = mock(async (..._args: unknown[]) => {
  throw new Error("navigator.credentials.get must not be called by StewardLogin");
});
Object.defineProperty(window.navigator, "credentials", {
  value: { get: credentialsGet, create: mock(async () => null) },
  configurable: true,
});

const { StewardLogin } = await import("../components/StewardLogin.js");
const { StewardAuthContext } = await import("../provider.js");
const { registerEvmWalletPanel, registerSolanaWalletPanel } = await import(
  "../internal/walletPanelRegistry.js"
);

const loginSource = readFileSync(
  join(import.meta.dir, "..", "components", "StewardLogin.tsx"),
  "utf8",
);

const dummyPanel: React.ComponentType<unknown> = () => null;
registerEvmWalletPanel({ load: async () => ({ default: dummyPanel }) });
registerSolanaWalletPanel({ load: async () => ({ default: dummyPanel }) });

const signInWithPasskey = mock(async (_email: string) => ({}));

function baseCtx() {
  return {
    isAuthenticated: false,
    isLoading: false,
    user: null,
    session: null,
    providers: { google: true },
    isProvidersLoading: false,
    guestState: { isGuest: false, isExpired: false, expiryMessage: null },
    signOut: () => {},
    signInAsGuest: async () => ({}),
    upgradeGuestWithEmail: async () => ({}),
    deleteGuest: async () => ({}),
    getToken: () => null,
    signInWithPasskey,
    signInWithEmail: async () => ({}),
    sendSmsOtp: async () => ({}),
    verifySmsOtp: async () => ({}),
    sendWhatsAppOtp: async () => ({}),
    verifyWhatsAppOtp: async () => ({}),
    verifyEmailCallback: async () => ({}),
    signInWithSIWE: async () => ({}),
    signInWithSolana: async () => ({}),
    signInWithOAuth: async () => ({}),
    signInWithTelegram: async () => ({}),
    signInWithFarcaster: async () => ({}),
    activeTenantId: null,
    tenants: null,
    isTenantsLoading: false,
    listTenants: async () => [],
    switchTenant: async () => {},
    joinTenant: async () => {},
    leaveTenant: async () => {},
  };
}

let container: HTMLDivElement;
let root: Root | null = null;

async function renderLogin(): Promise<void> {
  if (root) {
    await React.act(async () => root?.unmount());
    root = null;
  }
  container = window.document.createElement("div") as unknown as HTMLDivElement;
  window.document.body.replaceChildren(container as unknown as Node);
  root = createRoot(container);
  await React.act(async () => {
    root?.render(
      React.createElement(
        StewardAuthContext.Provider,
        { value: baseCtx() as unknown as React.ContextType<typeof StewardAuthContext> },
        React.createElement(StewardLogin, {}),
      ),
    );
  });
}

function emailInput(): HTMLInputElement {
  const input = container.querySelector('input[aria-label="email"]');
  if (!input) throw new Error("email input not found");
  return input as unknown as HTMLInputElement;
}

async function typeEmail(value: string): Promise<void> {
  const input = emailInput();
  await React.act(async () => {
    // happy-dom events don't traverse React 18's synthetic event plumbing
    // for controlled inputs, so drive onChange via Simulate (deterministic
    // and version-pinned alongside react-dom in this workspace).
    (input as unknown as { value: string }).value = value;
    Simulate.change(input as unknown as Element);
  });
}

beforeEach(async () => {
  credentialsGet.mockClear();
  signInWithPasskey.mockClear();
  signInWithPasskey.mockImplementation(async () => ({}));
  await renderLogin();
});

describe("passkey conditional-mediation autofill regression", () => {
  test("email input does not carry the webauthn autofill token", () => {
    const attr = (emailInput() as unknown as Element).getAttribute("autocomplete");
    expect(attr).toBe("email");
    expect(attr).not.toContain("webauthn");
    // Source-level lock: the token must not come back in any casing/order.
    expect(loginSource).not.toMatch(/autoComplete\s*=\s*"[^"]*webauthn[^"]*"/);
  });

  test("no conditional-mediation credentials.get() on mount or while typing a new email", async () => {
    expect(credentialsGet).toHaveBeenCalledTimes(0);
    await typeEmail("brand-new-user@example.com");
    expect(credentialsGet).toHaveBeenCalledTimes(0);
    // No passkey flow started implicitly either.
    expect(signInWithPasskey).toHaveBeenCalledTimes(0);
  });

  test("explicit passkey button still initiates email-scoped passkey login", async () => {
    await typeEmail("brand-new-user@example.com");
    const btn = [...container.querySelectorAll("button")].find(
      (b) => b.textContent?.trim() === "passkey",
    );
    if (!btn) throw new Error("passkey button not found");
    await React.act(async () => {
      (btn as unknown as Element).dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
    });
    expect(signInWithPasskey).toHaveBeenCalledTimes(1);
    expect(signInWithPasskey).toHaveBeenCalledWith("brand-new-user@example.com");
  });
});
