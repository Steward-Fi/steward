import { Window } from "happy-dom";
import * as React from "react";
import { createRoot } from "react-dom/client";
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

let credentialsCalls = 0;
Object.defineProperty(window.navigator, "credentials", {
  value: {
    get: async () => {
      credentialsCalls += 1;
      throw new Error("navigator.credentials.get must not be called by StewardLogin");
    },
    create: async () => null,
  },
  configurable: true,
});

const { StewardLogin } = await import("../../components/StewardLogin.js");
const { StewardAuthContext } = await import("../../provider.js");
const { registerEvmWalletPanel, registerSolanaWalletPanel } = await import(
  "../../internal/walletPanelRegistry.js"
);

const dummyPanel: React.ComponentType<unknown> = () => null;
registerEvmWalletPanel({ load: async () => ({ default: dummyPanel }) });
registerSolanaWalletPanel({ load: async () => ({ default: dummyPanel }) });

const passkeyCalls: string[] = [];
const contextValue = {
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
  signInWithPasskey: async (email: string) => {
    passkeyCalls.push(email);
    return {};
  },
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

const container = window.document.createElement("div") as unknown as HTMLDivElement;
window.document.body.replaceChildren(container as unknown as Node);
const root = createRoot(container);
await React.act(async () => {
  root.render(
    React.createElement(
      StewardAuthContext.Provider,
      { value: contextValue as unknown as React.ContextType<typeof StewardAuthContext> },
      React.createElement(StewardLogin, {}),
    ),
  );
});

const input = container.querySelector('input[aria-label="email"]');
if (!input) throw new Error("email input not found");
const autocomplete = input.getAttribute("autocomplete");
const credentialsCallsAfterMount = credentialsCalls;

await React.act(async () => {
  (input as unknown as { value: string }).value = "brand-new-user@example.com";
  Simulate.change(input);
});
const credentialsCallsAfterTyping = credentialsCalls;
const passkeyCallsAfterTyping = [...passkeyCalls];

const button = [...container.querySelectorAll("button")].find(
  (candidate) => candidate.textContent?.trim() === "passkey",
);
if (!button) throw new Error("passkey button not found");
await React.act(async () => {
  button.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
});

await React.act(async () => root.unmount());
console.log(
  JSON.stringify({
    autocomplete,
    credentialsCallsAfterMount,
    credentialsCallsAfterTyping,
    passkeyCallsAfterTyping,
    passkeyCallsAfterClick: passkeyCalls,
  }),
);
