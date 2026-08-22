import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { Window } from "happy-dom";
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";
import { Simulate } from "react-dom/test-utils";

const browser = new Window({ url: "https://app.example.test/accounts" });
const originalFetch = globalThis.fetch;
Object.assign(globalThis, {
  window: browser,
  document: browser.document,
  navigator: browser.navigator,
  HTMLElement: browser.HTMLElement,
  HTMLInputElement: browser.HTMLInputElement,
  HTMLSelectElement: browser.HTMLSelectElement,
  HTMLButtonElement: browser.HTMLButtonElement,
  Event: browser.Event,
  MouseEvent: browser.MouseEvent,
  IS_REACT_ACT_ENVIRONMENT: true,
});

let authed = true;
let client: Record<string, ReturnType<typeof mock>>;

const { StewardLinkedAccounts } = await import("../components/StewardLinkedAccounts.js");
const { StewardAuthContext, StewardProvider } = await import("../provider.js");

function authContext() {
  return {
    isAuthenticated: authed,
    isLoading: false,
    user: { id: "user-1", email: "user@example.test" },
    session: { token: "token", address: "", tenantId: "tenant-1" },
    getToken: () => "token",
  };
}

const account = (id: string, provider: string, providerAccountId: string) => ({
  id,
  provider,
  providerAccountId,
  expiresAt: null,
});

function linkedResult(id: string, provider: string, providerAccountId: string) {
  return { account: account(id, provider, providerAccountId), isNew: true };
}

function resetClient() {
  client = {
    getBaseUrl: mock(() => "https://api.example.test"),
    listUserAccounts: mock(async () => ({
      accounts: [account("github-1", "github", "octocat")],
      primaryLoginMethods: [{ provider: "email", providerAccountId: "user@example.test" }],
    })),
    unlinkUserAccount: mock(async () => ({ deleted: true, issuedBefore: 1 })),
    sendUserPhoneAccountLinkOtp: mock(async () => ({ phone: "***0123", expiresAt: "later" })),
    verifyUserPhoneAccountLinkOtp: mock(async () => linkedResult("phone-1", "phone", "phone:hash")),
    createUserEthereumWalletLinkNonce: mock(async () => ({
      nonce: "eth-nonce",
      message: "eth-message",
      expiresIn: 300,
    })),
    linkUserEthereumWallet: mock(async () => linkedResult("eth-1", "wallet:ethereum", "0x1")),
    createUserSolanaWalletLinkNonce: mock(async () => ({
      nonce: "sol-nonce",
      message: "sol-message",
      expiresIn: 300,
    })),
    linkUserSolanaWallet: mock(async () => linkedResult("sol-1", "wallet:solana", "sol-key")),
    createUserOAuthAccountLinkChallenge: mock(async () => ({
      state: "oauth-state",
      redirectUri: "https://app.example.test/callback",
      expiresIn: 300,
    })),
    linkUserOAuthAccount: mock(async () => linkedResult("oauth-1", "github", "octocat-2")),
    createUserTelegramAccountLinkChallenge: mock(async () => ({
      challengeId: "telegram-challenge",
      expiresIn: 300,
    })),
    linkUserTelegramAccount: mock(async () => linkedResult("telegram-1", "telegram", "12345")),
    createUserFarcasterAccountLinkNonce: mock(async () => ({
      nonce: "farcaster-nonce",
      expiresIn: 300,
    })),
    linkUserFarcasterAccount: mock(async () =>
      linkedResult("farcaster-1", "farcaster", "0xfarcaster"),
    ),
  };
}

let root: Root | null = null;
let container: HTMLDivElement;

async function mount(props: Record<string, unknown> = {}) {
  container = browser.document.createElement("div") as unknown as HTMLDivElement;
  browser.document.body.replaceChildren(container as unknown as Node);
  root = createRoot(container);
  await React.act(async () =>
    root?.render(
      React.createElement(
        StewardProvider,
        { client: client as any },
        React.createElement(
          StewardAuthContext.Provider,
          { value: authContext() as any },
          React.createElement(StewardLinkedAccounts, props),
        ),
      ),
    ),
  );
}

async function rerender(props: Record<string, unknown> = {}) {
  await React.act(async () =>
    root?.render(
      React.createElement(
        StewardProvider,
        { client: client as any },
        React.createElement(
          StewardAuthContext.Provider,
          { value: authContext() as any },
          React.createElement(StewardLinkedAccounts, props),
        ),
      ),
    ),
  );
}

function button(label: string): HTMLButtonElement {
  const result = [...container.querySelectorAll("button")].find(
    (candidate) => candidate.textContent?.trim() === label,
  );
  if (!result) throw new Error(`button not found: ${label}`);
  return result as unknown as HTMLButtonElement;
}

async function click(label: string) {
  await React.act(async () => {
    button(label).dispatchEvent(new browser.MouseEvent("click", { bubbles: true }));
  });
}

async function change(selector: string, value: string) {
  const input = container.querySelector(selector);
  if (!input) throw new Error(`input not found: ${selector}`);
  await React.act(async () => {
    (input as unknown as { value: string }).value = value;
    Simulate.change(input as unknown as Element);
  });
}

beforeEach(() => {
  authed = true;
  resetClient();
  globalThis.fetch = mock(async () => Response.json({ ok: true, data: {} }));
});

afterEach(async () => {
  if (root) await React.act(async () => root?.unmount());
  root = null;
  globalThis.fetch = originalFetch;
});

describe("<StewardLinkedAccounts /> mounted interactions", () => {
  test("keeps signed-out and loaded rendering gates", async () => {
    authed = false;
    await mount();
    expect(container.textContent).toContain("Sign in to manage linked accounts");
    expect(client.listUserAccounts).toHaveBeenCalledTimes(0);
  });

  test("unlinks with exact identity, reports success, then refreshes", async () => {
    const onUnlink = mock(() => {});
    await mount({ onUnlink });
    await click("unlink");
    expect(client.unlinkUserAccount).toHaveBeenCalledWith("github", "octocat");
    expect(onUnlink).toHaveBeenCalledTimes(1);
    expect(client.listUserAccounts).toHaveBeenCalledTimes(2);
  });

  for (const channel of ["sms", "whatsapp"] as const) {
    test(`links a phone using the ${channel} channel`, async () => {
      const onLink = mock(() => {});
      await mount({ onLink });
      if (channel === "whatsapp") await change("select", "whatsapp");
      await change('input[placeholder="+14155550123"]', " +14155550123 ");
      await React.act(async () => Simulate.submit(container.querySelector("form") as Element));
      expect(client.sendUserPhoneAccountLinkOtp).toHaveBeenCalledWith("+14155550123", channel);
      await change('input[placeholder="000000"]', " 123456 ");
      const forms = container.querySelectorAll("form");
      await React.act(async () => Simulate.submit(forms[1] as unknown as Element));
      expect(client.verifyUserPhoneAccountLinkOtp).toHaveBeenCalledWith(
        { phone: "+14155550123", code: "123456" },
        channel,
      );
      expect(onLink).toHaveBeenCalledTimes(1);
      expect(client.listUserAccounts).toHaveBeenCalledTimes(2);
    });
  }

  test("links Ethereum and Solana wallets with challenge-bound signatures", async () => {
    const ethereumSign = mock(async () => "0xeth-signature");
    const solanaSign = mock(async () => "sol-signature");
    const onLink = mock(() => {});
    await mount({
      ethereumWallet: {
        address: "0x0000000000000000000000000000000000000001",
        signMessage: ethereumSign,
      },
      solanaWallet: { publicKey: "sol-public-key", signMessage: solanaSign },
      onLink,
    });
    await click("link ethereum");
    expect(client.createUserEthereumWalletLinkNonce).toHaveBeenCalledWith(
      "0x0000000000000000000000000000000000000001",
    );
    expect(ethereumSign).toHaveBeenCalledWith("eth-message");
    expect(client.linkUserEthereumWallet).toHaveBeenCalledWith({
      address: "0x0000000000000000000000000000000000000001",
      message: "eth-message",
      signature: "0xeth-signature",
    });
    await click("link solana");
    expect(client.createUserSolanaWalletLinkNonce).toHaveBeenCalledWith("sol-public-key");
    expect(solanaSign).toHaveBeenCalledWith("sol-message");
    expect(client.linkUserSolanaWallet).toHaveBeenCalledWith({
      publicKey: "sol-public-key",
      message: "sol-message",
      signature: "sol-signature",
    });
    expect(onLink).toHaveBeenCalledTimes(2);
  });

  test("links OAuth, Telegram, and Farcaster with challenge-bound inputs", async () => {
    const oauth = mock(async () => ({ code: "provider-code", codeVerifier: "verifier" }));
    const telegram = mock(async () => ({ id: 12345, hash: "telegram-hash" }));
    const farcaster = mock(async () => ({
      message: "farcaster-message",
      signature: "0xfarcaster-signature",
      custodyAddress: "0x0000000000000000000000000000000000000001",
    }));
    await mount({
      oauthProviders: ["github"],
      oauthRedirectUri: "https://app.example.test/callback",
      onOAuthLinkRequest: oauth,
      onTelegramLinkRequest: telegram,
      onFarcasterLinkRequest: farcaster,
    });
    await click("link github");
    expect(client.createUserOAuthAccountLinkChallenge).toHaveBeenCalledWith("github", {
      redirectUri: "https://app.example.test/callback",
    });
    expect(oauth).toHaveBeenCalledWith("github", expect.objectContaining({ state: "oauth-state" }));
    expect(client.linkUserOAuthAccount).toHaveBeenCalledWith("github", {
      code: "provider-code",
      codeVerifier: "verifier",
      redirectUri: "https://app.example.test/callback",
      state: "oauth-state",
    });
    await click("link telegram");
    expect(telegram).toHaveBeenCalledWith("telegram-challenge");
    expect(client.linkUserTelegramAccount).toHaveBeenCalledWith({
      id: 12345,
      hash: "telegram-hash",
      challengeId: "telegram-challenge",
    });
    await click("link farcaster");
    expect(farcaster).toHaveBeenCalledWith("farcaster-nonce");
    expect(client.linkUserFarcasterAccount).toHaveBeenCalledWith({
      message: "farcaster-message",
      signature: "0xfarcaster-signature",
      custodyAddress: "0x0000000000000000000000000000000000000001",
    });
    expect(client.listUserAccounts).toHaveBeenCalledTimes(4);
  });

  test("renders stable errors without success callbacks or losing loaded accounts", async () => {
    client.unlinkUserAccount.mockImplementation(async () => {
      throw new Error("unlink refused");
    });
    const onUnlink = mock(() => {});
    const onError = mock(() => {});
    await mount({ onUnlink, onError });
    await click("unlink");
    expect(container.textContent).toContain("unlink refused");
    expect(container.textContent).toContain("octocat");
    expect(onUnlink).toHaveBeenCalledTimes(0);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(client.listUserAccounts).toHaveBeenCalledTimes(1);
  });

  test("an older refresh cannot overwrite a newer refresh result", async () => {
    let resolveOld: ((value: unknown) => void) | undefined;
    const old = new Promise((resolve) => {
      resolveOld = resolve;
    });
    await mount();
    client.listUserAccounts
      .mockImplementationOnce(() => old)
      .mockImplementationOnce(async () => ({
        accounts: [account("new", "github", "new-result")],
        primaryLoginMethods: [{ provider: "email", providerAccountId: "new@example.test" }],
      }));
    await click("refresh");
    await click("unlink");
    expect(container.textContent).toContain("new-result");
    await React.act(async () => {
      resolveOld?.({
        accounts: [account("old", "github", "stale-result")],
        primaryLoginMethods: [{ provider: "email", providerAccountId: "old@example.test" }],
      });
      await old;
    });
    expect(container.textContent).toContain("new-result");
    expect(container.textContent).not.toContain("stale-result");
  });

  test("signing out invalidates an in-flight account refresh", async () => {
    const onLoaded = mock(() => {});
    await mount({ onLoaded });
    expect(onLoaded).toHaveBeenCalledTimes(1);

    let resolveSignedInRefresh: ((value: unknown) => void) | undefined;
    const signedInRefresh = new Promise((resolve) => {
      resolveSignedInRefresh = resolve;
    });
    client.listUserAccounts.mockImplementationOnce(() => signedInRefresh);
    await click("refresh");

    authed = false;
    await rerender({ onLoaded });
    expect(container.textContent).toContain("Sign in to manage linked accounts");
    await React.act(async () => {
      resolveSignedInRefresh?.({
        accounts: [account("stale", "github", "stale-after-signout")],
        primaryLoginMethods: [{ provider: "email", providerAccountId: "stale@example.test" }],
      });
      await signedInRefresh;
    });

    expect(onLoaded).toHaveBeenCalledTimes(1);
    expect(container.textContent).not.toContain("stale-after-signout");
  });
});
