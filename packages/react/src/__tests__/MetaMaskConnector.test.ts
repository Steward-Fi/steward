import { describe, expect, mock, test } from "bun:test";

// Mirror the GlobalWallet test: mock the wagmi-native connector so we can assert
// the dapp params Steward passes through. metaMask() returns a CreateConnectorFn,
// here a tagged factory we can inspect.
const mockMetaMask = mock((params: unknown) => {
  const fn = () => ({ id: "metaMask", type: "metaMask" });
  (fn as unknown as { params: unknown }).params = params;
  return fn;
});

mock.module("wagmi/connectors", () => ({
  metaMask: mockMetaMask,
}));

const { createStewardMetaMaskConnector } = await import("../wallet/metamask.js");

describe("createStewardMetaMaskConnector", () => {
  test("returns a wagmi connector factory", () => {
    const connector = createStewardMetaMaskConnector();
    expect(typeof connector).toBe("function");
  });

  test("defaults the dapp name to Steward", () => {
    createStewardMetaMaskConnector();
    const lastCall = mockMetaMask.mock.calls.at(-1)?.[0] as { dapp?: { name?: string } };
    expect(lastCall.dapp?.name).toBe("Steward");
  });

  test("passes the caller dapp metadata through, overriding defaults", () => {
    createStewardMetaMaskConnector({
      dapp: { name: "My Steward App", url: "https://app.example.com", iconUrl: "https://app.example.com/icon.png" },
    });
    const lastCall = mockMetaMask.mock.calls.at(-1)?.[0] as {
      dapp?: { name?: string; url?: string; iconUrl?: string };
    };
    expect(lastCall.dapp).toMatchObject({
      name: "My Steward App",
      url: "https://app.example.com",
      iconUrl: "https://app.example.com/icon.png",
    });
  });

  test("forwards extra MetaMask parameters alongside dapp", () => {
    createStewardMetaMaskConnector({ connectAndSign: "hello" });
    const lastCall = mockMetaMask.mock.calls.at(-1)?.[0] as {
      dapp?: { name?: string };
      connectAndSign?: string;
    };
    expect(lastCall.connectAndSign).toBe("hello");
    expect(lastCall.dapp?.name).toBe("Steward");
  });
});
