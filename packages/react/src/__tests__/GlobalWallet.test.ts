import { describe, expect, mock, test } from "bun:test";

const mockCreateConnector = mock((connector: unknown) => connector);

mock.module("wagmi", () => ({
  createConnector: mockCreateConnector,
}));

const { createStewardGlobalWallet, createStewardGlobalWalletConnector } = await import(
  "../wallet/global.js"
);

describe("global wallet helpers", () => {
  test("wraps a wagmi connector as a RainbowKit wallet entry", () => {
    const connector = () => ({ id: "connector" });
    const wallet = createStewardGlobalWallet({
      id: "global",
      name: "Global Wallet",
      iconUrl: "https://example.com/icon.svg",
      connector,
      rdns: "fi.steward.global",
    });

    expect(wallet()).toMatchObject({
      id: "global",
      name: "Global Wallet",
      iconUrl: "https://example.com/icon.svg",
      iconBackground: "#070b12",
      rdns: "fi.steward.global",
      createConnector: expect.any(Function),
    });
    expect((wallet() as { createConnector: () => unknown }).createConnector()).toBe(connector);
  });

  test("creates a ConnectKit-compatible injected wagmi connector over EIP-1193", async () => {
    const events: Array<{ event: string; payload?: unknown }> = [];
    let chainId = "0x1";
    const provider = {
      request: mock(async ({ method, params }: { method: string; params?: unknown }) => {
        if (method === "eth_requestAccounts") return ["0x0000000000000000000000000000000000000001"];
        if (method === "eth_accounts") return ["0x0000000000000000000000000000000000000001"];
        if (method === "eth_chainId") return chainId;
        if (method === "wallet_switchEthereumChain") {
          chainId = (params as Array<{ chainId: string }>)[0]?.chainId ?? chainId;
          return null;
        }
        if (method === "wallet_revokePermissions") return null;
        throw new Error(`unexpected method ${method}`);
      }),
      on: mock(() => {}),
    };
    const connectorFactory = createStewardGlobalWalletConnector({
      id: "global",
      name: "Global Wallet",
      provider,
    });
    const connector = connectorFactory({
      chains: [
        { id: 1, name: "Ethereum" },
        { id: 8453, name: "Base" },
      ],
      emitter: {
        emit: (event: string, payload?: unknown) => events.push({ event, payload }),
      },
    });

    expect(connector.type).toBe("injected");
    expect(connector.id).toBe("global");
    await expect(connector.isAuthorized()).resolves.toBe(true);
    await expect(connector.getAccounts()).resolves.toEqual([
      "0x0000000000000000000000000000000000000001",
    ]);
    await expect(connector.connect({ chainId: 8453 })).resolves.toMatchObject({
      accounts: ["0x0000000000000000000000000000000000000001"],
      chainId: 8453,
    });
    expect(provider.request).toHaveBeenCalledWith({
      method: "wallet_switchEthereumChain",
      params: [{ chainId: "0x2105" }],
    });
    expect(events.some((entry) => entry.event === "connect")).toBe(true);
  });
});
