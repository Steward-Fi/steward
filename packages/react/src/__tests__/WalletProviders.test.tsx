import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

let capturedSolanaWallets: unknown[] | undefined;
const mockConnectors = [{ id: "connector" }];
const mockHttpTransport = { key: "http" };
const mockConnectorsForWallets = mock(() => mockConnectors);
const mockCreateConfig = mock((config: unknown) => ({ kind: "wagmi-config", config }));
const mockHttp = mock(() => mockHttpTransport);

class PhantomWalletAdapter {
  name = "Phantom";
}
class SolflareWalletAdapter {
  name = "Solflare";
}
class CoinbaseWalletAdapter {
  name = "Coinbase Wallet";
}
class TrustWalletAdapter {
  name = "Trust Wallet";
}
class LedgerWalletAdapter {
  name = "Ledger";
}
class TrezorWalletAdapter {
  name = "Trezor";
}
class MathWalletAdapter {
  name = "MathWallet";
}
class Coin98WalletAdapter {
  name = "Coin98";
}
class BackpackWalletAdapter {
  name = "Backpack";
}

mock.module("@rainbow-me/rainbowkit", () => ({
  ConnectButton: () =>
    React.createElement("div", { "data-testid": "rk-connect" }, "[ConnectButton]"),
  connectorsForWallets: mockConnectorsForWallets,
  darkTheme: () => ({}),
  lightTheme: () => ({}),
  RainbowKitProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("@rainbow-me/rainbowkit/wallets", () => ({
  metaMaskWallet: () => ({ id: "metaMask" }),
  coinbaseWallet: () => ({ id: "coinbase" }),
  walletConnectWallet: () => ({ id: "walletConnect" }),
  rainbowWallet: () => ({ id: "rainbow" }),
  rabbyWallet: () => ({ id: "rabby" }),
  trustWallet: () => ({ id: "trust" }),
  phantomWallet: () => ({ id: "phantom" }),
  ledgerWallet: () => ({ id: "ledger" }),
  safeWallet: () => ({ id: "safe" }),
  injectedWallet: () => ({ id: "injected" }),
}));

mock.module("@solana/wallet-adapter-react", () => ({
  useWallet: () => ({
    publicKey: {
      toBase58: () => "SoLPubKeyMock1111111111111111111111111111111",
      toBytes: () => new Uint8Array(),
    },
    connected: true,
    connecting: false,
    wallet: { adapter: { name: "Phantom", publicKey: null } },
    signMessage: async () => new Uint8Array([1, 2, 3, 4]),
    disconnect: async () => {},
  }),
  useConnection: () => ({ connection: null }),
  ConnectionProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
  WalletProvider: ({ wallets, children }: { wallets?: unknown[]; children?: React.ReactNode }) => {
    capturedSolanaWallets = wallets;
    return React.createElement(React.Fragment, null, children);
  },
}));

mock.module("@solana/wallet-adapter-react-ui", () => ({
  WalletMultiButton: () =>
    React.createElement("div", { "data-testid": "sol-connect" }, "[WalletMultiButton]"),
  WalletModalProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("@solana/wallet-adapter-wallets", () => ({
  BackpackWalletAdapter,
  PhantomWalletAdapter,
  SolflareWalletAdapter,
  CoinbaseWalletAdapter,
  TrustWalletAdapter,
  LedgerWalletAdapter,
  TrezorWalletAdapter,
  MathWalletAdapter,
  Coin98WalletAdapter,
}));

mock.module("@tanstack/react-query", () => ({
  QueryClient: class QueryClient {},
  QueryClientProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("wagmi", () => ({
  createConfig: mockCreateConfig,
  http: mockHttp,
  useAccount: () => ({
    address: "0xabc0000000000000000000000000000000000def",
    isConnected: true,
    connector: { name: "MetaMask" },
    chain: { id: 1, name: "Ethereum" },
  }),
  useDisconnect: () => ({ disconnect: () => {} }),
  useSignMessage: () => ({ signMessageAsync: async () => "0xdeadbeef" }),
  WagmiProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { createDefaultWagmiConfig, DEFAULT_SOLANA_WALLETS, SolanaWalletProvider } = await import(
  "../providers/WalletProviders.js"
);

function walletNames(wallets: unknown[]) {
  return wallets.map((wallet) => (wallet as { name?: string }).name);
}

describe("Wallet provider helpers", () => {
  beforeEach(() => {
    capturedSolanaWallets = undefined;
    mockConnectorsForWallets.mockClear();
    mockCreateConfig.mockClear();
    mockHttp.mockClear();
  });

  test("DEFAULT_SOLANA_WALLETS includes Phantom, Solflare, and software-only coverage", () => {
    expect(Array.isArray(DEFAULT_SOLANA_WALLETS)).toBe(true);
    expect(DEFAULT_SOLANA_WALLETS.length).toBeGreaterThanOrEqual(6);
    expect(walletNames(DEFAULT_SOLANA_WALLETS)).toEqual([
      "Phantom",
      "Solflare",
      "Coinbase Wallet",
      "Trust Wallet",
      "MathWallet",
      "Coin98",
    ]);
  });

  test("DEFAULT_SOLANA_WALLETS excludes hardware adapters (Ledger / Trezor) that lack signMessage", () => {
    const names = walletNames(DEFAULT_SOLANA_WALLETS);
    expect(names).not.toContain("Ledger");
    expect(names).not.toContain("Trezor");
  });

  test("SolanaWalletProvider uses DEFAULT_SOLANA_WALLETS when wallets is undefined", () => {
    renderToString(
      React.createElement(SolanaWalletProvider, {
        endpoint: "https://api.mainnet-beta.solana.com",
      }),
    );

    expect(capturedSolanaWallets).toBe(DEFAULT_SOLANA_WALLETS);
  });

  test("SolanaWalletProvider wallets prop overrides defaults", () => {
    const customAdapter = { name: "Custom" };

    renderToString(
      React.createElement(SolanaWalletProvider, {
        endpoint: "https://api.mainnet-beta.solana.com",
        wallets: [customAdapter],
      }),
    );

    expect(capturedSolanaWallets).toEqual([customAdapter]);
  });

  test("createDefaultWagmiConfig returns a wagmi config using curated connectors", () => {
    const chains = [
      {
        id: 1,
        name: "Ethereum",
        nativeCurrency: { decimals: 18, name: "Ether", symbol: "ETH" },
        rpcUrls: { default: { http: ["https://example.invalid"] } },
      },
    ] as const;

    const config = createDefaultWagmiConfig({
      projectId: "test-project-id",
      appName: "Steward Test",
      chains,
    });

    expect(config).toEqual({
      kind: "wagmi-config",
      config: {
        chains,
        connectors: mockConnectors,
        transports: { 1: mockHttpTransport },
        ssr: true,
      },
    });
    expect(mockConnectorsForWallets).toHaveBeenCalledTimes(1);
    expect(mockCreateConfig).toHaveBeenCalledTimes(1);
    expect(mockHttp).toHaveBeenCalledTimes(1);
  });
});
