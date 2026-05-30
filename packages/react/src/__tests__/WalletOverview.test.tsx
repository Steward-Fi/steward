/**
 * <WalletOverview /> branch coverage.
 *
 * Mock ../provider.js (feature flags) + ../hooks/useWallet.js, render via SSR:
 *   - loading                  → loading shell
 *   - error                    → error shell
 *   - null agent               → renders nothing
 *   - loaded with addresses    → header, truncated address, chain badge
 *   - balance present          → balance section (formatted + native fallback)
 *   - funding QR gating        → showQR prop overrides features.showFundingQR
 *   - chain filtering          → only requested chain families render
 *   - address fallback         → agent.walletAddress used when none returned
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

let mockFeatures = { showFundingQR: true };

let mockWallet: any = {
  agent: null,
  balance: null,
  addresses: [],
  isLoading: true,
  error: null,
};

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({ features: mockFeatures }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("../hooks/useWallet.js", () => ({
  useWallet: () => mockWallet,
}));

const { WalletOverview } = await import("../components/WalletOverview.js");

function render(props: Record<string, unknown> = {}): string {
  return renderToString(React.createElement(WalletOverview, props));
}

const AGENT = { id: "a1", name: "Treasury Agent", platformId: "discord:123" };

describe("<WalletOverview /> branch coverage", () => {
  beforeEach(() => {
    mockFeatures = { showFundingQR: true };
    mockWallet = {
      agent: null,
      balance: null,
      addresses: [],
      isLoading: true,
      error: null,
    };
  });

  test("loading branch renders the loading shell", () => {
    expect(render()).toContain("Loading wallet");
  });

  test("error branch renders the error message", () => {
    mockWallet = { ...mockWallet, isLoading: false, error: new Error("rpc down") };
    const html = render();
    expect(html).toContain("Failed to load wallet");
    expect(html).toContain("rpc down");
  });

  test("null agent renders nothing", () => {
    mockWallet = { ...mockWallet, isLoading: false, agent: null };
    expect(render()).toBe("");
  });

  test("loaded branch renders the agent name, platform badge, and a truncated address", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [{ chainFamily: "evm", address: "0x1234567890abcdef1234567890abcdef12345678" }],
    };
    const html = render();
    expect(html).toContain("Treasury Agent");
    expect(html).toContain("discord:123");
    expect(html).toContain("EVM");
    expect(html).toContain("0x1234...5678");
  });

  test("balance section renders the formatted native fallback when no nativeFormatted", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [{ chainFamily: "evm", address: "0xabc0000000000000000000000000000000000def" }],
      balance: { balances: { native: "1000000000000000000", symbol: "ETH", chainId: 8453 } },
    };
    const html = render();
    expect(html).toContain("Balance");
    expect(html).toContain("1.0000");
    expect(html).toContain("Chain ID:");
  });

  test("balance section prefers nativeFormatted when present", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [{ chainFamily: "evm", address: "0xabc0000000000000000000000000000000000def" }],
      balance: {
        balances: {
          native: "1000000000000000000",
          nativeFormatted: "1.23",
          symbol: "ETH",
          chainId: 1,
        },
      },
    };
    const html = render();
    expect(html).toContain("1.23");
  });

  test("funding QR shows when features.showFundingQR is true and addresses exist", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [{ chainFamily: "evm", address: "0xabc0000000000000000000000000000000000def" }],
    };
    const html = render();
    expect(html).toContain("Fund this wallet");
  });

  test("showQR={false} prop overrides the feature flag", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [{ chainFamily: "evm", address: "0xabc0000000000000000000000000000000000def" }],
    };
    const html = render({ showQR: false });
    expect(html).not.toContain("Fund this wallet");
  });

  test("chains prop filters out non-matching chain families", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: AGENT,
      addresses: [
        { chainFamily: "evm", address: "0x1111111111111111111111111111111111111111" },
        { chainFamily: "solana", address: "SoLPubKey1111111111111111111111111111111111" },
      ],
    };
    const html = render({ chains: ["solana"] });
    expect(html).toContain("SOLANA");
    expect(html).not.toContain("EVM");
  });

  test("falls back to agent.walletAddress when no addresses are returned", () => {
    mockWallet = {
      ...mockWallet,
      isLoading: false,
      agent: { ...AGENT, walletAddress: "0x9999999999999999999999999999999999999999" },
      addresses: [],
    };
    const html = render();
    // truncated agent.walletAddress
    expect(html).toContain("0x9999...9999");
    expect(html).toContain("EVM");
  });
});
