import { afterEach, describe, expect, it } from "bun:test";
import type { StewardClient } from "@stwd/sdk";
import type { AgentTraderConfig, TraderConfig } from "../config.js";
import { clearWalletCacheForTest, runTick, setWalletCacheTtlForTest } from "../loop.js";
import type { AgentState, Strategy } from "../strategies/types.js";

/**
 * SEC-188: the agentId → walletAddress cache must REFRESH — a wallet rotation
 * has to be picked up after the TTL instead of trading against a stale address
 * forever.
 */

const WALLET_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const WALLET_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TOKEN = "0x1111111111111111111111111111111111111111";
const PORTAL = "0x2222222222222222222222222222222222222222";

const agentConfig: AgentTraderConfig = {
  agentId: "agent-wallet-rotation",
  tokenAddress: TOKEN,
  strategy: "threshold",
  intervalSeconds: 60,
  enabled: true,
  chainId: 8453,
  portalAddress: PORTAL,
  slippageBps: 100,
  params: {},
};

const globalConfig: TraderConfig = {
  steward: { apiUrl: "http://localhost", tenantId: "t", apiKey: "k" },
  webhookPort: 4210,
  webhookSecret: "s",
  dryRun: false,
  agents: [agentConfig],
};

const holdStrategy: Strategy = {
  name: "hold-test",
  requiresPriceConfidence: false,
  evaluate: async () => ({ action: "hold", amount: "0", reason: "hold", confidence: 1 }),
};

const state: AgentState = {
  nativeBalance: 10n ** 19n,
  tokenBalance: 10n ** 21n,
  tokenPrice: 10n ** 15n,
  priceConfidence: "high",
  lastTradeAge: 100_000,
  dailyVolume: 0n,
  treasuryValue: 10n ** 19n,
};

/** Steward fake that serves wallets[current] and counts getAgent calls. */
function rotatingSteward(wallets: string[]) {
  const fake = { calls: 0 };
  const steward = {
    getAgent: async () => ({ walletAddress: wallets[Math.min(fake.calls++, wallets.length - 1)] }),
    getHistory: async () => [],
  } as unknown as StewardClient;
  return { steward, fake };
}

afterEach(() => {
  clearWalletCacheForTest();
});

describe("runTick — wallet cache refresh (SEC-188)", () => {
  it("reuses the cached wallet within the TTL (one getAgent call)", async () => {
    clearWalletCacheForTest();
    const { steward, fake } = rotatingSteward([WALLET_A, WALLET_B]);
    const seen: string[] = [];
    const deps = {
      fetchState: async (_c: AgentTraderConfig, walletAddress: string) => {
        seen.push(walletAddress);
        return state;
      },
    };

    await runTick(agentConfig, holdStrategy, steward, globalConfig, deps);
    await runTick(agentConfig, holdStrategy, steward, globalConfig, deps);

    expect(seen).toEqual([WALLET_A, WALLET_A]);
    expect(fake.calls).toBe(1);
  });

  it("picks up a wallet rotation after the cache entry expires", async () => {
    clearWalletCacheForTest();
    setWalletCacheTtlForTest(0); // every entry expires immediately
    const { steward, fake } = rotatingSteward([WALLET_A, WALLET_B]);
    const seen: string[] = [];
    const deps = {
      fetchState: async (_c: AgentTraderConfig, walletAddress: string) => {
        seen.push(walletAddress);
        return state;
      },
    };

    await runTick(agentConfig, holdStrategy, steward, globalConfig, deps);
    await runTick(agentConfig, holdStrategy, steward, globalConfig, deps);

    expect(seen).toEqual([WALLET_A, WALLET_B]); // rotation picked up, not stale
    expect(fake.calls).toBe(2);
  });
});
