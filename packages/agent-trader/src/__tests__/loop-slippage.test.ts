import { describe, expect, it } from "bun:test";
import type { SignTransactionInput, StewardClient } from "@stwd/sdk";
import { decodeFunctionData } from "viem";
import type { AgentTraderConfig, TraderConfig } from "../config.js";
import { runTick } from "../loop.js";
import type { AgentState, Strategy, TradeDecision } from "../strategies/types.js";
import { PORTAL_ABI } from "../trade-builder.js";

const WALLET = "0x4444444444444444444444444444444444444444";
const TOKEN = "0x1111111111111111111111111111111111111111";
const PORTAL = "0x2222222222222222222222222222222222222222";

/** Records every signTransaction call so we can inspect the signed calldata. */
function fakeSteward(signed: SignTransactionInput[]): StewardClient {
  return {
    getAgent: async () => ({ walletAddress: WALLET }),
    getHistory: async () => [],
    signTransaction: async (_agentId: string, tx: SignTransactionInput) => {
      signed.push(tx);
      return { txHash: "0xdeadbeef" };
    },
  } as unknown as StewardClient;
}

/** A strategy that always proposes the given decision (price-driven by default). */
function fixedStrategy(decision: TradeDecision, requiresPriceConfidence = true): Strategy {
  return {
    name: "fixed-test",
    requiresPriceConfidence,
    evaluate: async () => decision,
  };
}

const agentConfig: AgentTraderConfig = {
  agentId: "agent-1",
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

function stateWith(overrides: Partial<AgentState>): AgentState {
  return {
    nativeBalance: 10n ** 19n,
    tokenBalance: 10n ** 21n,
    tokenPrice: 10n ** 15n, // 0.001 native/token
    priceConfidence: "high",
    lastTradeAge: 100_000,
    dailyVolume: 0n,
    treasuryValue: 10n ** 19n,
    ...overrides,
  };
}

function decodeSwap(data?: string) {
  if (!data) throw new Error("no calldata signed");
  const { args } = decodeFunctionData({ abi: PORTAL_ABI, data: data as `0x${string}` });
  const [, , amountIn, amountOutMin] = args as readonly [string, string, bigint, bigint, string];
  return { amountIn, amountOutMin };
}

describe("runTick — live-signing slippage chokepoint (HIGH fix)", () => {
  it("(a) signs a swap whose amountOutMin is NON-ZERO and derived from slippageBps", async () => {
    const signed: SignTransactionInput[] = [];
    const buyAmount = 10n ** 18n;
    const decision: TradeDecision = {
      action: "buy",
      amount: buyAmount.toString(),
      reason: "test buy",
      confidence: 0.9,
    };

    await runTick(agentConfig, fixedStrategy(decision), fakeSteward(signed), globalConfig, {
      fetchState: async () => stateWith({ priceConfidence: "high" }),
    });

    expect(signed).toHaveLength(1);
    const { amountIn, amountOutMin } = decodeSwap(signed[0]?.data);
    expect(amountIn).toBe(buyAmount);
    expect(amountOutMin).toBeGreaterThan(0n);
    // expectedOut = 1e18 * 1e18 / 1e15 = 1e21; 1% slippage → 0.99e21
    expect(amountOutMin).toBe((10n ** 21n * 9900n) / 10000n);
  });

  it("(b) REFUSES to sign (fail-closed) when no price quote is available", async () => {
    const signed: SignTransactionInput[] = [];
    const decision: TradeDecision = {
      action: "buy",
      amount: (10n ** 18n).toString(),
      reason: "test buy with no price",
      confidence: 0.9,
    };

    // Strategy is price-agnostic so it doesn't short-circuit; the BUILDER must
    // fail closed because tokenPrice = 0 yields no quote → no amountOutMin.
    await runTick(
      agentConfig,
      fixedStrategy(decision, /* requiresPriceConfidence */ false),
      fakeSteward(signed),
      globalConfig,
      { fetchState: async () => stateWith({ tokenPrice: 0n, priceConfidence: "none" }) },
    );

    expect(signed).toHaveLength(0); // nothing signed — unprotected swap refused
  });

  it("(c) SUPPRESSES the trade when a price-driven strategy has low confidence", async () => {
    const signed: SignTransactionInput[] = [];
    const decision: TradeDecision = {
      action: "buy",
      amount: (10n ** 18n).toString(),
      reason: "buy on manipulable price",
      confidence: 0.9,
    };

    await runTick(
      agentConfig,
      fixedStrategy(decision, /* requiresPriceConfidence */ true),
      fakeSteward(signed),
      globalConfig,
      { fetchState: async () => stateWith({ priceConfidence: "low" }) },
    );

    expect(signed).toHaveLength(0); // gate held — no swap signed off a low-confidence price
  });

  it("dry-run never signs even with a valid protected quote", async () => {
    const signed: SignTransactionInput[] = [];
    const decision: TradeDecision = {
      action: "buy",
      amount: (10n ** 18n).toString(),
      reason: "dry run buy",
      confidence: 0.9,
    };

    await runTick(
      agentConfig,
      fixedStrategy(decision),
      fakeSteward(signed),
      { ...globalConfig, dryRun: true },
      { fetchState: async () => stateWith({ priceConfidence: "high" }) },
    );

    expect(signed).toHaveLength(0);
  });
});
