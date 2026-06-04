import { describe, expect, test } from "bun:test";

import { MockBridgeAdapter } from "../adapters/bridge.js";
import { AdapterValidationError } from "../types.js";

const USDC = { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 };
const BASE_USDC = {
  address: "0x4200000000000000000000000000000000000006",
  symbol: "USDbC",
  decimals: 6,
};
const RECIPIENT = "0x1111111111111111111111111111111111111111";
const OWNER = "0x2222222222222222222222222222222222222222";
const SESSION_OWNER = { tenantId: "tenant-bridge-test", userId: "user-bridge-test" };

describe("MockBridgeAdapter", () => {
  test("quotes a deterministic cross-chain transfer with fee and slippage minimum", async () => {
    const adapter = new MockBridgeAdapter({ now: () => 1779819300000 });

    const quote = await adapter.getQuote({
      fromChainId: 1,
      toChainId: 8453,
      fromToken: USDC,
      toToken: BASE_USDC,
      amount: "1000000",
      recipient: RECIPIENT,
      slippageBps: 100,
    });

    expect(quote).toEqual({
      provider: "mock",
      quoteId: "mock-bridge-1-8453-1000000-100",
      fromChainId: 1,
      toChainId: 8453,
      fromToken: USDC,
      toToken: BASE_USDC,
      amountIn: "1000000",
      amountOut: "998000",
      minAmountOut: "988020",
      feeAmount: "2000",
      recipient: RECIPIENT,
      route: [{ bridge: "mock-bridge", fromChainId: 1, toChainId: 8453 }],
      slippageBps: 100,
      expiresAt: 1779819360000,
    });
  });

  test("buildBridge returns an unsigned intent and never signs or broadcasts", async () => {
    const adapter = new MockBridgeAdapter({ now: () => 1779819300000 });
    const quote = await adapter.getQuote({
      fromChainId: 1,
      toChainId: 8453,
      fromToken: USDC,
      toToken: BASE_USDC,
      amount: "1000000",
      recipient: RECIPIENT,
    });

    const intent = await adapter.buildBridge({ quote, owner: OWNER });

    expect(intent).toEqual({
      signed: false,
      kind: "evm-tx",
      chainId: 1,
      to: USDC.address,
      value: "0",
      data: "0x",
      owner: OWNER,
      category: "bridge",
      provider: "mock",
      metadata: {
        quoteId: quote.quoteId,
        fromChainId: 1,
        toChainId: 8453,
        recipient: RECIPIENT,
        amountIn: "1000000",
        minAmountOut: "993010",
        slippageBps: 50,
      },
    });
  });

  test("creates and reads a bridge session without moving funds", async () => {
    const adapter = new MockBridgeAdapter({ now: () => 1779819300000 });
    const quote = await adapter.getQuote({
      fromChainId: 1,
      toChainId: 8453,
      fromToken: USDC,
      toToken: BASE_USDC,
      amount: "1000000",
      recipient: RECIPIENT,
    });

    const session = await adapter.createSession(quote, SESSION_OWNER);

    expect(session).toMatchObject({
      provider: "mock",
      tenantId: SESSION_OWNER.tenantId,
      userId: SESSION_OWNER.userId,
      quoteId: quote.quoteId,
      status: "created",
      fromChainId: 1,
      toChainId: 8453,
      recipient: RECIPIENT,
      createdAt: 1779819300000,
    });
    expect(session.id).toMatch(/^bridge_/);
    expect(await adapter.getSession(session.id)).toEqual(session);
    expect(await adapter.getSession("bridge_missing")).toBeNull();
  });

  test("rejects same-chain bridge quotes", async () => {
    const adapter = new MockBridgeAdapter();
    await expect(
      adapter.getQuote({
        fromChainId: 1,
        toChainId: 1,
        fromToken: USDC,
        toToken: BASE_USDC,
        amount: "1000000",
        recipient: RECIPIENT,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects expired quotes before building unsigned intents", async () => {
    const adapter = new MockBridgeAdapter({ now: () => 1779819300000 });
    const quote = await adapter.getQuote({
      fromChainId: 1,
      toChainId: 8453,
      fromToken: USDC,
      toToken: BASE_USDC,
      amount: "1000000",
      recipient: RECIPIENT,
    });

    const later = new MockBridgeAdapter({ now: () => 1779819360001 });
    await expect(later.buildBridge({ quote, owner: OWNER })).rejects.toThrow("quote has expired");
  });
});
