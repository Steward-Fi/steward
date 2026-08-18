import { describe, expect, it } from "vitest";
import { parseNativeAmount, transferAction } from "../actions/transfer.js";

describe("STEWARD_TRANSFER action", () => {
  it("has correct metadata", () => {
    expect(transferAction.name).toBe("STEWARD_TRANSFER");
    expect(transferAction.parameters).toBeDefined();
    expect(transferAction.parameters?.length).toBeGreaterThanOrEqual(2);
  });

  it("requires 'to' parameter", () => {
    const toParam = transferAction.parameters?.find((p) => p.name === "to");
    expect(toParam).toBeDefined();
    expect(toParam?.required).toBe(true);
  });

  it("requires 'amount' parameter", () => {
    const amountParam = transferAction.parameters?.find((p) => p.name === "amount");
    expect(amountParam).toBeDefined();
    expect(amountParam?.required).toBe(true);
  });

  it("requires an explicit chain", () => {
    const chainParam = transferAction.parameters?.find((p) => p.name === "chain");
    expect(chainParam).toBeDefined();
    expect(chainParam?.required).toBe(true);
  });

  it("validate returns false without steward service", async () => {
    const mockRuntime = {
      getService: () => null,
    } as any;
    const result = await transferAction.validate(mockRuntime, {} as any);
    expect(result).toBe(false);
  });

  it("handler returns error for missing params", async () => {
    const mockRuntime = {
      getService: () => ({ isConnected: () => true }),
    } as any;

    const result = await transferAction.handler(mockRuntime, {} as any, undefined, {
      parameters: {},
    });

    expect(result).toBeDefined();
    expect(result?.success).toBe(false);
    expect(result?.error).toContain("Missing required parameters");
  });

  it("converts native decimal values exactly without floating-point rounding", () => {
    expect(parseNativeAmount("0.000000000000000001 ETH").valueWei).toBe("1");
    expect(parseNativeAmount("123456789012345678.123456789012345678 ETH").valueWei).toBe(
      "123456789012345678123456789012345678",
    );
  });

  it.each([
    "1.2.3 ETH",
    "1.0000000000000000001 ETH",
    "1e3 ETH",
    "1",
    "0 ETH",
  ])("rejects malformed or unsafe amount %s", (amount) => {
    expect(() => parseNativeAmount(amount)).toThrow();
  });

  it("rejects absent chains and non-native symbols before calling Steward", async () => {
    let calls = 0;
    const mockRuntime = {
      getService: () => ({
        isConnected: () => true,
        signTransaction: async () => {
          calls += 1;
          return { txHash: "0xabc" };
        },
      }),
    } as any;
    const message = { id: "message-1" } as any;

    const absentChain = await transferAction.handler(mockRuntime, message, undefined, {
      parameters: { to: "0x1111111111111111111111111111111111111111", amount: "1 ETH" },
    });
    const usdc = await transferAction.handler(mockRuntime, message, undefined, {
      parameters: {
        to: "0x1111111111111111111111111111111111111111",
        amount: "1 USDC",
        chain: "base",
      },
    });
    const wrongNative = await transferAction.handler(mockRuntime, message, undefined, {
      parameters: {
        to: "0x1111111111111111111111111111111111111111",
        amount: "1 ETH",
        chain: "bsc",
      },
    });

    expect(absentChain?.success).toBe(false);
    expect(usdc?.success).toBe(false);
    expect(wrongNative?.success).toBe(false);
    expect(calls).toBe(0);
  });

  it("reuses the message-derived idempotency key on retries", async () => {
    const calls: unknown[] = [];
    const mockRuntime = {
      getService: () => ({
        isConnected: () => true,
        signTransaction: async (...args: unknown[]) => {
          calls.push(args);
          return { txHash: "0xabc" };
        },
      }),
    } as any;
    const message = { id: "stable-message-id" } as any;
    const options = {
      parameters: {
        to: "0x1111111111111111111111111111111111111111",
        amount: "1 ETH",
        chain: "base",
      },
    } as any;

    await transferAction.handler(mockRuntime, message, undefined, options);
    await transferAction.handler(mockRuntime, message, undefined, options);

    expect(calls).toHaveLength(2);
    expect(calls[0]?.[1]).toEqual({ idempotencyKey: "eliza-transfer:stable-message-id" });
    expect(calls[1]?.[1]).toEqual(calls[0]?.[1]);
  });
});
