import { describe, expect, it } from "vitest";
import { transferAction } from "../actions/transfer.js";

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

  it("has optional 'chain' parameter", () => {
    const chainParam = transferAction.parameters?.find((p) => p.name === "chain");
    expect(chainParam).toBeDefined();
    expect(chainParam?.required).toBeFalsy();
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

  it("rejects adversarial amount text without backtracking or reflection", async () => {
    const amount = `${"00".repeat(100_000)}!credential-canary`;
    const mockRuntime = {
      getService: () => ({ isConnected: () => true }),
    } as any;

    const result = await transferAction.handler(mockRuntime, {} as any, undefined, {
      parameters: { to: "0x0000000000000000000000000000000000000001", amount },
    });

    expect(result?.success).toBe(false);
    expect(result?.error).not.toContain("credential-canary");
  });

  it("converts decimal amounts to wei exactly", async () => {
    const calls: Array<Record<string, unknown>> = [];
    const mockRuntime = {
      getService: () => ({
        isConnected: () => true,
        signTransaction: async (input: Record<string, unknown>) => {
          calls.push(input);
          return { txHash: "0xabc" };
        },
      }),
    } as any;

    const result = await transferAction.handler(mockRuntime, {} as any, undefined, {
      parameters: {
        to: "0x0000000000000000000000000000000000000001",
        amount: "0.100000000000000001 ETH",
        chain: "base",
      },
    });

    expect(result?.success).toBe(true);
    expect(calls[0]?.value).toBe("100000000000000001");
  });

  it("rejects non-native symbols, malformed decimals, and sub-wei values before signing", async () => {
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
    for (const amount of ["100 USDC", "1.2.3 ETH", "1e3 ETH", "0.0000000000000000001 ETH"]) {
      const result = await transferAction.handler(mockRuntime, {} as any, undefined, {
        parameters: {
          to: "0x0000000000000000000000000000000000000001",
          amount,
          chain: "base",
        },
      });
      expect(result?.success).toBe(false);
    }
    expect(calls).toBe(0);
  });

  it("treats an omitted symbol as the selected chain's native currency", async () => {
    const calls: Record<string, unknown>[] = [];
    const mockRuntime = {
      getService: () => ({
        isConnected: () => true,
        signTransaction: async (input: Record<string, unknown>) => {
          calls.push(input);
          return { txHash: "0xabc" };
        },
      }),
    } as any;
    for (const amount of ["1", "1 BNB"]) {
      const result = await transferAction.handler(mockRuntime, {} as any, undefined, {
        parameters: {
          to: "0x0000000000000000000000000000000000000001",
          amount,
          chain: "bsc",
        },
      });
      expect(result?.success).toBe(true);
    }
    expect(calls).toHaveLength(2);
    expect(calls.every((call) => call.value === "1000000000000000000")).toBe(true);
  });
});
