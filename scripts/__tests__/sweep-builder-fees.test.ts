import { describe, expect, test } from "bun:test";
import { decodeFunctionData } from "viem";
import {
  ARBITRUM_CHAIN_ID,
  ARBITRUM_USDC,
  BUILDER_EOA,
  buildUsdcTransferData,
  configFromEnvAndArgs,
  formatUsdcBaseUnits,
  PLATFORM_SAFE,
  parseUsdcToBaseUnits,
  runSweep,
  type SweepConfig,
  type SweepDeps,
} from "../sweep-builder-fees";

const erc20TransferAbi = [
  {
    type: "function",
    name: "transfer",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

function config(overrides: Partial<SweepConfig> = {}): SweepConfig {
  return {
    dryRun: true,
    minUsdc: "50",
    keyPath: "/not/read/in/dry-run.json",
    hlBaseUrl: "https://api.hyperliquid.xyz",
    arbitrumRpcUrl: "https://arb1.arbitrum.io/rpc",
    settlementPollMs: 1,
    settlementTimeoutMs: 1,
    now: () => 1_770_000_000_000,
    ...overrides,
  };
}

function deps(args: { withdrawable: string; arbBalance?: bigint; calls?: string[] }): SweepDeps {
  const calls = args.calls ?? [];
  return {
    async fetchClearinghouseState(user) {
      calls.push(`info:${user}`);
      return { withdrawable: args.withdrawable };
    },
    chainClient: {
      async getUsdcBalance(owner) {
        calls.push(`balance:${owner}`);
        return args.arbBalance ?? 0n;
      },
      async sendUsdcTransfer({ to, amount }) {
        calls.push(`send:${to}:${amount}`);
        return "0xabc";
      },
    },
    async signAndSubmitWithdraw() {
      calls.push("signWithdraw");
      return { status: "ok" };
    },
    async loadPrivateKey() {
      calls.push("loadKey");
      return "0x0000000000000000000000000000000000000000000000000000000000000001";
    },
    async sleep() {
      calls.push("sleep");
    },
    log(message) {
      calls.push(`log:${message}`);
    },
  };
}

describe("USDC decimal helpers", () => {
  test("round-trip six-decimal USDC amounts", () => {
    expect(parseUsdcToBaseUnits("50")).toBe(50_000_000n);
    expect(parseUsdcToBaseUnits("1.234567")).toBe(1_234_567n);
    expect(formatUsdcBaseUnits(1_234_500n)).toBe("1.2345");
    expect(() => parseUsdcToBaseUnits("1.2345678")).toThrow("invalid USDC decimal");
  });
});

describe("config safety", () => {
  test("defaults to dry-run unless --execute is explicitly present", () => {
    expect(configFromEnvAndArgs({}, []).dryRun).toBe(true);
    expect(configFromEnvAndArgs({}, ["--dry-run"]).dryRun).toBe(true);
    expect(configFromEnvAndArgs({}, ["--execute"]).dryRun).toBe(false);
    expect(() => configFromEnvAndArgs({}, ["--dry-run", "--execute"])).toThrow("use only one");
  });
});

describe("builder fee sweep planning", () => {
  test("threshold-gates withdrawal and does not sign or send in dry-run", async () => {
    const calls: string[] = [];
    const result = await runSweep(config(), deps({ withdrawable: "49.999999", calls }));

    expect(result.dryRun).toBe(true);
    expect(result.shouldWithdraw).toBe(false);
    expect(result.withdrawalSubmitted).toBe(false);
    expect(result.transferSubmitted).toBe(false);
    expect(result.transfer).toBeNull();
    expect(calls).not.toContain("signWithdraw");
    expect(calls).not.toContain("loadKey");
    expect(calls.some((call) => call.startsWith("send:"))).toBe(false);
  });

  test("dry-run constructs the Safe-bound Arbitrum USDC transfer without signing", async () => {
    const calls: string[] = [];
    const result = await runSweep(
      config(),
      deps({ withdrawable: "125.25", arbBalance: 10_000_000n, calls }),
    );

    expect(result.shouldWithdraw).toBe(true);
    expect(result.withdrawalAmountUsdc).toBe("125.25");
    expect(result.withdrawalSubmitted).toBe(false);
    expect(result.transferSubmitted).toBe(false);
    expect(calls).not.toContain("signWithdraw");
    expect(calls).not.toContain("loadKey");

    expect(result.transfer).toEqual({
      chainId: ARBITRUM_CHAIN_ID,
      token: ARBITRUM_USDC,
      from: BUILDER_EOA,
      to: PLATFORM_SAFE,
      amount: 135_250_000n,
      data: buildUsdcTransferData(PLATFORM_SAFE, 135_250_000n),
    });

    const decoded = decodeFunctionData({
      abi: erc20TransferAbi,
      data: result.transfer?.data ?? "0x",
    });
    expect(decoded.functionName).toBe("transfer");
    expect(decoded.args[0]).toBe(PLATFORM_SAFE);
    expect(decoded.args[1]).toBe(135_250_000n);
  });
});
