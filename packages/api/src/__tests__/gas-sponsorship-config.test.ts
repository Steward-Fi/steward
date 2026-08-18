import { describe, expect, it } from "bun:test";
import {
  normalizeGasSpendQuery,
  normalizeGasSponsorshipConfig,
  publicGasSponsorshipState,
} from "../services/gas-sponsorship";

describe("gas sponsorship config", () => {
  it("normalizes fail-closed paymaster config", () => {
    expect(
      normalizeGasSponsorshipConfig({
        enabled: true,
        provider: "mock",
        mode: "erc4337",
        allowedChainIds: [8453, 8453],
        allowedCaip2: ["eip155:8453"],
        paymasterUrl: "https://paymaster.example/rpc",
        maxPerTxUsd: 1.239,
        requireSimulation: true,
      }),
    ).toMatchObject({
      enabled: true,
      provider: "mock",
      mode: "erc4337",
      allowedChainIds: [8453],
      allowedCaip2: ["eip155:8453"],
      paymasterUrl: "https://paymaster.example/rpc",
      maxPerTxUsd: 1.24,
      requireSimulation: true,
    });
  });

  it("rejects unsafe provider URLs and disables public state on circuit breaker", () => {
    expect(
      normalizeGasSponsorshipConfig({
        provider: "custom_evm_paymaster",
        paymasterUrl: "http://paymaster.example/rpc",
      }),
    ).toBe("paymasterUrl must use https");
    expect(
      publicGasSponsorshipState({
        enabled: true,
        provider: "mock",
        mode: "erc4337",
        circuitBreakerEnabled: true,
      }),
    ).toEqual({
      enabled: false,
      provider: null,
      mode: undefined,
      circuitBreakerEnabled: true,
    });
  });

  it("rejects non-public paymaster/bundler URL hosts (SEC-072)", () => {
    for (const url of [
      "https://192.168.1.10/rpc",
      "https://10.0.0.4/rpc",
      "https://169.254.169.254/latest/meta-data",
      "https://[::1]/rpc",
      "https://[fd00::1]/rpc",
      "https://paymaster.internal/rpc",
      "https://paymaster.local/rpc",
    ]) {
      const result = normalizeGasSponsorshipConfig({
        provider: "custom_evm_paymaster",
        paymasterUrl: url,
      });
      expect(result).toStartWith("paymasterUrl must be a public https URL");
    }

    // Public https hosts still pass, and the dev/test localhost exception holds.
    expect(
      normalizeGasSponsorshipConfig({
        provider: "custom_evm_paymaster",
        paymasterUrl: "https://paymaster.example/rpc",
      }),
    ).toMatchObject({ paymasterUrl: "https://paymaster.example/rpc" });
    expect(
      normalizeGasSponsorshipConfig({
        provider: "custom_bundler",
        bundlerUrl: "http://localhost:4337/rpc",
      }),
    ).toMatchObject({ bundlerUrl: "http://localhost:4337/rpc" });
  });

  it("normalizes gas spend queries with second or millisecond timestamps", () => {
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1", "agent-1", "agent-2"],
        startTimestamp: 1_764_195_200,
        endTimestamp: 1_764_281_600,
      }),
    ).toEqual({
      walletIds: ["agent-1", "agent-2"],
      start: new Date(1_764_195_200_000),
      end: new Date(1_764_281_600_000),
    });
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1"],
        startTimestamp: 1_764_195_200_000,
        endTimestamp: 1_764_281_600_000,
      }),
    ).toEqual({
      walletIds: ["agent-1"],
      start: new Date(1_764_195_200_000),
      end: new Date(1_764_281_600_000),
    });
  });

  it("rejects unsafe gas spend query ranges and wallet ids", () => {
    expect(normalizeGasSpendQuery({ walletIds: [] })).toBe("wallet_ids is required");
    expect(normalizeGasSpendQuery({ walletIds: ["bad/wallet"] })).toBe(
      "wallet_ids contains an invalid wallet id",
    );
    expect(
      normalizeGasSpendQuery({
        walletIds: Array.from({ length: 101 }, (_, index) => `agent-${index}`),
      }),
    ).toBe("wallet_ids can include at most 100 wallet ids");
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1"],
        startTimestamp: 1_764_281_600,
        endTimestamp: 1_764_195_200,
      }),
    ).toBe("start_timestamp must be before end_timestamp");
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1"],
        startTimestamp: 1_764_195_200,
        endTimestamp: 1_764_195_200 + 31 * 86400,
      }),
    ).toBe("gas spend queries cannot exceed 30 days");
  });
});
