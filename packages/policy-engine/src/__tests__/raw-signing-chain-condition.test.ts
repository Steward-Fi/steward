import { describe, expect, test } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { evaluatePolicy } from "../evaluators";

function req(): SignRequest {
  return {
    agentId: "agent-1",
    tenantId: "tenant-1",
    to: "0x1111111111111111111111111111111111111111",
    value: "0",
    chainId: 8453,
  };
}

function rule(config: Record<string, unknown>): PolicyRule {
  return {
    id: "raw-chain",
    type: "raw-signing-chain",
    enabled: true,
    config,
  };
}

describe("raw-signing-chain policy", () => {
  test("passes as not applicable for ordinary transaction signing", async () => {
    const result = await evaluatePolicy(rule({ allowedChains: ["sui"] }), {
      request: req(),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
    });

    expect(result).toEqual({
      policyId: "raw-chain",
      type: "raw-signing-chain",
      passed: true,
      reason: "Not a raw-digest signing request",
    });
  });

  test("allows explicit Sui ed25519 raw signing", async () => {
    const result = await evaluatePolicy(
      rule({ allowedChains: ["sui", "aptos", "movement"], allowedCurves: ["ed25519"] }),
      {
        request: req(),
        recentTxCount24h: 0,
        recentTxCount1h: 0,
        spentToday: 0n,
        spentThisWeek: 0n,
        rawSigning: { chain: "sui", curve: "ed25519" },
      },
    );

    expect(result.passed).toBe(true);
    expect(result.reason).toContain("sui");
  });

  test("allows explicit Tron/Tempo secp256k1 raw signing", async () => {
    for (const chain of ["tron", "tempo"] as const) {
      const result = await evaluatePolicy(rule({ allowedChains: ["tron", "tempo"] }), {
        request: req(),
        recentTxCount24h: 0,
        recentTxCount1h: 0,
        spentToday: 0n,
        spentThisWeek: 0n,
        rawSigning: { chain, curve: "secp256k1" },
      });
      expect(result.passed).toBe(true);
    }
  });

  test("denies when raw signing chain is outside allowlist", async () => {
    const result = await evaluatePolicy(rule({ allowedChains: ["sui"] }), {
      request: req(),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      rawSigning: { chain: "tron", curve: "secp256k1" },
    });

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in the allowed list");
  });

  test("denies curve mismatch for known chains", async () => {
    const result = await evaluatePolicy(rule({ allowedChains: ["sui"] }), {
      request: req(),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      rawSigning: { chain: "sui", curve: "secp256k1" },
    });

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("requires ed25519");
  });

  test("denies Starknet fail-closed by default", async () => {
    const result = await evaluatePolicy(rule({ allowedChains: ["starknet"] }), {
      request: req(),
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      rawSigning: { chain: "starknet", curve: "stark" },
    });

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not supported");
  });
});
