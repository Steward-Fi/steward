import { describe, expect, it } from "bun:test";
import type { PolicyRule, PriceOracle, SignRequest } from "@stwd/shared";
import { PolicyEngine } from "../engine";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";

const ONE_ETH = "1000000000000000000";

function makeRequest(overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    agentId: "agent-1",
    tenantId: "tenant-1",
    to: "0x1234567890123456789012345678901234567890",
    value: ONE_ETH,
    chainId: 8453,
    ...overrides,
  };
}

function makeContext(overrides: Partial<EvaluatorContext> = {}): EvaluatorContext {
  return {
    request: makeRequest(),
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}

function rule(type: PolicyRule["type"], config: Record<string, unknown>, id = type): PolicyRule {
  return { id, type, enabled: true, config };
}

function fixedOracle(priceUsd: number | null): PriceOracle {
  return {
    getNativeUsdPrice: async () => priceUsd,
    getTokenUsdPrice: async () => priceUsd,
    weiToUsd: async (weiValue: string) => {
      if (priceUsd === null) return null;
      return (Number(BigInt(weiValue)) / 1e18) * priceUsd;
    },
    usdToWei: async (usdValue: number) => {
      if (priceUsd === null || priceUsd === 0) return null;
      return BigInt(Math.floor((usdValue / priceUsd) * 1e18)).toString();
    },
  };
}

describe("USD policy evaluation", () => {
  it("uses USD spending limits when an oracle is available", async () => {
    const result = await evaluatePolicy(
      rule("spending-limit", {
        maxPerTx: "999999999999999999999999",
        maxPerTxUsd: 1_999,
      }),
      makeContext({ priceOracle: fixedOracle(2_000) }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("per-tx USD limit $1999");
  });

  it("passes exactly at the daily USD limit but fails one cent over", async () => {
    const policy = rule("spending-limit", { maxPerDayUsd: 200 });
    const atLimit = await evaluatePolicy(
      policy,
      makeContext({
        request: makeRequest({ value: "500000000000000000" }),
        spentToday: 1500000000000000000n,
        priceOracle: fixedOracle(100),
      }),
    );
    const overLimit = await evaluatePolicy(
      policy,
      makeContext({
        request: makeRequest({ value: "500100000000000000" }),
        spentToday: 1500000000000000000n,
        priceOracle: fixedOracle(100),
      }),
    );

    expect(atLimit.passed).toBe(true);
    expect(overLimit.passed).toBe(false);
    expect(overLimit.reason).toContain("daily USD spending limit");
  });

  it("falls back to wei limits when the oracle cannot price the chain", async () => {
    const result = await evaluatePolicy(
      rule("spending-limit", {
        maxPerTx: "500000000000000000",
        maxPerTxUsd: 10,
      }),
      makeContext({ priceOracle: fixedOracle(null) }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("per-tx limit");
  });

  it("uses USD auto-approval thresholds before legacy wei thresholds", async () => {
    const result = await evaluatePolicy(
      rule("auto-approve-threshold", {
        threshold: "0",
        thresholdUsd: 2_000,
      }),
      makeContext({ priceOracle: fixedOracle(2_000) }),
    );

    expect(result.passed).toBe(true);
    expect(result.reason).toContain("$2000.00");
  });

  it("falls back from unavailable USD threshold to legacy wei threshold", async () => {
    const result = await evaluatePolicy(
      rule("auto-approve-threshold", {
        threshold: ONE_ETH,
        thresholdUsd: 1,
      }),
      makeContext({ priceOracle: fixedOracle(null) }),
    );

    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Below auto-approve threshold");
  });
});

describe("policy edge cases and composition", () => {
  it("zero rate limit blocks the first transaction", async () => {
    const result = await evaluatePolicy(
      rule("rate-limit", { maxTxPerHour: 0, maxTxPerDay: 10 }),
      makeContext({ recentTxCount1h: 0 }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly tx limit reached (0)");
  });

  it("negative rate limit is fail-closed", async () => {
    const result = await evaluatePolicy(
      rule("rate-limit", { maxTxPerHour: -1, maxTxPerDay: -1 }),
      makeContext(),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly");
  });

  it("a negative auto-approve threshold never auto-approves a zero-value transaction", async () => {
    const result = await evaluatePolicy(
      rule("auto-approve-threshold", { threshold: "-1" }),
      makeContext({ request: makeRequest({ value: "0" }) }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("exceeds auto-approve threshold -1");
  });

  it("unknown policy types fail closed", async () => {
    const result = await evaluatePolicy(
      { id: "unknown", type: "not-real" as PolicyRule["type"], enabled: true, config: {} },
      makeContext(),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Unknown policy type");
  });

  it("hard allowlist rejection wins over a failing auto-approve threshold", async () => {
    const engine = new PolicyEngine();
    const result = await engine.evaluate(
      [
        rule("approved-addresses", {
          addresses: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
          mode: "whitelist",
        }),
        rule("auto-approve-threshold", { threshold: "1" }),
      ],
      {
        request: makeRequest(),
        recentTxCount1h: 0,
        recentTxCount24h: 0,
        spentToday: 0n,
        spentThisWeek: 0n,
      },
    );

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results.find((r) => r.type === "approved-addresses")?.passed).toBe(false);
    expect(result.results.find((r) => r.type === "auto-approve-threshold")?.passed).toBe(false);
  });
});
