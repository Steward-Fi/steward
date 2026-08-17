import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";
import { computeScaledLimit, evaluateReputationScaling } from "../evaluators/reputation-scaling";
import { evaluateReputationThreshold } from "../evaluators/reputation-threshold";
import { calculateInternalReputation, type ReputationInput } from "../reputation";

// ─── Helpers ──────────────────────────────────────────────────────────────

function makeRule(
  type: "reputation-threshold" | "reputation-scaling",
  config: Record<string, unknown>,
  id = "rep-1",
): PolicyRule {
  return { id, type, enabled: true, config };
}

function makeEvalCtx(overrides: Partial<EvaluatorContext> = {}): EvaluatorContext {
  const defaultRequest: SignRequest = {
    agentId: "test-agent",
    tenantId: "test-tenant",
    to: "0x1234567890123456789012345678901234567890",
    value: "1000000000000000000", // 1 ETH
    chainId: 8453,
  };
  return {
    request: defaultRequest,
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}

// ─── calculateInternalReputation ──────────────────────────────────────────

describe("calculateInternalReputation", () => {
  it("returns 100 for a perfect agent", () => {
    const input: ReputationInput = {
      totalTransactions: 1000,
      successRate: 1,
      policyViolationRate: 0,
      accountAgeDays: 365,
    };
    expect(calculateInternalReputation(input)).toBe(100);
  });

  it("returns 0 for a brand-new agent with no history", () => {
    const input: ReputationInput = {
      totalTransactions: 0,
      successRate: 0,
      policyViolationRate: 1,
      accountAgeDays: 0,
    };
    expect(calculateInternalReputation(input)).toBe(0);
  });

  it("caps age contribution at 365 days", () => {
    const a = calculateInternalReputation({
      totalTransactions: 0,
      successRate: 0,
      policyViolationRate: 1,
      accountAgeDays: 365,
    });
    const b = calculateInternalReputation({
      totalTransactions: 0,
      successRate: 0,
      policyViolationRate: 1,
      accountAgeDays: 730,
    });
    expect(a).toBe(b);
  });

  it("caps volume contribution at 1000 txs", () => {
    const a = calculateInternalReputation({
      totalTransactions: 1000,
      successRate: 0,
      policyViolationRate: 1,
      accountAgeDays: 0,
    });
    const b = calculateInternalReputation({
      totalTransactions: 5000,
      successRate: 0,
      policyViolationRate: 1,
      accountAgeDays: 0,
    });
    expect(a).toBe(b);
  });

  it("produces expected mid-range score", () => {
    const input: ReputationInput = {
      totalTransactions: 500,
      successRate: 0.8,
      policyViolationRate: 0.1,
      accountAgeDays: 180,
    };
    // success: 0.8*40 = 32, violation: 0.9*30 = 27, age: (180/365)*20 ≈ 9.86, volume: 0.5*10 = 5
    // total ≈ 73.86 → 74
    const score = calculateInternalReputation(input);
    expect(score).toBe(74);
  });
});

// ─── Reputation Threshold Evaluator ───────────────────────────────────────

describe("reputation-threshold evaluator", () => {
  const config = {
    minScore: 50,
    action: "block",
    source: "internal",
    fallbackAction: "require-approval",
  };

  it("passes when score meets minimum", () => {
    const rule = makeRule("reputation-threshold", config);
    const result = evaluateReputationThreshold(rule, { reputationScore: 75 });
    expect(result.passed).toBe(true);
    expect(result.reason).toContain("meets minimum");
  });

  it("passes when score equals minimum exactly", () => {
    const rule = makeRule("reputation-threshold", config);
    const result = evaluateReputationThreshold(rule, { reputationScore: 50 });
    expect(result.passed).toBe(true);
  });

  it("fails when score is below minimum", () => {
    const rule = makeRule("reputation-threshold", config);
    const result = evaluateReputationThreshold(rule, { reputationScore: 30 });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("below minimum");
  });

  it("uses fallbackAction when no score is available", () => {
    const rule = makeRule("reputation-threshold", config);
    const result = evaluateReputationThreshold(rule, {});
    expect(result.passed).toBe(false); // require-approval != approve
    expect(result.reason).toContain("fallback");
  });

  it("fails closed on fallback when fallbackAction is approve and no score is wired (SEC-040)", () => {
    const rule = makeRule("reputation-threshold", {
      ...config,
      fallbackAction: "approve",
    });
    const result = evaluateReputationThreshold(rule, {});
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("fail closed");
  });

  it("still honors action: approve when a score IS wired but below minimum", () => {
    const rule = makeRule("reputation-threshold", {
      ...config,
      action: "approve",
    });
    const result = evaluateReputationThreshold(rule, { reputationScore: 10 });
    expect(result.passed).toBe(true);
  });

  it("integrates through evaluatePolicy switch", async () => {
    const rule = makeRule("reputation-threshold", config);
    const ctx = makeEvalCtx({ reputationScore: 75 });
    const result = await evaluatePolicy(rule, ctx);
    expect(result.passed).toBe(true);
    expect(result.type).toBe("reputation-threshold");
  });
});

// ─── Reputation Scaling Evaluator ─────────────────────────────────────────

describe("reputation-scaling evaluator", () => {
  const linearConfig = {
    baseMaxPerTx: "100000000000000000", // 0.1 ETH
    maxMaxPerTx: "10000000000000000000", // 10 ETH
    curve: "linear",
  };

  const logConfig = {
    ...linearConfig,
    curve: "logarithmic",
  };

  describe("linear curve", () => {
    it("passes when tx value is within scaled limit", () => {
      const rule = makeRule("reputation-scaling", linearConfig);
      // score 50 → limit = 0.1 + (10 - 0.1) * 50/100 = 5.05 ETH
      const result = evaluateReputationScaling(rule, {
        reputationScore: 50,
        txValue: BigInt("5000000000000000000"), // 5 ETH
      });
      expect(result.passed).toBe(true);
    });

    it("fails when tx value exceeds scaled limit", () => {
      const rule = makeRule("reputation-scaling", linearConfig);
      // score 10 → limit = 0.1 + 9.9 * 10/100 = 1.09 ETH
      const result = evaluateReputationScaling(rule, {
        reputationScore: 10,
        txValue: BigInt("2000000000000000000"), // 2 ETH
      });
      expect(result.passed).toBe(false);
    });

    it("uses base limit when no score available (defaults to 0)", () => {
      const rule = makeRule("reputation-scaling", linearConfig);
      const result = evaluateReputationScaling(rule, {
        txValue: BigInt("100000000000000000"), // 0.1 ETH exactly
      });
      expect(result.passed).toBe(true);
    });

    it("uses max limit at score 100", () => {
      const limit = computeScaledLimit(linearConfig as any, 100);
      expect(limit).toBe(BigInt("10000000000000000000")); // 10 ETH
    });

    it("uses base limit at score 0", () => {
      const limit = computeScaledLimit(linearConfig as any, 0);
      expect(limit).toBe(BigInt("100000000000000000")); // 0.1 ETH
    });
  });

  describe("logarithmic curve", () => {
    it("produces higher limits at low scores than linear", () => {
      const logLimit = computeScaledLimit(logConfig as any, 20);
      const linLimit = computeScaledLimit(linearConfig as any, 20);
      // Log curve is concave, so at low scores the limit should be higher
      expect(logLimit).toBeGreaterThan(linLimit);
    });

    it("converges to max at score 100", () => {
      const limit = computeScaledLimit(logConfig as any, 100);
      // Should be exactly max (ln(101)/ln(101) = 1)
      expect(limit).toBe(BigInt("10000000000000000000"));
    });

    it("passes when tx value is within log-scaled limit", () => {
      const rule = makeRule("reputation-scaling", logConfig);
      // score 50, log curve: ln(51)/ln(101) ≈ 0.851 → limit ≈ 8.52 ETH
      const result = evaluateReputationScaling(rule, {
        reputationScore: 50,
        txValue: BigInt("8000000000000000000"), // 8 ETH
      });
      expect(result.passed).toBe(true);
    });
  });

  it("integrates through evaluatePolicy switch", async () => {
    const rule = makeRule("reputation-scaling", linearConfig);
    const ctx = makeEvalCtx({
      reputationScore: 80,
      request: {
        agentId: "test-agent",
        tenantId: "test-tenant",
        to: "0x1234567890123456789012345678901234567890",
        value: "5000000000000000000", // 5 ETH
        chainId: 8453,
      },
    });
    const result = await evaluatePolicy(rule, ctx);
    expect(result.passed).toBe(true);
    expect(result.type).toBe("reputation-scaling");
  });
});

describe("reputation-scaling malformed input (SEC-105)", () => {
  const linearConfig = {
    baseMaxPerTx: "100000000000000000", // 0.1 ETH
    maxMaxPerTx: "10000000000000000000", // 10 ETH
    curve: "linear",
  };

  it("denies with a structured reason on non-numeric wei limits instead of throwing", () => {
    const rule = makeRule("reputation-scaling", {
      baseMaxPerTx: "not-a-number",
      maxMaxPerTx: "10000000000000000000",
      curve: "linear",
    });
    const result = evaluateReputationScaling(rule, {
      reputationScore: 50,
      txValue: 1n,
    });
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("wei strings");
  });

  it("treats a non-finite score as 0 instead of throwing inside BigInt(NaN)", () => {
    const limit = computeScaledLimit(linearConfig as any, Number.NaN);
    expect(limit).toBe(BigInt("100000000000000000")); // base limit at score 0
    const rule = makeRule("reputation-scaling", linearConfig);
    const result = evaluateReputationScaling(rule, {
      reputationScore: Number.NaN,
      txValue: BigInt("100000000000000000"),
    });
    expect(result.passed).toBe(true); // exactly at the score-0 base limit
  });

  it("rejects the complete malformed runtime shape instead of silently choosing a curve", () => {
    for (const config of [
      { ...linearConfig, curve: "surprise" },
      { ...linearConfig, baseMaxPerTx: "100", maxMaxPerTx: "10" },
      null,
    ]) {
      const result = evaluateReputationScaling(makeRule("reputation-scaling", config as never), {
        reputationScore: 50,
        txValue: 1n,
      });
      expect(result.passed).toBe(false);
      expect(result.reason).toContain("malformed");
    }
  });
});
