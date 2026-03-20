import { describe, expect, it } from "bun:test";
import { evaluatePolicy, type EvaluatorContext } from "../evaluators";
import type { PolicyRule, SignRequest } from "@stwd/shared";

// ─── Test Helpers ─────────────────────────────────────────────────────────

function makeContext(overrides: Partial<EvaluatorContext> = {}): EvaluatorContext {
  const defaultRequest: SignRequest = {
    agentId: "test-agent",
    tenantId: "test-tenant",
    to: "0x1234567890123456789012345678901234567890",
    value: "1000000000000000000", // 1 ETH in wei
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

// ─── Spending Limit Tests ─────────────────────────────────────────────────

describe("Spending Limit Policy", () => {
  it("passes when value is under all limits (canonical format)", () => {
    const rule: PolicyRule = {
      id: "spending-1",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: "2000000000000000000",    // 2 ETH
        maxPerDay: "10000000000000000000",  // 10 ETH
        maxPerWeek: "50000000000000000000", // 50 ETH
      },
    };

    const ctx = makeContext({ 
      request: { ...makeContext().request, value: "1000000000000000000" } // 1 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when value exceeds per-tx limit", () => {
    const rule: PolicyRule = {
      id: "spending-1",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: "500000000000000000",     // 0.5 ETH
        maxPerDay: "10000000000000000000",
        maxPerWeek: "50000000000000000000",
      },
    };

    const ctx = makeContext(); // 1 ETH transaction
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("per-tx limit");
  });

  it("fails when value would exceed daily limit", () => {
    const rule: PolicyRule = {
      id: "spending-1",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: "10000000000000000000",
        maxPerDay: "5000000000000000000",   // 5 ETH daily
        maxPerWeek: "50000000000000000000",
      },
    };

    const ctx = makeContext({
      spentToday: BigInt("4500000000000000000"), // already spent 4.5 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("daily spending limit");
  });

  // ─── maxAmount/period format tests (Bug 2 fix) ─────────────────────────

  it("accepts maxAmount/period=tx format", () => {
    const rule: PolicyRule = {
      id: "spending-2",
      type: "spending-limit",
      enabled: true,
      config: {
        maxAmount: "2000000000000000000", // 2 ETH per tx
        period: "tx",
      },
    };

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" } // 1 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("accepts maxAmount/period=day format", () => {
    const rule: PolicyRule = {
      id: "spending-3",
      type: "spending-limit",
      enabled: true,
      config: {
        maxAmount: "5000000000000000000", // 5 ETH per day
        period: "day",
      },
    };

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" },
      spentToday: BigInt("3000000000000000000"), // already spent 3 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails maxAmount/period=day when over limit", () => {
    const rule: PolicyRule = {
      id: "spending-4",
      type: "spending-limit",
      enabled: true,
      config: {
        maxAmount: "5000000000000000000", // 5 ETH per day
        period: "day",
      },
    };

    const ctx = makeContext({
      request: { ...makeContext().request, value: "2000000000000000000" }, // 2 ETH
      spentToday: BigInt("4000000000000000000"), // already spent 4 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("daily spending limit");
  });

  it("accepts maxAmount/period=week format", () => {
    const rule: PolicyRule = {
      id: "spending-5",
      type: "spending-limit",
      enabled: true,
      config: {
        maxAmount: "10000000000000000000", // 10 ETH per week
        period: "week",
      },
    };

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" },
      spentThisWeek: BigInt("8000000000000000000"), // already spent 8 ETH this week
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails maxAmount/period=week when over limit", () => {
    const rule: PolicyRule = {
      id: "spending-6",
      type: "spending-limit",
      enabled: true,
      config: {
        maxAmount: "10000000000000000000", // 10 ETH per week
        period: "weekly",
      },
    };

    const ctx = makeContext({
      request: { ...makeContext().request, value: "3000000000000000000" }, // 3 ETH
      spentThisWeek: BigInt("9000000000000000000"), // already spent 9 ETH
    });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("weekly spending limit");
  });
});

// ─── Rate Limit Tests ─────────────────────────────────────────────────────

describe("Rate Limit Policy", () => {
  it("passes when under rate limits", () => {
    const rule: PolicyRule = {
      id: "rate-1",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 10,
        maxTxPerDay: 50,
      },
    };

    const ctx = makeContext({ recentTxCount1h: 5, recentTxCount24h: 20 });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when hourly limit reached", () => {
    const rule: PolicyRule = {
      id: "rate-2",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 10,
        maxTxPerDay: 50,
      },
    };

    const ctx = makeContext({ recentTxCount1h: 10, recentTxCount24h: 20 });
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly");
  });
});

// ─── Approved Addresses Tests ─────────────────────────────────────────────

describe("Approved Addresses Policy", () => {
  it("passes when address is whitelisted", () => {
    const rule: PolicyRule = {
      id: "approved-1",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: ["0x1234567890123456789012345678901234567890"],
        mode: "whitelist",
      },
    };

    const ctx = makeContext();
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when address is not whitelisted", () => {
    const rule: PolicyRule = {
      id: "approved-2",
      type: "approved-addresses",
      enabled: true,
      config: {
        addresses: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        mode: "whitelist",
      },
    };

    const ctx = makeContext();
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in whitelist");
  });
});

// ─── Disabled Policy Tests ────────────────────────────────────────────────

describe("Disabled Policies", () => {
  it("passes when policy is disabled", () => {
    const rule: PolicyRule = {
      id: "disabled-1",
      type: "spending-limit",
      enabled: false,
      config: {
        maxPerTx: "1", // Would fail if enabled
        maxPerDay: "1",
        maxPerWeek: "1",
      },
    };

    const ctx = makeContext();
    const result = evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Policy disabled");
  });
});
