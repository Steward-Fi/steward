import { describe, expect, it } from "bun:test";
import type { PolicyRule, SignRequest } from "@stwd/shared";
import { PolicyEngine } from "../engine";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";

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

function makeSpendingRule(config: Record<string, unknown>, id = "spending-1"): PolicyRule {
  return { id, type: "spending-limit", enabled: true, config };
}

function makeRateRule(config: Record<string, unknown>, id = "rate-1"): PolicyRule {
  return { id, type: "rate-limit", enabled: true, config };
}

function makeAddressRule(config: Record<string, unknown>, id = "addr-1"): PolicyRule {
  return { id, type: "approved-addresses", enabled: true, config };
}

function makeTimeWindowRule(config: Record<string, unknown>, id = "time-1"): PolicyRule {
  return { id, type: "time-window", enabled: true, config };
}

function makeAutoApproveRule(threshold: string, id = "auto-1"): PolicyRule {
  return {
    id,
    type: "auto-approve-threshold",
    enabled: true,
    config: { threshold },
  };
}

const unavailablePriceOracle = {
  getNativeUsdPrice: async () => null,
  getTokenUsdPrice: async () => null,
  weiToUsd: async () => null,
  usdToWei: async () => null,
};

function makeConditionSetRule(config: Record<string, unknown>, id = "condition-set-1"): PolicyRule {
  return { id, type: "condition-set", enabled: true, config };
}

function makeContractAllowlistRule(
  config: Record<string, unknown>,
  id = "contract-allowlist-1",
): PolicyRule {
  return { id, type: "contract-allowlist", enabled: true, config };
}

function abiAddress(address: string): string {
  return address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
}

function abiUint(value: bigint | number | string): string {
  return BigInt(value).toString(16).padStart(64, "0");
}

describe("Contract Allowlist Policy", () => {
  const contract = "0x1234567890123456789012345678901234567890";
  const otherContract = "0x9999999999999999999999999999999999999999";
  const recipient = "0x1111111111111111111111111111111111111111";
  const blockedRecipient = "0x2222222222222222222222222222222222222222";
  const selector = "0xa9059cbb";
  const rule = makeContractAllowlistRule({
    contracts: [{ address: contract, selectors: [selector] }],
  });

  it("passes native value transfers with no calldata", async () => {
    const result = await evaluatePolicy(rule, makeContext());

    expect(result.passed).toBe(true);
    expect(result.reason).toBe("No contract calldata");
  });

  it("passes when target contract and selector are explicitly allowed", async () => {
    const result = await evaluatePolicy(
      rule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: `${selector}00000000`,
        },
      }),
    );

    expect(result.passed).toBe(true);
  });

  it("fails when selector is not allowed for the contract", async () => {
    const result = await evaluatePolicy(
      rule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: "0x095ea7b300000000",
        },
      }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Selector 0x095ea7b3");
  });

  it("fails when contract is not allowed", async () => {
    const result = await evaluatePolicy(
      rule,
      makeContext({
        request: {
          ...makeContext().request,
          to: otherContract,
          data: `${selector}00000000`,
        },
      }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in the contract allowlist");
  });

  it("enforces ERC20 transfer recipient and amount constraints when configured", async () => {
    const constrainedRule = makeContractAllowlistRule({
      contracts: [
        {
          address: contract,
          selectors: [selector],
          constraints: {
            [selector]: {
              recipientAllowlist: [recipient],
              maxAmount: "100",
            },
          },
        },
      ],
    });

    const allowed = await evaluatePolicy(
      constrainedRule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: `${selector}${abiAddress(recipient)}${abiUint(100)}`,
        },
      }),
    );
    expect(allowed.passed).toBe(true);

    const blockedAddress = await evaluatePolicy(
      constrainedRule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: `${selector}${abiAddress(blockedRecipient)}${abiUint(1)}`,
        },
      }),
    );
    expect(blockedAddress.passed).toBe(false);
    expect(blockedAddress.reason).toContain("recipient");

    const blockedAmount = await evaluatePolicy(
      constrainedRule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: `${selector}${abiAddress(recipient)}${abiUint(101)}`,
        },
      }),
    );
    expect(blockedAmount.passed).toBe(false);
    expect(blockedAmount.reason).toContain("exceeds selector maxAmount");
  });

  it("enforces ERC20 approve spender constraints when configured", async () => {
    const approveSelector = "0x095ea7b3";
    const constrainedRule = makeContractAllowlistRule({
      contracts: [
        {
          address: contract,
          selectors: [approveSelector],
          constraints: {
            [approveSelector]: {
              spenderBlocklist: [blockedRecipient],
              maxAmount: "10",
            },
          },
        },
      ],
    });

    const blocked = await evaluatePolicy(
      constrainedRule,
      makeContext({
        request: {
          ...makeContext().request,
          to: contract,
          data: `${approveSelector}${abiAddress(blockedRecipient)}${abiUint(1)}`,
        },
      }),
    );
    expect(blocked.passed).toBe(false);
    expect(blocked.reason).toContain("spender");
  });
});

describe("Condition Set Policy", () => {
  it("passes when the selected transaction field is in the loaded condition set", async () => {
    const rule = makeConditionSetRule({
      conditionSetId: "approved-recipients",
      field: "ethereum_transaction.to",
      operator: "in_condition_set",
    });

    const result = await evaluatePolicy(
      rule,
      makeContext({
        conditionSets: {
          "approved-recipients": ["0x1234567890123456789012345678901234567890"],
        },
      }),
    );

    expect(result.passed).toBe(true);
  });

  it("fails closed when the referenced condition set was not loaded", async () => {
    const rule = makeConditionSetRule({ conditionSetId: "missing-set" });
    const result = await evaluatePolicy(rule, makeContext());

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("was not loaded");
  });

  it("supports not_in_condition_set for blocklists", async () => {
    const rule = makeConditionSetRule({
      conditionSetId: "blocked-recipients",
      operator: "not_in_condition_set",
    });

    const allowed = await evaluatePolicy(
      rule,
      makeContext({
        request: {
          ...makeContext().request,
          to: "0x9999999999999999999999999999999999999999",
        },
        conditionSets: {
          "blocked-recipients": ["0x1234567890123456789012345678901234567890"],
        },
      }),
    );
    expect(allowed.passed).toBe(true);

    const blocked = await evaluatePolicy(
      rule,
      makeContext({
        conditionSets: {
          "blocked-recipients": ["0x1234567890123456789012345678901234567890"],
        },
      }),
    );
    expect(blocked.passed).toBe(false);
  });

  it("fails closed for malformed condition-set operators and fields", async () => {
    const typoOperator = await evaluatePolicy(
      makeConditionSetRule({
        conditionSetId: "blocked-recipients",
        operator: "not-in-condition-set",
      }),
      makeContext({
        conditionSets: {
          "blocked-recipients": ["0x1234567890123456789012345678901234567890"],
        },
      }),
    );
    expect(typoOperator.passed).toBe(false);
    expect(typoOperator.reason).toContain("Unsupported condition set operator");

    const unknownField = await evaluatePolicy(
      makeConditionSetRule({
        conditionSetId: "blocked-recipients",
        field: "ethereum_transaction.recipient",
        operator: "not_in_condition_set",
      }),
      makeContext({
        conditionSets: {
          "blocked-recipients": ["0x1234567890123456789012345678901234567890"],
        },
      }),
    );
    expect(unknownField.passed).toBe(false);
    expect(unknownField.reason).toContain("Unsupported condition set field");
  });
});

// ─── Spending Limit Tests ─────────────────────────────────────────────────

describe("Spending Limit Policy", () => {
  it("passes when value is under all limits (canonical format)", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "2000000000000000000", // 2 ETH
      maxPerDay: "10000000000000000000", // 10 ETH
      maxPerWeek: "50000000000000000000", // 50 ETH
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" }, // 1 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when value exceeds per-tx limit", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "500000000000000000", // 0.5 ETH
      maxPerDay: "10000000000000000000",
      maxPerWeek: "50000000000000000000",
    });

    const ctx = makeContext(); // 1 ETH transaction
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("per-tx limit");
  });

  it("fails when value would exceed daily limit", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "10000000000000000000",
      maxPerDay: "5000000000000000000", // 5 ETH daily
      maxPerWeek: "50000000000000000000",
    });

    const ctx = makeContext({
      spentToday: BigInt("4500000000000000000"), // already spent 4.5 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("daily spending limit");
  });

  // ─── Per-tx boundary tests ─────────────────────────────────────────────

  it("passes when value is exactly at the per-tx limit (boundary)", async () => {
    const limit = "1000000000000000000"; // 1 ETH exactly
    const rule = makeSpendingRule({
      maxPerTx: limit,
      maxPerDay: "100000000000000000000",
      maxPerWeek: "100000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: limit },
    });
    const result = await evaluatePolicy(rule, ctx);

    // value === maxPerTx: 1e18 > 1e18 is false → should pass
    expect(result.passed).toBe(true);
  });

  it("fails when value is 1 wei over the per-tx limit", async () => {
    const limit = "1000000000000000000"; // 1 ETH
    const rule = makeSpendingRule({
      maxPerTx: limit,
      maxPerDay: "100000000000000000000",
      maxPerWeek: "100000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000001" }, // 1 wei over
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("per-tx limit");
  });

  it("passes when value is 1 wei under the per-tx limit", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "1000000000000000000", // 1 ETH
      maxPerDay: "100000000000000000000",
      maxPerWeek: "100000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "999999999999999999" }, // 1 wei under
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes for a zero-value transaction", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "1000000000000000000",
      maxPerDay: "10000000000000000000",
      maxPerWeek: "50000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "0" },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes when limits are set to max uint256", async () => {
    const MAX_UINT =
      "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const rule = makeSpendingRule({
      maxPerTx: MAX_UINT,
      maxPerDay: MAX_UINT,
      maxPerWeek: MAX_UINT,
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "99999999999999999999" }, // large amount
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  // ─── Per-day boundary ─────────────────────────────────────────────────

  it("fails when accumulated + tx equals daily limit exactly (edge: spentToday + value > limit is false at equality)", async () => {
    // spentToday + value == limit → NOT exceeding, should pass (uses > not >=)
    const dailyLimit = "5000000000000000000"; // 5 ETH
    const rule = makeSpendingRule({
      maxPerTx: "10000000000000000000",
      maxPerDay: dailyLimit,
      maxPerWeek: "50000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" }, // 1 ETH
      spentToday: BigInt("4000000000000000000"), // 4 ETH already spent
    });
    // 4 ETH + 1 ETH = 5 ETH which equals limit exactly → 5e18 > 5e18 is false → passes
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when accumulated + tx exceeds daily limit by 1 wei", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "10000000000000000000",
      maxPerDay: "5000000000000000000", // 5 ETH daily
      maxPerWeek: "50000000000000000000",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000001" }, // 1 ETH + 1 wei
      spentToday: BigInt("4000000000000000000"), // 4 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("daily spending limit");
  });

  it("fails when accumulated + tx exceeds weekly limit", async () => {
    const rule = makeSpendingRule({
      maxPerTx: "10000000000000000000",
      maxPerDay: "100000000000000000000",
      maxPerWeek: "10000000000000000000", // 10 ETH weekly
    });

    const ctx = makeContext({
      request: { ...makeContext().request, value: "3000000000000000000" }, // 3 ETH
      spentThisWeek: BigInt("8000000000000000000"), // 8 ETH this week
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("weekly spending limit");
  });

  // ─── maxAmount/period format tests ────────────────────────────────────

  it("accepts maxAmount/period=tx format", async () => {
    const rule = makeSpendingRule(
      {
        maxAmount: "2000000000000000000", // 2 ETH per tx
        period: "tx",
      },
      "spending-2",
    );

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" }, // 1 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("accepts maxAmount/period=day format", async () => {
    const rule = makeSpendingRule(
      {
        maxAmount: "5000000000000000000", // 5 ETH per day
        period: "day",
      },
      "spending-3",
    );

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" },
      spentToday: BigInt("3000000000000000000"), // already spent 3 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails maxAmount/period=day when over limit", async () => {
    const rule = makeSpendingRule(
      {
        maxAmount: "5000000000000000000", // 5 ETH per day
        period: "day",
      },
      "spending-4",
    );

    const ctx = makeContext({
      request: { ...makeContext().request, value: "2000000000000000000" }, // 2 ETH
      spentToday: BigInt("4000000000000000000"), // already spent 4 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("daily spending limit");
  });

  it("accepts maxAmount/period=week format", async () => {
    const rule = makeSpendingRule(
      {
        maxAmount: "10000000000000000000", // 10 ETH per week
        period: "week",
      },
      "spending-5",
    );

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000000" },
      spentThisWeek: BigInt("8000000000000000000"), // already spent 8 ETH this week
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails maxAmount/period=week when over limit", async () => {
    const rule = makeSpendingRule(
      {
        maxAmount: "10000000000000000000", // 10 ETH per week
        period: "weekly",
      },
      "spending-6",
    );

    const ctx = makeContext({
      request: { ...makeContext().request, value: "3000000000000000000" }, // 3 ETH
      spentThisWeek: BigInt("9000000000000000000"), // already spent 9 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("weekly spending limit");
  });

  it("fails closed when a USD spending limit cannot be priced", async () => {
    const rule = makeSpendingRule({ maxPerTxUsd: 1 });
    const result = await evaluatePolicy(
      rule,
      makeContext({
        request: { ...makeContext().request, chainId: 2147483647 },
        priceOracle: unavailablePriceOracle,
      }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("USD spending limit cannot be evaluated");
  });

  it("fails closed when transaction or configured wei values exceed uint256 bounds", async () => {
    const oversized = "9".repeat(79);

    const oversizedRequest = await evaluatePolicy(
      makeSpendingRule({ maxPerTx: "1000", maxPerDay: "1000", maxPerWeek: "1000" }),
      makeContext({ request: { ...makeContext().request, value: oversized } }),
    );
    expect(oversizedRequest.passed).toBe(false);
    expect(oversizedRequest.reason).toContain("uint256");

    const oversizedPolicy = await evaluatePolicy(
      makeSpendingRule({ maxPerTx: oversized, maxPerDay: "1000", maxPerWeek: "1000" }),
      makeContext(),
    );
    expect(oversizedPolicy.passed).toBe(false);
    expect(oversizedPolicy.reason).toContain("uint256");
  });

  // Regression: the daily cap is only safe when the caller reads spentToday and
  // commits the spend inside one per-agent lock (API: withAgentSpendLock). This
  // models that contract — a serialized read+commit window over a shared
  // committed balance. The first spend passes and commits; the second, re-reading
  // the now-updated balance, must be rejected. (Concurrent eval against a STALE
  // shared read would let both pass — that is the double-spend the lock prevents.)
  it("serializes daily cap under a per-agent lock (no double-spend)", async () => {
    const txValue = "6000000000000000000"; // 6 ETH each → only one fits in 10 ETH/day
    const rule = makeSpendingRule({
      maxPerTx: txValue,
      maxPerDay: "10000000000000000000",
      maxPerWeek: "50000000000000000000",
    });

    let committedToday = 0n; // shared committed-balance store
    let lock = Promise.resolve(); // serializes the read+commit window

    const runLocked = (): Promise<boolean> => {
      const result = (async () => {
        await lock;
        const ctx = makeContext({
          request: { ...makeContext().request, value: txValue },
          spentToday: committedToday, // read INSIDE the lock
        });
        const evalResult = await evaluatePolicy(rule, ctx);
        if (evalResult.passed) committedToday += BigInt(txValue); // commit INSIDE the lock
        return evalResult.passed;
      })();
      lock = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    };

    const [first, second] = await Promise.all([runLocked(), runLocked()]);
    expect([first, second].filter(Boolean).length).toBe(1); // exactly one succeeds
    expect(committedToday).toBe(BigInt(txValue)); // cap not exceeded
  });
});

// ─── Approved Addresses Tests ─────────────────────────────────────────────

describe("Approved Addresses Policy", () => {
  const TARGET_ADDR = "0x1234567890123456789012345678901234567890";

  it("passes when address is whitelisted", async () => {
    const rule = makeAddressRule({
      addresses: [TARGET_ADDR],
      mode: "whitelist",
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when address is not whitelisted", async () => {
    const rule = makeAddressRule({
      addresses: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      mode: "whitelist",
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in whitelist");
  });

  it("passes whitelist check with uppercase hex address (case-insensitive)", async () => {
    // The evaluator normalises to lowercase, so checksummed or uppercase addresses match
    const rule = makeAddressRule({
      addresses: [TARGET_ADDR.toUpperCase()],
      mode: "whitelist",
    });

    const ctx = makeContext(); // request.to is lowercase TARGET_ADDR
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes whitelist check when rule has mixed-case address and request is lowercase", async () => {
    const mixedCase = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
    const rule = makeAddressRule({
      addresses: [mixedCase],
      mode: "whitelist",
    });

    const ctx = makeContext({
      request: { ...makeContext().request, to: mixedCase.toLowerCase() },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("blocks with blocklist mode when address IS in the list", async () => {
    const rule = makeAddressRule({
      addresses: [TARGET_ADDR],
      mode: "blacklist",
    });

    const ctx = makeContext(); // request.to = TARGET_ADDR → blacklisted
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("blacklisted");
  });

  it("passes with blocklist mode when address is NOT in the list", async () => {
    const rule = makeAddressRule({
      addresses: ["0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
      mode: "blacklist",
    });

    const ctx = makeContext(); // request.to = TARGET_ADDR which is not in the blacklist
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("whitelist with empty list blocks all addresses", async () => {
    const rule = makeAddressRule({
      addresses: [],
      mode: "whitelist",
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in whitelist");
  });

  it("blacklist with empty list allows all addresses", async () => {
    const rule = makeAddressRule({
      addresses: [],
      mode: "blacklist",
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });
});

// ─── Rate Limit Tests ─────────────────────────────────────────────────────

describe("Rate Limit Policy", () => {
  it("passes when under rate limits", async () => {
    const rule = makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 });
    const ctx = makeContext({ recentTxCount1h: 5, recentTxCount24h: 20 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when hourly limit reached (count equals limit)", async () => {
    const rule = makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 });
    const ctx = makeContext({ recentTxCount1h: 10, recentTxCount24h: 20 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly");
  });

  it("fails when hourly count exceeds limit", async () => {
    const rule = makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 });
    const ctx = makeContext({ recentTxCount1h: 15, recentTxCount24h: 20 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly");
  });

  it("fails when daily limit reached (count equals limit)", async () => {
    const rule = makeRateRule({ maxTxPerHour: 100, maxTxPerDay: 50 });
    const ctx = makeContext({ recentTxCount1h: 0, recentTxCount24h: 50 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Daily");
  });

  it("fails when daily count exceeds limit", async () => {
    const rule = makeRateRule({ maxTxPerHour: 100, maxTxPerDay: 50 });
    const ctx = makeContext({ recentTxCount1h: 0, recentTxCount24h: 75 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Daily");
  });

  it("passes with zero recent transactions", async () => {
    const rule = makeRateRule({ maxTxPerHour: 1, maxTxPerDay: 1 });
    const ctx = makeContext({ recentTxCount1h: 0, recentTxCount24h: 0 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("hourly limit checked before daily limit", async () => {
    // Both limits breached — hourly reason should appear first
    const rule = makeRateRule({ maxTxPerHour: 5, maxTxPerDay: 10 });
    const ctx = makeContext({ recentTxCount1h: 5, recentTxCount24h: 10 });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Hourly");
  });
});

// ─── Time Window Tests ────────────────────────────────────────────────────

describe("Time Window Policy", () => {
  it("passes when no hour or day restrictions are set (always open)", async () => {
    const rule = makeTimeWindowRule({
      allowedHours: [],
      allowedDays: [],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes when window covers all 24 hours and all 7 days", async () => {
    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 0, end: 24 }],
      allowedDays: [0, 1, 2, 3, 4, 5, 6],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when allowed hours window is empty (start === end → zero-length range)", async () => {
    // hour >= 0 && hour < 0 is always false regardless of current time
    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 0, end: 0 }],
      allowedDays: [0, 1, 2, 3, 4, 5, 6],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("UTC not in allowed windows");
  });

  it("fails when allowed hours window is out-of-range (start >= 24 never matches getUTCHours 0-23)", async () => {
    // UTC hours are 0-23, so start=24 will never be reached
    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 24, end: 25 }],
      allowedDays: [0, 1, 2, 3, 4, 5, 6],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
  });

  it("passes when all 7 days are allowed with all-day hour window", async () => {
    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 0, end: 24 }],
      allowedDays: [0, 1, 2, 3, 4, 5, 6],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when today's day of week is excluded from allowedDays", async () => {
    // Compute all days except today — deterministic for this test run
    const today = new Date().getUTCDay();
    const allDaysExceptToday = [0, 1, 2, 3, 4, 5, 6].filter((d) => d !== today);

    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 0, end: 24 }],
      allowedDays: allDaysExceptToday,
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not allowed on day");
  });

  it("passes when allowedDays includes today but has no hour restrictions", async () => {
    const today = new Date().getUTCDay();
    const rule = makeTimeWindowRule({
      allowedHours: [],
      allowedDays: [today],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("midnight-spanning window (23 to 1) does NOT work with current linear hour check", async () => {
    // Known limitation: the evaluator checks `hour >= start && hour < end` linearly.
    // A window spanning midnight (e.g. {start:23, end:1}) will never match any hour
    // because no UTC hour satisfies both >= 23 AND < 1 simultaneously.
    // This test documents the existing behaviour.
    const rule = makeTimeWindowRule({
      allowedHours: [{ start: 23, end: 1 }], // intended midnight window
      allowedDays: [0, 1, 2, 3, 4, 5, 6],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    // The window never matches → always outside (documents the limitation)
    expect(result.passed).toBe(false);
  });

  it("multiple windows: passes when current hour falls in any window", async () => {
    // Combine a never-matching window with an always-matching one
    const rule = makeTimeWindowRule({
      allowedHours: [
        { start: 24, end: 25 }, // never matches
        { start: 0, end: 24 }, // always matches
      ],
      allowedDays: [],
    });

    const ctx = makeContext();
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });
});

// ─── Auto-Approve Threshold Tests ────────────────────────────────────────

describe("Auto-Approve Threshold Policy", () => {
  it("passes (auto-approves) when value is below threshold", async () => {
    const rule = makeAutoApproveRule("2000000000000000000"); // 2 ETH threshold

    const ctx = makeContext({
      request: { ...makeContext().request, value: "500000000000000000" }, // 0.5 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
    expect(result.reason).toContain("auto-approve threshold");
  });

  it("passes (auto-approves) when value is exactly at threshold", async () => {
    const threshold = "1000000000000000000"; // 1 ETH
    const rule = makeAutoApproveRule(threshold);

    const ctx = makeContext({
      request: { ...makeContext().request, value: threshold },
    });
    // value === threshold → txValue <= threshold → passes
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails (queues for approval) when value exceeds threshold", async () => {
    const rule = makeAutoApproveRule("1000000000000000000"); // 1 ETH threshold

    const ctx = makeContext({
      request: { ...makeContext().request, value: "2000000000000000000" }, // 2 ETH
    });
    const result = await evaluatePolicy(rule, ctx);

    // Note: failing auto-approve-threshold is a "soft" fail — triggers manual review,
    // not a hard rejection. The policy result is failed though.
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("exceeds auto-approve threshold");
  });

  it("fails when value is 1 wei over threshold", async () => {
    const threshold = "1000000000000000000"; // 1 ETH exactly
    const rule = makeAutoApproveRule(threshold);

    const ctx = makeContext({
      request: { ...makeContext().request, value: "1000000000000000001" }, // 1 wei over
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
  });

  it("fails closed when a USD auto-approve threshold cannot be priced", async () => {
    const rule: PolicyRule = {
      id: "auto-usd",
      type: "auto-approve-threshold",
      enabled: true,
      config: { thresholdUsd: 1 },
    };
    const result = await evaluatePolicy(
      rule,
      makeContext({
        request: { ...makeContext().request, chainId: 2147483647 },
        priceOracle: unavailablePriceOracle,
      }),
    );

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("Auto-approve USD threshold cannot be evaluated");
  });

  it("passes with zero-value transaction under any threshold", async () => {
    const rule = makeAutoApproveRule("1"); // 1 wei threshold

    const ctx = makeContext({
      request: { ...makeContext().request, value: "0" },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });
});

// ─── Allowed Chains Tests ─────────────────────────────────────────────────

describe("Allowed Chains Policy", () => {
  function makeAllowedChainsRule(chains: string[], id = "chains-1"): PolicyRule {
    return { id, type: "allowed-chains", enabled: true, config: { chains } };
  }

  it("passes when request chainId matches the single allowed chain", async () => {
    const rule = makeAllowedChainsRule(["eip155:8453"]); // Base only
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 8453 },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes when request chainId matches one of multiple allowed chains", async () => {
    const rule = makeAllowedChainsRule(["eip155:1", "eip155:56", "eip155:8453"]);
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 56 },
    }); // BSC
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("passes when request chainId is Gnosis", async () => {
    const rule = makeAllowedChainsRule(["eip155:100"]);
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 100 },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
  });

  it("fails when request chainId is not in the allowed list", async () => {
    const rule = makeAllowedChainsRule(["eip155:1"]); // Ethereum only
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 8453 },
    }); // Base
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("eip155:8453");
    expect(result.reason).toContain("not in the allowed chains list");
  });

  it("fails when chainId maps to a known chain not in the allowed list", async () => {
    const rule = makeAllowedChainsRule(["eip155:8453", "eip155:56"]); // Base and BSC
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 137 },
    }); // Polygon
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("eip155:137");
  });

  it("fails when chainId is unknown/unmapped (cannot convert to CAIP-2)", async () => {
    const rule = makeAllowedChainsRule(["eip155:1", "eip155:8453"]);
    // chainId 9999 is not in the CHAINS registry
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 9999 },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("9999");
    expect(result.reason).toContain("not a recognised chain");
  });

  it("fails closed when chainId is 0 (absent/unset)", async () => {
    const rule = makeAllowedChainsRule(["eip155:1"]); // Ethereum only — would fail for Base
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 0 },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("chainId is required");
  });

  it("fails closed when chainId is undefined", async () => {
    const rule = makeAllowedChainsRule(["eip155:1"]);
    // Force undefined at runtime (type cast to exercise the JS falsy guard)
    const ctx = makeContext({
      request: {
        ...makeContext().request,
        chainId: undefined as unknown as number,
      },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("chainId is required");
  });

  it("fails all requests when allowed chains array is empty (nothing is permitted)", async () => {
    const rule = makeAllowedChainsRule([]); // empty — nothing allowed
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 8453 },
    });
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(false);
    expect(result.reason).toContain("not in the allowed chains list");
  });

  it("CAIP-2 matching is case-sensitive (uppercase variant does not match lowercase entry)", async () => {
    // Policy stores lowercase CAIP-2 as per the CHAINS registry.
    // If someone stores "EIP155:8453" instead of "eip155:8453", it should NOT match.
    const rule = makeAllowedChainsRule(["EIP155:8453"]); // wrong casing
    const ctx = makeContext({
      request: { ...makeContext().request, chainId: 8453 },
    });
    const result = await evaluatePolicy(rule, ctx);

    // toCaip2(8453) returns "eip155:8453" (lowercase), which !== "EIP155:8453"
    expect(result.passed).toBe(false);
  });

  it("allows ETH mainnet (eip155:1) and BSC (eip155:56) — default chain list scenario", async () => {
    const rule = makeAllowedChainsRule(["eip155:1", "eip155:56"]);

    const ethCtx = makeContext({
      request: { ...makeContext().request, chainId: 1 },
    });
    expect((await evaluatePolicy(rule, ethCtx)).passed).toBe(true);

    const bscCtx = makeContext({
      request: { ...makeContext().request, chainId: 56 },
    });
    expect((await evaluatePolicy(rule, bscCtx)).passed).toBe(true);

    const baseCtx = makeContext({
      request: { ...makeContext().request, chainId: 8453 },
    });
    expect((await evaluatePolicy(rule, baseCtx)).passed).toBe(false);
  });
});

// ─── Disabled Policy Tests ────────────────────────────────────────────────

describe("Disabled Policies", () => {
  it("passes when policy is disabled", async () => {
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
    const result = await evaluatePolicy(rule, ctx);

    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Policy disabled");
  });
});

// ─── PolicyEngine.evaluate() Tests ───────────────────────────────────────

describe("PolicyEngine.evaluate()", () => {
  const engine = new PolicyEngine();

  function makeEngineCtx(overrides: Partial<EvaluatorContext> = {}) {
    return {
      request: {
        agentId: "agent-1",
        tenantId: "tenant-1",
        to: "0x1234567890123456789012345678901234567890",
        value: "1000000000000000000", // 1 ETH
        chainId: 8453,
      },
      recentTxCount1h: 0,
      recentTxCount24h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      ...overrides,
    };
  }

  it("no policies -> rejected closed (approved=false, requiresManualApproval=false)", async () => {
    const result = await engine.evaluate([], makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results).toHaveLength(0);
  });

  it("all hard policies pass → approved", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 }),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results.every((r) => r.passed)).toBe(true);
  });

  it("one hard policy fails → rejected (approved=false, requiresManualApproval=false)", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      // This will fail — spending limit 0.1 ETH when tx is 1 ETH
      makeSpendingRule(
        {
          maxPerTx: "100000000000000000",
          maxPerDay: "1000000000000000000",
          maxPerWeek: "5000000000000000000",
        },
        "spending-2",
      ),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("hard policy fails even when auto-approve would pass → hard rejection wins", async () => {
    const policies: PolicyRule[] = [
      // Hard fail: per-tx limit too low
      makeSpendingRule(
        {
          maxPerTx: "100000000000000000",
          maxPerDay: "100000000000000000000",
          maxPerWeek: "100000000000000000000",
        },
        "spending-hard",
      ),
      // Auto-approve: 2 ETH threshold — tx is 1 ETH so this would pass
      makeAutoApproveRule("2000000000000000000"),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("all hard policies pass but auto-approve threshold exceeded → requiresManualApproval", async () => {
    const policies: PolicyRule[] = [
      // Hard policies all pass
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 }),
      // Auto-approve threshold: 0.5 ETH — tx is 1 ETH, so this fails
      makeAutoApproveRule("500000000000000000"),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("requires manual approval when any duplicate auto-approve threshold fails", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      makeAutoApproveRule("2000000000000000000", "auto-permissive"),
      makeAutoApproveRule("500000000000000000", "auto-strict"),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("all policies including auto-approve pass → fully approved", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      // Auto-approve: 2 ETH threshold — tx is 1 ETH → passes
      makeAutoApproveRule("2000000000000000000"),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("mixed policies: approved-addresses fail → hard rejection", async () => {
    const policies: PolicyRule[] = [
      // Spending limit: passes
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      // Address whitelist: fails (tx.to not in list)
      makeAddressRule({
        addresses: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        mode: "whitelist",
      }),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    const failedResult = result.results.find((r) => r.type === "approved-addresses");
    expect(failedResult?.passed).toBe(false);
  });

  it("results array contains one entry per policy evaluated", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "100000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 }),
      makeAutoApproveRule("2000000000000000000"),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.results).toHaveLength(3);
    expect(result.results.map((r) => r.type)).toContain("spending-limit");
    expect(result.results.map((r) => r.type)).toContain("rate-limit");
    expect(result.results.map((r) => r.type)).toContain("auto-approve-threshold");
  });

  it("allowed-chains pass alongside other passing policies → approved", async () => {
    // Request is on Base (8453), which is in the allowed list
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      {
        id: "chains-1",
        type: "allowed-chains",
        enabled: true,
        config: { chains: ["eip155:8453", "eip155:1"] },
      },
    ];

    const result = await engine.evaluate(policies, makeEngineCtx()); // default chainId=8453

    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
    const chainsResult = result.results.find((r) => r.type === "allowed-chains");
    expect(chainsResult?.passed).toBe(true);
  });

  it("allowed-chains fail → hard rejection even when other policies pass", async () => {
    // Request is on Base (8453), but only Ethereum is allowed
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
      makeRateRule({ maxTxPerHour: 10, maxTxPerDay: 50 }),
      {
        id: "chains-1",
        type: "allowed-chains",
        enabled: true,
        config: { chains: ["eip155:1"] },
      },
    ];

    const result = await engine.evaluate(
      policies,
      makeEngineCtx({ request: { ...makeEngineCtx().request, chainId: 8453 } }),
    );

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    const chainsResult = result.results.find((r) => r.type === "allowed-chains");
    expect(chainsResult?.passed).toBe(false);
    expect(chainsResult?.reason).toContain("eip155:8453");
  });

  it("simulate accepts transaction shape and evaluates as before", async () => {
    const policies: PolicyRule[] = [
      makeSpendingRule({
        maxPerTx: "500000000000000000",
        maxPerDay: "10000000000000000000",
        maxPerWeek: "10000000000000000000",
      }),
    ];

    const result = await engine.simulate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.results[0].type).toBe("spending-limit");
  });

  it("simulate accepts proxy shape and evaluates rate/spend policies", async () => {
    const policies: PolicyRule[] = [
      makeRateRule({ maxTxPerHour: 1, maxTxPerDay: 10 }),
      makeSpendingRule({
        maxPerTx: "100",
        maxPerDay: "1000",
        maxPerWeek: "1000",
      }),
      makeAddressRule({
        addresses: ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        mode: "whitelist",
      }),
    ];

    const result = await engine.simulate(policies, {
      ...makeEngineCtx({ recentTxCount1h: 1 }),
      request: { kind: "proxy", method: "POST", url: "/v1/orders", body: { value: "50" } },
    });

    expect(result.approved).toBe(false);
    expect(result.results.map((r) => r.type)).toEqual(["rate-limit", "spending-limit"]);
    expect(result.results.find((r) => r.type === "rate-limit")?.passed).toBe(false);
    expect(result.results.find((r) => r.type === "spending-limit")?.passed).toBe(true);
  });

  it("disabled-only policy sets fail closed inside engine", async () => {
    const policies: PolicyRule[] = [
      {
        id: "disabled",
        type: "spending-limit",
        enabled: false,
        config: { maxPerTx: "1", maxPerDay: "1", maxPerWeek: "1" }, // would fail if enabled
      },
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results[0].passed).toBe(true);
    expect(result.results[0].reason).toBe("Policy disabled");
  });

  it("disabled policies do not block approval when at least one enabled policy passes", async () => {
    const policies: PolicyRule[] = [
      {
        id: "disabled",
        type: "spending-limit",
        enabled: false,
        config: { maxPerTx: "1", maxPerDay: "1", maxPerWeek: "1" },
      },
      makeSpendingRule({
        maxPerTx: "10000000000000000000",
        maxPerDay: "50000000000000000000",
        maxPerWeek: "100000000000000000000",
      }),
    ];

    const result = await engine.evaluate(policies, makeEngineCtx());

    expect(result.approved).toBe(true);
    expect(result.requiresManualApproval).toBe(false);
    expect(result.results).toHaveLength(2);
  });
});
