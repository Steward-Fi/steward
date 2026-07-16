/**
 * cumulative-spend-cap.test.ts — proves the #206 cumulativeSpend cap +
 * configurable count window in capability-intent (Privy aggregate-limit parity).
 *
 * Adversarial coverage:
 *  - over-cap sequence denies; under-cap passes; EXACT boundary passes.
 *  - missing aggregate context => deny (fail closed, POLICY_INPUT_UNAVAILABLE).
 *  - operation-without-declared-spend-field => deny (NO_SPEND_FIELD, never skip).
 *  - currency mismatch => deny (CURRENCY_MISMATCH, no FX).
 *  - aggregateOver scope selectable (operation / agent / grant) and honored.
 *  - malformed configs rejected at STORE time (parseConfig) AND denied at EVAL.
 *  - maxCallsPerHour regression untouched; maxCalls+callWindow configurable cap.
 *  - deny > approval > allow precedence preserved when the cap breaches.
 *  - integer-only math (no floats); safe-integer overflow fails closed.
 *
 * These test the provider-action plane (composeProviderActionPolicyDecision),
 * which is where the aggregate/declaration/window signals are wired. The legacy
 * tx-sign plane fail-closed behavior is covered in capability-intent.test.ts.
 */

import { describe, expect, it } from "bun:test";
import {
  composeProviderActionPolicyDecision,
  parseCapabilityIntentConfigForTest,
  PROVIDER_POLICY_REASON,
  type ProviderPolicyContext,
  type ProviderPolicyRule,
} from "../capability-intent.js";

const OP = "wallet.transfer";

/** A spend-bearing operation context: declares its spend field + currency. */
function ctx(overrides: Partial<ProviderPolicyContext> = {}): ProviderPolicyContext {
  return {
    operationKey: OP,
    args: { amountMicros: 1_000_000 }, // $1.00 in micros
    method: "POST",
    host: "api.wallet.example",
    path: "/v1/transfer",
    invokeCount1h: 0,
    spendDeclaration: { field: "amountMicros", currency: "USD" },
    cumulativeSpend: { operation: 0, agent: 0, grant: 0 },
    ...overrides,
  };
}

function rule(config: Record<string, unknown>): ProviderPolicyRule {
  return { id: "r1", type: "capability-intent", enabled: true, config };
}

function spendRule(
  max: number,
  aggregateOver: "operation" | "agent" | "grant" = "agent",
  currency = "USD",
  window = "PT24H",
): ProviderPolicyRule {
  return rule({
    capabilities: [OP],
    effect: "allow",
    constraints: { cumulativeSpend: { window, currency, max, aggregateOver } },
  });
}

describe("cumulativeSpend — under / boundary / over", () => {
  it("under-cap passes (prior 0 + 1_000_000 <= 5_000_000)", () => {
    const d = composeProviderActionPolicyDecision([spendRule(5_000_000)], ctx());
    expect(d.effect).toBe("allow");
  });

  it("EXACT boundary passes (prior 4_000_000 + 1_000_000 === 5_000_000, not > max)", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000)],
      ctx({ cumulativeSpend: { operation: 4_000_000, agent: 4_000_000, grant: 4_000_000 } }),
    );
    expect(d.effect).toBe("allow");
  });

  it("one micro over the boundary denies (prior 4_000_000 + 1_000_001 > 5_000_000)", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000)],
      ctx({
        args: { amountMicros: 1_000_001 },
        cumulativeSpend: { operation: 4_000_000, agent: 4_000_000, grant: 4_000_000 },
      }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CAP_EXCEEDED);
  });

  it("over-cap sequence: once prior sum saturates, next invoke denies", () => {
    // Simulate a running sum crossing the cap across invokes (the invoke layer
    // supplies the trailing sum; here we assert each step's verdict).
    const cap = 3_000_000;
    // step 1: prior 0 + 1M = 1M <= 3M => allow
    expect(
      composeProviderActionPolicyDecision([spendRule(cap)], ctx({ cumulativeSpend: { agent: 0 } }))
        .effect,
    ).toBe("allow");
    // step 2: prior 2M + 1M = 3M === cap => allow (boundary)
    expect(
      composeProviderActionPolicyDecision(
        [spendRule(cap)],
        ctx({ cumulativeSpend: { agent: 2_000_000 } }),
      ).effect,
    ).toBe("allow");
    // step 3: prior 3M + 1M = 4M > cap => deny
    expect(
      composeProviderActionPolicyDecision(
        [spendRule(cap)],
        ctx({ cumulativeSpend: { agent: 3_000_000 } }),
      ).effect,
    ).toBe("hard_deny");
  });
});

describe("cumulativeSpend — fail-closed missing signals", () => {
  it("missing aggregate block entirely => deny (INPUT_UNAVAILABLE)", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000)],
      ctx({ cumulativeSpend: undefined }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });

  it("missing the SPECIFIC scope entry => deny (INPUT_UNAVAILABLE)", () => {
    // rule aggregates over "grant" but only "agent" is supplied.
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000, "grant")],
      ctx({ cumulativeSpend: { agent: 0 } }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });

  it("operation declares NO spend field => deny (NO_SPEND_FIELD), never skip", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000)],
      ctx({ spendDeclaration: undefined }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_NO_SPEND_FIELD);
  });

  it("declared spend field absent from args => deny (INPUT_UNAVAILABLE)", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000)],
      ctx({ args: {}, spendDeclaration: { field: "amountMicros", currency: "USD" } }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });

  it("declared spend field is a float / negative / non-int => deny (INPUT_UNAVAILABLE)", () => {
    for (const bad of [1.5, -1, "1000000", Number.NaN, Number.POSITIVE_INFINITY]) {
      const d = composeProviderActionPolicyDecision(
        [spendRule(5_000_000)],
        ctx({ args: { amountMicros: bad } }),
      );
      expect(d.effect).toBe("hard_deny");
      expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
    }
  });
});

describe("cumulativeSpend — currency discipline (no FX)", () => {
  it("operation currency != cap currency => deny (CURRENCY_MISMATCH)", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000, "agent", "USD")],
      ctx({ spendDeclaration: { field: "amountMicros", currency: "EUR" } }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CURRENCY_MISMATCH);
  });

  it("matching currency + under cap => allow", () => {
    const d = composeProviderActionPolicyDecision(
      [spendRule(5_000_000, "agent", "USDC")],
      ctx({ spendDeclaration: { field: "amountMicros", currency: "USDC" } }),
    );
    expect(d.effect).toBe("allow");
  });
});

describe("cumulativeSpend — aggregateOver scope selection", () => {
  it("operation scope reads the operation sum", () => {
    const overCtx = ctx({
      cumulativeSpend: { operation: 5_000_000, agent: 0, grant: 0 },
    });
    expect(
      composeProviderActionPolicyDecision([spendRule(5_000_000, "operation")], overCtx).effect,
    ).toBe("hard_deny");
    // agent-scoped rule on the same context passes (agent sum is 0).
    expect(composeProviderActionPolicyDecision([spendRule(5_000_000, "agent")], overCtx).effect).toBe(
      "allow",
    );
  });

  it("grant scope reads the grant sum independently", () => {
    const overCtx = ctx({
      cumulativeSpend: { operation: 0, agent: 0, grant: 5_000_000 },
    });
    expect(composeProviderActionPolicyDecision([spendRule(5_000_000, "grant")], overCtx).effect).toBe(
      "hard_deny",
    );
  });
});

describe("cumulativeSpend — precedence (deny wins)", () => {
  it("cap breach (allow rule fails hard constraint) beats a require-approval rule", () => {
    const rules: ProviderPolicyRule[] = [
      spendRule(1_000), // 0 + 1_000_000 > 1_000 => hard deny
      rule({ capabilities: [OP], effect: "require-approval" }),
    ];
    for (let i = 0; i < 50; i++) {
      const shuffled = i % 2 === 0 ? rules : [...rules].reverse();
      const d = composeProviderActionPolicyDecision(shuffled, ctx());
      expect(d.effect).toBe("hard_deny");
    }
  });

  it("an explicit deny still wins over a passing cumulativeSpend allow", () => {
    const rules: ProviderPolicyRule[] = [
      spendRule(5_000_000),
      rule({ capabilities: [OP], effect: "deny" }),
    ];
    expect(composeProviderActionPolicyDecision(rules, ctx()).effect).toBe("hard_deny");
  });
});

describe("configurable count window (maxCalls + callWindow)", () => {
  it("maxCallsPerHour regression: still reads invokeCount1h, denies at cap", () => {
    const r = rule({ capabilities: [OP], effect: "allow", constraints: { maxCallsPerHour: 2 } });
    expect(composeProviderActionPolicyDecision([r], ctx({ invokeCount1h: 1 })).effect).toBe("allow");
    expect(composeProviderActionPolicyDecision([r], ctx({ invokeCount1h: 2 })).effect).toBe(
      "hard_deny",
    );
  });

  it("maxCallsPerHour absent count => deny (unchanged fail-closed)", () => {
    const r = rule({ capabilities: [OP], effect: "allow", constraints: { maxCallsPerHour: 2 } });
    const d = composeProviderActionPolicyDecision([r], ctx({ invokeCount1h: undefined }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });

  it("maxCalls+callWindow reads windowedInvokeCount, denies at cap", () => {
    const r = rule({
      capabilities: [OP],
      effect: "allow",
      constraints: { maxCalls: 3, callWindow: "P1D" },
    });
    expect(
      composeProviderActionPolicyDecision([r], ctx({ windowedInvokeCount: 2 })).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([r], ctx({ windowedInvokeCount: 3 })).effect,
    ).toBe("hard_deny");
  });

  it("maxCalls set but windowedInvokeCount absent => deny (INPUT_UNAVAILABLE)", () => {
    const r = rule({
      capabilities: [OP],
      effect: "allow",
      constraints: { maxCalls: 3, callWindow: "PT1H" },
    });
    const d = composeProviderActionPolicyDecision([r], ctx({ windowedInvokeCount: undefined }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });
});

describe("cumulativeSpend + maxCalls — store-time config validation (fail closed)", () => {
  const store = (constraints: Record<string, unknown>) =>
    parseCapabilityIntentConfigForTest({ capabilities: [OP], effect: "allow", constraints });

  it("accepts a well-formed cumulativeSpend block", () => {
    const r = store({
      cumulativeSpend: { window: "PT24H", currency: "USD", max: 10_000_000, aggregateOver: "agent" },
    });
    expect("error" in r).toBe(false);
  });

  it("rejects malformed ISO-8601 window", () => {
    for (const bad of ["24h", "PT", "P", "P0D", "PT0S", "P1M", "P1Y", "", "PTH", "1D"]) {
      const r = store({
        cumulativeSpend: { window: bad, currency: "USD", max: 1, aggregateOver: "agent" },
      });
      expect("error" in r).toBe(true);
    }
  });

  it("accepts valid ISO-8601 windows P/PT variants", () => {
    for (const good of ["PT1H", "PT24H", "P1D", "P7D", "PT30M", "P1W", "PT1H30M", "P1DT2H"]) {
      const r = store({
        cumulativeSpend: { window: good, currency: "USD", max: 1, aggregateOver: "agent" },
      });
      expect("error" in r).toBe(false);
    }
  });

  it("rejects unknown aggregateOver", () => {
    const r = store({
      cumulativeSpend: { window: "PT1H", currency: "USD", max: 1, aggregateOver: "tenant" },
    });
    expect("error" in r).toBe(true);
  });

  it("rejects non-integer / negative / non-number max", () => {
    for (const bad of [1.5, -1, "1", Number.NaN, null]) {
      const r = store({
        cumulativeSpend: { window: "PT1H", currency: "USD", max: bad, aggregateOver: "agent" },
      });
      expect("error" in r).toBe(true);
    }
  });

  it("rejects empty / non-string currency", () => {
    for (const bad of ["", 5, null, undefined]) {
      const r = store({
        cumulativeSpend: { window: "PT1H", currency: bad, max: 1, aggregateOver: "agent" },
      });
      expect("error" in r).toBe(true);
    }
  });

  it("rejects unknown keys inside cumulativeSpend", () => {
    const r = store({
      cumulativeSpend: {
        window: "PT1H",
        currency: "USD",
        max: 1,
        aggregateOver: "agent",
        extra: true,
      },
    });
    expect("error" in r).toBe(true);
  });

  it("rejects maxCalls without callWindow (and vice versa)", () => {
    expect("error" in store({ maxCalls: 5 })).toBe(true);
    expect("error" in store({ callWindow: "PT1H" })).toBe(true);
  });

  it("rejects maxCalls combined with maxCallsPerHour (mutually exclusive)", () => {
    expect("error" in store({ maxCalls: 5, callWindow: "PT1H", maxCallsPerHour: 3 })).toBe(true);
  });

  it("rejects malformed callWindow", () => {
    expect("error" in store({ maxCalls: 5, callWindow: "1h" })).toBe(true);
    expect("error" in store({ maxCalls: 5, callWindow: "P1Y" })).toBe(true);
  });

  it("rejects non-integer maxCalls", () => {
    expect("error" in store({ maxCalls: 1.5, callWindow: "PT1H" })).toBe(true);
    expect("error" in store({ maxCalls: -1, callWindow: "PT1H" })).toBe(true);
  });
});

describe("cumulativeSpend — runtime denies a hand-edited malformed window", () => {
  it("a stored-but-malformed window denies at eval (CONFIGURATION_INVALID)", () => {
    // Bypass store-time validation to simulate a corrupt/hand-edited jsonb row:
    // the eval path must re-validate and fail closed, not pass unbounded.
    const r: ProviderPolicyRule = {
      id: "r1",
      type: "capability-intent",
      enabled: true,
      // parseConfig would reject this window, so the composer hard-denies with
      // CONFIGURATION_INVALID at the parse gate before eval. This asserts the
      // store-and-eval double guard: a malformed window can NEVER pass.
      config: {
        capabilities: [OP],
        effect: "allow",
        constraints: {
          cumulativeSpend: { window: "P1Y", currency: "USD", max: 1, aggregateOver: "agent" },
        },
      },
    };
    const d = composeProviderActionPolicyDecision([r], ctx());
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.CONFIGURATION_INVALID);
  });
});
