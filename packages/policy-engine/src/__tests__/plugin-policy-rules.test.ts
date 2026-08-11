/**
 * plugin-policy-rules.test.ts — proves the Phase 2b pluggable policy-rule
 * mechanism end-to-end at the policy-engine layer:
 *
 *  1. a registered plugin evaluator runs for a rule of its contributed type
 *     (the `default:` fallthrough consults the registry, NOT "Unknown policy
 *     type").
 *  2. an UNregistered non-core rule type still denies as "Unknown policy type"
 *     (the historical default is preserved).
 *  3. a plugin CANNOT register a rule type that collides with a core type or
 *     another plugin's type (fail closed).
 *  4. a throwing plugin evaluator fails CLOSED (deny), never crashing the
 *     money-route decision.
 *  5. core rule evaluation is unaffected by registering a plugin rule type.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import type { ContributedPolicyResult, PolicyRule, SignRequest } from "@stwd/shared";
import { UNPRINTABLE_THROWN_VALUE } from "@stwd/shared";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";
import {
  CORE_POLICY_RULE_TYPES,
  PolicyRuleRegistry,
  PolicyRuleRegistryError,
  policyRuleRegistry,
} from "../policy-rule-registry";

function makeContext(overrides: Partial<EvaluatorContext> = {}): EvaluatorContext {
  const request: SignRequest = {
    agentId: "test-agent",
    tenantId: "test-tenant",
    to: "0x1234567890123456789012345678901234567890",
    value: "1000000000000000000",
    chainId: 8453,
  };
  return {
    request,
    recentTxCount1h: 0,
    recentTxCount24h: 0,
    spentToday: 0n,
    spentThisWeek: 0n,
    ...overrides,
  };
}

/** Build a rule of an arbitrary (possibly non-core) type. Cast because the core
 * `PolicyType` union is closed; a plugin rule type is a runtime string. */
function makeRule(type: string, config: Record<string, unknown> = {}, id = "r1"): PolicyRule {
  return { id, type: type as PolicyRule["type"], enabled: true, config };
}

// The default process-wide registry is mutated by the host in prod; tests keep
// it clean so a stray registration can't leak across cases.
afterEach(() => {
  policyRuleRegistry.clear();
});

describe("PolicyRuleRegistry — registration rules", () => {
  let registry: PolicyRuleRegistry;
  beforeEach(() => {
    registry = new PolicyRuleRegistry();
  });

  it("registers a plugin evaluator and looks it up by type", () => {
    registry.register({
      type: "test-custom-rule",
      pluginName: "demo",
      evaluate: () => ({ policyId: "x", type: "test-custom-rule", passed: true }),
    });
    expect(registry.has("test-custom-rule")).toBe(true);
    expect(registry.get("test-custom-rule")?.pluginName).toBe("demo");
  });

  it("rejects a rule type that collides with a CORE rule type (fail closed)", () => {
    for (const coreType of CORE_POLICY_RULE_TYPES) {
      expect(() =>
        registry.register({
          type: coreType,
          pluginName: "evil",
          evaluate: () => ({ policyId: "x", type: coreType, passed: true }),
        }),
      ).toThrow(PolicyRuleRegistryError);
    }
  });

  it("rejects a rule type already registered by another plugin (fail closed)", () => {
    registry.register({
      type: "shared-type",
      pluginName: "first",
      evaluate: () => ({ policyId: "x", type: "shared-type", passed: true }),
    });
    expect(() =>
      registry.register({
        type: "shared-type",
        pluginName: "second",
        evaluate: () => ({ policyId: "x", type: "shared-type", passed: true }),
      }),
    ).toThrow(PolicyRuleRegistryError);
  });

  it("rejects an empty/blank rule type", () => {
    expect(() =>
      registry.register({
        type: "   ",
        pluginName: "demo",
        evaluate: () => ({ policyId: "x", type: "x", passed: true }),
      }),
    ).toThrow(PolicyRuleRegistryError);
  });
});

describe("evaluatePolicy — plugin rule fallthrough (uses the process-wide registry)", () => {
  it("runs a registered plugin evaluator for its contributed type", async () => {
    let sawRule = false;
    policyRuleRegistry.register({
      type: "test-custom-rule",
      pluginName: "demo",
      evaluate: (rule): ContributedPolicyResult => {
        sawRule = true;
        const min = Number(rule.config.minValue ?? 0);
        return {
          policyId: rule.id,
          type: rule.type,
          passed: min <= 5,
          reason: min <= 5 ? "within bound" : "exceeds bound",
        };
      },
    });

    const pass = await evaluatePolicy(makeRule("test-custom-rule", { minValue: 3 }), makeContext());
    expect(sawRule).toBe(true);
    expect(pass.passed).toBe(true);
    expect(pass.type).toBe("test-custom-rule");
    expect(pass.reason).toBe("within bound");

    const fail = await evaluatePolicy(makeRule("test-custom-rule", { minValue: 9 }), makeContext());
    expect(fail.passed).toBe(false);
    expect(fail.reason).toBe("exceeds bound");
  });

  it("still denies an UNregistered non-core type as 'Unknown policy type'", async () => {
    const result = await evaluatePolicy(makeRule("never-registered-type"), makeContext());
    expect(result.passed).toBe(false);
    expect(result.reason).toBe("Unknown policy type: never-registered-type");
  });

  it("fails CLOSED (deny) when a plugin evaluator throws", async () => {
    policyRuleRegistry.register({
      type: "throwing-rule",
      pluginName: "buggy",
      evaluate: () => {
        throw new Error("boom");
      },
    });
    const result = await evaluatePolicy(makeRule("throwing-rule"), makeContext());
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("threw");
  });

  // ROUND-2 P0: the generic engine catch used
  //   `error instanceof Error ? error.message : String(error)`
  // to build the deny reason. A thrown value whose toString/valueOf/
  // Symbol.toPrimitive (or a Proxy `.message` getter) THROWS made the catch
  // block itself throw, escaping the registry dispatch as a raw exception (500).
  // These assert the generic dispatch NEVER throws and ALWAYS fails closed for
  // an evaluator that throws an unprintable value.
  it("fails CLOSED (deny), NO exception, when an evaluator throws a value with a throwing toString", async () => {
    policyRuleRegistry.register({
      type: "hostile-tostring-rule",
      pluginName: "hostile",
      evaluate: () => {
        // intentional hostile throw: a non-Error value whose toString throws
        const hostile = {
          toString() {
            throw new Error("secondary stringify failure");
          },
        };
        throw hostile;
      },
    });
    let result: Awaited<ReturnType<typeof evaluatePolicy>> | undefined;
    await expect(
      (async () => {
        result = await evaluatePolicy(makeRule("hostile-tostring-rule"), makeContext());
      })(),
    ).resolves.toBeUndefined();
    expect(result?.passed).toBe(false);
    expect(result?.reason).toContain("threw");
  });

  it("fails CLOSED (deny), NO exception, when toString AND valueOf AND Symbol.toPrimitive all throw", async () => {
    policyRuleRegistry.register({
      type: "hostile-all-coercion-rule",
      pluginName: "hostile",
      evaluate: () => {
        throw {
          toString() {
            throw new Error("toString throws");
          },
          valueOf() {
            throw new Error("valueOf throws");
          },
          [Symbol.toPrimitive]() {
            throw new Error("toPrimitive throws");
          },
        };
      },
    });
    let result: Awaited<ReturnType<typeof evaluatePolicy>> | undefined;
    await expect(
      (async () => {
        result = await evaluatePolicy(makeRule("hostile-all-coercion-rule"), makeContext());
      })(),
    ).resolves.toBeUndefined();
    expect(result?.passed).toBe(false);
    // Static unprintable fallback is embedded; never leaked / never threw.
    expect(result?.reason).toContain(UNPRINTABLE_THROWN_VALUE);
  });

  it("fails CLOSED (deny), NO exception, when the evaluator throws a Proxy(Error) with a throwing `.message` getter", async () => {
    policyRuleRegistry.register({
      type: "hostile-proxy-error-rule",
      pluginName: "hostile",
      evaluate: () => {
        throw new Proxy(new Error("real"), {
          get(_t, prop) {
            if (prop === "message") throw new Error("hostile message getter");
            if (prop === "toString" || prop === Symbol.toPrimitive || prop === "valueOf") {
              return () => {
                throw new Error("hostile coercion");
              };
            }
            return undefined;
          },
        });
      },
    });
    let result: Awaited<ReturnType<typeof evaluatePolicy>> | undefined;
    await expect(
      (async () => {
        result = await evaluatePolicy(makeRule("hostile-proxy-error-rule"), makeContext());
      })(),
    ).resolves.toBeUndefined();
    expect(result?.passed).toBe(false);
    expect(result?.reason).toContain(UNPRINTABLE_THROWN_VALUE);
  });

  it("pins policyId/type to the rule so a plugin can't mislabel the verdict", async () => {
    policyRuleRegistry.register({
      type: "liar-rule",
      pluginName: "liar",
      // returns a mislabeled identity; the engine must overwrite with the rule's.
      evaluate: () => ({ policyId: "WRONG", type: "spending-limit", passed: true }),
    });
    const result = await evaluatePolicy(makeRule("liar-rule", {}, "the-real-id"), makeContext());
    expect(result.policyId).toBe("the-real-id");
    expect(result.type).toBe("liar-rule");
    expect(result.passed).toBe(true);
  });

  it("treats a non-true `passed` as deny (coerced)", async () => {
    policyRuleRegistry.register({
      type: "sloppy-rule",
      pluginName: "sloppy",
      evaluate: () =>
        ({
          policyId: "x",
          type: "sloppy-rule",
          passed: "yes",
        }) as unknown as ContributedPolicyResult,
    });
    const result = await evaluatePolicy(makeRule("sloppy-rule"), makeContext());
    expect(result.passed).toBe(false);
  });
});

describe("evaluatePolicy — core rules unaffected by plugin registration", () => {
  it("a disabled rule still passes as 'Policy disabled' regardless of registry", async () => {
    policyRuleRegistry.register({
      type: "test-custom-rule",
      pluginName: "demo",
      evaluate: () => ({ policyId: "x", type: "test-custom-rule", passed: false }),
    });
    const disabled: PolicyRule = {
      id: "d1",
      type: "spending-limit",
      enabled: false,
      config: {},
    };
    const result = await evaluatePolicy(disabled, makeContext());
    expect(result.passed).toBe(true);
    expect(result.reason).toBe("Policy disabled");
  });

  it("a core spending-limit rule evaluates via the core case, not the registry", async () => {
    // register a plugin rule that would PASS — if the core rule somehow routed
    // through the registry it'd pass; instead the core wei comparison must fire.
    policyRuleRegistry.register({
      type: "test-custom-rule",
      pluginName: "demo",
      evaluate: () => ({ policyId: "x", type: "test-custom-rule", passed: true }),
    });
    // value 1 ETH, per-tx cap 0.5 ETH → core evaluator denies.
    const rule = makeRule("spending-limit", { maxPerTx: "500000000000000000" });
    const result = await evaluatePolicy(rule, makeContext());
    expect(result.passed).toBe(false);
    expect(result.reason).toContain("exceeds per-tx limit");
  });
});
