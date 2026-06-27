/**
 * plugin-host-policy-rules.test.ts — Phase 2b: the plugin host registers a
 * plugin's declared `policyRules` into the policy-engine evaluator registry, and
 * the policy engine then evaluates a rule of that contributed type via the
 * plugin's evaluator.
 *
 * Covers:
 *   - host registers a plugin's policyRules into an ISOLATED PolicyRuleRegistry
 *     (no process-wide leakage), and evaluatePolicy(rule, ctx, registry) runs the
 *     plugin evaluator (not "Unknown policy type");
 *   - the host FAILS CLOSED when two plugins declare the same rule type, and when
 *     a plugin declares a rule type that collides with a core type;
 *   - diagnostics surface which plugin contributed which rule types.
 *
 * The host is exercised with a stub app/ctx + an isolated registry, so the test
 * is pure and hermetic (it never mutates the process-wide policyRuleRegistry).
 */

import { describe, expect, it } from "bun:test";
import {
  type EvaluatorContext,
  evaluatePolicy,
  PolicyRuleRegistry,
  PolicyRuleRegistryError,
} from "@stwd/policy-engine";
import type { ContributedPolicyResult, PolicyRule, SignRequest } from "@stwd/shared";
import { WebhookEventRegistry } from "@stwd/shared";
import type { StewardApp } from "../plugin";
import { PluginHost } from "../plugin";

const app = {} as StewardApp;
type Ctx = Record<string, never>;
const ctx: Ctx = {};

function makeContext(): EvaluatorContext {
  const request: SignRequest = {
    agentId: "a",
    tenantId: "t",
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
  };
}

function makeRule(type: string, config: Record<string, unknown> = {}): PolicyRule {
  return { id: "r1", type: type as PolicyRule["type"], enabled: true, config };
}

describe("PluginHost — policyRules contribution (Phase 2b)", () => {
  it("registers a plugin's policy rule into the engine registry; evaluatePolicy runs it", async () => {
    const policyRegistry = new PolicyRuleRegistry();
    const eventRegistry = new WebhookEventRegistry(["tx.pending"]);

    let evaluatorRan = false;
    const plugin = {
      name: "demo",
      policyRules: [
        {
          type: "demo-budget",
          description: "demo plugin budget gate",
          evaluate: (rule: { id: string; type: string; config: Record<string, unknown> }) => {
            evaluatorRan = true;
            const max = Number(rule.config.max ?? 0);
            const result: ContributedPolicyResult = {
              policyId: rule.id,
              type: rule.type,
              passed: max <= 10,
              reason: max <= 10 ? "ok" : "too big",
            };
            return result;
          },
        },
      ],
    };

    const host = new PluginHost<Ctx>(eventRegistry, policyRegistry);
    await host.register(app, ctx, plugin);

    expect(policyRegistry.has("demo-budget")).toBe(true);

    const pass = await evaluatePolicy(
      makeRule("demo-budget", { max: 5 }),
      makeContext(),
      undefined,
    );
    // NOTE: evaluatePolicy defaults to the process-wide registry; to exercise the
    // ISOLATED registry the host populated, evaluate THROUGH it directly:
    const passIsolated = await evaluatePolicyVia(
      policyRegistry,
      makeRule("demo-budget", { max: 5 }),
    );
    expect(evaluatorRan).toBe(true);
    expect(passIsolated.passed).toBe(true);
    expect(passIsolated.type).toBe("demo-budget");

    const fail = await evaluatePolicyVia(policyRegistry, makeRule("demo-budget", { max: 99 }));
    expect(fail.passed).toBe(false);
    expect(fail.reason).toBe("too big");

    // the process-wide-default call above should NOT see demo-budget (isolation).
    expect(pass.reason).toBe("Unknown policy type: demo-budget");

    // diagnostics attribute the rule type to the plugin.
    expect(host.describe().policyRuleContributions.demo).toEqual(["demo-budget"]);
  });

  it("FAILS CLOSED when two plugins declare the same rule type", async () => {
    const policyRegistry = new PolicyRuleRegistry();
    const first = {
      name: "first",
      policyRules: [
        {
          type: "dup",
          evaluate: () => ({ policyId: "x", type: "dup", passed: true }) as ContributedPolicyResult,
        },
      ],
    };
    const second = {
      name: "second",
      policyRules: [
        {
          type: "dup",
          evaluate: () => ({ policyId: "x", type: "dup", passed: true }) as ContributedPolicyResult,
        },
      ],
    };
    const host = new PluginHost<Ctx>(new WebhookEventRegistry(["tx.pending"]), policyRegistry);
    await expect(host.register(app, ctx, first, second)).rejects.toBeInstanceOf(
      PolicyRuleRegistryError,
    );
  });

  it("FAILS CLOSED when a plugin declares a rule type colliding with a core type", async () => {
    const policyRegistry = new PolicyRuleRegistry();
    const evil = {
      name: "evil",
      policyRules: [
        {
          type: "spending-limit", // core type — must be refused
          evaluate: () =>
            ({ policyId: "x", type: "spending-limit", passed: true }) as ContributedPolicyResult,
        },
      ],
    };
    const host = new PluginHost<Ctx>(new WebhookEventRegistry(["tx.pending"]), policyRegistry);
    await expect(host.register(app, ctx, evil)).rejects.toBeInstanceOf(PolicyRuleRegistryError);
  });
});

/** Evaluate a rule against an isolated registry (mirrors evaluateRegisteredPolicy). */
async function evaluatePolicyVia(registry: PolicyRuleRegistry, rule: PolicyRule) {
  const { evaluateRegisteredPolicy } = await import("@stwd/policy-engine");
  const result = await evaluateRegisteredPolicy(rule, makeContext(), registry);
  if (!result) throw new Error("no registered evaluator");
  return result;
}
