/**
 * capability-intent.test.ts — proves the `capability-intent` contributed rule
 * (W-1b) at the policy-engine layer:
 *
 *  - APPLICABILITY: inert when ctx.capability is absent; not-applicable (pass)
 *    when the invoked capability name doesn't match the rule's list.
 *  - EFFECTS: allow / deny / require-approval (incl. the requiresManualApproval
 *    signal shape, and that it survives the registry passthrough).
 *  - CONSTRAINTS: argEquals (hit/miss/missing-arg), argMatches (match / no-match
 *    / invalid-regex-in-config => deny-no-throw), maxCallsPerHour (absent count
 *    => deny; under/over limit).
 *  - GLOB: "github.*" prefix match, exact-only, case sensitivity.
 *  - CONFIG VALIDATION: malformed config fails closed.
 *  - REGISTRY INTEGRATION: registered under its type and driven end-to-end
 *    through evaluatePolicy's default arm with ctx.capability set.
 *  - COMPOSITION: multiple capability-intent rules under all-must-pass.
 */

import { afterEach, describe, expect, it } from "bun:test";
import type { ContributedPolicyRule, PolicyRule, SignRequest } from "@stwd/shared";
import {
  CAPABILITY_INTENT_RULE_TYPE,
  capabilityIntentContribution,
  evaluateCapabilityIntent,
} from "../capability-intent";
import { PolicyEngine } from "../engine";
import { type EvaluatorContext, evaluatePolicy } from "../evaluators";
import { policyRuleRegistry } from "../policy-rule-registry";

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

function cap(
  overrides: Partial<NonNullable<EvaluatorContext["capability"]>> = {},
): NonNullable<EvaluatorContext["capability"]> {
  return {
    name: "github.pr.comment",
    args: {},
    host: "api.github.com",
    path: "/repos/x/y/issues/1/comments",
    method: "POST",
    ...overrides,
  };
}

function rule(config: Record<string, unknown>, id = "cr1"): ContributedPolicyRule {
  return { id, type: CAPABILITY_INTENT_RULE_TYPE, enabled: true, config };
}

afterEach(() => {
  policyRuleRegistry.clear();
});

describe("capability-intent — applicability (fail-open only where safe)", () => {
  it("passes (inert) when ctx.capability is absent — cannot interfere with tx signing", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "deny" }),
      makeContext(),
    );
    expect(r.passed).toBe(true);
    expect(r.reason).toBe("not a capability invoke");
  });

  it("passes (not applicable) when the capability name is not governed by the rule", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["gitlab.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "github.pr.comment" }) }),
    );
    expect(r.passed).toBe(true);
    expect(r.reason).toContain("not governed");
  });
});

describe("capability-intent — effects", () => {
  it("allow: matched capability with no constraints passes", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.pr.comment"], effect: "allow" }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(true);
    expect(r.reason).toContain("allowed");
  });

  it("deny: matched capability is denied", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.pr.comment"], effect: "deny" }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("denied");
  });

  it("require-approval: matched capability fails with requiresManualApproval:true", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(false);
    expect((r as { requiresManualApproval?: boolean }).requiresManualApproval).toBe(true);
    expect(r.reason).toContain("manual approval");
  });
});

describe("capability-intent — argEquals constraint", () => {
  const base = { capabilities: ["github.*"], effect: "allow" as const };

  it("passes when every configured arg strictly equals", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argEquals: { repo: "steward" } } }),
      makeContext({ capability: cap({ args: { repo: "steward" } }) }),
    );
    expect(r.passed).toBe(true);
  });

  it("denies on a mismatch", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argEquals: { repo: "steward" } } }),
      makeContext({ capability: cap({ args: { repo: "other" } }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain('must equal "steward"');
  });

  it("denies when the required arg is absent (fail closed)", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argEquals: { repo: "steward" } } }),
      makeContext({ capability: cap({ args: {} }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("is absent");
  });

  it("denies a non-string arg (strict === against configured string)", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argEquals: { count: "3" } } }),
      makeContext({ capability: cap({ args: { count: 3 } }) }),
    );
    expect(r.passed).toBe(false);
  });
});

describe("capability-intent — argMatches constraint", () => {
  const base = { capabilities: ["github.*"], effect: "allow" as const };

  it("passes when the arg matches the (anchored) regex", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: "feat/.+" } } }),
      makeContext({ capability: cap({ args: { branch: "feat/x" } }) }),
    );
    expect(r.passed).toBe(true);
  });

  it("denies a partial match (full-string anchored)", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: "feat" } } }),
      makeContext({ capability: cap({ args: { branch: "feature/x" } }) }),
    );
    expect(r.passed).toBe(false);
  });

  it("denies when the arg is absent", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: ".+" } } }),
      makeContext({ capability: cap({ args: {} }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("is absent");
  });

  it("denies a non-string arg", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { n: "\\d+" } } }),
      makeContext({ capability: cap({ args: { n: 5 } }) }),
    );
    expect(r.passed).toBe(false);
  });

  it("denies (never throws) on an invalid regex in config", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: "(" } } }),
      makeContext({ capability: cap({ args: { branch: "anything" } }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("invalid regex");
  });
});

describe("capability-intent — maxCallsPerHour constraint (fail closed)", () => {
  const base = { capabilities: ["github.*"], effect: "allow" as const };

  it("DENIES when maxCallsPerHour is set but capabilityInvokeCount1h is absent", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { maxCallsPerHour: 5 } }),
      makeContext({ capability: cap() }), // no capabilityInvokeCount1h
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("invoke count not wired");
  });

  it("passes when the invoke count is under the limit", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { maxCallsPerHour: 5 } }),
      makeContext({ capability: cap(), capabilityInvokeCount1h: 4 }),
    );
    expect(r.passed).toBe(true);
  });

  it("denies when the invoke count has reached the limit", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { maxCallsPerHour: 5 } }),
      makeContext({ capability: cap(), capabilityInvokeCount1h: 5 }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("hourly invoke cap reached");
  });
});

describe("capability-intent — name matching (glob + exact + case)", () => {
  it('"github.*" matches "github.pr.comment"', () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "github.pr.comment" }) }),
    );
    expect(r.passed).toBe(false);
  });

  it('"github.*" does NOT match "gitlab.pr.x"', () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "gitlab.pr.x" }) }),
    );
    expect(r.passed).toBe(true); // not applicable
  });

  it('"github.*" does NOT match bare "github" (prefix requires the dot)', () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "github" }) }),
    );
    expect(r.passed).toBe(true);
  });

  it('"github.*" does NOT match "githubx.y" (no substring/general glob)', () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "githubx.y" }) }),
    );
    expect(r.passed).toBe(true);
  });

  it("exact-only pattern matches only the exact name", () => {
    const denyExact = rule({ capabilities: ["github.pr.comment"], effect: "deny" });
    expect(
      evaluateCapabilityIntent(
        denyExact,
        makeContext({ capability: cap({ name: "github.pr.comment" }) }),
      ).passed,
    ).toBe(false);
    expect(
      evaluateCapabilityIntent(
        denyExact,
        makeContext({ capability: cap({ name: "github.pr.delete" }) }),
      ).passed,
    ).toBe(true); // not applicable
  });

  it("matching is case-sensitive", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["GitHub.*"], effect: "deny" }),
      makeContext({ capability: cap({ name: "github.pr.comment" }) }),
    );
    expect(r.passed).toBe(true); // no case-insensitive match -> not applicable
  });
});

describe("capability-intent — config validation (fail closed)", () => {
  it("denies when capabilities is missing/empty", () => {
    expect(
      evaluateCapabilityIntent(rule({ effect: "allow" }), makeContext({ capability: cap() }))
        .passed,
    ).toBe(false);
    expect(
      evaluateCapabilityIntent(
        rule({ capabilities: [], effect: "allow" }),
        makeContext({ capability: cap() }),
      ).passed,
    ).toBe(false);
  });

  it("denies an unknown effect", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "maybe" }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("effect");
  });

  it("denies a non-integer maxCallsPerHour", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow", constraints: { maxCallsPerHour: 1.5 } }),
      makeContext({ capability: cap(), capabilityInvokeCount1h: 0 }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("maxCallsPerHour");
  });

  it("denies non-string-record argEquals", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow", constraints: { argEquals: { k: 3 } } }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("argEquals");
  });

  it("config validation happens BEFORE effect, but AFTER the absent-capability short-circuit", () => {
    // absent capability => pass regardless of a bad config (inert on tx signs).
    const r = evaluateCapabilityIntent(rule({ effect: "banana" }), makeContext());
    expect(r.passed).toBe(true);
    expect(r.reason).toBe("not a capability invoke");
  });
});

describe("capability-intent — registry integration (end-to-end via evaluatePolicy)", () => {
  function coreRule(type: string, config: Record<string, unknown> = {}, id = "r1"): PolicyRule {
    return { id, type: type as PolicyRule["type"], enabled: true, config };
  }

  it("registers under its type and runs through the default arm with ctx.capability set", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });

    const allowed = await evaluatePolicy(
      coreRule(CAPABILITY_INTENT_RULE_TYPE, { capabilities: ["github.*"], effect: "allow" }),
      makeContext({ capability: cap() }),
    );
    expect(allowed.passed).toBe(true);
    expect(allowed.type).toBe(CAPABILITY_INTENT_RULE_TYPE);

    const denied = await evaluatePolicy(
      coreRule(CAPABILITY_INTENT_RULE_TYPE, { capabilities: ["github.*"], effect: "deny" }),
      makeContext({ capability: cap() }),
    );
    expect(denied.passed).toBe(false);
  });

  it("require-approval signal SURVIVES the registry passthrough", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const result = await evaluatePolicy(
      coreRule(CAPABILITY_INTENT_RULE_TYPE, {
        capabilities: ["github.pr.delete"],
        effect: "require-approval",
      }),
      makeContext({ capability: cap({ name: "github.pr.delete" }) }),
    );
    expect(result.passed).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("does NOT forward requiresManualApproval on a passing result", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const result = await evaluatePolicy(
      coreRule(CAPABILITY_INTENT_RULE_TYPE, { capabilities: ["github.*"], effect: "allow" }),
      makeContext({ capability: cap() }),
    );
    expect(result.passed).toBe(true);
    expect(result.requiresManualApproval).toBeUndefined();
  });

  it("inert on an ordinary tx sign (no ctx.capability) through the engine", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const result = await evaluatePolicy(
      coreRule(CAPABILITY_INTENT_RULE_TYPE, { capabilities: ["github.*"], effect: "deny" }),
      makeContext(), // a normal transaction sign, no capability channel
    );
    expect(result.passed).toBe(true);
  });
});

describe("capability-intent — PolicyEngine.evaluate seam (capability ctx must flow through)", () => {
  function capRule(config: Record<string, unknown>, id = "cr1"): PolicyRule {
    return { id, type: CAPABILITY_INTENT_RULE_TYPE as PolicyRule["type"], enabled: true, config };
  }
  function engineCtx(overrides: Partial<EvaluatorContext> = {}) {
    return {
      request: {
        agentId: "a",
        tenantId: "t",
        to: "0x1234567890123456789012345678901234567890",
        value: "0",
        chainId: 8453,
      } as SignRequest,
      recentTxCount24h: 0,
      recentTxCount1h: 0,
      spentToday: 0n,
      spentThisWeek: 0n,
      ...overrides,
    };
  }

  it("a deny rule ENFORCES through PolicyEngine.evaluate when capability ctx is present", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const engine = new PolicyEngine();
    const result = await engine.evaluate(
      [capRule({ capabilities: ["github.*"], effect: "deny" })],
      engineCtx({ capability: cap({ name: "github.pr.delete" }) }),
    );
    // if the engine dropped ctx.capability, this would be approved:true (inert pass).
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(false);
  });

  it("require-approval routes to manual approval through the engine", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const engine = new PolicyEngine();
    const result = await engine.evaluate(
      [capRule({ capabilities: ["github.*"], effect: "require-approval" })],
      engineCtx({ capability: cap() }),
    );
    expect(result.approved).toBe(false);
    expect(result.requiresManualApproval).toBe(true);
  });

  it("maxCallsPerHour reads capabilityInvokeCount1h through the engine seam", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const engine = new PolicyEngine();
    const over = await engine.evaluate(
      [
        capRule({
          capabilities: ["github.*"],
          effect: "allow",
          constraints: { maxCallsPerHour: 2 },
        }),
      ],
      engineCtx({ capability: cap(), capabilityInvokeCount1h: 2 }),
    );
    expect(over.approved).toBe(false);
    const under = await engine.evaluate(
      [
        capRule({
          capabilities: ["github.*"],
          effect: "allow",
          constraints: { maxCallsPerHour: 2 },
        }),
      ],
      engineCtx({ capability: cap(), capabilityInvokeCount1h: 1 }),
    );
    expect(under.approved).toBe(true);
  });

  it("stays inert on an ordinary tx sign through the engine (no capability ctx)", async () => {
    policyRuleRegistry.register({
      type: capabilityIntentContribution.type,
      pluginName: "capability-plugin",
      evaluate: capabilityIntentContribution.evaluate,
    });
    const engine = new PolicyEngine();
    const result = await engine.evaluate(
      [capRule({ capabilities: ["github.*"], effect: "deny" })],
      engineCtx(), // no capability channel
    );
    // rule is inert (passes); with only this rule, all hard policies pass => approved.
    expect(result.approved).toBe(true);
  });
});

describe("capability-intent — multi-rule composition (all-must-pass)", () => {
  // The engine composes rules with all-must-pass; the invoke layer (W-1c) adds
  // the effective default-deny. These assertions model that composition at the
  // rule level: a deny match fails; an allow match that passes constraints
  // passes; a non-match is inert.
  it("a deny rule fails even alongside an allow rule for the same capability", () => {
    const allow = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow" }),
      makeContext({ capability: cap() }),
    );
    const deny = evaluateCapabilityIntent(
      rule({ capabilities: ["github.pr.comment"], effect: "deny" }),
      makeContext({ capability: cap() }),
    );
    expect(allow.passed).toBe(true);
    expect(deny.passed).toBe(false);
    // all-must-pass => the composite is a deny.
    expect(allow.passed && deny.passed).toBe(false);
  });

  it("rules that don't match are inert (pass) and don't block a matching allow", () => {
    const other = evaluateCapabilityIntent(
      rule({ capabilities: ["gitlab.*"], effect: "deny" }),
      makeContext({ capability: cap() }),
    );
    const allow = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow" }),
      makeContext({ capability: cap() }),
    );
    expect(other.passed).toBe(true);
    expect(allow.passed).toBe(true);
    expect(other.passed && allow.passed).toBe(true);
  });
});
