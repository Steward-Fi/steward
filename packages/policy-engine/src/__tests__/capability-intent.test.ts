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
import { UNPRINTABLE_THROWN_VALUE } from "@stwd/shared";
import {
  CAPABILITY_INTENT_RULE_TYPE,
  capabilityIntentContribution,
  composeCapabilityIntentDecision,
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

  it("denies an over-long operator pattern (SEC-107 ReDoS bound)", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: `(a+)+${".".repeat(300)}` } } }),
      makeContext({ capability: cap({ args: { branch: "feat/x" } }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("must not exceed 256 chars");
  });

  it("denies an over-long agent-controlled arg value (SEC-107 ReDoS bound)", () => {
    const r = evaluateCapabilityIntent(
      rule({ ...base, constraints: { argMatches: { branch: "feat/.+" } } }),
      makeContext({ capability: cap({ args: { branch: `feat/${"x".repeat(9000)}` } }) }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("match input cap");
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

  it("denies a malformed glob pattern (* not in trailing .* position => fail closed)", () => {
    for (const bad of ["github.*.delete", "*.delete", "git*hub", "github.**", "*"]) {
      const r = evaluateCapabilityIntent(
        rule({ capabilities: [bad], effect: "deny" }),
        makeContext({ capability: cap({ name: "github.pr.delete" }) }),
      );
      expect(r.passed).toBe(false);
      expect(r.reason).toContain("unsupported glob");
    }
  });

  it("accepts the supported trailing .* glob and a bare exact name", () => {
    // sanity: valid patterns still parse (deny fires on match).
    expect(
      evaluateCapabilityIntent(
        rule({ capabilities: ["github.*"], effect: "deny" }),
        makeContext({ capability: cap({ name: "github.pr.delete" }) }),
      ).passed,
    ).toBe(false);
    expect(
      evaluateCapabilityIntent(
        rule({ capabilities: ["github.pr.comment"], effect: "deny" }),
        makeContext({ capability: cap({ name: "github.pr.comment" }) }),
      ).passed,
    ).toBe(false);
  });

  it("denies an unknown top-level config key (typo => fail closed)", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow", effects: "deny" }),
      makeContext({ capability: cap() }),
    );
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("unknown config key");
  });

  it("denies an unknown constraint key (misspelled maxCallPerHour => fail closed, not fail open)", () => {
    const r = evaluateCapabilityIntent(
      rule({ capabilities: ["github.*"], effect: "allow", constraints: { maxCallPerHour: 5 } }),
      makeContext({ capability: cap(), capabilityInvokeCount1h: 999 }),
    );
    // without the guard this would ALLOW (the typo'd cap silently dropped); with
    // it, the config is rejected and the action denied.
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("unknown constraint key");
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

describe("capability-intent — composeCapabilityIntentDecision (canonical precedence)", () => {
  // The canonical composition (master-plan §5.3 / PR2 spec §6.3):
  //   1. malformed/unknown rule config or unavailable input => hard_deny
  //   2. any matching hard deny (deny effect OR failed hard constraint) => hard_deny
  //   3. else any matching require-approval => approval_required
  //   4. else any matching passing allow => allow
  //   5. else (no governing passing allow) => hard_deny
  // These tests are the SINGLE SOURCE OF TRUTH for capability-intent precedence
  // and directly guard the "allow-over-approval" regression.

  const ctx = makeContext({ capability: cap() });

  it("REGRESSION: approval_required is NOT shadowed by a matching passing allow", () => {
    // This is the exact bug: allow + require-approval on the SAME capability.
    // The old invoke-layer logic let the passing allow short-circuit to ALLOW.
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("approval_required");
  });

  it("REGRESSION holds regardless of rule order (approval listed first)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("approval_required");
  });

  it("deny + allow => hard_deny (deny wins over allow)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
        rule({ capabilities: ["github.pr.comment"], effect: "deny" }, "deny-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("deny + approval => hard_deny (deny wins over approval, never softened)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
        rule({ capabilities: ["github.pr.comment"], effect: "deny" }, "deny-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("deny + approval + allow => hard_deny (deny is absolute)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
        rule({ capabilities: ["github.pr.comment"], effect: "deny" }, "deny-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("approval + allow => approval_required", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("approval_required");
  });

  it("multiple allows => allow", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-1"),
        rule({ capabilities: ["github.pr.comment"], effect: "allow" }, "allow-2"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("single matching allow => allow", () => {
    const d = composeCapabilityIntentDecision(
      [rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule")],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("malformed rule config present => hard_deny (even alongside a passing allow)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
        // unknown top-level key fails closed in parseConfig
        rule({ capabilities: ["github.*"], effect: "allow", bogus: true }, "malformed-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("malformed rule config => hard_deny, never softened into approval", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
        rule({ capabilities: ["github.*"], effect: "allow", bogus: true }, "malformed-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("failed hard constraint on an allow => hard_deny (counts as deny, not approval)", () => {
    // allow rule whose maxCallsPerHour is exceeded => the allow FAILS a hard
    // constraint. That is a hard deny and must win over a co-present approval.
    const overCtx = makeContext({ capability: cap(), capabilityInvokeCount1h: 5 });
    const d = composeCapabilityIntentDecision(
      [
        rule(
          { capabilities: ["github.*"], effect: "allow", constraints: { maxCallsPerHour: 2 } },
          "capped-allow",
        ),
        rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
      ],
      overCtx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("no matching rule (all non-governing) => hard_deny (effective default-deny)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["gitlab.*"], effect: "allow" }, "other-allow"),
        rule({ capabilities: ["bitbucket.*"], effect: "deny" }, "other-deny"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("empty rule set => hard_deny (no governing allow)", () => {
    const d = composeCapabilityIntentDecision([], ctx);
    expect(d.effect).toBe("hard_deny");
  });

  it("no ctx.capability => hard_deny (fail closed, not a capability invoke)", () => {
    const d = composeCapabilityIntentDecision(
      [rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule")],
      makeContext(),
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("precedence is stable under 100 shuffles of a deny+approval+allow set", () => {
    const base = [
      rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
      rule({ capabilities: ["github.pr.comment"], effect: "deny" }, "deny-rule"),
    ];
    for (let i = 0; i < 100; i++) {
      const shuffled = [...base];
      for (let j = shuffled.length - 1; j > 0; j--) {
        const k = Math.floor(Math.random() * (j + 1));
        [shuffled[j], shuffled[k]] = [shuffled[k], shuffled[j]];
      }
      expect(composeCapabilityIntentDecision(shuffled, ctx).effect).toBe("hard_deny");
    }
  });

  it("approval+allow precedence is stable under 100 shuffles (approval wins)", () => {
    const base = [
      rule({ capabilities: ["github.*"], effect: "allow" }, "allow-1"),
      rule({ capabilities: ["github.pr.comment"], effect: "allow" }, "allow-2"),
      rule({ capabilities: ["github.pr.comment"], effect: "require-approval" }, "approval-rule"),
    ];
    for (let i = 0; i < 100; i++) {
      const shuffled = [...base];
      for (let j = shuffled.length - 1; j > 0; j--) {
        const k = Math.floor(Math.random() * (j + 1));
        [shuffled[j], shuffled[k]] = [shuffled[k], shuffled[j]];
      }
      expect(composeCapabilityIntentDecision(shuffled, ctx).effect).toBe("approval_required");
    }
  });
});

describe("capability-intent — composeCapabilityIntentDecision (malformed rule cannot be dropped)", () => {
  const ctx = makeContext({ capability: cap() });

  it("a malformed rule with a misspelled `capabilities` key hard-denies even alongside a matching allow", () => {
    // The rule's `capabilities` is misspelled, so a naive governing-match filter
    // (Array.isArray(cfg.capabilities)) would treat it as non-governing and DROP
    // it, failing open. The composer parses every rule first and hard-denies.
    const d = composeCapabilityIntentDecision(
      [
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
        // @ts-expect-error intentionally malformed config for the fail-closed test
        {
          id: "typo",
          type: CAPABILITY_INTENT_RULE_TYPE,
          enabled: true,
          config: { capabilties: ["github.*"], effect: "deny" },
        },
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("parseConfig runs BEFORE capabilityMatches, so a malformed non-governing-looking rule still hard-denies", () => {
    const d = composeCapabilityIntentDecision(
      [
        // unsupported glob makes parseConfig fail (badPattern) even though it
        // "looks" like it governs github.* — must hard-deny, not be treated inert.
        rule({ capabilities: ["git*hub.pr"], effect: "deny" }, "bad-glob"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });
});

describe("capability-intent — composeCapabilityIntentDecision (disabled rules are inert)", () => {
  const ctx = makeContext({ capability: cap() });

  function disabled(config: Record<string, unknown>, id: string): ContributedPolicyRule {
    return { id, type: CAPABILITY_INTENT_RULE_TYPE, enabled: false, config };
  }

  it("a DISABLED deny rule does NOT block a matching enabled allow", () => {
    const d = composeCapabilityIntentDecision(
      [
        disabled({ capabilities: ["github.pr.comment"], effect: "deny" }, "disabled-deny"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("a DISABLED require-approval rule does NOT queue approval over an enabled allow", () => {
    const d = composeCapabilityIntentDecision(
      [
        disabled(
          { capabilities: ["github.pr.comment"], effect: "require-approval" },
          "disabled-approval",
        ),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("a DISABLED malformed rule does NOT fail the composition closed", () => {
    const d = composeCapabilityIntentDecision(
      [
        // @ts-expect-error intentionally malformed but DISABLED => must be inert
        {
          id: "disabled-bad",
          type: CAPABILITY_INTENT_RULE_TYPE,
          enabled: false,
          config: { capabilties: ["github.*"], effect: "deny" },
        },
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("only DISABLED rules present => default-deny (no enabled governing allow)", () => {
    const d = composeCapabilityIntentDecision(
      [disabled({ capabilities: ["github.*"], effect: "allow" }, "disabled-allow")],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("a rule with enabled:undefined is inert (falsy-enabled, matches the generic engine)", () => {
    // NIT alignment: the composer skips ANY falsy `enabled`, not only
    // `enabled === false`. An undefined-enabled deny must not block a valid allow.
    const d = composeCapabilityIntentDecision(
      [
        {
          id: "undef-enabled-deny",
          type: CAPABILITY_INTENT_RULE_TYPE,
          enabled: undefined,
          config: { capabilities: ["github.pr.comment"], effect: "deny" },
        } as unknown as ContributedPolicyRule,
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });
});

describe("capability-intent — malformed runtime input never throws (FINDING 1)", () => {
  // `rule.config` is opaque jsonb: at runtime it can be null / a scalar / an
  // array (untyped storage, bad migration, hand-edited row). The composer must
  // turn ANY such malformation into a fail-closed decision, NEVER a thrown
  // TypeError (which surfaces as an HTTP 500 instead of a deny).

  const ctx = makeContext({ capability: cap() });

  // Build a rule whose config bypasses the compile-time `Record<string,unknown>`
  // type so we can exercise the true runtime shapes (null / scalar / array).
  function rawRule(config: unknown, id: string): ContributedPolicyRule {
    return {
      id,
      type: CAPABILITY_INTENT_RULE_TYPE,
      enabled: true,
      config,
    } as ContributedPolicyRule;
  }

  it("evaluateCapabilityIntent: config null => deny (no throw)", () => {
    const r = evaluateCapabilityIntent(rawRule(null, "null-cfg"), ctx);
    expect(r.passed).toBe(false);
    expect(r.reason).toContain("config must be a non-null object");
  });

  it("composeCapabilityIntentDecision: config null => hard_deny (no throw), even beside a passing allow", () => {
    // The null-config rule has an unrecoverable selector => governing-ambiguous
    // => hard_deny. Critically: it must NOT throw a TypeError.
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision(
        [
          rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
          rawRule(null, "null-cfg"),
        ],
        ctx,
      );
    }).not.toThrow();
    expect(d?.effect).toBe("hard_deny");
  });

  for (const [label, badConfig] of [
    ["string", "not-an-object"],
    ["number", 42],
    ["boolean", true],
    ["array", ["github.*"]],
  ] as const) {
    it(`composeCapabilityIntentDecision: config ${label} => hard_deny (no throw)`, () => {
      let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
      expect(() => {
        d = composeCapabilityIntentDecision([rawRule(badConfig, `bad-${label}`)], ctx);
      }).not.toThrow();
      expect(d?.effect).toBe("hard_deny");
    });
  }

  it("composeCapabilityIntentDecision: an evaluator that THROWS => hard_deny (never approval, never 500)", () => {
    // Inject a throw at the evaluation seam. `constraints.argMatches` is applied
    // during evaluation; we make Object.entries hit a hostile getter for THIS
    // rule's constraints object, proving the composer's try/catch converts a
    // thrown evaluator error into a hard_deny.
    const hostile: Record<string, unknown> = {};
    Object.defineProperty(hostile, "boom", {
      enumerable: true,
      get() {
        throw new Error("injected evaluator failure");
      },
    });
    // A well-formed, GOVERNING allow rule whose argMatches constraint iteration
    // hits the hostile getter and throws inside evaluateConstraints.
    const throwingRule = rule(
      { capabilities: ["github.*"], effect: "allow", constraints: { argMatches: hostile } },
      "throwing-rule",
    );
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision([throwingRule], ctx);
    }).not.toThrow();
    expect(d?.effect).toBe("hard_deny");
    expect(d?.reason).toContain("evaluator error");
  });
});

describe("capability-intent — malformed-input precedence is SCOPED to governing rules (FINDING 2)", () => {
  // master-plan §5.3: malformed-input precedence applies to GOVERNING rules. A
  // malformed rule provably scoped to a DIFFERENT capability must not brick an
  // unrelated invoke; a malformed rule whose SELECTOR is unrecoverable fails
  // closed (its scope cannot be determined).

  const ctx = makeContext({ capability: cap() }); // requests github.pr.comment

  function rawRule(config: unknown, id: string): ContributedPolicyRule {
    return {
      id,
      type: CAPABILITY_INTENT_RULE_TYPE,
      enabled: true,
      config,
    } as ContributedPolicyRule;
  }

  it("malformed rule SCOPED ELSEWHERE (valid selector, other capability) + valid allow => ALLOW (inert, not bricked)", () => {
    // Selector `gitlab.*` is well-formed and provably does NOT govern
    // github.pr.comment, so the malformed remainder (bogus key) is irrelevant.
    const d = composeCapabilityIntentDecision(
      [
        rawRule(
          { capabilities: ["gitlab.*"], effect: "allow", bogus: true },
          "malformed-elsewhere",
        ),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("malformed rule scoped elsewhere with an unknown-constraint typo + valid allow => ALLOW (inert)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rawRule(
          { capabilities: ["gitlab.*"], effect: "allow", constraints: { maxCallPerHour: 2 } },
          "malformed-elsewhere-2",
        ),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("allow");
  });

  it("malformed rule with UNRECOVERABLE selector (misspelled capabilities key) + valid allow for another capability => HARD_DENY (fail closed on ambiguous scope)", () => {
    // The selector cannot be recovered (`capabilities` is missing), so we cannot
    // prove this rule is non-governing. Fail closed.
    const d = composeCapabilityIntentDecision(
      [
        rawRule({ capabilties: ["gitlab.*"], effect: "deny" }, "unrecoverable-selector"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("malformed rule with null config (unrecoverable selector) + valid allow => HARD_DENY (fail closed)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rawRule(null, "null-selector"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("malformed rule with an ILLEGAL glob selector (ambiguous scope) + valid allow => HARD_DENY (fail closed)", () => {
    // `git*hub.*` is an illegal glob: patternMatches would treat it as an exact
    // literal that can never match, so we cannot trust it to be non-governing.
    const d = composeCapabilityIntentDecision(
      [
        rawRule({ capabilities: ["git*hub.*"], effect: "deny", bogus: true }, "illegal-glob"),
        rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("malformed GOVERNING rule (valid selector matches THIS capability, malformed rest) => HARD_DENY (existing semantics preserved)", () => {
    const d = composeCapabilityIntentDecision(
      [
        rawRule(
          { capabilities: ["github.*"], effect: "allow", bogus: true },
          "malformed-governing",
        ),
        rule({ capabilities: ["github.pr.comment"], effect: "allow" }, "allow-rule"),
      ],
      ctx,
    );
    expect(d.effect).toBe("hard_deny");
  });

  it("scoping is order-independent: allow-first vs malformed-elsewhere-first both => ALLOW", () => {
    const malformedElsewhere = rawRule(
      { capabilities: ["gitlab.*"], effect: "deny", bogus: true },
      "malformed-elsewhere",
    );
    const validAllow = rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule");
    expect(composeCapabilityIntentDecision([validAllow, malformedElsewhere], ctx).effect).toBe(
      "allow",
    );
    expect(composeCapabilityIntentDecision([malformedElsewhere, validAllow], ctx).effect).toBe(
      "allow",
    );
  });
});

describe("capability-intent — composer catch is fail-closed against HOSTILE thrown values (P0)", () => {
  // ROUND-2 P0: the per-rule catch used to build its deny reason with
  //   `err instanceof Error ? err.message : String(err)`
  // A thrown value whose toString/valueOf/Symbol.toPrimitive (or a Proxy
  // `.message` getter) THROWS made that catch block ITSELF throw, unwinding past
  // the fail-closed `return { effect: "hard_deny" }` and escaping the composer as
  // a raw exception (=> HTTP 500 at the invoke boundary). These tests assert the
  // composer NEVER throws and ALWAYS hard-denies for a governing rule whose
  // evaluation throws an unprintable value.
  const ctx = makeContext({ capability: cap() });

  // A config that is a GOVERNING match for `github.pr.comment` (valid selector,
  // so it is not scoped-elsewhere / inert) but whose `constraints` access throws
  // `thrown` during parseConfig — reproducing an evaluator throw on the governing
  // rule. `capabilities` and `effect` are plain so recoverSelectorMatch succeeds.
  function governingConfigThatThrows(thrown: unknown): ContributedPolicyRule {
    const config: Record<string, unknown> = {
      capabilities: ["github.pr.comment"],
      effect: "allow",
    };
    Object.defineProperty(config, "constraints", {
      enumerable: true,
      configurable: true,
      get() {
        throw thrown;
      },
    });
    return { id: "hostile-throw", type: CAPABILITY_INTENT_RULE_TYPE, enabled: true, config };
  }

  it("thrown value with a throwing toString => hard_deny, NO exception (the exact probe)", () => {
    const hostile = {
      toString() {
        throw new Error("secondary stringify failure");
      },
    };
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision([governingConfigThatThrows(hostile)], ctx);
    }).not.toThrow();
    expect(d?.effect).toBe("hard_deny");
  });

  it("thrown value with throwing toString AND valueOf AND Symbol.toPrimitive => hard_deny, NO exception", () => {
    const hostile = {
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
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision([governingConfigThatThrows(hostile)], ctx);
    }).not.toThrow();
    expect(d?.effect).toBe("hard_deny");
    // Reason falls back to the static unprintable message (never leaks / throws).
    expect(d?.reason).toContain(UNPRINTABLE_THROWN_VALUE);
  });

  it("thrown Proxy(Error) whose `.message` getter throws => hard_deny, NO exception", () => {
    // instanceof Error is TRUE for this Proxy, so the old `.message` read would
    // have invoked the throwing get-trap and escaped.
    const hostile = new Proxy(new Error("real"), {
      get(_t, prop) {
        if (prop === "message") throw new Error("hostile message getter");
        // Also make string coercion hostile so we exercise the full fallback.
        if (prop === "toString" || prop === Symbol.toPrimitive || prop === "valueOf") {
          return () => {
            throw new Error("hostile coercion");
          };
        }
        return undefined;
      },
    });
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision([governingConfigThatThrows(hostile)], ctx);
    }).not.toThrow();
    expect(d?.effect).toBe("hard_deny");
    expect(d?.reason).toContain(UNPRINTABLE_THROWN_VALUE);
  });

  it("a hostile throw on a NON-governing (scoped-elsewhere) rule stays inert; sibling allow still wins", () => {
    // The hostile rule's selector is well-formed and scoped to gitlab.* (NOT this
    // capability), so the throw is on an inert rule and must not deny.
    const hostile = {
      toString() {
        throw new Error("boom");
      },
    };
    const elsewhereConfig: Record<string, unknown> = {
      capabilities: ["gitlab.*"],
      effect: "deny",
    };
    Object.defineProperty(elsewhereConfig, "constraints", {
      enumerable: true,
      configurable: true,
      get() {
        throw hostile;
      },
    });
    const hostileElsewhere: ContributedPolicyRule = {
      id: "hostile-elsewhere",
      type: CAPABILITY_INTENT_RULE_TYPE,
      enabled: true,
      config: elsewhereConfig,
    };
    const validAllow = rule({ capabilities: ["github.*"], effect: "allow" }, "allow-rule");
    let d: ReturnType<typeof composeCapabilityIntentDecision> | undefined;
    expect(() => {
      d = composeCapabilityIntentDecision([hostileElsewhere, validAllow], ctx);
    }).not.toThrow();
    expect(d?.effect).toBe("allow");
  });
});
