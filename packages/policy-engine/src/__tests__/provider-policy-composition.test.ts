/**
 * composeProviderActionPolicyDecision precedence + effectiveness.
 *
 * The key property (Conflict 9 fix): a passing allow must NEVER suppress a
 * simultaneous approval requirement, and any hard deny wins over both. Proven
 * across 100 rule-order shuffles so the composition can't be order-dependent.
 */

import { describe, expect, it } from "bun:test";
import {
  composeProviderActionPolicyDecision,
  PROVIDER_POLICY_REASON,
  type ProviderPolicyContext,
  type ProviderPolicyRule,
} from "../capability-intent.js";

const OP = "github.pr.comment.create";

const ctx: ProviderPolicyContext = {
  operationKey: OP,
  args: { owner: "octo", repo: "hello", pullNumber: 42, body: "hi" },
  method: "POST",
  host: "api.github.com",
  path: "/repos/octo/hello/issues/42/comments",
  invokeCount1h: 0,
};

function rule(
  id: string,
  effect: "allow" | "deny" | "require-approval",
  extra: Partial<ProviderPolicyRule["config"]> = {},
): ProviderPolicyRule {
  return {
    id,
    type: "capability-intent",
    enabled: true,
    config: { capabilities: [OP], effect, ...extra },
  };
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

describe("composeProviderActionPolicyDecision precedence", () => {
  it("empty governing rules => hard_deny / no governing allow", () => {
    const d = composeProviderActionPolicyDecision([], ctx);
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.NO_GOVERNING_ALLOW);
  });

  it("single passing allow => allow", () => {
    expect(composeProviderActionPolicyDecision([rule("r1", "allow")], ctx).effect).toBe("allow");
  });

  it("single require-approval => approval_required", () => {
    expect(composeProviderActionPolicyDecision([rule("r1", "require-approval")], ctx).effect).toBe(
      "approval_required",
    );
  });

  it("single deny => hard_deny", () => {
    expect(composeProviderActionPolicyDecision([rule("r1", "deny")], ctx).effect).toBe("hard_deny");
  });

  it("allow + approval => approval_required (THE Conflict-9 fix)", () => {
    const rules = [rule("allow1", "allow"), rule("appr1", "require-approval")];
    for (let i = 0; i < 100; i++) {
      const d = composeProviderActionPolicyDecision(shuffle(rules), ctx);
      expect(d.effect).toBe("approval_required");
    }
  });

  it("deny + approval => hard_deny under all orders", () => {
    const rules = [rule("deny1", "deny"), rule("appr1", "require-approval")];
    for (let i = 0; i < 100; i++) {
      expect(composeProviderActionPolicyDecision(shuffle(rules), ctx).effect).toBe("hard_deny");
    }
  });

  it("deny + allow => hard_deny", () => {
    const rules = [rule("deny1", "deny"), rule("allow1", "allow")];
    for (let i = 0; i < 100; i++) {
      expect(composeProviderActionPolicyDecision(shuffle(rules), ctx).effect).toBe("hard_deny");
    }
  });

  it("failed hard constraint + approval => hard_deny (constraint not negotiable)", () => {
    const rules = [
      rule("allow1", "allow", { constraints: { argEquals: { owner: "someone-else" } } }),
      rule("appr1", "require-approval"),
    ];
    for (let i = 0; i < 100; i++) {
      expect(composeProviderActionPolicyDecision(shuffle(rules), ctx).effect).toBe("hard_deny");
    }
  });

  it("malformed config => hard_deny / configuration invalid", () => {
    const bad: ProviderPolicyRule = {
      id: "bad",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [OP], effect: "allow", bogusKey: 1 },
    };
    const d = composeProviderActionPolicyDecision([bad], ctx);
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.CONFIGURATION_INVALID);
  });

  it("unknown rule type => hard_deny", () => {
    const foreign: ProviderPolicyRule = {
      id: "x",
      type: "not-a-capability-intent",
      enabled: true,
      config: {},
    };
    expect(composeProviderActionPolicyDecision([foreign], ctx).effect).toBe("hard_deny");
  });

  it("disabled rules are ignored", () => {
    const disabledDeny: ProviderPolicyRule = { ...rule("d", "deny"), enabled: false };
    const d = composeProviderActionPolicyDecision([disabledDeny, rule("a", "allow")], ctx);
    expect(d.effect).toBe("allow");
  });

  it("non-governing rule (different capability) is not applicable", () => {
    const other = rule("o", "deny");
    (other.config as { capabilities: string[] }).capabilities = ["github.issue.list"];
    const d = composeProviderActionPolicyDecision([other, rule("a", "allow")], ctx);
    expect(d.effect).toBe("allow");
  });

  it("rate cap with unavailable count => input unavailable => hard_deny", () => {
    const capRule = rule("c", "allow", { constraints: { maxCallsPerHour: 5 } });
    const d = composeProviderActionPolicyDecision([capRule], { ...ctx, invokeCount1h: undefined });
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);
  });

  it("rate cap reached => hard_deny; under cap => allow", () => {
    const capRule = rule("c", "allow", { constraints: { maxCallsPerHour: 5 } });
    expect(composeProviderActionPolicyDecision([capRule], { ...ctx, invokeCount1h: 5 }).effect).toBe(
      "hard_deny",
    );
    expect(composeProviderActionPolicyDecision([capRule], { ...ctx, invokeCount1h: 4 }).effect).toBe(
      "allow",
    );
  });
});
