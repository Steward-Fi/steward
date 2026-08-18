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

  it("enforces Google recipient-domain array allowlists element by element", () => {
    const operationKey = "google.gmail.send";
    const domainRule: ProviderPolicyRule = {
      id: "google-domain-allowlist",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [operationKey],
        effect: "allow",
        constraints: {
          argArraySubset: { toDomainSet: ["example.com", "partner.test"] },
        },
      },
    };
    const googleContext = (toDomainSet: unknown): ProviderPolicyContext => ({
      ...ctx,
      operationKey,
      args: { toDomainSet },
      host: "gmail.googleapis.com",
      path: "/gmail/v1/users/me/messages/send",
    });

    expect(
      composeProviderActionPolicyDecision([domainRule], googleContext(["example.com"])).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([domainRule], googleContext(["attacker.test"])).effect,
    ).toBe("hard_deny");
    expect(
      composeProviderActionPolicyDecision(
        [domainRule],
        googleContext(["example.com", "attacker.test"]),
      ).effect,
    ).toBe("hard_deny");
  });

  it("fails closed when an array-subset arg is absent, scalar, empty, or mixed-type", () => {
    const operationKey = "google.gmail.send";
    const domainRule: ProviderPolicyRule = {
      id: "google-domain-allowlist",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [operationKey],
        effect: "allow",
        constraints: { argArraySubset: { toDomainSet: ["example.com"] } },
      },
    };
    for (const args of [
      {},
      { toDomainSet: "example.com" },
      { toDomainSet: [] },
      { toDomainSet: ["example.com", 7] },
    ]) {
      expect(
        composeProviderActionPolicyDecision([domainRule], { ...ctx, operationKey, args }).effect,
      ).toBe("hard_deny");
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

  it("malformed rule provably scoped to a DIFFERENT operation stays inert (SEC-181)", () => {
    // Same malformed-config semantics as the legacy-plane composer: a broken
    // rule must not brick operations it does not govern.
    const scopedElsewhere: ProviderPolicyRule = {
      id: "bad-elsewhere",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: ["x.tweet.create"], effect: "allow", bogusKey: 1 },
    };
    const d = composeProviderActionPolicyDecision([scopedElsewhere, rule("a", "allow")], ctx);
    expect(d.effect).toBe("allow");
  });

  it("malformed rule with an unrecoverable selector still hard-denies (SEC-181)", () => {
    const ambiguous: ProviderPolicyRule = {
      id: "bad-ambiguous",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: "not-an-array", effect: "allow" },
    };
    const d = composeProviderActionPolicyDecision([ambiguous, rule("a", "allow")], ctx);
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
    expect(
      composeProviderActionPolicyDecision([capRule], { ...ctx, invokeCount1h: 5 }).effect,
    ).toBe("hard_deny");
    expect(
      composeProviderActionPolicyDecision([capRule], { ...ctx, invokeCount1h: 4 }).effect,
    ).toBe("allow");
  });

  it("enforces IANA business hours from the server-supplied instant", () => {
    const businessHours = rule("hours", "allow", {
      constraints: {
        timeWindow: {
          timezone: "America/Los_Angeles",
          allow: [{ days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" }],
        },
      },
    });
    expect(
      composeProviderActionPolicyDecision([businessHours], {
        ...ctx,
        evaluatedAt: "2026-08-17T19:00:00.000Z", // Monday noon PDT
      }).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([businessHours], {
        ...ctx,
        evaluatedAt: "2026-08-17T23:59:00.000Z", // Monday 16:59 PDT
      }).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([businessHours], {
        ...ctx,
        evaluatedAt: "2026-08-18T00:00:00.000Z", // Monday 17:00 PDT, exclusive
      }).effect,
    ).toBe("hard_deny");
  });

  it("handles overnight windows against the opening weekday", () => {
    const overnight = rule("overnight", "allow", {
      constraints: {
        timeWindow: {
          timezone: "America/Los_Angeles",
          allow: [{ days: ["mon"], from: "22:00", to: "02:00" }],
        },
      },
    });
    expect(
      composeProviderActionPolicyDecision([overnight], {
        ...ctx,
        evaluatedAt: "2026-08-18T08:00:00.000Z", // Tuesday 01:00 PDT
      }).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([overnight], {
        ...ctx,
        evaluatedAt: "2026-08-18T09:00:00.000Z", // Tuesday 02:00 PDT
      }).effect,
    ).toBe("hard_deny");
  });

  it("is deterministic across DST gaps and repeated local times", () => {
    const dstWindow = rule("dst", "allow", {
      constraints: {
        timeWindow: {
          timezone: "America/New_York",
          allow: [{ days: ["sun"], from: "01:00", to: "03:00" }],
        },
      },
    });
    // Spring-forward: 01:30 exists; the next sampled instant is 03:30 and denied.
    expect(
      composeProviderActionPolicyDecision([dstWindow], {
        ...ctx,
        evaluatedAt: "2026-03-08T06:30:00.000Z",
      }).effect,
    ).toBe("allow");
    expect(
      composeProviderActionPolicyDecision([dstWindow], {
        ...ctx,
        evaluatedAt: "2026-03-08T07:30:00.000Z",
      }).effect,
    ).toBe("hard_deny");
    // Fall-back: both distinct instants mapping to 01:30 are treated alike.
    for (const evaluatedAt of ["2026-11-01T05:30:00.000Z", "2026-11-01T06:30:00.000Z"]) {
      expect(composeProviderActionPolicyDecision([dstWindow], { ...ctx, evaluatedAt }).effect).toBe(
        "allow",
      );
    }
  });

  it("fails closed on absent time, invalid timezone, unknown keys, and empty windows", () => {
    const valid = rule("hours", "allow", {
      constraints: {
        timeWindow: {
          timezone: "UTC",
          allow: [{ days: ["mon"], from: "09:00", to: "17:00" }],
        },
      },
    });
    const missing = composeProviderActionPolicyDecision([valid], {
      ...ctx,
      evaluatedAt: undefined,
    });
    expect(missing.effect).toBe("hard_deny");
    expect(missing.reasonCodes).toContain(PROVIDER_POLICY_REASON.INPUT_UNAVAILABLE);

    for (const timeWindow of [
      { timezone: "Not/A_Zone", allow: [{ days: ["mon"], from: "09:00", to: "17:00" }] },
      // ECMA-402 accepts ISO offset identifiers in some runtimes, but the
      // Steward schema deliberately requires an IANA time-zone identifier.
      { timezone: "+01:00", allow: [{ days: ["mon"], from: "09:00", to: "17:00" }] },
      { timezone: "UTC", allow: [] },
      { timezone: "UTC", allow: [{ days: ["MON"], from: "09:00", to: "17:00" }] },
      { timezone: "UTC", allow: [{ days: ["mon"], from: "09:00", to: "09:00" }] },
      { timezone: "UTC", allow: [{ days: ["mon"], from: "09:00", to: "17:00", extra: true }] },
    ]) {
      const malformed = rule("bad-hours", "allow", { constraints: { timeWindow } });
      const decision = composeProviderActionPolicyDecision([malformed], {
        ...ctx,
        evaluatedAt: "2026-08-17T12:00:00.000Z",
      });
      expect(decision.effect).toBe("hard_deny");
      expect(decision.reasonCodes).toContain(PROVIDER_POLICY_REASON.CONFIGURATION_INVALID);
    }
  });
});
