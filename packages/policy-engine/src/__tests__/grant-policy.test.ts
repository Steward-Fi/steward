/**
 * grant-policy.test.ts — bidirectional coverage for the per-grant policy module
 * (C1): every rule must BLOCK what it should AND ALLOW what it should, malformed
 * policy must fail closed at parse, and every verdict must name the rule that
 * fired (the audit contract).
 */

import { describe, expect, test } from "bun:test";
import {
  evaluateGrantPolicy,
  GRANT_POLICY_VERSION,
  type GrantPolicyInput,
  type GrantPolicyV1,
  grantPolicySignals,
  LEGACY_DEFAULT_GRANT_POLICY,
  MAX_AGGREGATE_WINDOW_SECONDS,
  noPolicyVerdict,
  parseGrantPolicy,
} from "../index";

const CAP = {
  name: "github.pr.comment",
  host: "api.github.com",
  path: "/repos/acme/app/issues/1/comments",
  method: "POST",
};

function input(overrides: Partial<GrantPolicyInput> = {}): GrantPolicyInput {
  return {
    now: new Date("2026-07-30T12:00:00Z"),
    capability: CAP,
    args: {},
    ...overrides,
  };
}

function policy(overrides: Partial<GrantPolicyV1> = {}): GrantPolicyV1 {
  return { version: GRANT_POLICY_VERSION, class: "plain-secret", ...overrides };
}

// ─── parse: fail-closed ──────────────────────────────────────────────────────

describe("parseGrantPolicy (fail-closed)", () => {
  test("accepts the explicit permissive default", () => {
    const r = parseGrantPolicy({ version: 1, class: "plain-secret" });
    expect(r.ok).toBe(true);
  });

  test("accepts the frozen LEGACY_DEFAULT_GRANT_POLICY constant", () => {
    const r = parseGrantPolicy(LEGACY_DEFAULT_GRANT_POLICY);
    expect(r.ok).toBe(true);
  });

  test.each([
    ["non-object", "nope"],
    ["null", null],
    ["array", [1]],
    ["missing version", { class: "plain-secret" }],
    ["wrong version", { version: 2, class: "plain-secret" }],
    ["missing class", { version: 1 }],
    ["bad class", { version: 1, class: "root" }],
    ["unknown top-level key", { version: 1, class: "plain-secret", raet: {} }],
  ])("rejects %s", (_label, raw) => {
    const r = parseGrantPolicy(raw);
    expect(r.ok).toBe(false);
  });

  test("value-bearing WITHOUT an amount block is a config error", () => {
    const r = parseGrantPolicy({ version: 1, class: "value-bearing" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("requires an `amount` block");
  });

  test("value-bearing WITH an amount bound parses", () => {
    const r = parseGrantPolicy({
      version: 1,
      class: "value-bearing",
      amount: { argField: "amountMicros", perInvokeMaxMicros: 5_000_000 },
    });
    expect(r.ok).toBe(true);
  });

  test.each([
    ["rate missing maxInvokes", { rate: { windowSeconds: 60 } }],
    ["rate zero maxInvokes", { rate: { maxInvokes: 0, windowSeconds: 60 } }],
    ["rate float maxInvokes", { rate: { maxInvokes: 1.5, windowSeconds: 60 } }],
    ["rate zero window", { rate: { maxInvokes: 5, windowSeconds: 0 } }],
    [
      "rate over-retention window (silent under-enforcement)",
      { rate: { maxInvokes: 5, windowSeconds: MAX_AGGREGATE_WINDOW_SECONDS + 1 } },
    ],
    ["rate unknown key", { rate: { maxInvokes: 5, windowSeconds: 60, burst: 2 } }],
    ["amount empty (no bound)", { amount: { argField: "v" } }],
    ["amount missing argField", { amount: { perInvokeMaxMicros: 1 } }],
    ["amount float cap", { amount: { argField: "v", perInvokeMaxMicros: 1.5 } }],
    ["amount negative cap", { amount: { argField: "v", perInvokeMaxMicros: -1 } }],
    [
      "amount window missing maxMicros",
      { amount: { argField: "v", window: { windowSeconds: 60 } } },
    ],
    [
      "amount window over retention",
      {
        amount: {
          argField: "v",
          window: { maxMicros: 10, windowSeconds: MAX_AGGREGATE_WINDOW_SECONDS + 1 },
        },
      },
    ],
    ["venue empty object", { venue: {} }],
    ["venue empty hosts array", { venue: { hosts: [] } }],
    ["venue non-string host", { venue: { hosts: [3] } }],
    ["venue path prefix without leading slash", { venue: { pathPrefixes: ["repos"] } }],
    ["venue unknown key", { venue: { hosts: ["a.com"], ports: [443] } }],
    ["time empty object", { time: {} }],
    ["time bad notBefore", { time: { notBefore: "not-a-date" } }],
    [
      "time notBefore >= notAfter",
      { time: { notBefore: "2026-02-01T00:00:00Z", notAfter: "2026-01-01T00:00:00Z" } },
    ],
    [
      "time window start === end (ambiguous)",
      { time: { allowedWindowUtc: { startMinuteUtc: 100, endMinuteUtc: 100 } } },
    ],
    [
      "time window minute out of range",
      { time: { allowedWindowUtc: { startMinuteUtc: 0, endMinuteUtc: 1440 } } },
    ],
    ["approval non-boolean always", { approval: { always: "yes" } }],
    ["approval unknown key", { approval: { quorum: 2 } }],
  ])("rejects %s", (_label, partial) => {
    const r = parseGrantPolicy({ version: 1, class: "plain-secret", ...partial });
    expect(r.ok).toBe(false);
  });

  test("normalizes venue hosts to lowercase and methods to uppercase", () => {
    const r = parseGrantPolicy({
      version: 1,
      class: "plain-secret",
      venue: { hosts: ["API.GitHub.com"], methods: ["post"] },
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.policy.venue?.hosts).toEqual(["api.github.com"]);
      expect(r.policy.venue?.methods).toEqual(["POST"]);
    }
  });

  test("never throws on hostile config (throwing getters)", () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys: () => {
          throw new Error("boom");
        },
        get: () => {
          throw new Error("boom");
        },
      },
    );
    // a throw inside parse would escape as an exception; assert it does not.
    let r: ReturnType<typeof parseGrantPolicy>;
    try {
      r = parseGrantPolicy(hostile);
    } catch {
      // acceptable ONLY if the invoke layer catches it — but our contract is
      // stronger: parse must not throw. Fail the test.
      throw new Error("parseGrantPolicy threw on hostile input");
    }
    expect(r.ok).toBe(false);
  });
});

// ─── signals ─────────────────────────────────────────────────────────────────

describe("grantPolicySignals", () => {
  test("names exactly the windows the policy needs", () => {
    const p = policy({
      rate: { maxInvokes: 5, windowSeconds: 300 },
      amount: { argField: "v", window: { maxMicros: 100, windowSeconds: 86400 } },
      class: "value-bearing",
    });
    expect(grantPolicySignals(p)).toEqual({
      rateWindowSeconds: 300,
      amountWindowSeconds: 86400,
    });
  });

  test("empty for the permissive default", () => {
    expect(grantPolicySignals(LEGACY_DEFAULT_GRANT_POLICY)).toEqual({
      rateWindowSeconds: undefined,
      amountWindowSeconds: undefined,
    });
  });
});

// ─── evaluate: each rule blocks AND allows ───────────────────────────────────

describe("evaluateGrantPolicy — rate", () => {
  const p = policy({ rate: { maxInvokes: 3, windowSeconds: 600 } });

  test("allows under the cap", () => {
    const v = evaluateGrantPolicy(p, input({ invokesInWindow: 2 }));
    expect(v.effect).toBe("allow");
    expect(v.rule).toBe("allow");
  });

  test("denies at the cap, naming the rule", () => {
    const v = evaluateGrantPolicy(p, input({ invokesInWindow: 3 }));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("rate.limit");
  });

  test("denies when the count signal is missing (fail closed)", () => {
    const v = evaluateGrantPolicy(p, input({}));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("rate.signal-missing");
  });
});

describe("evaluateGrantPolicy — amount", () => {
  const p = policy({
    class: "value-bearing",
    amount: {
      argField: "amountMicros",
      perInvokeMaxMicros: 10_000_000,
      window: { maxMicros: 25_000_000, windowSeconds: 86400 },
      approvalOverMicros: 5_000_000,
    },
  });

  test("allows a small amount under every bound, carrying amountMicros", () => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: { amountMicros: 1_000_000 }, allowedAmountMicrosInWindow: 0 }),
    );
    expect(v.effect).toBe("allow");
    expect(v.amountMicros).toBe(1_000_000);
  });

  test("routes over-threshold (but under hard cap) to approval", () => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: { amountMicros: 6_000_000 }, allowedAmountMicrosInWindow: 0 }),
    );
    expect(v.effect).toBe("approval_required");
    expect(v.rule).toBe("amount.approvalOver");
    expect(v.amountMicros).toBe(6_000_000);
  });

  test("denies over the per-invoke hard cap (never softened to approval)", () => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: { amountMicros: 10_000_001 }, allowedAmountMicrosInWindow: 0 }),
    );
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("amount.perInvokeMax");
  });

  test("denies when the rolling window would be exceeded", () => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: { amountMicros: 2_000_000 }, allowedAmountMicrosInWindow: 24_000_000 }),
    );
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("amount.windowMax");
  });

  test("allows exactly at the rolling window boundary", () => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: { amountMicros: 1_000_000 }, allowedAmountMicrosInWindow: 24_000_000 }),
    );
    // 24M + 1M = 25M, not > 25M => within cap. 1M is under approval threshold.
    expect(v.effect).toBe("allow");
  });

  test("denies when the window sum signal is missing (fail closed)", () => {
    const v = evaluateGrantPolicy(p, input({ args: { amountMicros: 1_000_000 } }));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("amount.signal-missing");
  });

  test.each([
    ["missing arg", {}],
    ["string arg", { amountMicros: "100" }],
    ["float arg", { amountMicros: 1.5 }],
    ["negative arg", { amountMicros: -1 }],
    ["NaN arg", { amountMicros: Number.NaN }],
    ["unsafe integer arg", { amountMicros: Number.MAX_SAFE_INTEGER + 2 }],
  ])("denies an unreadable amount arg: %s", (_label, args) => {
    const v = evaluateGrantPolicy(
      p,
      input({ args: args as Record<string, unknown>, allowedAmountMicrosInWindow: 0 }),
    );
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("amount.arg");
  });
});

describe("evaluateGrantPolicy — venue", () => {
  test("host allowlist blocks a non-matching host and allows a matching one", () => {
    const p = policy({ venue: { hosts: ["api.github.com"] } });
    expect(evaluateGrantPolicy(p, input()).effect).toBe("allow");
    const v = evaluateGrantPolicy(p, input({ capability: { ...CAP, host: "api.evil.com" } }));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("venue.host");
  });

  test("wildcard host entry matches subdomains but never the bare apex", () => {
    const p = policy({ venue: { hosts: ["*.github.com"] } });
    expect(
      evaluateGrantPolicy(p, input({ capability: { ...CAP, host: "api.github.com" } })).effect,
    ).toBe("allow");
    expect(
      evaluateGrantPolicy(p, input({ capability: { ...CAP, host: "github.com" } })).effect,
    ).toBe("deny");
    expect(
      evaluateGrantPolicy(p, input({ capability: { ...CAP, host: "evilgithub.com" } })).effect,
    ).toBe("deny");
  });

  test("method allowlist blocks and allows", () => {
    const p = policy({ venue: { methods: ["GET", "POST"] } });
    expect(evaluateGrantPolicy(p, input()).effect).toBe("allow");
    const v = evaluateGrantPolicy(p, input({ capability: { ...CAP, method: "DELETE" } }));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("venue.method");
  });

  test("path prefix matches on segment boundaries only", () => {
    const p = policy({ venue: { pathPrefixes: ["/repos/acme"] } });
    expect(evaluateGrantPolicy(p, input()).effect).toBe("allow");
    // /repos/acmeX must NOT match the /repos/acme prefix.
    const v = evaluateGrantPolicy(
      p,
      input({ capability: { ...CAP, path: "/repos/acmeX/issues" } }),
    );
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("venue.path");
  });
});

describe("evaluateGrantPolicy — time", () => {
  test("notBefore blocks early use and allows after", () => {
    const p = policy({ time: { notBefore: "2026-07-30T13:00:00Z" } });
    const early = evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T12:59:59Z") }));
    expect(early.effect).toBe("deny");
    expect(early.rule).toBe("time.notBefore");
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T13:00:00Z") })).effect).toBe(
      "allow",
    );
  });

  test("notAfter allows before and blocks after", () => {
    const p = policy({ time: { notAfter: "2026-07-30T13:00:00Z" } });
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T12:00:00Z") })).effect).toBe(
      "allow",
    );
    const late = evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T13:00:01Z") }));
    expect(late.effect).toBe("deny");
    expect(late.rule).toBe("time.notAfter");
  });

  test("minute-of-day window blocks outside and allows inside", () => {
    // allowed 09:00-17:00 UTC.
    const p = policy({ time: { allowedWindowUtc: { startMinuteUtc: 540, endMinuteUtc: 1020 } } });
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T12:00:00Z") })).effect).toBe(
      "allow",
    );
    const night = evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T03:00:00Z") }));
    expect(night.effect).toBe("deny");
    expect(night.rule).toBe("time.window");
  });

  test("wrapped window spans midnight", () => {
    // allowed 22:00-02:00 UTC.
    const p = policy({ time: { allowedWindowUtc: { startMinuteUtc: 1320, endMinuteUtc: 120 } } });
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T23:30:00Z") })).effect).toBe(
      "allow",
    );
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T01:30:00Z") })).effect).toBe(
      "allow",
    );
    expect(evaluateGrantPolicy(p, input({ now: new Date("2026-07-30T12:00:00Z") })).effect).toBe(
      "deny",
    );
  });
});

describe("evaluateGrantPolicy — approval + precedence", () => {
  test("approval.always routes every invoke to approval", () => {
    const p = policy({ approval: { always: true } });
    const v = evaluateGrantPolicy(p, input());
    expect(v.effect).toBe("approval_required");
    expect(v.rule).toBe("approval.always");
  });

  test("a hard deny is NEVER softened into an approval (deny-first)", () => {
    const p = policy({
      approval: { always: true },
      venue: { hosts: ["other.example.com"] },
    });
    const v = evaluateGrantPolicy(p, input());
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("venue.host");
  });

  test("rate exhaustion beats amount approval threshold", () => {
    const p = policy({
      class: "value-bearing",
      rate: { maxInvokes: 1, windowSeconds: 60 },
      amount: { argField: "amountMicros", approvalOverMicros: 0 },
    });
    const v = evaluateGrantPolicy(p, input({ invokesInWindow: 1, args: { amountMicros: 5 } }));
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("rate.limit");
  });

  test("the permissive default allows with the audit-visible allow rule", () => {
    const v = evaluateGrantPolicy(LEGACY_DEFAULT_GRANT_POLICY, input());
    expect(v.effect).toBe("allow");
    expect(v.rule).toBe("allow");
  });

  test("determinism: identical inputs produce identical verdicts", () => {
    const p = policy({ rate: { maxInvokes: 2, windowSeconds: 60 } });
    const a = evaluateGrantPolicy(p, input({ invokesInWindow: 1 }));
    const b = evaluateGrantPolicy(p, input({ invokesInWindow: 1 }));
    expect(a).toEqual(b);
  });
});

describe("noPolicyVerdict (strict-mode flag)", () => {
  test("strict mode denies a policy-less grant", () => {
    const v = noPolicyVerdict(true);
    expect(v.effect).toBe("deny");
    expect(v.rule).toBe("no-policy.strict");
  });

  test("compatibility mode allows with an explicit audited rule", () => {
    const v = noPolicyVerdict(false);
    expect(v.effect).toBe("allow");
    expect(v.rule).toBe("no-policy.permissive");
  });
});
