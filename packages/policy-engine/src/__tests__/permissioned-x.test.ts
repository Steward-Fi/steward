/**
 * Permissioned-X policy vocabulary — unit coverage over the SAME composer the
 * provider-action service calls (`composeProviderActionPolicyDecision`) plus the
 * standalone `evaluateXConstraints`.
 *
 * Covers every Phase-1 policy dimension positive + negative, the
 * escalate-to-approval path, the summoned-reply upstream-403 modeled as a policy
 * denial class, spend-cap accumulation, quiet hours (incl. midnight wrap), and
 * the fail-closed matrix from docs/security/permissioned-x.mdx. Each guard is
 * mutation-provable (see scripts/x-permissioned-mutation-proofs.sh, which weakens
 * a guard and watches the matching `deny`/`escalate` assertion flip).
 *
 * The composer is the authority-plane enforcement surface; asserting effects
 * here proves the vocabulary is load-bearing independent of the DB E2E.
 */

import { describe, expect, it } from "bun:test";
import {
  composeProviderActionPolicyDecision,
  estimateXPostMicros,
  evaluateXConstraints,
  type ProviderPolicyContext,
  type ProviderPolicyRule,
  PROVIDER_POLICY_REASON as R,
  X_POST_PRICE_TABLE_V1,
  type XConstraints,
} from "../capability-intent.js";

const OP_TWEET = "x.tweet.create";

/** A tweet.create policy context with sensible defaults; override per test. */
function ctx(
  args: Record<string, unknown> = {},
  extra: Partial<ProviderPolicyContext> = {},
): ProviderPolicyContext {
  const builtArgs = {
    isReply: false,
    hasUrl: false,
    summoned: false,
    textCodePointLength: 5,
    textByteLength: 5,
    ...args,
  };
  const { x: extraX, ...rest } = extra;
  return {
    operationKey: OP_TWEET,
    args: builtArgs,
    method: "POST",
    host: "api.x.com",
    path: "/2/tweets",
    invokeCount1h: 0,
    x: {
      ...(typeof builtArgs.isReply === "boolean" ? { isReply: builtArgs.isReply } : {}),
      ...(typeof builtArgs.hasUrl === "boolean" ? { hasUrl: builtArgs.hasUrl } : {}),
      ...(typeof builtArgs.summoned === "boolean" ? { summoned: builtArgs.summoned } : {}),
      ...(typeof builtArgs.textCodePointLength === "number"
        ? { textCodePointLength: builtArgs.textCodePointLength }
        : {}),
      ...extraX,
    },
    ...rest,
  };
}

/** An allow rule carrying an X constraint sub-block. */
function allowX(x: XConstraints, id = "r-x-1"): ProviderPolicyRule {
  return {
    id,
    type: "capability-intent",
    enabled: true,
    config: { capabilities: [OP_TWEET], effect: "allow", constraints: { x } },
  };
}

/** Compose a single allow+X rule and return the effect + reason codes. */
function decide(x: XConstraints, c: ProviderPolicyContext) {
  return composeProviderActionPolicyDecision([allowX(x)], c);
}

// ─── price table ──────────────────────────────────────────────────────────────

describe("permissioned-X: price table", () => {
  it("plain post is 15000 micros ($0.015), url post 200000 ($0.20)", () => {
    expect(X_POST_PRICE_TABLE_V1.plainMicros).toBe(15_000);
    expect(X_POST_PRICE_TABLE_V1.urlMicros).toBe(200_000);
    expect(estimateXPostMicros(false)).toBe(15_000);
    expect(estimateXPostMicros(true)).toBe(200_000);
  });
});

// ─── replyPolicy ────────────────────────────────────────────────────────────

describe("permissioned-X: replyPolicy", () => {
  it("mode=none denies a reply, allows an original", () => {
    const x: XConstraints = { replyPolicy: { mode: "none" } };
    expect(decide(x, ctx({ isReply: true })).effect).toBe("hard_deny");
    expect(decide(x, ctx({ isReply: true })).reasonCodes).toContain(R.X_REPLY_FORBIDDEN);
    expect(decide(x, ctx({ isReply: false })).effect).toBe("allow");
  });

  it("mode=summoned-only denies an un-summoned reply (upstream-403 class)", () => {
    const x: XConstraints = { replyPolicy: { mode: "summoned-only" } };
    const denied = decide(x, ctx({ isReply: true, summoned: false }));
    expect(denied.effect).toBe("hard_deny");
    expect(denied.reasonCodes).toContain(R.X_REPLY_NOT_SUMMONED);
  });

  it("mode=summoned-only allows a summoned reply", () => {
    const x: XConstraints = { replyPolicy: { mode: "summoned-only" } };
    expect(decide(x, ctx({ isReply: true, summoned: true })).effect).toBe("allow");
  });

  it("mode=any allows a reply (operator accepts upstream risk)", () => {
    const x: XConstraints = { replyPolicy: { mode: "any" } };
    expect(decide(x, ctx({ isReply: true, summoned: false })).effect).toBe("allow");
  });

  it("replyPolicy is inert on an original post", () => {
    const x: XConstraints = { replyPolicy: { mode: "none" } };
    expect(decide(x, ctx({ isReply: false })).effect).toBe("allow");
  });
});

// ─── contentPolicy ──────────────────────────────────────────────────────────

describe("permissioned-X: contentPolicy", () => {
  it("allowUrls=false denies a URL post (also the $0.20 spend class)", () => {
    const x: XConstraints = { contentPolicy: { allowUrls: false } };
    const d = decide(x, ctx({ hasUrl: true }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.X_URL_FORBIDDEN);
    expect(decide(x, ctx({ hasUrl: false })).effect).toBe("allow");
  });

  it("maxLength denies an over-length post", () => {
    const x: XConstraints = { contentPolicy: { maxLength: 10 } };
    expect(decide(x, ctx({ textCodePointLength: 11 })).reasonCodes).toContain(R.X_CONTENT_TOO_LONG);
    expect(decide(x, ctx({ textCodePointLength: 10 })).effect).toBe("allow");
  });

  it("maxLength fails closed when length signal absent", () => {
    const x: XConstraints = { contentPolicy: { maxLength: 10 } };
    const c = ctx();
    // strip the length signal
    delete (c.x as { textCodePointLength?: number }).textCodePointLength;
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("typed ctx.x signals win over contradictory caller args (SEC-182)", () => {
    const noUrls: XConstraints = { contentPolicy: { allowUrls: false } };
    // args (caller-influenced) claims a URL; the adapter-derived typed channel
    // says there is none — the typed channel is authoritative.
    expect(decide(noUrls, ctx({ hasUrl: true }, { x: { hasUrl: false } })).effect).toBe("allow");
    // and the reverse: typed hasUrl=true denies even when args claims none.
    const d = decide(noUrls, ctx({ hasUrl: false }, { x: { hasUrl: true } }));
    expect(d.reasonCodes).toContain(R.X_URL_FORBIDDEN);

    // same preference for the length signal
    const maxLen: XConstraints = { contentPolicy: { maxLength: 10 } };
    expect(decide(maxLen, ctx({}, { x: { textCodePointLength: 5 } })).effect).toBe("allow");
    expect(decide(maxLen, ctx({}, { x: { textCodePointLength: 11 } })).reasonCodes).toContain(
      R.X_CONTENT_TOO_LONG,
    );
  });

  it("does not fall back to caller args when a typed signal is missing (SEC-182)", () => {
    const x: XConstraints = { replyPolicy: { mode: "summoned-only" } };
    const c = ctx({ isReply: true, summoned: true });
    delete (c.x as { summoned?: boolean }).summoned;
    const decision = decide(x, c);
    expect(decision.effect).toBe("hard_deny");
    expect(decision.reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("blockedPatterns denies a matching text via the in-memory policyText channel", () => {
    // Patterns are standard JS RegExp source (no inline (?i) flag). Author
    // case-insensitivity into the pattern itself.
    const x: XConstraints = {
      contentPolicy: { blockedPatterns: ["[Aa][Ii][Rr][Dd][Rr][Oo][Pp]"] },
    };
    const c = ctx({}, { policyText: "free AIRDROP now" });
    expect(decide(x, c).reasonCodes).toContain(R.X_CONTENT_BLOCKED);
    const clean = ctx({}, { policyText: "gm friends" });
    expect(decide(x, clean).effect).toBe("allow");
  });

  it("blockedPatterns fails closed when policyText is absent", () => {
    const x: XConstraints = { contentPolicy: { blockedPatterns: ["spam"] } };
    // no policyText on ctx
    expect(decide(x, ctx()).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("invalid blockedPatterns regex fails closed (config invalid, never throws)", () => {
    const x: XConstraints = { contentPolicy: { blockedPatterns: ["([unterminated"] } };
    // NB: an invalid regex is caught at parse-time too; assert composition denies.
    const rule: ProviderPolicyRule = {
      id: "r-bad-regex",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [OP_TWEET],
        effect: "allow",
        constraints: { x },
      },
    };
    const d = composeProviderActionPolicyDecision([rule], ctx({}, { policyText: "anything" }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.CONFIGURATION_INVALID);
  });

  it("over-long blockedPatterns fail closed as a config error (SEC-107 ReDoS bound)", () => {
    const rule: ProviderPolicyRule = {
      id: "r-long-regex",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [OP_TWEET],
        effect: "allow",
        constraints: { x: { contentPolicy: { blockedPatterns: [`(a+)+${".".repeat(300)}`] } } },
      },
    };
    const d = composeProviderActionPolicyDecision([rule], ctx({}, { policyText: "anything" }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.CONFIGURATION_INVALID);
  });

  it("over-long policyText fails closed instead of being scanned (SEC-107 ReDoS bound)", () => {
    const x: XConstraints = { contentPolicy: { blockedPatterns: ["spam"] } };
    const c = ctx({}, { policyText: `gm ${"x".repeat(9000)}` });
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });
});

// ─── maxPostsPerWindow ──────────────────────────────────────────────────────

describe("permissioned-X: maxPostsPerWindow", () => {
  const x: XConstraints = { maxPostsPerWindow: { max: 3, windowSeconds: 3600 } };

  it("denies when the window count is at/over the cap", () => {
    const d = decide(x, ctx({}, { x: { postsInWindow: 3 } }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.X_RATE_CAP_EXCEEDED);
  });

  it("allows under the cap", () => {
    expect(decide(x, ctx({}, { x: { postsInWindow: 2 } })).effect).toBe("allow");
  });

  it("fails closed when the count input is unavailable", () => {
    expect(decide(x, ctx()).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });
});

// ─── spendPolicy + accumulation ─────────────────────────────────────────────

describe("permissioned-X: spendPolicy (estimated-spend cap)", () => {
  it("denies when accumulated + this action exceeds the cap (URL post)", () => {
    // cap 250000; already spent 100000; url post adds 200000 => 300000 > cap
    const x: XConstraints = { spendPolicy: { maxSpendMicros: 250_000 } };
    const d = decide(
      x,
      ctx({ hasUrl: true }, { x: { accumulatedSpendMicros: 100_000, hasUrl: true } }),
    );
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.X_SPEND_CAP_EXCEEDED);
  });

  it("allows when accumulated + this action is within the cap (plain post)", () => {
    const x: XConstraints = { spendPolicy: { maxSpendMicros: 250_000 } };
    // 100000 + 15000 = 115000 <= 250000
    expect(
      decide(x, ctx({ hasUrl: false }, { x: { accumulatedSpendMicros: 100_000, hasUrl: false } }))
        .effect,
    ).toBe("allow");
  });

  it("accumulation crosses the cap across two plain posts", () => {
    const x: XConstraints = { spendPolicy: { maxSpendMicros: 20_000 } };
    // first plain post: accumulated 0 + 15000 = 15000 <= 20000 => allow
    expect(decide(x, ctx({}, { x: { accumulatedSpendMicros: 0, hasUrl: false } })).effect).toBe(
      "allow",
    );
    // second plain post: accumulated 15000 + 15000 = 30000 > 20000 => deny
    expect(
      decide(x, ctx({}, { x: { accumulatedSpendMicros: 15_000, hasUrl: false } })).effect,
    ).toBe("hard_deny");
  });

  it("fails closed when the accumulated-spend input is unavailable", () => {
    const x: XConstraints = { spendPolicy: { maxSpendMicros: 250_000 } };
    expect(decide(x, ctx({ hasUrl: true })).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });
});

// ─── quietHours ─────────────────────────────────────────────────────────────

describe("permissioned-X: quietHours", () => {
  it("denies inside a non-wrapping window", () => {
    const x: XConstraints = { quietHours: { startMinuteUtc: 540, endMinuteUtc: 600 } }; // 9:00-10:00
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 570 } })).reasonCodes).toContain(R.X_QUIET_HOURS);
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 600 } })).effect).toBe("allow"); // end exclusive
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 539 } })).effect).toBe("allow");
  });

  it("denies inside a midnight-wrapping window (start>end)", () => {
    const x: XConstraints = { quietHours: { startMinuteUtc: 1380, endMinuteUtc: 360 } }; // 23:00-06:00
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 1410 } })).reasonCodes).toContain(
      R.X_QUIET_HOURS,
    ); // 23:30
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 120 } })).reasonCodes).toContain(R.X_QUIET_HOURS); // 02:00
    expect(decide(x, ctx({}, { x: { nowMinuteUtc: 720 } })).effect).toBe("allow"); // noon
  });

  it("fails closed when the now-minute input is unavailable", () => {
    const x: XConstraints = { quietHours: { startMinuteUtc: 0, endMinuteUtc: 60 } };
    expect(decide(x, ctx()).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });
});

// ─── escalation (allow -> approval_required) ────────────────────────────────

describe("permissioned-X: escalation", () => {
  it("urlPostRequiresApproval escalates a URL post to approval", () => {
    const x: XConstraints = {
      contentPolicy: { allowUrls: true },
      escalation: { urlPostRequiresApproval: true },
    };
    expect(decide(x, ctx({ hasUrl: true })).effect).toBe("approval_required");
    // a plain post under the same rule just allows
    expect(decide(x, ctx({ hasUrl: false })).effect).toBe("allow");
  });

  it("spendOverMicros escalates a spend over the soft threshold to approval", () => {
    const x: XConstraints = {
      escalation: { spendOverMicrosRequiresApproval: 100_000 },
    };
    // url post: 200000 > 100000 => escalate
    expect(
      decide(x, ctx({ hasUrl: true }, { x: { accumulatedSpendMicros: 0, hasUrl: true } })).effect,
    ).toBe("approval_required");
    // plain post: 15000 <= 100000 => allow
    expect(
      decide(x, ctx({ hasUrl: false }, { x: { accumulatedSpendMicros: 0, hasUrl: false } })).effect,
    ).toBe("allow");
  });

  it("a hard deny is NEVER softened into an approval by escalation", () => {
    // allowUrls=false hard-denies a URL post even though escalation would escalate.
    const x: XConstraints = {
      contentPolicy: { allowUrls: false },
      escalation: { urlPostRequiresApproval: true },
    };
    const d = decide(x, ctx({ hasUrl: true }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.X_URL_FORBIDDEN);
  });
});

// ─── x-block scoping + fail-closed ──────────────────────────────────────────

describe("permissioned-X: scoping + fail-closed", () => {
  it("an x block on a NON-x operation is a config error (hard_deny)", () => {
    const rule: ProviderPolicyRule = {
      id: "r-nonx",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: ["github.pr.comment.create"],
        effect: "allow",
        constraints: { x: { replyPolicy: { mode: "none" } } },
      },
    };
    const ghCtx: ProviderPolicyContext = {
      operationKey: "github.pr.comment.create",
      args: { isReply: true },
      method: "POST",
      host: "api.github.com",
      path: "/x",
      invokeCount1h: 0,
    };
    const d = composeProviderActionPolicyDecision([rule], ghCtx);
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.CONFIGURATION_INVALID);
  });

  it("unknown x sub-key fails closed at parse (config invalid)", () => {
    const rule: ProviderPolicyRule = {
      id: "r-typo",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [OP_TWEET],
        effect: "allow",
        // @ts-expect-error deliberate typo to prove fail-closed
        constraints: { x: { replyPolicyy: { mode: "none" } } },
      },
    };
    const d = composeProviderActionPolicyDecision([rule], ctx({ isReply: true }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.CONFIGURATION_INVALID);
  });

  it("evaluateXConstraints returns pass when no X block present", () => {
    expect(evaluateXConstraints(undefined, ctx()).kind).toBe("pass");
  });

  // codex P2: a required boolean signal that is ABSENT/non-boolean must fail
  // closed (POLICY_INPUT_UNAVAILABLE), NOT coerce to false and silently pass.
  it("allowUrls=false fails closed when the hasUrl signal is absent", () => {
    const x: XConstraints = { contentPolicy: { allowUrls: false } };
    const c = ctx();
    delete (c.x as { hasUrl?: boolean }).hasUrl;
    const d = decide(x, c);
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("allowUrls=false fails closed when hasUrl is a non-boolean", () => {
    const x: XConstraints = { contentPolicy: { allowUrls: false } };
    const c = ctx({ hasUrl: "true" as unknown as boolean });
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("replyPolicy fails closed when the isReply signal is absent", () => {
    const x: XConstraints = { replyPolicy: { mode: "none" } };
    const c = ctx();
    delete (c.x as { isReply?: boolean }).isReply;
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("summoned-only fails closed when the summoned signal is absent on a reply", () => {
    const x: XConstraints = { replyPolicy: { mode: "summoned-only" } };
    const c = ctx({ isReply: true });
    delete (c.x as { summoned?: boolean }).summoned;
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("url escalation fails closed when hasUrl is absent", () => {
    const x: XConstraints = { escalation: { urlPostRequiresApproval: true } };
    const c = ctx();
    delete (c.x as { hasUrl?: boolean }).hasUrl;
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("spendPolicy fails closed when hasUrl is absent (cannot price the action)", () => {
    const x: XConstraints = { spendPolicy: { maxSpendMicros: 1_000_000 } };
    const c = ctx({}, { x: { accumulatedSpendMicros: 0 } });
    delete (c.x as { hasUrl?: boolean }).hasUrl;
    expect(decide(x, c).reasonCodes).toContain(R.INPUT_UNAVAILABLE);
  });

  it("evaluateXConstraints denies an x block on a non-x op directly", () => {
    const v = evaluateXConstraints(
      { replyPolicy: { mode: "none" } },
      { ...ctx(), operationKey: "github.pr.comment.create" },
    );
    expect(v.kind).toBe("deny");
  });
});

// ─── deny precedence: X deny wins over a co-matching allow ───────────────────

describe("permissioned-X: composition precedence with X constraints", () => {
  it("an X hard-deny wins over a separate plain allow rule", () => {
    const plainAllow: ProviderPolicyRule = {
      id: "r-plain",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [OP_TWEET], effect: "allow" },
    };
    const urlDeny = allowX({ contentPolicy: { allowUrls: false } }, "r-urldeny");
    const d = composeProviderActionPolicyDecision([plainAllow, urlDeny], ctx({ hasUrl: true }));
    expect(d.effect).toBe("hard_deny");
    expect(d.reasonCodes).toContain(R.X_URL_FORBIDDEN);
  });

  it("an X escalation + a plain allow => approval (approval outranks allow)", () => {
    const plainAllow: ProviderPolicyRule = {
      id: "r-plain",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [OP_TWEET], effect: "allow" },
    };
    const escalate = allowX(
      { contentPolicy: { allowUrls: true }, escalation: { urlPostRequiresApproval: true } },
      "r-esc",
    );
    const d = composeProviderActionPolicyDecision([plainAllow, escalate], ctx({ hasUrl: true }));
    expect(d.effect).toBe("approval_required");
  });
});
