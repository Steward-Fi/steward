/**
 * X adapter operation-schema tests.
 *
 * Proves: strict argument validation (unknown/missing/typed/id-regex/length deny
 * with stable CANON_* codes), dynamic path segments are validated (not
 * concatenated raw), fixed query canonical order, canonical action construction
 * is deterministic and matches the shared X canonicalizer, safe_summary never
 * leaks full tweet text, and risk classes are correct. Re-runs the X golden
 * corpus as a REQUIRED consumer suite and includes a digest-stability
 * mutation proof.
 */

import { describe, expect, it } from "bun:test";
import {
  CanonError,
  computeXActionDigest,
  X_GOLDEN_VECTORS,
  type XCanonicalActionV1,
  xCanonicalActionBytes,
} from "@stwd/shared";
import { buildXAction, isXOperationKey, X_OPERATION_RISK } from "../operations.js";

function expectCanon(fn: () => unknown, code: string) {
  try {
    fn();
    throw new Error(`expected CanonError ${code} but none thrown`);
  } catch (e) {
    if (!(e instanceof CanonError)) throw e;
    expect(e.code).toBe(code);
  }
}

describe("X golden corpus re-run (adapter consumer suite)", () => {
  it("has vectors and each reproduces its bytes + digest", () => {
    expect(X_GOLDEN_VECTORS.length).toBeGreaterThanOrEqual(6);
    for (const gv of X_GOLDEN_VECTORS) {
      expect(xCanonicalActionBytes(gv.action)).toBe(gv.canonicalActionBytes);
      expect(computeXActionDigest(gv.action)).toBe(gv.actionDigest);
    }
  });

  it("adapter output equals the golden vectors byte-for-byte", () => {
    const byId = new Map(X_GOLDEN_VECTORS.map((gv) => [gv.id, gv]));
    const cases: Array<[string, Parameters<typeof buildXAction>[0], unknown]> = [
      ["XGV-01", "x.user.me.read", {}],
      ["XGV-02", "x.tweet.create", { text: "hello world" }],
      ["XGV-03", "x.tweet.create", { text: "thanks!", replyToTweetId: "1234567890" }],
      ["XGV-04", "x.tweet.create", { text: "café ☕ 日本" }],
      ["XGV-05", "x.tweet.create", { text: "  spaced out  " }],
      ["XGV-06", "x.tweet.delete", { tweetId: "9876543210987654321" }],
    ];
    for (const [id, key, args] of cases) {
      const gv = byId.get(id);
      if (!gv) throw new Error(`missing golden vector ${id}`);
      const b = buildXAction(key, args);
      expect(xCanonicalActionBytes(b.action)).toBe(gv.canonicalActionBytes);
      expect(computeXActionDigest(b.action)).toBe(gv.actionDigest);
    }
  });

  it("MUTATION: reordering canonicalBody keys does not change the digest (JCS sorts)", () => {
    // Build a reply action with keys deliberately transposed vs the builder's
    // insertion order; JCS must re-sort so the digest is stable.
    const base = buildXAction("x.tweet.create", {
      text: "thanks!",
      replyToTweetId: "1234567890",
    }).action;
    const mutated: XCanonicalActionV1 = {
      ...base,
      canonicalBody: { text: "thanks!", reply: { in_reply_to_tweet_id: "1234567890" } },
    };
    expect(computeXActionDigest(mutated)).toBe(computeXActionDigest(base));
  });

  it("MUTATION: changing a body value DOES change the digest (corpus is not vacuous)", () => {
    const base = buildXAction("x.tweet.create", { text: "hello world" }).action;
    const mutated: XCanonicalActionV1 = { ...base, canonicalBody: { text: "hello worlds" } };
    expect(computeXActionDigest(mutated)).not.toBe(computeXActionDigest(base));
  });
});

describe("x.tweet.create", () => {
  it("builds a deterministic POST action with JSON body + injected content-type", () => {
    const b = buildXAction("x.tweet.create", { text: "gm" });
    expect(b.method).toBe("POST");
    expect(b.risk).toBe("write");
    expect(b.action.normalizedPath).toBe("/2/tweets");
    expect(b.action.origin).toBe("https://api.x.com");
    expect(b.action.canonicalBody).toEqual({ text: "gm" });
    expect(b.action.selectedHeaders).toEqual([["content-type", "application/json"]]);
    expect(b.action.orderedQueryPairs).toEqual([]);
  });

  it("nests reply only when replyToTweetId present", () => {
    const noReply = buildXAction("x.tweet.create", { text: "standalone" });
    expect(noReply.action.canonicalBody).toEqual({ text: "standalone" });

    const reply = buildXAction("x.tweet.create", { text: "re", replyToTweetId: "42" });
    expect(reply.action.canonicalBody).toEqual({
      text: "re",
      reply: { in_reply_to_tweet_id: "42" },
    });
  });

  it("is order-insensitive at the argument level (deterministic digest)", () => {
    const a = buildXAction("x.tweet.create", { text: "x", replyToTweetId: "7" });
    const b = buildXAction("x.tweet.create", { replyToTweetId: "7", text: "x" });
    expect(computeXActionDigest(a.action)).toBe(computeXActionDigest(b.action));
  });

  it("trims surrounding whitespace before length check and in the body", () => {
    const b = buildXAction("x.tweet.create", { text: "   hi   " });
    expect(b.action.canonicalBody).toEqual({ text: "hi" });
  });

  it("counts length by code points: a 280-astral-char tweet passes, 281 fails", () => {
    const astral = "😀"; // one code point, two UTF-16 units
    const ok = astral.repeat(280);
    expect(() => buildXAction("x.tweet.create", { text: ok })).not.toThrow();
    const tooLong = astral.repeat(281);
    expectCanon(
      () => buildXAction("x.tweet.create", { text: tooLong }),
      "CANON_FIELD_TYPE_INVALID",
    );
  });

  it("safe_summary shows length + sha256 only, never any slice of the text", () => {
    const secret = "this is a secret tweet body that must not leak in full ".repeat(3).trim();
    const b = buildXAction("x.tweet.create", { text: secret });
    const s = JSON.stringify(b.safeSummary);
    expect(s).not.toContain(secret);
    expect(b.safeSummary.textByteLength).toBe(Buffer.from(secret, "utf8").length);
    expect(String(b.safeSummary.textSha256)).toMatch(/^sha256:[0-9a-f]{64}$/);
    // no preview field exists at all (codex P2 fix): summaries carry no text slice.
    expect("textPreview" in b.safeSummary).toBe(false);
  });

  it("safe_summary of a SHORT tweet does not leak the body (codex P2 regression)", () => {
    // A 2-char tweet must not appear verbatim anywhere in the summary.
    const b = buildXAction("x.tweet.create", { text: "gm" });
    const s = JSON.stringify(b.safeSummary);
    expect(s).not.toContain("gm");
    expect("textPreview" in b.safeSummary).toBe(false);
  });

  it("policy args are validated scalars only (no raw text, no raw body)", () => {
    const b = buildXAction("x.tweet.create", { text: "hello", replyToTweetId: "9" });
    expect(b.policyArgs).toEqual({
      isReply: true,
      hasUrl: false,
      summoned: false,
      textCodePointLength: 5,
      textByteLength: 5,
      replyToTweetId: "9",
    });
    // policyArgs is scalar/boolean only — NEVER the raw tweet text.
    expect(JSON.stringify(b.policyArgs)).not.toContain("hello");
    // The raw text lives ONLY on the separate, non-persisted policyText channel.
    expect(b.policyText).toBe("hello");
  });

  it("derives hasUrl (content + spend signal) and summoned policy args", () => {
    const plain = buildXAction("x.tweet.create", { text: "gm frens" });
    expect(plain.policyArgs.hasUrl).toBe(false);
    expect(plain.policyArgs.summoned).toBe(false);

    const withUrl = buildXAction("x.tweet.create", { text: "check https://example.com/x" });
    expect(withUrl.policyArgs.hasUrl).toBe(true);
    expect(withUrl.safeSummary.hasUrl).toBe(true);

    const bareHost = buildXAction("x.tweet.create", { text: "see example.com for more" });
    expect(bareHost.policyArgs.hasUrl).toBe(true);

    const bareWww = buildXAction("x.tweet.create", { text: "visit www.foo.io today" });
    expect(bareWww.policyArgs.hasUrl).toBe(true);

    // prose with a period must NOT be misread as a URL
    const prose = buildXAction("x.tweet.create", { text: "i.e. this is fine. really." });
    expect(prose.policyArgs.hasUrl).toBe(false);

    const summoned = buildXAction("x.tweet.create", {
      text: "thanks!",
      replyToTweetId: "9",
      summoned: true,
    });
    expect(summoned.policyArgs.summoned).toBe(true);
    expect(summoned.policyArgs.isReply).toBe(true);
  });

  it("rejects a non-boolean summoned arg (fail closed on type)", () => {
    expectCanon(
      () => buildXAction("x.tweet.create", { text: "hi", summoned: "yes" }),
      "CANON_FIELD_TYPE_INVALID",
    );
  });

  it("safe_summary carries hasUrl + summoned booleans but no text slice", () => {
    const b = buildXAction("x.tweet.create", { text: "launch https://waifu.fun now" });
    expect(b.safeSummary.hasUrl).toBe(true);
    expect(b.safeSummary.summoned).toBe(false);
    expect(JSON.stringify(b.safeSummary)).not.toContain("waifu");
    expect("policyText" in b.safeSummary).toBe(false);
  });

  it("rejects empty/whitespace-only, unknown fields, missing required, bad types", () => {
    expectCanon(() => buildXAction("x.tweet.create", { text: "" }), "CANON_BODY_REQUIRED");
    expectCanon(() => buildXAction("x.tweet.create", { text: "   " }), "CANON_BODY_REQUIRED");
    expectCanon(
      () => buildXAction("x.tweet.create", { text: "hi", nope: 1 }),
      "CANON_UNKNOWN_FIELD",
    );
    expectCanon(() => buildXAction("x.tweet.create", {}), "CANON_REQUIRED_FIELD_MISSING");
    expectCanon(() => buildXAction("x.tweet.create", { text: 5 }), "CANON_FIELD_TYPE_INVALID");
  });

  it("rejects a non-numeric or overlong replyToTweetId (id regex enforced)", () => {
    expectCanon(
      () => buildXAction("x.tweet.create", { text: "hi", replyToTweetId: "12a" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildXAction("x.tweet.create", { text: "hi", replyToTweetId: "1".repeat(26) }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildXAction("x.tweet.create", { text: "hi", replyToTweetId: 42 }),
      "CANON_FIELD_TYPE_INVALID",
    );
  });

  it("rejects a lone surrogate in text", () => {
    expectCanon(
      () => buildXAction("x.tweet.create", { text: `bad\uD800end` }),
      "CANON_UNICODE_INVALID",
    );
  });
});

describe("x.tweet.delete", () => {
  it("builds a deterministic DELETE with id path from validated value", () => {
    const b = buildXAction("x.tweet.delete", { tweetId: "1750000000000000000" });
    expect(b.method).toBe("DELETE");
    expect(b.risk).toBe("write");
    expect(b.action.normalizedPath).toBe("/2/tweets/1750000000000000000");
    expect(b.action.canonicalBody).toBeNull();
    expect(b.action.selectedHeaders).toEqual([]);
    expect(b.safeSummary).toEqual({ operation: "x.tweet.delete", tweetId: "1750000000000000000" });
    expect(b.policyArgs).toEqual({ tweetId: "1750000000000000000" });
  });

  it("rejects path-injection via tweetId (validated segment, not raw concat)", () => {
    expectCanon(
      () => buildXAction("x.tweet.delete", { tweetId: "1/../2" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildXAction("x.tweet.delete", { tweetId: "../evil" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildXAction("x.tweet.delete", { tweetId: "12%2F34" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildXAction("x.tweet.delete", { tweetId: "" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
  });

  it("rejects unknown fields, missing required, and non-string id", () => {
    expectCanon(
      () => buildXAction("x.tweet.delete", { tweetId: "1", extra: 1 }),
      "CANON_UNKNOWN_FIELD",
    );
    expectCanon(() => buildXAction("x.tweet.delete", {}), "CANON_REQUIRED_FIELD_MISSING");
    expectCanon(() => buildXAction("x.tweet.delete", { tweetId: 1 }), "CANON_FIELD_TYPE_INVALID");
  });
});

describe("x.user.me.read", () => {
  it("builds a deterministic GET with fixed canonical query and no body", () => {
    const b = buildXAction("x.user.me.read", {});
    expect(b.method).toBe("GET");
    expect(b.risk).toBe("read");
    expect(b.action.normalizedPath).toBe("/2/users/me");
    expect(b.action.orderedQueryPairs).toEqual([["user.fields", "id,name,username"]]);
    expect(b.action.canonicalBody).toBeNull();
    expect(b.action.selectedHeaders).toEqual([]);
  });

  it("accepts undefined args (no-arg op) but rejects any provided field", () => {
    expect(() => buildXAction("x.user.me.read", undefined)).not.toThrow();
    expectCanon(() => buildXAction("x.user.me.read", { foo: 1 }), "CANON_UNKNOWN_FIELD");
  });
});

describe("operation-key guard + risk map", () => {
  it("recognizes only the three workstream-B operations", () => {
    expect(isXOperationKey("x.tweet.create")).toBe(true);
    expect(isXOperationKey("x.tweet.delete")).toBe(true);
    expect(isXOperationKey("x.user.me.read")).toBe(true);
    expect(isXOperationKey("x.dm.send")).toBe(false);
    expect(isXOperationKey(42)).toBe(false);
  });

  it("classifies writes and reads correctly", () => {
    expect(X_OPERATION_RISK["x.tweet.create"]).toBe("write");
    expect(X_OPERATION_RISK["x.tweet.delete"]).toBe("write");
    expect(X_OPERATION_RISK["x.user.me.read"]).toBe("read");
  });
});
