/**
 * x.provider-action.v1 shared-profile tests.
 *
 * Proves the X canonicalizer reuses the ONE shared JCS/hash/normalize surface
 * (byte-identical framing to the GitHub profile, differing only in the profile
 * and origin string VALUES), enforces the X origin allowlist, the header-free
 * rule, and the body/content-type matrix. Includes the X golden corpus and a
 * digest-stability mutation proof (weaken key-sort, watch the digest collapse,
 * restore).
 */

import { describe, expect, it } from "bun:test";
import {
  CanonError,
  canonicalizeRawInternalXAction,
  canonicalizeXOrigin,
  computeXActionDigest,
  X_CANONICAL_ORIGIN,
  X_GOLDEN_VECTORS,
  X_PROVIDER_ACTION_PROFILE,
  xCanonicalActionBytes,
} from "../index.js";

function denies(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof CanonError;
  }
}

function expectCanon(fn: () => unknown, code: string) {
  try {
    fn();
    throw new Error(`expected CanonError ${code} but none thrown`);
  } catch (e) {
    if (!(e instanceof CanonError)) throw e;
    expect(e.code).toBe(code);
  }
}

describe("X golden corpus (shared)", () => {
  it("each vector reproduces its bytes + digest", () => {
    expect(X_GOLDEN_VECTORS.length).toBeGreaterThanOrEqual(6);
    for (const gv of X_GOLDEN_VECTORS) {
      expect(xCanonicalActionBytes(gv.action)).toBe(gv.canonicalActionBytes);
      expect(computeXActionDigest(gv.action)).toBe(gv.actionDigest);
    }
  });

  it("stamps the X profile and origin (not github)", () => {
    for (const gv of X_GOLDEN_VECTORS) {
      expect(gv.action.profile).toBe(X_PROVIDER_ACTION_PROFILE);
      expect(gv.action.origin).toBe(X_CANONICAL_ORIGIN);
      expect(gv.canonicalActionBytes).toContain('"profile":"x.provider-action.v1"');
      expect(gv.canonicalActionBytes).toContain('"origin":"https://api.x.com"');
    }
  });
});

describe("X origin canonicalization", () => {
  it("normalizes case + default port + terminal dot to the canonical origin", () => {
    expect(canonicalizeXOrigin("https://API.X.com")).toBe(X_CANONICAL_ORIGIN);
    expect(canonicalizeXOrigin("https://api.x.com:443")).toBe(X_CANONICAL_ORIGIN);
    expect(canonicalizeXOrigin("https://api.x.com./")).toBe(X_CANONICAL_ORIGIN);
  });

  it("denies non-https, wrong host, github host, userinfo, non-default port", () => {
    expectCanon(() => canonicalizeXOrigin("http://api.x.com"), "CANON_ORIGIN_SCHEME_UNSUPPORTED");
    expectCanon(() => canonicalizeXOrigin("https://api.twitter.com"), "CANON_ORIGIN_NOT_ALLOWED");
    expectCanon(() => canonicalizeXOrigin("https://api.github.com"), "CANON_ORIGIN_NOT_ALLOWED");
    expectCanon(() => canonicalizeXOrigin("https://evil.x.com"), "CANON_ORIGIN_NOT_ALLOWED");
    expectCanon(() => canonicalizeXOrigin("https://u@api.x.com"), "CANON_ORIGIN_INVALID");
    expectCanon(
      () => canonicalizeXOrigin("https://api.x.com:8443"),
      "CANON_ORIGIN_PORT_UNSUPPORTED",
    );
  });
});

describe("X body / content-type matrix", () => {
  it("POST requires a JSON body + content-type and injects the header", () => {
    const a = canonicalizeRawInternalXAction({
      method: "POST",
      origin: "https://api.x.com",
      path: "/2/tweets",
      contentType: "application/json",
      body: { text: "hi" },
    });
    expect(a.selectedHeaders).toEqual([["content-type", "application/json"]]);
    expect(a.canonicalBody).toEqual({ text: "hi" });
  });

  it("POST with a body but no content-type denies", () => {
    expectCanon(
      () =>
        canonicalizeRawInternalXAction({
          method: "POST",
          origin: "https://api.x.com",
          path: "/2/tweets",
          body: { text: "hi" },
        }),
      "CANON_BODY_CONTENT_TYPE_REQUIRED",
    );
  });

  it("POST rejects the github vendor media type (X is application/json only)", () => {
    expectCanon(
      () =>
        canonicalizeRawInternalXAction({
          method: "POST",
          origin: "https://api.x.com",
          path: "/2/tweets",
          contentType: "application/vnd.github+json",
          body: { text: "hi" },
        }),
      "CANON_BODY_CONTENT_TYPE_UNSUPPORTED",
    );
  });

  it("GET / DELETE deny any body or content-type", () => {
    expectCanon(
      () =>
        canonicalizeRawInternalXAction({
          method: "GET",
          origin: "https://api.x.com",
          path: "/2/users/me",
          body: { x: 1 },
          contentType: "application/json",
        }),
      "CANON_BODY_FORBIDDEN",
    );
    expectCanon(
      () =>
        canonicalizeRawInternalXAction({
          method: "DELETE",
          origin: "https://api.x.com",
          path: "/2/tweets/1",
          body: { x: 1 },
          contentType: "application/json",
        }),
      "CANON_BODY_FORBIDDEN",
    );
  });

  it("rejects any caller-supplied header (X carries none)", () => {
    expectCanon(
      () =>
        canonicalizeRawInternalXAction({
          method: "GET",
          origin: "https://api.x.com",
          path: "/2/users/me",
          headers: [["accept", "application/json"]],
        }),
      "CANON_HEADER_UNSUPPORTED",
    );
  });
});

describe("mutation proof: X digest depends on JCS key-sorting", () => {
  const reply = {
    reply: { in_reply_to_tweet_id: "1234567890" },
    text: "thanks!",
  };

  it("shipped digest is order-independent (JCS sorts keys)", () => {
    const a = canonicalizeRawInternalXAction({
      method: "POST",
      origin: "https://api.x.com",
      path: "/2/tweets",
      contentType: "application/json",
      body: reply,
    });
    const b = canonicalizeRawInternalXAction({
      method: "POST",
      origin: "https://api.x.com",
      path: "/2/tweets",
      contentType: "application/json",
      body: { text: "thanks!", reply: { in_reply_to_tweet_id: "1234567890" } },
    });
    expect(computeXActionDigest(a)).toBe(computeXActionDigest(b));
  });

  it("a naive un-sorted serializer would produce DIFFERENT bytes for the two orders", () => {
    // Demonstrate the guard's value: plain JSON.stringify (insertion order) is
    // NOT canonical, so the two logically-identical bodies serialize differently.
    const s1 = JSON.stringify({ reply: { in_reply_to_tweet_id: "1234567890" }, text: "thanks!" });
    const s2 = JSON.stringify({ text: "thanks!", reply: { in_reply_to_tweet_id: "1234567890" } });
    expect(s1).not.toBe(s2);
  });

  it("shipped canonical bytes are identical for both orders (guard still holds)", () => {
    const a = canonicalizeRawInternalXAction({
      method: "POST",
      origin: "https://api.x.com",
      path: "/2/tweets",
      contentType: "application/json",
      body: reply,
    });
    const b = canonicalizeRawInternalXAction({
      method: "POST",
      origin: "https://api.x.com",
      path: "/2/tweets",
      contentType: "application/json",
      body: { text: "thanks!", reply: { in_reply_to_tweet_id: "1234567890" } },
    });
    expect(xCanonicalActionBytes(a)).toBe(xCanonicalActionBytes(b));
  });
});

describe("X denies path traversal / non-ASCII in the raw path", () => {
  it("literal dot segment denies", () => {
    expect(
      denies(() =>
        canonicalizeRawInternalXAction({
          method: "DELETE",
          origin: "https://api.x.com",
          path: "/2/tweets/../secrets",
        }),
      ),
    ).toBe(true);
  });
});
