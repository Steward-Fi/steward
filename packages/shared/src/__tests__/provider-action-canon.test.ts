/**
 * Table-driven deny-class + JCS/Unicode/number + ordering-property coverage for
 * the canonicalization primitives. Complements the golden-vector suite.
 *
 * These exercise the ~70 malformed-input deny classes at the primitive level
 * (method/origin/path/query/header/content-type/number/JCS) and prove:
 *   - every semantic mutation changes the action digest;
 *   - normalization-only mutation does NOT change the digest;
 *   - query ordering is independent of input order (shuffle/property);
 *   - the strict JSON parser rejects duplicates at every depth and forbidden
 *     numbers where JSON.parse would silently accept.
 */

import { describe, expect, it } from "bun:test";
import {
  assertDecimalString,
  CanonError,
  type CanonErrorCode,
  canonicalizeContentType,
  canonicalizeHeaders,
  canonicalizeMethod,
  canonicalizeOrigin,
  canonicalizeQueryPairs,
  computeActionDigest,
  GITHUB_PROVIDER_ACTION_PROFILE,
  type GithubCanonicalActionV1,
  jcsStringify,
  normalizePath,
  parseRawQuery,
  parseStrictInteger,
  strictParseJson,
} from "../provider-action.js";

function expectCanon(fn: () => unknown, code: CanonErrorCode) {
  try {
    fn();
    throw new Error(`expected CanonError ${code} but no error thrown`);
  } catch (e) {
    if (!(e instanceof CanonError)) throw e;
    expect(e.code).toBe(code);
  }
}

// ─── Method ──────────────────────────────────────────────────────────────────

describe("method", () => {
  it("uppercases lowercase", () => expect(canonicalizeMethod("get")).toBe("GET"));
  it.each([" GET", "GET ", "G ET", "GET\t", "\nGET"])("rejects whitespace %p", (m) =>
    expectCanon(() => canonicalizeMethod(m), "CANON_METHOD_INVALID"));
  it.each(["", "GET1", "G3T"])("rejects non-alpha token %p", (m) =>
    expectCanon(() => canonicalizeMethod(m), "CANON_METHOD_INVALID"));
  it.each(["CONNECT", "TRACE", "OPTIONS", "PROPFIND"])("rejects unsupported %p", (m) =>
    expectCanon(() => canonicalizeMethod(m), "CANON_METHOD_UNSUPPORTED"));
});

// ─── Origin ──────────────────────────────────────────────────────────────────

describe("origin", () => {
  it("normalizes case + terminal dot + :443", () => {
    expect(canonicalizeOrigin("HTTPS://API.GITHUB.COM.:443")).toBe("https://api.github.com");
  });
  it("accepts canonical", () =>
    expect(canonicalizeOrigin("https://api.github.com")).toBe("https://api.github.com"));
  it.each(["http://api.github.com", "ftp://api.github.com"])("rejects non-https %p", (o) =>
    expectCanon(() => canonicalizeOrigin(o), "CANON_ORIGIN_SCHEME_UNSUPPORTED"));
  it("rejects userinfo", () =>
    expectCanon(() => canonicalizeOrigin("https://u@api.github.com"), "CANON_ORIGIN_INVALID"));
  it("rejects query", () =>
    expectCanon(() => canonicalizeOrigin("https://api.github.com?a=1"), "CANON_ORIGIN_INVALID"));
  it("rejects fragment", () =>
    expectCanon(() => canonicalizeOrigin("https://api.github.com#x"), "CANON_ORIGIN_INVALID"));
  it("rejects nondefault port", () =>
    expectCanon(
      () => canonicalizeOrigin("https://api.github.com:8443"),
      "CANON_ORIGIN_PORT_UNSUPPORTED",
    ));
  it("rejects non-ASCII host", () =>
    expectCanon(() => canonicalizeOrigin("https://api.gïthub.com"), "CANON_ORIGIN_HOST_INVALID"));
  it("rejects percent-escaped host", () =>
    expectCanon(() => canonicalizeOrigin("https://api.g%69thub.com"), "CANON_ORIGIN_HOST_INVALID"));
  it("rejects IPv4 literal", () =>
    expectCanon(() => canonicalizeOrigin("https://140.82.112.3"), "CANON_ORIGIN_HOST_INVALID"));
  it("rejects IPv6 literal", () =>
    expectCanon(() => canonicalizeOrigin("https://[::1]"), "CANON_ORIGIN_HOST_INVALID"));
  it("rejects double terminal dot", () =>
    expectCanon(() => canonicalizeOrigin("https://api.github.com.."), "CANON_ORIGIN_HOST_INVALID"));
  it("rejects a different allowed-shape host", () =>
    expectCanon(() => canonicalizeOrigin("https://evil.example.com"), "CANON_ORIGIN_NOT_ALLOWED"));
  it("rejects path beyond /", () =>
    expectCanon(() => canonicalizeOrigin("https://api.github.com/x"), "CANON_ORIGIN_INVALID"));
});

// ─── Path ────────────────────────────────────────────────────────────────────

describe("path", () => {
  it("root ok", () => expect(normalizePath("/")).toBe("/"));
  it("decodes unreserved ~", () =>
    expect(normalizePath("/repos/octo/%7ehello/issues")).toBe("/repos/octo/~hello/issues"));
  it("passes plain path", () =>
    expect(normalizePath("/repos/octo/hello/issues")).toBe("/repos/octo/hello/issues"));
  it("rejects missing leading slash", () =>
    expectCanon(() => normalizePath("repos/x"), "CANON_PATH_INVALID"));
  it("rejects embedded query", () =>
    expectCanon(() => normalizePath("/repos/x?a=1"), "CANON_PATH_INVALID"));
  it("rejects space", () =>
    expectCanon(() => normalizePath("/repos/ x"), "CANON_PATH_FORBIDDEN_BYTE"));
  it("rejects backslash", () =>
    expectCanon(() => normalizePath("/repos\\x"), "CANON_PATH_FORBIDDEN_BYTE"));
  it("rejects non-ASCII", () =>
    expectCanon(() => normalizePath("/repos/café"), "CANON_PATH_FORBIDDEN_BYTE"));
  it("rejects empty segment", () =>
    expectCanon(() => normalizePath("/repos//x"), "CANON_PATH_EMPTY_SEGMENT"));
  it("rejects trailing slash", () =>
    expectCanon(() => normalizePath("/repos/x/"), "CANON_PATH_EMPTY_SEGMENT"));
  it.each(["/repos/.", "/repos/..", "/..", "/./x"])("rejects dot segment %p", (p) =>
    expectCanon(() => normalizePath(p), "CANON_PATH_TRAVERSAL"));
  it.each([
    "/repos/%2e",
    "/repos/%2E",
    "/repos/%2f",
    "/repos/%5c",
    "/repos/%25",
    "/repos/%00",
  ])("rejects encoded ambiguity %p", (p) =>
    expectCanon(() => normalizePath(p), "CANON_PATH_ENCODED_AMBIGUITY"));
  it.each(["/repos/%2", "/repos/%zz", "/repos/%g0"])("rejects malformed percent %p", (p) =>
    expectCanon(() => normalizePath(p), "CANON_PATH_PERCENT_INVALID"));
  it("rejects encoded high byte", () =>
    expectCanon(() => normalizePath("/repos/%80"), "CANON_PATH_ENCODED_AMBIGUITY"));
});

// ─── Query ───────────────────────────────────────────────────────────────────

describe("query", () => {
  it("sorts bytewise by encoded name then value", () => {
    const out = canonicalizeQueryPairs([
      ["state", "open"],
      ["per_page", "30"],
    ]);
    expect(out).toEqual([
      ["per_page", "30"],
      ["state", "open"],
    ]);
  });
  it("allows empty value", () => {
    expect(canonicalizeQueryPairs([["page", ""]])).toEqual([["page", ""]]);
  });
  it("rejects duplicate name", () =>
    expectCanon(
      () =>
        canonicalizeQueryPairs([
          ["a", "1"],
          ["a", "2"],
        ]),
      "CANON_QUERY_DUPLICATE_KEY",
    ));
  it("rejects empty name", () =>
    expectCanon(() => canonicalizeQueryPairs([["", "1"]]), "CANON_QUERY_NAME_EMPTY"));
  it("rejects control in value", () =>
    expectCanon(() => canonicalizeQueryPairs([["a", "x\u0001"]]), "CANON_QUERY_VALUE_INVALID"));

  it("ordering is independent of input order (property/shuffle)", () => {
    const base: Array<[string, string]> = [
      ["z", "1"],
      ["a", "2"],
      ["m", "3"],
      ["b", "4"],
      ["per_page", "10"],
    ];
    const canonical = canonicalizeQueryPairs(base);
    for (let trial = 0; trial < 50; trial++) {
      const shuffled = [...base];
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }
      expect(canonicalizeQueryPairs(shuffled)).toEqual(canonical);
    }
  });

  describe("parseRawQuery", () => {
    it("decodes %20 to space, treats + literally", () => {
      expect(parseRawQuery("q=a%20b+c")).toEqual([["q", "a b+c"]]);
    });
    it("decodes UTF-8 percent sequences", () => {
      expect(parseRawQuery("q=caf%C3%A9%20repo%3Aocto%2Fhello")).toEqual([
        ["q", "café repo:octo/hello"],
      ]);
    });
    it("rejects bare key", () =>
      expectCanon(() => parseRawQuery("flag"), "CANON_QUERY_SYNTAX_AMBIGUOUS"));
    it("rejects semicolon separator", () =>
      expectCanon(() => parseRawQuery("a=1;b=2"), "CANON_QUERY_SYNTAX_AMBIGUOUS"));
    it("rejects fragment", () =>
      expectCanon(() => parseRawQuery("a=1#x"), "CANON_QUERY_SYNTAX_AMBIGUOUS"));
    it("rejects truncated percent", () =>
      expectCanon(() => parseRawQuery("a=%2"), "CANON_QUERY_PERCENT_INVALID"));
    it("rejects invalid UTF-8 percent", () =>
      expectCanon(() => parseRawQuery("a=%C3%28"), "CANON_QUERY_PERCENT_INVALID"));
  });
});

// ─── Headers ─────────────────────────────────────────────────────────────────

describe("headers", () => {
  it("lowercases + sorts + trims OWS", () => {
    expect(
      canonicalizeHeaders([
        ["X-GitHub-Api-Version", "2022-11-28"],
        ["Accept", "application/vnd.github+json"],
      ]),
    ).toEqual([
      ["accept", "application/vnd.github+json"],
      ["x-github-api-version", "2022-11-28"],
    ]);
  });
  it("normalizes if-none-match OWS", () => {
    expect(canonicalizeHeaders([["IF-NONE-MATCH", '  "abc"  ']])).toEqual([
      ["if-none-match", '"abc"'],
    ]);
  });
  it("accepts weak etag", () => {
    expect(canonicalizeHeaders([["if-none-match", 'W/"7"']])).toEqual([["if-none-match", 'W/"7"']]);
  });
  it("accepts '*' conditional", () => {
    expect(canonicalizeHeaders([["if-match", "*"]])).toEqual([["if-match", "*"]]);
  });
  it("rejects duplicate header name", () =>
    expectCanon(
      () =>
        canonicalizeHeaders([
          ["accept", "application/json"],
          ["Accept", "application/json"],
        ]),
      "CANON_HEADER_DUPLICATE",
    ));
  it.each([
    "authorization",
    "proxy-authorization",
    "cookie",
    "host",
    "connection",
    "content-length",
    "x-forwarded-for",
    "x-http-method-override",
    "x-steward-tenant",
  ])("rejects forbidden header %p", (h) =>
    expectCanon(() => canonicalizeHeaders([[h, "v"]]), "CANON_HEADER_CREDENTIAL_FORBIDDEN"));
  it("rejects non-allowlisted header", () =>
    expectCanon(() => canonicalizeHeaders([["x-custom", "v"]]), "CANON_HEADER_UNSUPPORTED"));
  it("rejects CRLF injection in value", () =>
    expectCanon(
      () => canonicalizeHeaders([["accept", "application/json\r\nX-Evil: 1"]]),
      "CANON_HEADER_INVALID",
    ));
  it("rejects accept list", () =>
    expectCanon(
      () => canonicalizeHeaders([["accept", "application/json, text/plain"]]),
      "CANON_ACCEPT_INVALID",
    ));
  it("rejects wrong github version", () =>
    expectCanon(
      () => canonicalizeHeaders([["x-github-api-version", "2020-01-01"]]),
      "CANON_GITHUB_VERSION_INVALID",
    ));
  it("rejects malformed etag", () =>
    expectCanon(
      () => canonicalizeHeaders([["if-match", "abc"]]),
      "CANON_CONDITIONAL_HEADER_INVALID",
    ));
});

// ─── Content-type matrix ─────────────────────────────────────────────────────

describe("content-type", () => {
  it.each([
    ["application/json", "application/json"],
    ["application/json; charset=utf-8", "application/json"],
    ["Application/JSON; CharSet=UTF-8", "application/json"],
    ["application/vnd.github+json", "application/vnd.github+json"],
  ])("canonicalizes %p", (input, expected) =>
    expect(canonicalizeContentType(input)).toBe(expected));
  it("rejects form", () =>
    expectCanon(
      () => canonicalizeContentType("application/x-www-form-urlencoded"),
      "CANON_BODY_CONTENT_TYPE_UNSUPPORTED",
    ));
  it("rejects quoted charset", () =>
    expectCanon(
      () => canonicalizeContentType('application/json; charset="utf-8"'),
      "CANON_BODY_CONTENT_TYPE_INVALID",
    ));
  it("rejects non-utf-8 charset", () =>
    expectCanon(
      () => canonicalizeContentType("application/json; charset=latin1"),
      "CANON_BODY_CONTENT_TYPE_INVALID",
    ));
  it("rejects extra parameter", () =>
    expectCanon(
      () => canonicalizeContentType("application/json; boundary=x"),
      "CANON_BODY_CONTENT_TYPE_INVALID",
    ));
  it("rejects duplicate parameter", () =>
    expectCanon(
      () => canonicalizeContentType("application/json; charset=utf-8; charset=utf-8"),
      "CANON_BODY_CONTENT_TYPE_INVALID",
    ));
});

// ─── Numbers / decimals ──────────────────────────────────────────────────────

describe("numbers", () => {
  it.each(["0", "12", "-7", "9007199254740991", "-9007199254740991"])("accepts %p", (n) =>
    expect(parseStrictInteger(n)).toBe(Number(n)));
  it.each(["-0", "1.0", "1e0", "1E5", "01", "+1", "00", "1.5"])("rejects format %p", (n) =>
    expectCanon(() => parseStrictInteger(n), "CANON_NUMBER_FORMAT_UNSUPPORTED"));
  it.each([
    "9007199254740992",
    "-9007199254740992",
    "99999999999999999",
  ])("rejects unsafe %p", (n) => expectCanon(() => parseStrictInteger(n), "CANON_NUMBER_UNSAFE"));
});

describe("decimal strings", () => {
  it.each(["0", "12", "12.50", "12.5", "0.001"])("accepts %p", (d) =>
    expect(() => assertDecimalString(d)).not.toThrow());
  it.each(["-1", "01", "1.", ".5", "1.2.3", "1e3", ""])("rejects %p", (d) =>
    expectCanon(() => assertDecimalString(d), "CANON_DECIMAL_STRING_INVALID"));
  it("preserves trailing-zero distinction (string identity)", () => {
    // 12.50 and 12.5 are different strings and must remain different bytes.
    expect(jcsStringify({ a: "12.50" })).not.toBe(jcsStringify({ a: "12.5" }));
  });
});

// ─── Strict JSON parser ──────────────────────────────────────────────────────

describe("strictParseJson", () => {
  it("parses nested objects", () => {
    expect(strictParseJson('{"b":1,"a":{"z":true,"y":null}}')).toEqual({
      b: 1,
      a: { z: true, y: null },
    });
  });
  it("rejects duplicate key at top level", () =>
    expectCanon(() => strictParseJson('{"a":1,"a":2}'), "CANON_JSON_DUPLICATE_KEY"));
  it("rejects duplicate key nested", () =>
    expectCanon(() => strictParseJson('{"x":{"a":1,"a":2}}'), "CANON_JSON_DUPLICATE_KEY"));
  it("rejects duplicate key deep in array", () =>
    expectCanon(() => strictParseJson('{"x":[{"a":1,"a":2}]}'), "CANON_JSON_DUPLICATE_KEY"));
  // SEC-045: a `__proto__` member must never silently replace the result's
  // prototype (object value) or vanish (primitive value); reject it outright.
  it("rejects __proto__ member with object value", () =>
    expectCanon(
      () => strictParseJson('{"__proto__":{"isAdmin":true}}'),
      "CANON_JSON_FORBIDDEN_KEY",
    ));
  it("rejects __proto__ member with primitive value", () =>
    expectCanon(() => strictParseJson('{"__proto__":1,"text":"hi"}'), "CANON_JSON_FORBIDDEN_KEY"));
  it("rejects __proto__ member nested at any depth", () =>
    expectCanon(() => strictParseJson('{"x":[{"__proto__":null}]}'), "CANON_JSON_FORBIDDEN_KEY"));
  it("rejects constructor/prototype members", () => {
    expectCanon(() => strictParseJson('{"constructor":{}}'), "CANON_JSON_FORBIDDEN_KEY");
    expectCanon(() => strictParseJson('{"prototype":{}}'), "CANON_JSON_FORBIDDEN_KEY");
  });
  it("never returns an object with a replaced prototype", () => {
    // Defense in depth: whatever the parser returns, property reads must not
    // observe smuggled members through the prototype chain.
    const parsed = strictParseJson('{"text":"hi"}') as Record<string, unknown>;
    expect(Object.getPrototypeOf(parsed)).toBe(Object.prototype);
    expect((parsed as { isAdmin?: unknown }).isAdmin).toBeUndefined();
  });
  it("rejects trailing content", () =>
    expectCanon(() => strictParseJson('{"a":1} garbage'), "CANON_JSON_SYNTAX_INVALID"));
  it("rejects trailing comma", () =>
    expectCanon(() => strictParseJson('{"a":1,}'), "CANON_JSON_SYNTAX_INVALID"));
  it("rejects comment", () =>
    expectCanon(() => strictParseJson('{"a":1 /* c */}'), "CANON_JSON_SYNTAX_INVALID"));
  it("rejects BOM", () =>
    expectCanon(() => strictParseJson('\uFEFF{"a":1}'), "CANON_INVALID_UTF8"));
  it("rejects forbidden number in body", () =>
    expectCanon(() => strictParseJson('{"a":1.5}'), "CANON_NUMBER_FORMAT_UNSUPPORTED"));
  it("rejects unsafe number in body", () =>
    expectCanon(() => strictParseJson('{"a":9007199254740992}'), "CANON_NUMBER_UNSAFE"));
  it("preserves surrogate-pair emoji via escapes", () => {
    expect(strictParseJson('{"e":"\\uD83D\\uDE00"}')).toEqual({ e: "😀" });
  });
  it("rejects lone high surrogate escape", () =>
    expectCanon(() => strictParseJson('{"e":"\\uD83D"}'), "CANON_UNICODE_INVALID"));
});

// ─── JCS runtime-value rejection (Conflict 13) ───────────────────────────────

describe("jcsStringify rejects non-JSON runtime values", () => {
  it("bigint", () => expectCanon(() => jcsStringify({ a: 1n }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("undefined member", () =>
    expectCanon(() => jcsStringify({ a: undefined }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("NaN", () =>
    expectCanon(() => jcsStringify({ a: Number.NaN }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("Infinity", () =>
    expectCanon(
      () => jcsStringify({ a: Number.POSITIVE_INFINITY }),
      "CANON_RUNTIME_VALUE_UNSUPPORTED",
    ));
  it("Date", () =>
    expectCanon(() => jcsStringify({ a: new Date() }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("Map", () => expectCanon(() => jcsStringify(new Map()), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("function", () =>
    expectCanon(() => jcsStringify({ a: () => 1 }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("symbol", () =>
    expectCanon(() => jcsStringify({ a: Symbol("x") }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("sparse array hole", () => {
    // biome-ignore lint/suspicious/noSparseArray: The hole is intentional to prove JCS rejects sparse arrays.
    const arr = [1, , 3];
    expectCanon(() => jcsStringify(arr), "CANON_RUNTIME_VALUE_UNSUPPORTED");
  });
  it("non-integer runtime number", () =>
    expectCanon(() => jcsStringify({ a: 1.5 }), "CANON_RUNTIME_VALUE_UNSUPPORTED"));
  it("accessor property — getter is rejected, never invoked (SEC-191)", () => {
    let getterRan = false;
    const exotic = Object.defineProperty({}, "a", {
      enumerable: true,
      get() {
        getterRan = true;
        return 1;
      },
    });
    expectCanon(() => jcsStringify(exotic), "CANON_RUNTIME_VALUE_UNSUPPORTED");
    expect(getterRan).toBe(false);
  });
});

describe("jcs key ordering (UTF-16 code units)", () => {
  it("sorts by code unit, not locale", () => {
    // 'Z' (0x5A) < 'a' (0x61) by code unit
    expect(jcsStringify({ a: 1, Z: 2 })).toBe('{"Z":2,"a":1}');
  });
  it("astral vs BMP ordering by first code unit", () => {
    // '~' 0x7E vs surrogate high 0xD800 — surrogate sorts after
    const s = jcsStringify({ "~": 1, "😀": 2 });
    expect(s.indexOf('"~"')).toBeLessThan(s.indexOf('"😀"'));
  });
});

// ─── Mutation invariants: semantic change => digest change ───────────────────

describe("digest mutation sensitivity", () => {
  const base: GithubCanonicalActionV1 = {
    profile: GITHUB_PROVIDER_ACTION_PROFILE,
    method: "POST",
    origin: "https://api.github.com",
    normalizedPath: "/repos/octo/hello/issues/42/comments",
    orderedQueryPairs: [["a", "1"]],
    selectedHeaders: [["content-type", "application/json"]],
    canonicalBody: { body: "hi" },
  };
  const baseDigest = computeActionDigest(base);

  it("method change", () =>
    expect(computeActionDigest({ ...base, method: "PUT" })).not.toBe(baseDigest));
  it("path change", () =>
    expect(computeActionDigest({ ...base, normalizedPath: "/x" })).not.toBe(baseDigest));
  it("query value change", () =>
    expect(computeActionDigest({ ...base, orderedQueryPairs: [["a", "2"]] })).not.toBe(baseDigest));
  it("header value change", () =>
    expect(
      computeActionDigest({
        ...base,
        selectedHeaders: [["content-type", "application/vnd.github+json"]],
      }),
    ).not.toBe(baseDigest));
  it("body change", () =>
    expect(computeActionDigest({ ...base, canonicalBody: { body: "bye" } })).not.toBe(baseDigest));
  it("body key add", () =>
    expect(computeActionDigest({ ...base, canonicalBody: { body: "hi", x: 1 } })).not.toBe(
      baseDigest,
    ));
});
