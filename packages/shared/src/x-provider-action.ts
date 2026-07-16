/**
 * x-provider-action.ts — the `x.provider-action.v1` canonicalization profile.
 *
 * This module is the X (Twitter) sibling of the `github.provider-action.v1`
 * profile in provider-action.ts. It defines, for the governed-provider-authority
 * plan (issue #195 workstream B):
 *   - the X canonical origin (`https://api.x.com`) + host allowlist;
 *   - the X canonical action type (`XCanonicalActionV1`) and profile string;
 *   - the X origin canonicalizer + the thin body/content-type orchestration that
 *     produces a canonical action from a raw internal HTTP representation.
 *
 * SECURITY POSTURE. This module deliberately does NOT re-implement JCS, hashing,
 * path normalization, query canonicalization, method canonicalization, or the
 * content-type matrix. It imports the ONE shared canonicalizer surface from
 * provider-action.ts and composes those primitives. The only X-specific logic
 * here is: which origin/host is allowed, which profile string is stamped, and
 * which request headers are allowlisted (X ops carry no caller-supplied headers;
 * the sole header is the `content-type` injected by the body matrix). Every
 * ambiguity fails closed with a stable CANON_* code, never a 500, never a coerce.
 *
 * Because `XCanonicalActionV1` is structurally identical to
 * `GithubCanonicalActionV1` (same field set and shapes, differing only in the
 * `profile` and `origin` string VALUES), the shared JCS serializer produces
 * byte-identical framing and the action digest is computed by the exact same
 * `sha256HexPrefixed(jcsStringify(...))` path the GitHub profile uses.
 */

import {
  canonicalizeContentType,
  canonicalizeMethod,
  canonicalizeQueryPairs,
  CanonError,
  type CanonicalMethod,
  jcsStringify,
  type JsonValue,
  normalizePath,
  type QueryPair,
  sha256HexPrefixed,
} from "./provider-action.js";

// ─────────────────────────────────────────────────────────────────────────────
// Profile constants
// ─────────────────────────────────────────────────────────────────────────────

export const X_PROVIDER_ACTION_PROFILE = "x.provider-action.v1" as const;

/**
 * The X canonical origin. Equivalent to GitHub's `CANONICAL_ORIGIN`. Only this
 * exact host reaches an X action; every other origin denies. Chosen to match X's
 * v2 REST base host (`api.x.com`); the legacy `api.twitter.com` alias is NOT
 * accepted so a single canonical bytes representation exists per action.
 */
export const X_CANONICAL_ORIGIN = "https://api.x.com" as const;

const X_ALLOWED_HOST = "api.x.com" as const;

const X_JSON_CONTENT_TYPE = "application/json" as const;

// ─────────────────────────────────────────────────────────────────────────────
// Canonical action type
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The fully-canonical X provider action. Structurally identical to
 * {@link GithubCanonicalActionV1}: the shared JCS framing depends only on the
 * field set (which is the same), so digests are computed on the same path.
 */
export interface XCanonicalActionV1 {
  profile: typeof X_PROVIDER_ACTION_PROFILE;
  method: CanonicalMethod;
  origin: string;
  normalizedPath: string;
  orderedQueryPairs: Array<[string, string]>;
  selectedHeaders: Array<[string, string]>;
  canonicalBody: null | JsonValue;
}

// ─────────────────────────────────────────────────────────────────────────────
// Origin canonicalization (X)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalize a raw origin string to the canonical `https://api.x.com`, or deny.
 * Mirrors the GitHub origin canonicalizer's posture EXACTLY (scheme/host ASCII
 * lowercasing, one terminal DNS-dot removal, explicit :443 omission, empty-or-`/`
 * path, no IDNA, no IP literals, DNS-label validation) with the sole difference
 * that the accepted host is `api.x.com`. Kept as a small self-contained function
 * rather than parameterizing the GitHub canonicalizer so the GitHub profile's
 * golden bytes remain provably untouched.
 */
export function canonicalizeXOrigin(raw: string): string {
  if (typeof raw !== "string" || raw.length === 0)
    throw new CanonError("CANON_ORIGIN_INVALID", "origin must be a non-empty string");
  if (/[\u0000-\u0020\u007f]/.test(raw))
    throw new CanonError("CANON_ORIGIN_INVALID", "control/space in origin");

  const schemeMatch = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(raw);
  if (!schemeMatch) throw new CanonError("CANON_ORIGIN_INVALID", "origin missing scheme://");
  const scheme = schemeMatch[1].toLowerCase();
  if (scheme !== "https")
    throw new CanonError("CANON_ORIGIN_SCHEME_UNSUPPORTED", `scheme '${scheme}' not https`);

  const rest = raw.slice(schemeMatch[0].length);
  if (rest.includes("@")) throw new CanonError("CANON_ORIGIN_INVALID", "userinfo not allowed");
  if (rest.includes("?"))
    throw new CanonError("CANON_ORIGIN_INVALID", "query not allowed in origin");
  if (rest.includes("#"))
    throw new CanonError("CANON_ORIGIN_INVALID", "fragment not allowed in origin");

  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  const path = slash === -1 ? "" : rest.slice(slash);
  if (path !== "" && path !== "/")
    throw new CanonError("CANON_ORIGIN_INVALID", "origin path must be empty or '/'");

  if (authority.includes("[") || authority.includes("]"))
    throw new CanonError("CANON_ORIGIN_HOST_INVALID", "IP literal host");

  let host = authority;
  const colon = authority.lastIndexOf(":");
  if (colon !== -1) {
    const portStr = authority.slice(colon + 1);
    host = authority.slice(0, colon);
    if (!/^[0-9]+$/.test(portStr))
      throw new CanonError("CANON_ORIGIN_PORT_UNSUPPORTED", "invalid port");
    if (portStr !== "443")
      throw new CanonError("CANON_ORIGIN_PORT_UNSUPPORTED", `nondefault port ${portStr}`);
  }

  if (/%/.test(host)) throw new CanonError("CANON_ORIGIN_HOST_INVALID", "percent escape in host");
  if (/[^\x00-\x7f]/.test(host))
    throw new CanonError("CANON_ORIGIN_HOST_INVALID", "non-ASCII host");
  let h = host.toLowerCase();
  if (h.endsWith(".."))
    throw new CanonError("CANON_ORIGIN_HOST_INVALID", "multiple terminal dots");
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (h.startsWith("[")) throw new CanonError("CANON_ORIGIN_HOST_INVALID", "IP literal host");
  if (/^[0-9]+(\.[0-9]+)*$/.test(h))
    throw new CanonError("CANON_ORIGIN_HOST_INVALID", "numeric/IPv4 host");
  for (const label of h.split(".")) {
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
      throw new CanonError("CANON_ORIGIN_HOST_INVALID", `invalid DNS label '${label}'`);
  }
  if (h !== X_ALLOWED_HOST)
    throw new CanonError("CANON_ORIGIN_NOT_ALLOWED", `host '${h}' not allowed`);
  return X_CANONICAL_ORIGIN;
}

// ─────────────────────────────────────────────────────────────────────────────
// Raw internal HTTP representation → canonical X action (body/content-type matrix)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A raw, INTERNAL HTTP representation of an X provider action. Mirrors
 * {@link RawInternalAction} for GitHub. Fields are raw/pre-canonical; the X
 * adapter constructs these from validated operation arguments and the PR-C proxy
 * recomputation / offline verifier feed the same shape in, so there is exactly
 * ONE X canonicalization path and the golden corpus proves it byte-for-byte.
 *
 * X operations carry NO caller-supplied headers: the only header that can appear
 * on a canonical X action is the `content-type` injected by the body matrix for
 * a body-bearing mutation. A non-empty `headers` array therefore denies.
 */
export interface RawInternalXAction {
  method: string;
  origin: string;
  path: string;
  query?: ReadonlyArray<QueryPair>;
  /** X ops declare no caller headers; a non-empty list denies. */
  headers?: ReadonlyArray<[string, string]>;
  /** Raw content-type header value when a body is present; omit for no body. */
  contentType?: string;
  /** Already-parsed JSON body value, or absent/undefined for no body. */
  body?: JsonValue;
}

const X_BODYLESS_METHODS: ReadonlySet<CanonicalMethod> = new Set(["GET", "HEAD"]);
const X_BODY_METHODS: ReadonlySet<CanonicalMethod> = new Set(["POST", "PUT", "PATCH"]);

/**
 * Canonicalize a raw internal X HTTP representation into the fully-canonical
 * {@link XCanonicalActionV1}, applying the body/content-type matrix. Throws
 * {@link CanonError} on any ambiguity (never a 500).
 *
 * Reuses the shared method/path/query/content-type canonicalizers verbatim; the
 * only X-specific steps are the origin allowlist and the profile stamp. The
 * content-type header is validated and injected HERE (X ops pass no headers
 * otherwise) so the body and its media type are canonicalized together.
 */
export function canonicalizeRawInternalXAction(raw: RawInternalXAction): XCanonicalActionV1 {
  const method = canonicalizeMethod(raw.method);
  const origin = canonicalizeXOrigin(raw.origin);
  const normalizedPath = normalizePath(raw.path);
  const orderedQueryPairs = canonicalizeQueryPairs(raw.query ?? []);

  // X operations supply no caller headers. Reject any provided rather than
  // silently dropping them (fail closed, no coercion).
  if (raw.headers !== undefined && raw.headers.length > 0)
    throw new CanonError("CANON_HEADER_UNSUPPORTED", "X actions carry no caller headers");

  const selectedHeaders: Array<[string, string]> = [];
  const hasBody = raw.body !== undefined;
  const hasContentType = raw.contentType !== undefined;

  let canonicalBody: JsonValue | null = null;

  if (X_BODYLESS_METHODS.has(method)) {
    if (hasBody || hasContentType)
      throw new CanonError("CANON_BODY_FORBIDDEN", `${method} must not carry a body`);
  } else if (X_BODY_METHODS.has(method)) {
    if (!hasBody) throw new CanonError("CANON_BODY_REQUIRED", `${method} requires a body`);
    if (!hasContentType)
      throw new CanonError("CANON_BODY_CONTENT_TYPE_REQUIRED", "body present without content-type");
    const media = canonicalizeContentType(raw.contentType as string);
    // X v2 accepts JSON only in this profile; the shared content-type matrix also
    // admits the GitHub vendor media type, so pin JSON explicitly here.
    if (media !== X_JSON_CONTENT_TYPE)
      throw new CanonError(
        "CANON_BODY_CONTENT_TYPE_UNSUPPORTED",
        `X body content-type must be application/json, got '${media}'`,
      );
    selectedHeaders.push(["content-type", media]);
    if (raw.body === null || typeof raw.body !== "object" || Array.isArray(raw.body))
      throw new CanonError("CANON_JSON_SHAPE_INVALID", "body must be a JSON object");
    canonicalBody = raw.body;
  } else {
    // DELETE: bodyless only in this profile.
    if (hasBody || hasContentType)
      throw new CanonError("CANON_BODY_FORBIDDEN", `${method} must not carry a body`);
  }

  return {
    profile: X_PROVIDER_ACTION_PROFILE,
    method,
    origin,
    normalizedPath,
    orderedQueryPairs,
    selectedHeaders,
    canonicalBody,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonical action bytes + digest (X)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the JCS-serializable canonical action object. Property order here is
 * irrelevant (JCS re-sorts); we build a plain object so the serializer never
 * sees a class instance. Field set is identical to the GitHub action object.
 */
function toXCanonicalActionObject(a: XCanonicalActionV1): Record<string, unknown> {
  return {
    profile: a.profile,
    method: a.method,
    origin: a.origin,
    normalizedPath: a.normalizedPath,
    orderedQueryPairs: a.orderedQueryPairs.map(([n, v]) => [n, v]),
    selectedHeaders: a.selectedHeaders.map(([n, v]) => [n, v]),
    canonicalBody: a.canonicalBody,
  };
}

/** `canonicalActionBytes` for an X action as a UTF-8 string (no newline). */
export function xCanonicalActionBytes(a: XCanonicalActionV1): string {
  return jcsStringify(toXCanonicalActionObject(a));
}

/** `actionDigest` = sha256: hex of the X canonical action bytes. */
export function computeXActionDigest(a: XCanonicalActionV1): string {
  return sha256HexPrefixed(xCanonicalActionBytes(a));
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden vectors — the authoritative X corpus, imported by every suite.
//
// Byte-exact canonical action bytes + digests for one representative case of
// each operation plus the reply / unicode / trim / query-order edge cases. Tests
// assert both that OUR serializer reproduces `canonicalActionBytes` and that the
// recorded digests match, so a byte corruption in either direction fails.
// ─────────────────────────────────────────────────────────────────────────────

export interface XGoldenVector {
  id: string;
  description: string;
  action: XCanonicalActionV1;
  canonicalActionBytes: string;
  actionDigest: string;
}

function xa(
  method: CanonicalMethod,
  normalizedPath: string,
  orderedQueryPairs: Array<[string, string]>,
  selectedHeaders: Array<[string, string]>,
  canonicalBody: null | JsonValue,
): XCanonicalActionV1 {
  return {
    profile: X_PROVIDER_ACTION_PROFILE,
    method,
    origin: X_CANONICAL_ORIGIN,
    normalizedPath,
    orderedQueryPairs,
    selectedHeaders,
    canonicalBody,
  };
}

export const X_GOLDEN_VECTORS: XGoldenVector[] = [
  {
    id: "XGV-01",
    description: "user.me.read fixed query, canonical order",
    action: xa("GET", "/2/users/me", [["user.fields", "id,name,username"]], [], null),
    canonicalActionBytes:
      '{"canonicalBody":null,"method":"GET","normalizedPath":"/2/users/me","orderedQueryPairs":[["user.fields","id,name,username"]],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[]}',
    actionDigest: "sha256:1f9294f2c964103e13fdec37e08442e7a8e2480f24937a475fff992ec8c281f2",
  },
  {
    id: "XGV-02",
    description: "tweet.create basic text body",
    action: xa(
      "POST",
      "/2/tweets",
      [],
      [["content-type", "application/json"]],
      { text: "hello world" },
    ),
    canonicalActionBytes:
      '{"canonicalBody":{"text":"hello world"},"method":"POST","normalizedPath":"/2/tweets","orderedQueryPairs":[],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:7a37b4b65790940602d89529ec31198810046eaaaeea5a14a83740595cabd1f6",
  },
  {
    id: "XGV-03",
    description: "tweet.create reply (nested reply object, JCS key-sorted)",
    action: xa("POST", "/2/tweets", [], [["content-type", "application/json"]], {
      reply: { in_reply_to_tweet_id: "1234567890" },
      text: "thanks!",
    }),
    canonicalActionBytes:
      '{"canonicalBody":{"reply":{"in_reply_to_tweet_id":"1234567890"},"text":"thanks!"},"method":"POST","normalizedPath":"/2/tweets","orderedQueryPairs":[],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:a9f340cac72bcfde034729f925c05782b5776ab8b2c8a16b27519de4c29a0e6a",
  },
  {
    id: "XGV-04",
    description: "tweet.create unicode text preserved (no normalization)",
    action: xa("POST", "/2/tweets", [], [["content-type", "application/json"]], {
      text: "café ☕ 日本",
    }),
    canonicalActionBytes:
      '{"canonicalBody":{"text":"café ☕ 日本"},"method":"POST","normalizedPath":"/2/tweets","orderedQueryPairs":[],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:7cd23ae2ea1e37f58917f39fd2023e3f3f3bf4a5f9f64c443d7baeb9f49726dc",
  },
  {
    id: "XGV-05",
    description: "tweet.create trims surrounding whitespace to authoritative body",
    action: xa(
      "POST",
      "/2/tweets",
      [],
      [["content-type", "application/json"]],
      { text: "spaced out" },
    ),
    canonicalActionBytes:
      '{"canonicalBody":{"text":"spaced out"},"method":"POST","normalizedPath":"/2/tweets","orderedQueryPairs":[],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[["content-type","application/json"]]}',
    actionDigest: "sha256:13cb864da52a15a468bf3945de99d00a36c09479a3b4678acdf0ae2d86852397",
  },
  {
    id: "XGV-06",
    description: "tweet.delete path segment from validated id",
    action: xa("DELETE", "/2/tweets/9876543210987654321", [], [], null),
    canonicalActionBytes:
      '{"canonicalBody":null,"method":"DELETE","normalizedPath":"/2/tweets/9876543210987654321","orderedQueryPairs":[],"origin":"https://api.x.com","profile":"x.provider-action.v1","selectedHeaders":[]}',
    actionDigest: "sha256:dc0f5eb1befcb5e92bffb9b6f6cae628f947343a9c50552c35ff7c6cdfdf33a5",
  },
];
