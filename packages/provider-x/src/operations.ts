/**
 * operations.ts — X provider-action operation schemas + canonical action
 * construction.
 *
 * This adapter owns method, origin, path construction, header selection, and
 * body shape for the three supported operations. It validates operation
 * ARGUMENTS strictly (fail closed with stable CANON_* codes), builds a raw
 * internal HTTP representation, and runs it through the ONE shared X
 * canonicalizer (`canonicalizeRawInternalXAction`) so the action digest matches
 * the golden corpus byte-for-byte. Dynamic id segments are encoded from
 * VALIDATED values, never concatenated from a raw path.
 *
 * It also derives the non-authoritative `safeSummary` (display only) and the
 * validated policy-context arguments the provider policy composer reads. The
 * policy layer never lifts arbitrary scalar fields from raw JSON: policyArgs is
 * validated scalars only, never a raw body.
 *
 * TEXT LENGTH SIMPLIFICATION. X enforces a "weighted" tweet length: URLs count
 * as a fixed 23 regardless of their real length, CJK ideographs count as 2, and
 * some ranges count as 1. Reproducing that weighting requires X's tco URL model
 * and the published character-count ranges, which drift. This adapter instead
 * counts by Unicode code points (`[...text].length`) after trimming leading and
 * trailing ASCII/Unicode whitespace, bounding 1..280. This is STRICTER-or-equal
 * to X for pure text (code points >= weighted length for non-URL text is not
 * guaranteed, so an occasional server-side rejection is possible for exotic
 * inputs), and it is fully deterministic and re-derivable by the proxy and the
 * offline verifier. The simplification is documented here and in the PR body.
 */

import { createHash } from "node:crypto";
import {
  CanonError,
  type CanonicalMethod,
  canonicalizeRawInternalXAction,
  type JsonValue,
  type XCanonicalActionV1,
} from "@stwd/shared";

export const X_OPERATION_KEYS = ["x.tweet.create", "x.tweet.delete", "x.user.me.read"] as const;
export type XOperationKey = (typeof X_OPERATION_KEYS)[number];

export function isXOperationKey(v: unknown): v is XOperationKey {
  return typeof v === "string" && (X_OPERATION_KEYS as readonly string[]).includes(v);
}

/** Risk class per operation (write = approval-worthy, read = low risk). */
export type XOperationRisk = "read" | "write";
export const X_OPERATION_RISK: Readonly<Record<XOperationKey, XOperationRisk>> = {
  "x.tweet.create": "write",
  "x.tweet.delete": "write",
  "x.user.me.read": "read",
};

/** The result of validating + canonicalizing an operation's arguments. */
export interface XActionBuild {
  operationKey: XOperationKey;
  method: CanonicalMethod;
  risk: XOperationRisk;
  action: XCanonicalActionV1;
  /** Non-authoritative, adapter-derived display summary. */
  safeSummary: Record<string, unknown>;
  /** Validated arguments a provider policy may read. Never raw JSON. */
  policyArgs: Record<string, unknown>;
  /**
   * IN-MEMORY-ONLY text channel for content-pattern policy matching
   * (`contentPolicy.blockedPatterns`). Present ONLY for text-bearing operations
   * (x.tweet.create). It is DELIBERATELY separate from {@link policyArgs} so the
   * "policyArgs = validated scalars, never raw text" contract holds: the composer
   * reads `policyText` during evaluation and it is NEVER persisted to the
   * decision doc, the safe-summary, or the audit event. See
   * docs/security/permissioned-x.mdx "Text availability".
   */
  policyText?: string;
}

const JSON_CONTENT_TYPE = "application/json";

/** X object ids (tweet id, user id) are decimal snowflakes: 1..25 digits. */
const ID_RE = /^[0-9]{1,25}$/;

const TWEET_TEXT_MIN = 1;
const TWEET_TEXT_MAX = 280;

// ─── shared field helpers (stable CANON_* codes) ──────────────────────────────

function fieldError(message: string): never {
  throw new CanonError("CANON_FIELD_TYPE_INVALID", message);
}

function unknownField(name: string): never {
  throw new CanonError("CANON_UNKNOWN_FIELD", `unknown argument '${name}'`);
}

function requiredMissing(name: string): never {
  throw new CanonError("CANON_REQUIRED_FIELD_MISSING", `missing required argument '${name}'`);
}

function rejectUnknownKeys(args: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  for (const key of Object.keys(args)) {
    if (!allowed.has(key)) unknownField(key);
  }
}

function asObject(args: unknown): Record<string, unknown> {
  if (typeof args !== "object" || args === null || Array.isArray(args))
    throw new CanonError("CANON_JSON_SHAPE_INVALID", "arguments must be a JSON object");
  return args as Record<string, unknown>;
}

/** Validate a decimal X id string against {@link ID_RE}; return it verbatim. */
function validateId(v: unknown, name: string): string {
  if (typeof v !== "string") fieldError(`${name} must be a string`);
  if (!ID_RE.test(v))
    throw new CanonError("CANON_PATH_SEGMENT_INVALID", `invalid ${name} '${String(v)}'`);
  return v;
}

/** Reject lone UTF-16 surrogates in a caller-supplied string. */
function assertNoLoneSurrogate(v: string, label: string): void {
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = v.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new CanonError("CANON_UNICODE_INVALID", `lone surrogate in ${label}`);
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonError("CANON_UNICODE_INVALID", `lone surrogate in ${label}`);
    }
  }
}

/**
 * Detect whether tweet text contains a URL. Used ONLY to derive the `hasUrl`
 * policy arg (which is BOTH a content signal and a spend signal: a URL post
 * costs $0.20 vs $0.015 for a plain post — see docs/security/permissioned-x.mdx
 * and X_POST_PRICE_TABLE_V1). This is deliberately BROADER-or-equal to X's own
 * t.co URL detection: we match `scheme://` URLs, bare `www.` hosts, and bare
 * `host.tld` / `host.tld/path` forms. Over-detection is the SAFE direction for a
 * no-URL policy (a false positive denies a borderline post; a false negative
 * would let an expensive/forbidden URL through). It is a policy signal only — it
 * never alters the tweet body or the canonical action digest.
 *
 * The detection is intentionally simple + deterministic (re-derivable offline).
 * It does NOT attempt X's exact weighted URL model.
 */
function textHasUrl(text: string): boolean {
  // Remove format controls that can visually join a host while splitting the
  // token seen by the detector. This normalized copy is used only for the
  // derived policy signal. The posted text and canonical digest remain exact.
  // Include bidi embedding/override/isolate controls as the fail-safe choice.
  const detectionText = text.replace(/\p{Cf}/gu, "");
  // scheme://... (http, https, ftp, etc.)
  if (/[a-z][a-z0-9+.-]*:\/\/\S/i.test(detectionText)) return true;
  // bare www. host
  if (/\bwww\.[^\s.]+\.[^\s]/i.test(detectionText)) return true;
  // Bare IPv4 literal, optionally followed by a path. Deliberately accepts any
  // four decimal octets rather than risking a false negative on a policy signal.
  if (/\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\S*)?(?=$|[^\d.])/i.test(detectionText)) return true;
  // bare host.tld optionally with a path. We OVER-DETECT here (fail toward
  // treating an ambiguous token as a URL), because a false negative would let a
  // `contentPolicy.allowUrls:false` / URL-spend / URL-approval policy be BYPASSED
  // by a real bare domain on an uncommon TLD (e.g. `example.social`, `foo.shop`).
  // A false positive only denies/escalates a borderline post, which is the safe
  // direction (codex P2, PR review). We therefore treat ANY `label.tld` token
  // (tld = 2+ ASCII letters) with a path OR a plausible domain shape as a URL,
  // and EXCLUDE only a small deny-list of common English abbreviations that
  // appear as `word.word` in ordinary prose.
  //
  // The dot must be immediately followed by 2+ ASCII letters (`\.[a-z]{2,}`), so
  // ordinary prose with a space after the period ("fine. really") does NOT match
  // — only a glued `label.tld` token does. Common English abbreviations with a
  // single-letter right side ("e.g", "i.e", "p.m", "a.m", "u.s", "u.k") also do
  // not match (1-letter tld). What remains are host-shaped tokens, which we
  // OVER-DETECT as URLs regardless of TLD (a path is not required). We keep a
  // tiny deny-list only for the rare glued 2+-letter-tld prose abbreviations.
  const PROSE_ABBREVIATIONS: ReadonlySet<string> = new Set([
    "etc.al", // "etc.al" style typo runs
    "vs.the",
  ]);
  const hostRe = /\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.([a-z]{2,})((?:\/\S*)?)/gi;
  for (const m of detectionText.matchAll(hostRe)) {
    const label = m[1].toLowerCase();
    const tld = m[2].toLowerCase();
    const hasPath = m[3].length > 0;
    // A path always makes it a URL.
    if (hasPath) return true;
    // Skip a couple of glued prose abbreviations; everything else host-shaped is
    // over-detected as a URL (safe direction for a no-URL / spend policy).
    if (PROSE_ABBREVIATIONS.has(`${label}.${tld}`)) continue;
    return true;
  }
  return false;
}

/**
 * Trim leading/trailing whitespace then validate the tweet text length by
 * Unicode code points (see the module-level simplification note). Returns the
 * TRIMMED text (the trimmed value is authoritative: it is what goes in the body).
 */
function validateTweetText(v: unknown): string {
  if (typeof v !== "string") fieldError("text must be a string");
  assertNoLoneSurrogate(v, "tweet text");
  const trimmed = v.trim();
  // Code-point count (not UTF-16 length): astral chars count once.
  const codePoints = [...trimmed].length;
  if (codePoints < TWEET_TEXT_MIN)
    throw new CanonError("CANON_BODY_REQUIRED", "tweet text is empty after trim");
  if (codePoints > TWEET_TEXT_MAX)
    fieldError(`tweet text exceeds ${TWEET_TEXT_MAX} code points (got ${codePoints})`);
  return trimmed;
}

// ─── x.tweet.create ───────────────────────────────────────────────────────────

// `summoned` is a POLICY-ONLY hint (the caller asserts the account was
// @mentioned/quoted by the post being replied to — the Feb-2026 anti-spam
// precondition for a programmatic reply). It NEVER enters the tweet body or the
// canonical action digest; it only flows to policyArgs so `replyPolicy:
// summoned-only` can gate. It is validated as a strict boolean.
const TWEET_CREATE_KEYS = new Set(["text", "replyToTweetId", "summoned"]);

function validateBool(v: unknown, name: string): boolean {
  if (typeof v !== "boolean") fieldError(`${name} must be a boolean`);
  return v;
}

function buildTweetCreate(rawArgs: unknown): XActionBuild {
  const args = asObject(rawArgs);
  rejectUnknownKeys(args, TWEET_CREATE_KEYS);
  if (!("text" in args)) requiredMissing("text");
  const text = validateTweetText(args.text);

  let replyToTweetId: string | undefined;
  if ("replyToTweetId" in args && args.replyToTweetId !== undefined) {
    replyToTweetId = validateId(args.replyToTweetId, "replyToTweetId");
  }

  // `summoned` defaults to false (fail-closed for summoned-only reply policy:
  // an unasserted reply is treated as NOT summoned). Only meaningful on a reply,
  // but accepted+validated regardless so the arg shape is stable.
  let summoned = false;
  if ("summoned" in args && args.summoned !== undefined) {
    summoned = validateBool(args.summoned, "summoned");
  }

  const hasUrl = textHasUrl(text);

  // Body: {text} plus a nested reply object only when replying. The shared JCS
  // sorts object keys, so insertion order here is irrelevant to the digest.
  const jsonBody: { [k: string]: JsonValue } = { text };
  if (replyToTweetId !== undefined) {
    jsonBody.reply = { in_reply_to_tweet_id: replyToTweetId };
  }

  const action = canonicalizeRawInternalXAction({
    method: "POST",
    origin: "https://api.x.com",
    path: "/2/tweets",
    contentType: JSON_CONTENT_TYPE,
    body: jsonBody,
  });

  const byteLength = Buffer.from(text, "utf8").length;
  const codePointLength = [...text].length;
  const textSha256 = `sha256:${createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex")}`;

  // Safe summary mirrors the GitHub adapter: length + sha256 only, never any
  // slice of the text. A preview would equal the full body for short tweets, which
  // would leak user content the summary is contractually forbidden to contain.
  const safeSummary: Record<string, unknown> = {
    operation: "x.tweet.create",
    isReply: replyToTweetId !== undefined,
    // Booleans/lengths only — NEVER any slice of the text. `hasUrl` is a
    // derived boolean signal (content + spend), safe to surface.
    hasUrl,
    summoned,
    textCodePointLength: codePointLength,
    textByteLength: byteLength,
    textSha256,
  };
  if (replyToTweetId !== undefined) safeSummary.replyToTweetId = replyToTweetId;

  // policyArgs carries ONLY validated scalars/booleans the composer gates on —
  // NEVER raw text (that contract is asserted by the operations test). The raw
  // text for blockedPatterns matching travels on the SEPARATE, non-persisted
  // `policyText` field of the build (see XActionBuild.policyText).
  const policyArgs: Record<string, unknown> = {
    isReply: replyToTweetId !== undefined,
    hasUrl,
    summoned,
    textCodePointLength: codePointLength,
    textByteLength: byteLength,
  };
  if (replyToTweetId !== undefined) policyArgs.replyToTweetId = replyToTweetId;

  return {
    operationKey: "x.tweet.create",
    method: "POST",
    risk: "write",
    action,
    safeSummary,
    policyArgs,
    policyText: text,
  };
}

// ─── x.tweet.delete ───────────────────────────────────────────────────────────

const TWEET_DELETE_KEYS = new Set(["tweetId"]);

function buildTweetDelete(rawArgs: unknown): XActionBuild {
  const args = asObject(rawArgs);
  rejectUnknownKeys(args, TWEET_DELETE_KEYS);
  if (!("tweetId" in args)) requiredMissing("tweetId");
  const tweetId = validateId(args.tweetId, "tweetId");

  const action = canonicalizeRawInternalXAction({
    method: "DELETE",
    origin: "https://api.x.com",
    // Path built from the VALIDATED id (ID_RE guarantees [0-9]{1,25}: no
    // percent-encoding needed, no traversal possible).
    path: `/2/tweets/${tweetId}`,
  });

  return {
    operationKey: "x.tweet.delete",
    method: "DELETE",
    risk: "write",
    action,
    safeSummary: { operation: "x.tweet.delete", tweetId },
    policyArgs: { tweetId },
  };
}

// ─── x.user.me.read ───────────────────────────────────────────────────────────

const USER_ME_KEYS = new Set<string>([]);

function buildUserMeRead(rawArgs: unknown): XActionBuild {
  // Accept a missing/empty args object; any field is unknown.
  const args = rawArgs === undefined ? {} : asObject(rawArgs);
  rejectUnknownKeys(args, USER_ME_KEYS);

  const action = canonicalizeRawInternalXAction({
    method: "GET",
    origin: "https://api.x.com",
    path: "/2/users/me",
    // Fixed query, single pair. The shared canonicalizer sorts + validates it.
    query: [["user.fields", "id,name,username"]],
  });

  return {
    operationKey: "x.user.me.read",
    method: "GET",
    risk: "read",
    action,
    safeSummary: { operation: "x.user.me.read" },
    policyArgs: {},
  };
}

/**
 * Validate + canonicalize the arguments for an X operation. Throws
 * {@link CanonError} (never a 500) on any argument or canonicalization ambiguity.
 */
export function buildXAction(operationKey: XOperationKey, args: unknown): XActionBuild {
  switch (operationKey) {
    case "x.tweet.create":
      return buildTweetCreate(args);
    case "x.tweet.delete":
      return buildTweetDelete(args);
    case "x.user.me.read":
      return buildUserMeRead(args);
    default: {
      const _never: never = operationKey;
      throw new CanonError("CANON_PROFILE_UNSUPPORTED", `unknown operation '${String(_never)}'`);
    }
  }
}
