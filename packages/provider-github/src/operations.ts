/**
 * operations.ts — GitHub provider-action operation schemas + canonical action
 * construction (action-creation spec §2.2, §3.10).
 *
 * This adapter owns method, origin, path construction, header selection, and
 * body shape for the two action-creation operations. It validates operation ARGUMENTS
 * strictly (fail closed with stable CANON_* codes), builds a raw internal HTTP
 * representation, and runs it through the ONE shared canonicalizer
 * (`canonicalizeRawInternalAction`) so the action digest matches the golden
 * corpus byte-for-byte. Dynamic owner/repo/number segments are encoded from
 * VALIDATED values, never concatenated from a raw path.
 *
 * It also derives the non-authoritative `safe_summary` (§3.10) and the validated
 * policy-context arguments the provider policy composer reads (§6.3) — the policy
 * layer never lifts arbitrary scalar fields from raw JSON.
 */

import { createHash } from "node:crypto";
import {
  CANONICAL_ORIGIN,
  CanonError,
  type CanonicalMethod,
  canonicalizeRawInternalAction,
  type GithubCanonicalActionV1,
  type JsonValue,
} from "@stwd/shared";

export const GITHUB_OPERATION_KEYS = ["github.issue.list", "github.pr.comment.create"] as const;
export type GithubOperationKey = (typeof GITHUB_OPERATION_KEYS)[number];

export function isGithubOperationKey(v: unknown): v is GithubOperationKey {
  return typeof v === "string" && (GITHUB_OPERATION_KEYS as readonly string[]).includes(v);
}

/** The result of validating + canonicalizing an operation's arguments. */
export interface GithubActionBuild {
  operationKey: GithubOperationKey;
  method: CanonicalMethod;
  action: GithubCanonicalActionV1;
  /** Non-authoritative, adapter-derived display summary (§3.10). */
  safeSummary: Record<string, unknown>;
  /** Validated arguments a provider policy may read (§6.3). Never raw JSON. */
  policyArgs: Record<string, unknown>;
}

const GITHUB_API_VERSION = "2022-11-28";
const ACCEPT = "application/vnd.github+json";
const JSON_CONTENT_TYPE = "application/json";

// Owner: /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
// Repo: 1..100 ASCII [A-Za-z0-9._-], not "." or ".."
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;

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

function validateOwner(v: unknown): string {
  if (typeof v !== "string") fieldError("owner must be a string");
  if (!OWNER_RE.test(v)) throw new CanonError("CANON_PATH_SEGMENT_INVALID", `invalid owner '${v}'`);
  return v;
}

function validateRepo(v: unknown): string {
  if (typeof v !== "string") fieldError("repo must be a string");
  if (v === "." || v === ".." || !REPO_RE.test(v))
    throw new CanonError("CANON_PATH_SEGMENT_INVALID", `invalid repo '${v}'`);
  return v;
}

function validateSafeInt(v: unknown, name: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isInteger(v))
    throw new CanonError("CANON_NUMBER_FORMAT_UNSUPPORTED", `${name} must be an integer`);
  if (!Number.isSafeInteger(v))
    throw new CanonError("CANON_NUMBER_UNSAFE", `${name} is not a safe integer`);
  if (v < min || v > max)
    throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", `${name} out of range`);
  return v;
}

function validateEnum<T extends string>(v: unknown, name: string, values: readonly T[]): T {
  if (typeof v !== "string" || !(values as readonly string[]).includes(v))
    throw new CanonError("CANON_QUERY_VALUE_OUT_OF_RANGE", `invalid ${name} '${String(v)}'`);
  return v as T;
}

// ─── github.issue.list ────────────────────────────────────────────────────────

const ISSUE_LIST_KEYS = new Set(["owner", "repo", "state", "sort", "direction", "perPage", "page"]);

function buildIssueList(rawArgs: unknown): GithubActionBuild {
  const args = asObject(rawArgs);
  rejectUnknownKeys(args, ISSUE_LIST_KEYS);
  if (!("owner" in args)) requiredMissing("owner");
  if (!("repo" in args)) requiredMissing("repo");
  const owner = validateOwner(args.owner);
  const repo = validateRepo(args.repo);

  // Logical query pairs in insertion order; the shared canonicalizer sorts them.
  const query: Array<[string, string]> = [];
  if ("state" in args && args.state !== undefined) {
    query.push(["state", validateEnum(args.state, "state", ["open", "closed", "all"] as const)]);
  }
  if ("sort" in args && args.sort !== undefined) {
    query.push([
      "sort",
      validateEnum(args.sort, "sort", ["created", "updated", "comments"] as const),
    ]);
  }
  if ("direction" in args && args.direction !== undefined) {
    query.push(["direction", validateEnum(args.direction, "direction", ["asc", "desc"] as const)]);
  }
  if ("perPage" in args && args.perPage !== undefined) {
    query.push(["per_page", String(validateSafeInt(args.perPage, "perPage", 1, 100))]);
  }
  if ("page" in args && args.page !== undefined) {
    query.push(["page", String(validateSafeInt(args.page, "page", 1, 2147483647))]);
  }

  const action = canonicalizeRawInternalAction({
    method: "GET",
    origin: CANONICAL_ORIGIN,
    path: `/repos/${owner}/${repo}/issues`,
    query,
    headers: [
      ["accept", ACCEPT],
      ["x-github-api-version", GITHUB_API_VERSION],
    ],
  });

  const filters: Record<string, unknown> = {};
  for (const [k, v] of query) filters[k] = v;

  return {
    operationKey: "github.issue.list",
    method: "GET",
    action,
    safeSummary: { operation: "github.issue.list", owner, repo, filters },
    policyArgs: { owner, repo, ...Object.fromEntries(query) },
  };
}

// ─── github.pr.comment.create ─────────────────────────────────────────────────

const PR_COMMENT_KEYS = new Set(["owner", "repo", "pullNumber", "body"]);
const MAX_COMMENT_BYTES = 65536;

function validateCommentBody(v: unknown): string {
  if (typeof v !== "string") fieldError("body must be a string");
  if (v.length === 0) throw new CanonError("CANON_BODY_REQUIRED", "comment body must be nonempty");
  // Valid Unicode scalar values: reject lone surrogates.
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = v.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff))
        throw new CanonError("CANON_UNICODE_INVALID", "lone surrogate in comment body");
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonError("CANON_UNICODE_INVALID", "lone surrogate in comment body");
    }
  }
  const bytes = Buffer.from(v, "utf8").length;
  if (bytes > MAX_COMMENT_BYTES)
    throw new CanonError("CANON_FIELD_TYPE_INVALID", "comment body exceeds 65536 UTF-8 bytes");
  return v;
}

function buildPrComment(rawArgs: unknown): GithubActionBuild {
  const args = asObject(rawArgs);
  rejectUnknownKeys(args, PR_COMMENT_KEYS);
  for (const req of ["owner", "repo", "pullNumber", "body"]) {
    if (!(req in args)) requiredMissing(req);
  }
  const owner = validateOwner(args.owner);
  const repo = validateRepo(args.repo);
  const pullNumber = validateSafeInt(args.pullNumber, "pullNumber", 1, 2147483647);
  const body = validateCommentBody(args.body);

  const jsonBody: JsonValue = { body };

  const action = canonicalizeRawInternalAction({
    method: "POST",
    origin: CANONICAL_ORIGIN,
    path: `/repos/${owner}/${repo}/issues/${pullNumber}/comments`,
    headers: [
      ["accept", ACCEPT],
      ["x-github-api-version", GITHUB_API_VERSION],
    ],
    contentType: JSON_CONTENT_TYPE,
    body: jsonBody,
  });

  const byteLength = Buffer.from(body, "utf8").length;
  const bodySha256 = `sha256:${createHash("sha256").update(Buffer.from(body, "utf8")).digest("hex")}`;

  return {
    operationKey: "github.pr.comment.create",
    method: "POST",
    action,
    safeSummary: {
      operation: "github.pr.comment.create",
      owner,
      repo,
      pullNumber,
      bodyByteLength: byteLength,
      bodySha256,
    },
    policyArgs: { owner, repo, pullNumber, bodyByteLength: byteLength },
  };
}

/**
 * Validate + canonicalize the arguments for a GitHub operation. Throws
 * {@link CanonError} (never a 500) on any argument or canonicalization ambiguity.
 */
export function buildGithubAction(
  operationKey: GithubOperationKey,
  args: unknown,
): GithubActionBuild {
  switch (operationKey) {
    case "github.issue.list":
      return buildIssueList(args);
    case "github.pr.comment.create":
      return buildPrComment(args);
    default: {
      // Exhaustiveness guard: an unknown key is a profile/operation mismatch.
      const _never: never = operationKey;
      throw new CanonError("CANON_PROFILE_UNSUPPORTED", `unknown operation '${String(_never)}'`);
    }
  }
}
