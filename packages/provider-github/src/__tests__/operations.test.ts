/**
 * GitHub adapter operation-schema tests.
 *
 * Proves: strict argument validation (unknown/missing/typed/range fields deny
 * with stable CANON_* codes), dynamic path segments are validated (not
 * concatenated raw), canonical action construction is deterministic and matches
 * the shared canonicalizer, and safe_summary never leaks comment text. Also
 * re-runs the golden corpus as a REQUIRED consumer suite (spec §9.1).
 */

import { describe, expect, it } from "bun:test";
import {
  CanonError,
  canonicalActionBytes,
  computeActionDigest,
  computeRequestHash,
  GOLDEN_VECTORS,
  goldenEnvelope,
} from "@stwd/shared";
import { buildGithubAction, isGithubOperationKey } from "../operations.js";

function expectCanon(fn: () => unknown, code: string) {
  try {
    fn();
    throw new Error(`expected CanonError ${code} but none thrown`);
  } catch (e) {
    if (!(e instanceof CanonError)) throw e;
    expect(e.code).toBe(code);
  }
}

describe("golden corpus re-run (adapter consumer suite)", () => {
  it("has exactly 17 vectors and each reproduces its digests", () => {
    expect(GOLDEN_VECTORS).toHaveLength(17);
    for (const gv of GOLDEN_VECTORS) {
      expect(canonicalActionBytes(gv.action)).toBe(gv.canonicalActionBytes);
      expect(computeActionDigest(gv.action)).toBe(gv.actionDigest);
      expect(computeRequestHash(goldenEnvelope(gv.actionDigest))).toBe(gv.requestHash);
    }
  });
});

describe("github.issue.list", () => {
  it("builds a deterministic GET action with sorted query + fixed headers", () => {
    const b = buildGithubAction("github.issue.list", {
      owner: "octo",
      repo: "hello",
      state: "open",
      perPage: 30,
    });
    expect(b.method).toBe("GET");
    expect(b.action.normalizedPath).toBe("/repos/octo/hello/issues");
    // query sorted bytewise by encoded name: per_page < state
    expect(b.action.orderedQueryPairs).toEqual([
      ["per_page", "30"],
      ["state", "open"],
    ]);
    // headers sorted by lowercase name: accept < x-github-api-version
    expect(b.action.selectedHeaders).toEqual([
      ["accept", "application/vnd.github+json"],
      ["x-github-api-version", "2022-11-28"],
    ]);
    expect(b.action.canonicalBody).toBeNull();
    // deterministic
    const b2 = buildGithubAction("github.issue.list", {
      repo: "hello",
      owner: "octo",
      perPage: 30,
      state: "open",
    });
    expect(computeActionDigest(b2.action)).toBe(computeActionDigest(b.action));
  });

  it("rejects unknown, missing, mistyped, and out-of-range arguments", () => {
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "r", nope: 1 }),
      "CANON_UNKNOWN_FIELD",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { repo: "r" }),
      "CANON_REQUIRED_FIELD_MISSING",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: 5, repo: "r" }),
      "CANON_FIELD_TYPE_INVALID",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "r", state: "weird" }),
      "CANON_QUERY_VALUE_OUT_OF_RANGE",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "r", perPage: 0 }),
      "CANON_QUERY_VALUE_OUT_OF_RANGE",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "r", perPage: 1.5 }),
      "CANON_NUMBER_FORMAT_UNSUPPORTED",
    );
  });

  it("rejects path-injection via owner/repo (validated segments, not raw concat)", () => {
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "a/b", repo: "r" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "../x" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: ".." }),
      "CANON_PATH_SEGMENT_INVALID",
    );
    expectCanon(
      () => buildGithubAction("github.issue.list", { owner: "o", repo: "a b" }),
      "CANON_PATH_SEGMENT_INVALID",
    );
  });
});

describe("github.pr.comment.create", () => {
  it("builds a deterministic POST action with JSON body + content-type", () => {
    const b = buildGithubAction("github.pr.comment.create", {
      owner: "octo",
      repo: "hello",
      pullNumber: 42,
      body: "looks good",
    });
    expect(b.method).toBe("POST");
    expect(b.action.normalizedPath).toBe("/repos/octo/hello/issues/42/comments");
    expect(b.action.canonicalBody).toEqual({ body: "looks good" });
    expect(b.action.selectedHeaders).toEqual([
      ["accept", "application/vnd.github+json"],
      ["content-type", "application/json"],
      ["x-github-api-version", "2022-11-28"],
    ]);
  });

  it("safe_summary shows byte length + sha256, never the comment text", () => {
    const secret = "super secret internal note";
    const b = buildGithubAction("github.pr.comment.create", {
      owner: "o",
      repo: "r",
      pullNumber: 1,
      body: secret,
    });
    const s = JSON.stringify(b.safeSummary);
    expect(s).not.toContain(secret);
    expect(b.safeSummary.bodyByteLength).toBe(Buffer.from(secret, "utf8").length);
    expect(String(b.safeSummary.bodySha256)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects empty body, oversize body, unknown fields, missing required", () => {
    expectCanon(
      () =>
        buildGithubAction("github.pr.comment.create", {
          owner: "o",
          repo: "r",
          pullNumber: 1,
          body: "",
        }),
      "CANON_BODY_REQUIRED",
    );
    expectCanon(
      () =>
        buildGithubAction("github.pr.comment.create", {
          owner: "o",
          repo: "r",
          pullNumber: 1,
          body: "x".repeat(65537),
        }),
      "CANON_FIELD_TYPE_INVALID",
    );
    expectCanon(
      () =>
        buildGithubAction("github.pr.comment.create", {
          owner: "o",
          repo: "r",
          pullNumber: 1,
          body: "hi",
          extra: 1,
        }),
      "CANON_UNKNOWN_FIELD",
    );
    expectCanon(
      () => buildGithubAction("github.pr.comment.create", { owner: "o", repo: "r", body: "hi" }),
      "CANON_REQUIRED_FIELD_MISSING",
    );
    expectCanon(
      () =>
        buildGithubAction("github.pr.comment.create", {
          owner: "o",
          repo: "r",
          pullNumber: 0,
          body: "hi",
        }),
      "CANON_QUERY_VALUE_OUT_OF_RANGE",
    );
  });
});

describe("operation-key guard", () => {
  it("recognizes only the two supported operations", () => {
    expect(isGithubOperationKey("github.issue.list")).toBe(true);
    expect(isGithubOperationKey("github.pr.comment.create")).toBe(true);
    expect(isGithubOperationKey("github.repo.delete")).toBe(false);
    expect(isGithubOperationKey(42)).toBe(false);
  });
});
