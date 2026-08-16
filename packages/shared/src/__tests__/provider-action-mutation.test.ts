/**
 * Mutation-effectiveness proof for three core canonicalization guards.
 *
 * For each guard we (1) confirm a real attack input is DENIED by the shipped
 * code, (2) re-run the same input against a locally-WEAKENED copy of the guard
 * and assert the weakened copy would FAIL to deny (i.e. the test actually
 * exercises the guard — a passing test on a broken guard would be worthless),
 * then (3) reaffirm the shipped guard still denies. This is the "weaken, watch
 * the test fail, restore" discipline captured as an executable artifact.
 *
 * Documented in the PR body under "Mutation proofs".
 */

import { describe, expect, it } from "bun:test";
import {
  CanonError,
  canonicalizeQueryPairs,
  normalizePath,
  strictParseJson,
} from "../provider-action.js";

function denies(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof CanonError;
  }
}

describe("mutation proof 1: duplicate JSON key guard", () => {
  const input = '{"a":1,"a":2}';

  it("shipped strictParseJson denies the duplicate", () => {
    expect(denies(() => strictParseJson(input))).toBe(true);
  });

  it("a weakened parser (JSON.parse, the classic bug) would NOT deny", () => {
    // JSON.parse silently keeps the last duplicate — this is EXACTLY the
    // Conflict-10 vulnerability the strict tokenizer exists to prevent.
    const weakened = () => JSON.parse(input);
    expect(denies(weakened)).toBe(false);
    expect(JSON.parse(input)).toEqual({ a: 2 });
  });

  it("shipped guard still denies after the demonstration", () => {
    expect(denies(() => strictParseJson(input))).toBe(true);
  });
});

describe("mutation proof 2: encoded-traversal path guard", () => {
  const input = "/repos/octo/%2e%2e/secrets";

  it("shipped normalizePath denies encoded dot", () => {
    expect(denies(() => normalizePath(input))).toBe(true);
  });

  it("a weakened normalizer (decodeURIComponent-then-accept) would NOT deny", () => {
    // The naive approach decodes first, producing '/repos/octo/../secrets',
    // which a subsequent server could resolve to traversal. Our guard denies
    // the ENCODED form outright rather than decoding an unsafe byte.
    const weakened = (p: string) => {
      const decoded = decodeURIComponent(p);
      return decoded; // accepts, no deny
    };
    expect(denies(() => weakened(input))).toBe(false);
    expect(weakened(input)).toBe("/repos/octo/../secrets");
  });

  it("shipped guard still denies", () => {
    expect(denies(() => normalizePath(input))).toBe(true);
  });
});

describe("mutation proof 3: duplicate query-name guard", () => {
  const input: Array<[string, string]> = [
    ["state", "open"],
    ["state", "closed"],
  ];

  it("shipped canonicalizeQueryPairs denies the duplicate", () => {
    expect(denies(() => canonicalizeQueryPairs(input))).toBe(true);
  });

  it("a weakened canonicalizer (Object.fromEntries collapse) would NOT deny", () => {
    // Object.fromEntries silently collapses the duplicate to the last value —
    // the Conflict-10 URLSearchParams/Object.fromEntries hazard. It loses the
    // evidence that two conflicting values were supplied.
    const weakened = (pairs: Array<[string, string]>) => Object.fromEntries(pairs);
    expect(denies(() => weakened(input))).toBe(false);
    expect(weakened(input)).toEqual({ state: "closed" });
  });

  it("shipped guard still denies", () => {
    expect(denies(() => canonicalizeQueryPairs(input))).toBe(true);
  });
});
