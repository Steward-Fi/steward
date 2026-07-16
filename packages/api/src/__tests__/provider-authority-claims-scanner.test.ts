/**
 * PR6 prohibited-claim scanner (U8 / PN38).
 *
 * A seeded claims-discipline guard (the full generalized scanner is PR10; this
 * is the PR6 seed scoped to the PR6 docs). It asserts the PR6 provider-authority
 * docs do NOT assert any of the prohibited pre-real-proof claims: MPC,
 * operator-proof, exactly-once, SOC2, or product-wide enforcement. Doc text that
 * explicitly NEGATES a claim ("NOT an operator-integrity proof", "does not use
 * MPC") is allowed — the scanner flags AFFIRMATIVE claims only.
 *
 * Mutation guard: flipping a doc to an affirmative prohibited claim (e.g. "this
 * is exactly-once") must fail this test.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";

const DOCS_ROOT = join(import.meta.dir, "..", "..", "..", "..", "docs");
const PR6_DOCS = [
  join(DOCS_ROOT, "guides", "provider-authority-golden-path.mdx"),
  join(DOCS_ROOT, "security", "provider-authority-threat-model.mdx"),
  join(DOCS_ROOT, "runbooks", "provider-authority-operations.mdx"),
];

/**
 * Affirmative prohibited-claim patterns. Each is an ASSERTION of a guarantee.
 * The negating forms ("not exactly-once", "does not use MPC", "NOT a SOC2
 * attestation") are intentionally NOT matched — the docs are REQUIRED to state
 * those negations.
 */
const PROHIBITED = [
  // "is exactly-once" / "guarantees exactly-once" — but not "not exactly-once".
  /\b(is|are|provides?|guarantees?)\s+exactly[- ]once\b/i,
  // affirmative MPC claim.
  /\b(uses?|via|through|with)\s+MPC\b/i,
  // affirmative operator-integrity/operator-proof claim.
  /\b(is|provides?|proves?)\s+(an?\s+)?operator[- ](integrity|proof)\b/i,
  // affirmative SOC2 attestation claim.
  /\b(is|provides?|holds?)\s+(an?\s+)?SOC\s?2\b/i,
  // product-wide enforcement claim.
  /\b(enforced|enforcement)\s+(product[- ]wide|across the (whole|entire) product)\b/i,
];

function stripNegatingContext(line: string): string {
  // Remove clauses that clearly NEGATE, so a nearby negation doesn't get
  // mistaken for an affirmative claim on the same line.
  return line
    .replace(/\bnot\b[^.]*/gi, "")
    .replace(/\bnever\b[^.]*/gi, "")
    .replace(/\bdoes not\b[^.]*/gi, "")
    .replace(/\bwithout\b[^.]*/gi, "");
}

describe("PR6 prohibited-claim scanner (U8/PN38)", () => {
  for (const path of PR6_DOCS) {
    test(`no affirmative prohibited claim in ${path.split("/docs/")[1]}`, () => {
      const text = readFileSync(path, "utf8");
      const offenders: string[] = [];
      for (const rawLine of text.split(/\r?\n/)) {
        const line = stripNegatingContext(rawLine);
        for (const re of PROHIBITED) {
          if (re.test(line)) offenders.push(`${re} :: ${rawLine.trim()}`);
        }
      }
      expect(offenders).toEqual([]);
    });
  }

  test("the threat-model doc DOES state the required negations (fail-closed on missing)", () => {
    const tm = readFileSync(PR6_DOCS[1], "utf8");
    // These explicit negations are REQUIRED (U8): their absence is a gate
    // failure. Markdown emphasis (**not**) is tolerated between tokens.
    expect(tm).toMatch(/operator-integrity proof/i);
    expect(tm).toMatch(/exactly-once/i);
    expect(tm).toMatch(/MPC/);
    expect(tm).toMatch(/SOC\s?2/i);
    // And each appears in a NEGATED sentence (the doc's "What is NOT claimed"
    // section explicitly negates all four).
    expect(tm).toMatch(/not\b[\s\S]{0,80}operator-integrity proof/i);
    expect(tm).toMatch(/not\b[\s\S]{0,40}exactly-once/i);
    expect(tm).toMatch(/not\b[\s\S]{0,20}use MPC/i);
    expect(tm).toMatch(/not\b[\s\S]{0,20}SOC2|not\b[\s\S]{0,20}SOC 2/i);
  });
});
