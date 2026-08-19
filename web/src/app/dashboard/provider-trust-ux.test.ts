// @ts-nocheck
/**
 * Provider-authority trust-UX invariants (U4/U5). The browser accessibility
 * suite exercises the rendered approval flow; these complementary structural
 * assertions pin non-enumeration, completeness, fingerprint, bulk-action, and
 * credential-surface properties that its happy-path fixture does not cover.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const HERE = import.meta.dir;
const approvalDetail = readFileSync(join(HERE, "approvals", "[id]", "page.tsx"), "utf8");
const caseDetail = readFileSync(join(HERE, "actions", "[id]", "page.tsx"), "utf8");
const approvalsList = readFileSync(join(HERE, "approvals", "page.tsx"), "utf8");
const clientLib = readFileSync(join(HERE, "..", "..", "lib", "provider-actions.ts"), "utf8");

describe("provider-authority approval-detail UX (U4)", () => {
  test("M11: approve and deny are equal-weight (identical button classes + flex-1)", () => {
    // Both decision buttons share the SAME class list and flex-1 (equal width).
    const buttonClass =
      "flex-1 px-4 py-2 text-sm font-600 border border-border bg-bg-elevated hover:bg-bg-surface transition-colors focus:outline-none focus:ring-2 focus:ring-accent disabled:opacity-40 disabled:cursor-not-allowed";
    const occurrences = approvalDetail.split(buttonClass).length - 1;
    expect(occurrences).toBe(2); // approve and deny use byte-identical styling
    expect(approvalDetail).toContain('aria-label="Approve this provider action"');
    expect(approvalDetail).toContain('aria-label="Deny this provider action"');
  });

  test("M13: a typed reason is required for BOTH decisions (client block)", () => {
    expect(approvalDetail).toContain("A typed reason is required for both approve and deny.");
    expect(approvalDetail).toContain("if (reason.trim().length === 0)");
    expect(approvalDetail).toContain('aria-required="true"');
  });

  test("PN35: only safe summary + digests are rendered, NEVER canonical bytes", () => {
    // The page renders digests + safeSummary; it must not read a canonicalBytes /
    // canonicalActionBytes / commentBody field (those never leave the API).
    expect(approvalDetail).toContain("detail.actionDigest");
    expect(approvalDetail).toContain("detail.safeSummary");
    // No field-access to canonical bytes / comment body (those never leave the
    // API). Match property access forms, not prose in comments.
    expect(approvalDetail).not.toMatch(
      /\.canonicalBytes\b|\.canonicalActionBytes\b|\.commentBody\b|detail\.body\b/,
    );
  });

  test("honest terminal state disables decision controls", () => {
    expect(approvalDetail).toContain("isDecidableStatus");
    expect(approvalDetail).toContain("disabled={!decidable || submitting !== null}");
    expect(approvalDetail).toContain("Decision controls are disabled");
  });

  test("M12: the approvals LIST exposes no one-click bulk-approve control", () => {
    // No bulk/select-all/approve-all affordance on the list page.
    expect(approvalsList).not.toMatch(/bulk[- ]?approve|approve[- ]?all|select[- ]?all/i);
  });
});

describe("provider-authority case/evidence UX (U5)", () => {
  test("PN34: completeness is rendered VERBATIM and never upgraded", () => {
    expect(caseDetail).toContain("manifest.completeness");
    expect(caseDetail).toContain("manifest.incompletenessReasons");
    // Only `complete` reads as success; incomplete/unknown are warning-toned.
    expect(caseDetail).toContain('if (c === "complete") return');
    // The page must NOT hard-code "verified" / "complete" independent of the API.
    expect(caseDetail).not.toMatch(/completeness\s*=\s*["']complete["']/);
  });

  test("E7: the operator-key trust limit + fingerprint verify command are shown", () => {
    expect(caseDetail).toContain("--expected-key-fingerprint");
    expect(caseDetail).toContain("verify-evidence-bundle.mjs");
    expect(caseDetail).toContain("NOT an operator-integrity proof");
    expect(caseDetail).toContain("verifying against the embedded key");
  });

  test("no credential or canonical bytes are ever displayed", () => {
    expect(caseDetail).not.toMatch(/canonicalBytes|Bearer |ghp_|credential.*value/);
    // Only the HASH of the provider idempotency key is surfaced.
    expect(caseDetail).toContain("providerIdempotencyKeyHash");
  });
});

describe("provider-authority provider-actions client (safe surface)", () => {
  test("non-enumerating errors collapse to a uniform not-found/not-authorized", () => {
    expect(clientLib).toContain("ProviderActionError");
    expect(clientLib).toContain("not found / not authorized");
  });
});
