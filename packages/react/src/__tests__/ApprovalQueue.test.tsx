/**
 * <ApprovalQueue /> branch coverage.
 *
 * Mock ../provider.js (feature flags) + ../hooks/useApprovals.js, render via
 * SSR, assert on emitted HTML:
 *   - feature flag OFF      → renders nothing
 *   - loading               → loading shell
 *   - error                 → error shell
 *   - empty pending list    → "No pending approvals" empty state
 *   - non-empty list        → renders rows with truncated addr, value, count
 *   - policy reasons        → shows triggered (failed) policy results
 *
 * The confirm-dialog flow is driven by component state (setConfirmAction) and
 * the approve/reject hook callbacks; that interaction is exercised at the hook
 * level in hooks.useApprovals.test.tsx and in the browser e2e suite. SSR only
 * renders the initial (no-dialog) tree.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

type Features = { showApprovalQueue: boolean };
let mockFeatures: Features = { showApprovalQueue: true };

let mockApprovals: any = {
  pending: [],
  isLoading: true,
  error: null,
  approve: async () => {},
  reject: async () => {},
  isResolving: false,
};

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({ features: mockFeatures }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("../hooks/useApprovals.js", () => ({
  useApprovals: () => mockApprovals,
}));

const { ApprovalQueue } = await import("../components/ApprovalQueue.js");

function render(props: Record<string, unknown> = {}): string {
  return renderToString(React.createElement(ApprovalQueue, props));
}

describe("<ApprovalQueue /> branch coverage", () => {
  beforeEach(() => {
    mockFeatures = { showApprovalQueue: true };
    mockApprovals = {
      pending: [],
      isLoading: true,
      error: null,
      approve: async () => {},
      reject: async () => {},
      isResolving: false,
    };
  });

  test("feature flag OFF renders nothing", () => {
    mockFeatures = { showApprovalQueue: false };
    expect(render()).toBe("");
  });

  test("loading branch renders the loading shell", () => {
    mockApprovals = { ...mockApprovals, isLoading: true };
    expect(render()).toContain("Loading approvals");
  });

  test("error branch renders the error message", () => {
    mockApprovals = { ...mockApprovals, isLoading: false, error: new Error("nope") };
    const html = render();
    expect(html).toContain("Failed to load approvals");
    expect(html).toContain("nope");
  });

  test("empty pending list renders the empty state", () => {
    mockApprovals = { ...mockApprovals, isLoading: false, pending: [] };
    expect(render()).toContain("No pending approvals");
  });

  test("non-empty list renders rows with the pending count badge", () => {
    mockApprovals = {
      ...mockApprovals,
      isLoading: false,
      pending: [
        {
          id: "a1",
          txId: "tx-1",
          to: "0x1234567890abcdef1234567890abcdef12345678",
          value: "1000000000000000000",
          chainId: 8453,
          createdAt: new Date(),
          policyResults: [],
        },
      ],
    };
    const html = render();
    expect(html).toContain("Pending Approvals");
    expect(html).toContain("stwd-approval-list");
    // truncated destination address
    expect(html).toContain("0x1234...5678");
    // value formatted to ETH (1.0000)
    expect(html).toContain("1.0000");
    expect(html).toContain("Approve");
    expect(html).toContain("Deny");
  });

  test("renders triggered (failed) policy reasons when showPolicyReason is on", () => {
    mockApprovals = {
      ...mockApprovals,
      isLoading: false,
      pending: [
        {
          id: "a1",
          txId: "tx-1",
          to: "0xabc0000000000000000000000000000000000def",
          value: "0",
          chainId: 1,
          createdAt: new Date(),
          policyResults: [
            { type: "spend_limit", passed: false, reason: "daily cap exceeded" },
            { type: "allowlist", passed: true },
          ],
        },
      ],
    };
    const html = render({ showPolicyReason: true });
    expect(html).toContain("Triggered policies");
    expect(html).toContain("spend_limit");
    expect(html).toContain("daily cap exceeded");
    // The passing policy should not surface as a triggered reason.
    expect(html).not.toContain("allowlist");
  });

  test("hides policy reasons when showPolicyReason is false", () => {
    mockApprovals = {
      ...mockApprovals,
      isLoading: false,
      pending: [
        {
          id: "a1",
          txId: "tx-1",
          to: "0xabc0000000000000000000000000000000000def",
          value: "0",
          chainId: 1,
          createdAt: new Date(),
          policyResults: [{ type: "spend_limit", passed: false, reason: "x" }],
        },
      ],
    };
    const html = render({ showPolicyReason: false });
    expect(html).not.toContain("Triggered policies");
  });
});
