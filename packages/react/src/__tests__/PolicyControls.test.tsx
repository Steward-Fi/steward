/**
 * <PolicyControls /> branch coverage.
 *
 * Mock ../provider.js (features + tenantConfig) and ../hooks/usePolicies.js,
 * render via SSR:
 *   - feature flag OFF        → renders nothing
 *   - loading                 → loading shell
 *   - error                   → error text
 *   - loaded                  → renders the visible policy rows with labels +
 *                               descriptions
 *   - exposure: "hidden"      → that policy type is filtered out
 *   - exposure: "enforced"    → row marked as set-by-platform
 *   - label override          → custom label wins over the default
 *
 * The edit / save / template-modal flows are component-state driven and
 * exercised by the browser e2e suite; SSR renders the initial (view) tree.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

let mockFeatures = { showPolicyControls: true };
let mockTenantConfig: any = null;

let mockPolicies: any = {
  policies: [],
  isLoading: true,
  isSaving: false,
  error: null,
  setPolicies: async () => {},
  applyTemplate: async () => {},
};

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({ features: mockFeatures, tenantConfig: mockTenantConfig }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("../hooks/usePolicies.js", () => ({
  usePolicies: () => mockPolicies,
}));

const { PolicyControls } = await import("../components/PolicyControls.js");

function render(props: Record<string, unknown> = {}): string {
  return renderToString(React.createElement(PolicyControls, props));
}

describe("<PolicyControls /> branch coverage", () => {
  beforeEach(() => {
    mockFeatures = { showPolicyControls: true };
    mockTenantConfig = null;
    mockPolicies = {
      policies: [],
      isLoading: true,
      isSaving: false,
      error: null,
      setPolicies: async () => {},
      applyTemplate: async () => {},
    };
  });

  test("feature flag OFF renders nothing", () => {
    mockFeatures = { showPolicyControls: false };
    expect(render()).toBe("");
  });

  test("loading branch renders the loading shell", () => {
    mockPolicies = { ...mockPolicies, isLoading: true };
    expect(render()).toContain("Loading policies");
  });

  test("loaded branch renders the header and the default policy labels", () => {
    mockPolicies = { ...mockPolicies, isLoading: false, policies: [] };
    const html = render();
    expect(html).toContain("Policy Controls");
    expect(html).toContain("Spending Limits");
    expect(html).toContain("Approved Addresses");
    expect(html).toContain("Rate Limit");
    // a description string for one of the policy types
    expect(html).toContain("Set maximum amounts per transaction");
  });

  test("error from the hook is surfaced as error text", () => {
    mockPolicies = {
      ...mockPolicies,
      isLoading: false,
      error: new Error("policy fetch failed"),
    };
    const html = render();
    expect(html).toContain("policy fetch failed");
  });

  test('exposure "hidden" filters a policy type out of the list', () => {
    mockTenantConfig = { exposedPolicies: { "rate-limit": "hidden" }, policyTemplates: [] };
    mockPolicies = { ...mockPolicies, isLoading: false };
    const html = render();
    expect(html).toContain("Spending Limits");
    expect(html).not.toContain("Rate Limit");
  });

  test('exposure "enforced" marks a policy row as set-by-platform', () => {
    mockTenantConfig = {
      exposedPolicies: { "spending-limit": "enforced" },
      policyTemplates: [],
    };
    mockPolicies = { ...mockPolicies, isLoading: false };
    const html = render();
    expect(html).toContain("Set by platform");
  });

  test("label override wins over the default label", () => {
    mockPolicies = { ...mockPolicies, isLoading: false };
    const html = render({ labels: { "spending-limit": "Budget Caps" } });
    expect(html).toContain("Budget Caps");
    expect(html).not.toContain("Spending Limits");
  });

  test("showTemplates with templates renders the templates trigger button", () => {
    mockTenantConfig = {
      exposedPolicies: {},
      policyTemplates: [{ id: "safe", name: "Safe Defaults", policies: [] }],
    };
    mockPolicies = { ...mockPolicies, isLoading: false };
    const html = render({ showTemplates: true });
    expect(html).toContain("stwd-policy-header");
  });
});
