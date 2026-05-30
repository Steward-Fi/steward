/**
 * Tests for usePolicies().
 *
 * The test runner has no jsdom and renderToString does not flush effects, so
 * we focus on the logic that lives in the returned callbacks rather than
 * effect-driven fetches. We mock ../provider.js to inject a fake
 * StewardContext (client + tenantConfig) and capture the hook's return value
 * via an SSR probe, then drive `setPolicies` / `applyTemplate` directly and
 * assert against the mocked client + the thrown errors.
 *
 * Effect-driven initial fetch (fetchPolicies on mount) is covered by the
 * browser e2e suite; SSR cannot flush it.
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

type PolicyRule = { type: string; config: Record<string, unknown> };

const setPoliciesMock = mock(async (_agentId: string, _policies: PolicyRule[]) => {});
const getPoliciesMock = mock(async (_agentId: string) => [] as PolicyRule[]);

let mockTenantConfig: {
  policyTemplates: Array<{ id: string; policies: PolicyRule[] }>;
} | null = null;

// NOTE on isolation: bun's `mock.module` is process-global. This suite is run
// one-file-per-process by the package's test script
// (`for f in src/__tests__/*.test.*; do bun test "$f"; done`), which is what
// keeps each file's `../provider.js` / hook-module mocks from clobbering each
// other. Run individual files (or via `bun run test`) rather than a single
// `bun test <glob>` over the whole directory.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      getPolicies: getPoliciesMock,
      setPolicies: setPoliciesMock,
      getBaseUrl: () => "https://api.test",
    },
    agentId: "agent-1",
    tenantConfig: mockTenantConfig,
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { usePolicies } = await import("../hooks/usePolicies.js");

type UsePoliciesReturn = ReturnType<typeof usePolicies>;

function captureHook(): UsePoliciesReturn {
  let captured: UsePoliciesReturn | null = null;
  function Probe() {
    captured = usePolicies();
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

describe("usePolicies()", () => {
  beforeEach(() => {
    setPoliciesMock.mockClear();
    getPoliciesMock.mockClear();
    mockTenantConfig = null;
  });

  test("initial return shape: loading, empty policies, no error", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.policies).toEqual([]);
    expect(api.error).toBeNull();
    expect(api.isSaving).toBe(false);
    expect(typeof api.setPolicies).toBe("function");
    expect(typeof api.applyTemplate).toBe("function");
    expect(typeof api.refetch).toBe("function");
  });

  test("setPolicies forwards the policies to client.setPolicies", async () => {
    const api = captureHook();
    const next: PolicyRule[] = [{ type: "spend_limit", config: { daily: "1000" } }];
    await api.setPolicies(next);
    expect(setPoliciesMock).toHaveBeenCalledTimes(1);
    expect(setPoliciesMock.mock.calls[0]).toEqual(["agent-1", next]);
  });

  test("setPolicies rethrows when the client rejects", async () => {
    setPoliciesMock.mockImplementationOnce(async () => {
      throw new Error("network down");
    });
    const api = captureHook();
    await expect(api.setPolicies([])).rejects.toThrow("network down");
  });

  test("applyTemplate throws when the template id is unknown", async () => {
    mockTenantConfig = { policyTemplates: [{ id: "conservative", policies: [] }] };
    const api = captureHook();
    await expect(api.applyTemplate("does-not-exist")).rejects.toThrow(
      'Template "does-not-exist" not found',
    );
  });

  test("applyTemplate clones the template and saves it (no overrides)", async () => {
    const templatePolicies: PolicyRule[] = [{ type: "spend_limit", config: { daily: "5" } }];
    mockTenantConfig = {
      policyTemplates: [{ id: "default", policies: templatePolicies }],
    };
    const api = captureHook();
    await api.applyTemplate("default");
    expect(setPoliciesMock).toHaveBeenCalledTimes(1);
    const savedArg = setPoliciesMock.mock.calls[0][1];
    expect(savedArg).toEqual(templatePolicies);
    // structuredClone => not the same reference as the template source.
    expect(savedArg).not.toBe(templatePolicies);
    expect(savedArg[0]).not.toBe(templatePolicies[0]);
  });

  test("applyTemplate applies a top-level field override before saving", async () => {
    mockTenantConfig = {
      policyTemplates: [{ id: "tpl", policies: [{ type: "spend_limit", config: { daily: "1" } }] }],
    };
    const api = captureHook();
    await api.applyTemplate("tpl", { "spend_limit.daily": "999" });
    const saved = setPoliciesMock.mock.calls[0][1] as PolicyRule[];
    expect(saved[0].config.daily).toBe("999");
  });

  test("applyTemplate applies a nested field override before saving", async () => {
    mockTenantConfig = {
      policyTemplates: [
        {
          id: "tpl",
          policies: [{ type: "allowlist", config: { limits: { perTx: "1" } } }],
        },
      ],
    };
    const api = captureHook();
    await api.applyTemplate("tpl", { "allowlist.limits.perTx": "42" });
    const saved = setPoliciesMock.mock.calls[0][1] as PolicyRule[];
    expect((saved[0].config.limits as Record<string, unknown>).perTx).toBe("42");
  });
});
