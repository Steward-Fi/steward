/**
 * Tests for useSpend().
 *
 * Covers the deterministic surface: initial return shape and the refetch()
 * URL construction (encoded agentId + range query param). The mount-time
 * polling fetch is effect-driven and covered by the browser e2e suite.
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: { getBaseUrl: () => "https://api.test" },
    agentId: "a b", // space to verify encoding
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useSpend } = await import("../hooks/useSpend.js");

type UseSpendReturn = ReturnType<typeof useSpend>;

function captureHook(range?: Parameters<typeof useSpend>[0]): UseSpendReturn {
  let captured: UseSpendReturn | null = null;
  function Probe() {
    captured = useSpend(range);
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useSpend()", () => {
  beforeEach(() => {
    fetchMock = mock(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true, data: { range: "7d" } }),
    }));
    globalThis.fetch = fetchMock as any;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("initial return shape: loading, null stats, no error", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.stats).toBeNull();
    expect(api.error).toBeNull();
    expect(typeof api.refetch).toBe("function");
  });

  test("refetch hits the spend-stats endpoint with the default 7d range", async () => {
    const api = captureHook();
    await api.refetch();
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toBe("https://api.test/agents/a%20b/spend-stats?range=7d");
  });

  test("refetch honors a custom range", async () => {
    const api = captureHook("30d");
    await api.refetch();
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("range=30d");
  });
});
