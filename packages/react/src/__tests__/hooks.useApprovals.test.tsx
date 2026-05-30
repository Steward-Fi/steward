/**
 * Tests for useApprovals().
 *
 * Effect-driven polling fetch is not flushed by SSR, so we focus on the
 * approve() / reject() callbacks which call the global `fetch` with the right
 * URL + method + body. We mock `fetch` per-test and capture the hook return
 * via an SSR probe. The optimistic `setPending` filter is a post-render state
 * update that SSR cannot observe; the network contract is what matters and is
 * fully asserted here.
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
    agentId: "agent x", // contains a space to verify URL encoding
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useApprovals } = await import("../hooks/useApprovals.js");

type UseApprovalsReturn = ReturnType<typeof useApprovals>;

function captureHook(): UseApprovalsReturn {
  let captured: UseApprovalsReturn | null = null;
  function Probe() {
    captured = useApprovals();
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useApprovals()", () => {
  beforeEach(() => {
    fetchMock = mock(async () => ({ ok: true, status: 200, json: async () => ({}) }));
    globalThis.fetch = fetchMock as any;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("initial return shape: loading, empty pending, not resolving", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.pending).toEqual([]);
    expect(api.error).toBeNull();
    expect(api.isResolving).toBe(false);
    expect(typeof api.approve).toBe("function");
    expect(typeof api.reject).toBe("function");
    expect(typeof api.refetch).toBe("function");
  });

  test("approve() POSTs to the encoded approve endpoint", async () => {
    const api = captureHook();
    await api.approve("tx-123");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    // agentId "agent x" must be percent-encoded.
    expect(url).toBe("https://api.test/agents/agent%20x/approvals/tx-123/approve");
    expect(opts.method).toBe("POST");
  });

  test("approve() throws on a non-ok response", async () => {
    fetchMock = mock(async () => ({ ok: false, status: 500, json: async () => ({}) }));
    globalThis.fetch = fetchMock as any;
    const api = captureHook();
    await expect(api.approve("tx-1")).rejects.toThrow("Approve failed: 500");
  });

  test("reject() POSTs the reason in the JSON body", async () => {
    const api = captureHook();
    await api.reject("tx-9", "looks sketchy");
    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://api.test/agents/agent%20x/approvals/tx-9/reject");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(String(opts.body))).toEqual({ reason: "looks sketchy" });
  });

  test("reject() throws on a non-ok response", async () => {
    fetchMock = mock(async () => ({ ok: false, status: 403, json: async () => ({}) }));
    globalThis.fetch = fetchMock as any;
    const api = captureHook();
    await expect(api.reject("tx-2")).rejects.toThrow("Reject failed: 403");
  });
});
