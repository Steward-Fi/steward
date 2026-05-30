/**
 * Tests for useTransactions().
 *
 * SSR does not flush the polling effect, so state-driven pagination (page
 * advancing) is out of scope here and lives in the browser e2e suite. We
 * cover the deterministic surface:
 *   - initial return shape
 *   - refetch() builds the paginated-endpoint URL with the right query params
 *     (page, pageSize, status, chainId), all properly encoded
 *   - the getHistory() fallback path is taken when the paginated endpoint
 *     returns a non-ok / malformed response
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const getHistoryMock = mock(
  async (_agentId: string) => [] as Array<{ value: string; timestamp: number }>,
);

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      getBaseUrl: () => "https://api.test",
      getHistory: getHistoryMock,
    },
    agentId: "agent/1", // slash to verify encoding
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useTransactions } = await import("../hooks/useTransactions.js");

type UseTxReturn = ReturnType<typeof useTransactions>;

function captureHook(opts?: Parameters<typeof useTransactions>[0]): UseTxReturn {
  let captured: UseTxReturn | null = null;
  function Probe() {
    captured = useTransactions(opts);
    return null;
  }
  renderToString(React.createElement(Probe));
  if (!captured) throw new Error("hook did not render");
  return captured;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useTransactions()", () => {
  beforeEach(() => {
    getHistoryMock.mockClear();
    getHistoryMock.mockImplementation(async () => []);
    fetchMock = mock(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true, data: { transactions: [] } }),
    }));
    globalThis.fetch = fetchMock as any;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("initial return shape: loading, empty list, page 1, totalPages 1", () => {
    const api = captureHook();
    expect(api.isLoading).toBe(true);
    expect(api.transactions).toEqual([]);
    expect(api.error).toBeNull();
    expect(api.page).toBe(1);
    expect(api.totalPages).toBe(1);
    expect(typeof api.nextPage).toBe("function");
    expect(typeof api.prevPage).toBe("function");
    expect(typeof api.refetch).toBe("function");
  });

  test("refetch builds the paginated endpoint URL with default page/pageSize", async () => {
    const api = captureHook();
    await api.refetch();
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("https://api.test/agents/agent%2F1/transactions?");
    expect(url).toContain("page=1");
    expect(url).toContain("pageSize=20");
  });

  test("refetch includes status + chainId query params when provided", async () => {
    const api = captureHook({
      pageSize: 5,
      status: ["pending", "confirmed"],
      chainId: 8453,
    });
    await api.refetch();
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toContain("pageSize=5");
    // URLSearchParams encodes the comma in the joined status list.
    expect(url).toContain("status=pending%2Cconfirmed");
    expect(url).toContain("chainId=8453");
  });

  test("falls back to getHistory() when the paginated endpoint is not ok", async () => {
    fetchMock = mock(async () => ({ ok: false, status: 404, json: async () => ({}) }));
    globalThis.fetch = fetchMock as any;
    getHistoryMock.mockImplementation(async () => [
      { value: "1000000000000000000", timestamp: 1_700_000_000 },
    ]);
    const api = captureHook({ chainId: 56 });
    await api.refetch();
    expect(getHistoryMock).toHaveBeenCalledTimes(1);
    expect(getHistoryMock.mock.calls[0][0]).toBe("agent/1");
  });

  test("falls back to getHistory() when the paginated payload lacks transactions", async () => {
    fetchMock = mock(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ ok: true, data: {} }), // no transactions field
    }));
    globalThis.fetch = fetchMock as any;
    const api = captureHook();
    await api.refetch();
    expect(getHistoryMock).toHaveBeenCalledTimes(1);
  });
});
