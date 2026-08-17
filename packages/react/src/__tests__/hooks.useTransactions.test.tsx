/**
 * Tests for useTransactions().
 *
 * The hook fetches the credentialed history via client.getTransactionHistory
 * and filters/paginates client-side — the old raw-fetch "paginated endpoint"
 * never existed on the API and sent no credentials (SEC-195 regression).
 *
 * The test runner has no jsdom and renderToString does not flush effects, so
 * we assert on the mocked client calls and thrown errors via an SSR probe,
 * and cover the status/chain filtering (filterTransactions) as a pure
 * function.
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const getTransactionHistoryMock = mock(async (_agentId: string) => [] as any[]);

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      getTransactionHistory: getTransactionHistoryMock,
    },
    agentId: "agent/1",
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useTransactions, filterTransactions } = await import("../hooks/useTransactions.js");

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

function txRecord(overrides: Record<string, unknown> = {}) {
  return {
    id: "tx-1",
    agentId: "agent/1",
    status: "confirmed",
    request: { agentId: "agent/1", tenantId: "t", to: "0xabc", value: "100", chainId: 8453 },
    policyResults: [],
    createdAt: new Date("2026-01-01T00:00:00Z"),
    ...overrides,
  } as any;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useTransactions()", () => {
  beforeEach(() => {
    getTransactionHistoryMock.mockClear();
    getTransactionHistoryMock.mockImplementation(async () => []);
    fetchMock = mock(async () => {
      throw new Error("raw fetch must not be used");
    });
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

  test("refetch loads history through the credentialed client only", async () => {
    const api = captureHook();
    await api.refetch();
    expect(getTransactionHistoryMock).toHaveBeenCalledTimes(1);
    expect(getTransactionHistoryMock.mock.calls[0]?.[0]).toBe("agent/1");
    // SEC-195: no credential-less raw fetch on any path.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test("client errors do not reject refetch (state updates are SSR-invisible)", async () => {
    getTransactionHistoryMock.mockImplementation(async () => {
      throw new Error("history unavailable");
    });
    const api = captureHook();
    // The hook catches client errors into its error state; SSR cannot observe
    // the state write, but the call must resolve and never touch raw fetch.
    await api.refetch();
    expect(getTransactionHistoryMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("filterTransactions()", () => {
  const records = [
    txRecord({ id: "tx-ok", status: "confirmed" }),
    txRecord({ id: "tx-pending", status: "pending" }),
    txRecord({
      id: "tx-other-chain",
      status: "confirmed",
      request: { chainId: 56, to: "0xdef", value: "1" },
    }),
  ];

  test("no filters returns everything", () => {
    expect(filterTransactions(records as any, {}).map((t) => t.id)).toEqual([
      "tx-ok",
      "tx-pending",
      "tx-other-chain",
    ]);
  });

  test("filters by status list", () => {
    expect(filterTransactions(records as any, { status: ["confirmed"] }).map((t) => t.id)).toEqual([
      "tx-ok",
      "tx-other-chain",
    ]);
  });

  test("filters by chainId", () => {
    expect(filterTransactions(records as any, { chainId: 8453 }).map((t) => t.id)).toEqual([
      "tx-ok",
      "tx-pending",
    ]);
  });

  test("combines status and chainId", () => {
    expect(
      filterTransactions(records as any, { status: ["pending", "confirmed"], chainId: 8453 }).map(
        (t) => t.id,
      ),
    ).toEqual(["tx-ok", "tx-pending"]);
  });
});
