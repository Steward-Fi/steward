/**
 * Tests for useSpend().
 *
 * Stats are derived from the credentialed client.listTransactions —
 * the old raw-fetch /agents/:id/spend-stats endpoint never existed on the
 * API and sent no credentials (SEC-195 regression).
 *
 * The test runner has no jsdom and renderToString does not flush effects, so
 * we assert on the mocked client calls via an SSR probe, and cover the stats
 * computation (computeSpendStats) as a pure function.
 */

import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

const listTransactionsMock = mock(async (_agentId: string, _opts: unknown) => ({
  transactions: [] as any[],
  limit: 200,
  offset: 0,
}));

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({
    client: {
      listTransactions: listTransactionsMock,
    },
    agentId: "a b",
    pollInterval: 30000,
    features: {},
    theme: {},
    isLoading: false,
  }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

const { useSpend, computeSpendStats } = await import("../hooks/useSpend.js");

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

const ETH = 10n ** 18n;
const NOW = Date.parse("2026-06-15T12:00:00Z");

function txRecord(overrides: Record<string, unknown> = {}) {
  return {
    id: "tx-1",
    agentId: "a b",
    status: "confirmed",
    request: { agentId: "a b", tenantId: "t", to: "0xabc", value: ETH.toString(), chainId: 8453 },
    txHash: "0xhash",
    policyResults: [],
    createdAt: new Date("2026-06-15T00:00:00Z"),
    ...overrides,
  } as any;
}

const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof mock>;

describe("useSpend()", () => {
  beforeEach(() => {
    listTransactionsMock.mockClear();
    listTransactionsMock.mockImplementation(async () => ({
      transactions: [],
      limit: 200,
      offset: 0,
    }));
    fetchMock = mock(async () => {
      throw new Error("raw fetch must not be used");
    });
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

  test("refetch derives stats from the credentialed history only", async () => {
    const api = captureHook();
    await api.refetch();
    expect(listTransactionsMock).toHaveBeenCalledTimes(1);
    expect(listTransactionsMock).toHaveBeenCalledWith("a b", { limit: 200, offset: 0 });
    // SEC-195: no credential-less raw fetch on any path.
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("computeSpendStats()", () => {
  test("aggregates totals, averages, largest, daily, and destinations", () => {
    const stats = computeSpendStats(
      "7d",
      [
        txRecord({ id: "tx-1" }),
        txRecord({
          id: "tx-2",
          request: { to: "0xdef", value: (ETH * 2n).toString() },
          txHash: "0xhash2",
        }),
        txRecord({ id: "tx-failed", status: "failed" }), // not counted
        txRecord({ id: "tx-signed", status: "signed" }), // signed is not on-chain spend
      ],
      NOW,
    );
    expect(stats.range).toBe("7d");
    expect(stats.txCount).toBe(2);
    expect(stats.totalSpent).toBe((ETH * 3n).toString());
    expect(stats.totalSpentFormatted).toBe("3.0000");
    expect(stats.avgTxValueFormatted).toBe("1.5000");
    expect(stats.largestTx).toEqual({
      value: (ETH * 2n).toString(),
      txHash: "0xhash2",
      timestamp: "2026-06-15T00:00:00.000Z",
    });
    expect(stats.daily).toEqual([
      {
        date: "2026-06-15",
        spent: (ETH * 3n).toString(),
        spentFormatted: "3.0000",
        txCount: 2,
      },
    ]);
    expect(stats.topDestinations[0]).toEqual({
      address: "0xdef",
      totalSent: (ETH * 2n).toString(),
      txCount: 1,
    });
    expect(stats.budgetUsage).toBeUndefined();
  });

  test("range=24h excludes older transactions; range=all includes them", () => {
    const old = txRecord({ id: "tx-old", createdAt: new Date("2026-06-01T00:00:00Z") });
    const recent = txRecord({ id: "tx-recent" });
    expect(computeSpendStats("24h", [old, recent], NOW).txCount).toBe(1);
    expect(computeSpendStats("all", [old, recent], NOW).txCount).toBe(2);
    // 10 days old: inside 30d, outside 7d
    expect(computeSpendStats("7d", [old, recent], NOW).txCount).toBe(1);
    expect(computeSpendStats("30d", [old, recent], NOW).txCount).toBe(2);
  });

  test("does not count signed-only value and conservatively counts unknown broadcast outcomes", () => {
    const signedOnly = txRecord({ id: "signed", status: "signed" });
    const unknown = txRecord({ id: "unknown", status: "outcome_unknown" });
    const stats = computeSpendStats("all", [signedOnly, unknown], NOW);
    expect(stats.txCount).toBe(1);
    expect(stats.totalSpent).toBe(ETH.toString());
  });

  test("empty history yields zeroed stats", () => {
    const stats = computeSpendStats("7d", [], NOW);
    expect(stats.txCount).toBe(0);
    expect(stats.totalSpent).toBe("0");
    expect(stats.avgTxValue).toBe("0");
    expect(stats.largestTx).toEqual({ value: "0", txHash: "", timestamp: "" });
    expect(stats.daily).toEqual([]);
    expect(stats.topDestinations).toEqual([]);
  });
});
