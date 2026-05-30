/**
 * <SpendDashboard /> branch coverage.
 *
 * Mirrors the TransactionHistory test style: mock ../provider.js (feature
 * flags) and ../hooks/useSpend.js, then render via SSR and assert on the
 * emitted HTML for each branch:
 *   - feature flag OFF             → renders nothing
 *   - loading                      → loading shell
 *   - error                        → error shell
 *   - no stats                     → empty state
 *   - loaded with stats            → stat cards + range label + budget bars
 *   - budget bar color thresholds  → exercised via dailyPercent values
 */

import { beforeEach, describe, expect, mock, test } from "bun:test";
import * as React from "react";
import { renderToString } from "react-dom/server";

type Features = { showSpendDashboard: boolean };
let mockFeatures: Features = { showSpendDashboard: true };

let mockSpend: any = { stats: null, isLoading: true, error: null };

// NOTE: bun's `mock.module` is process-global; this suite is run
// one-file-per-process by the package's test script. Run individual files
// (or `bun run test`), not a single `bun test <glob>`.
mock.module("../provider.js", () => ({
  useStewardContext: () => ({ features: mockFeatures }),
  StewardAuthContext: React.createContext(null),
  StewardProvider: ({ children }: { children?: React.ReactNode }) =>
    React.createElement(React.Fragment, null, children),
}));

mock.module("../hooks/useSpend.js", () => ({
  useSpend: () => mockSpend,
}));

const { SpendDashboard } = await import("../components/SpendDashboard.js");

function render(): string {
  return renderToString(React.createElement(SpendDashboard, {}));
}

const FULL_STATS = {
  range: "7d",
  totalSpentFormatted: "1.25",
  txCount: 7,
  avgTxValueFormatted: "0.18",
  largestTx: { value: "0.9" },
  budgetUsage: {
    dailyPercent: 40,
    dailyUsed: "400",
    dailyLimit: "1000",
    weeklyPercent: 80,
    weeklyUsed: "800",
    weeklyLimit: "1000",
  },
  daily: [
    { date: "2026-01-01", spentFormatted: "0.5", txCount: 2 },
    { date: "2026-01-02", spentFormatted: "0.75", txCount: 5 },
  ],
  topDestinations: [
    { address: "0x1234567890abcdef1234567890abcdef12345678", totalSent: "500", txCount: 3 },
  ],
};

describe("<SpendDashboard /> branch coverage", () => {
  beforeEach(() => {
    mockFeatures = { showSpendDashboard: true };
    mockSpend = { stats: null, isLoading: true, error: null };
  });

  test("feature flag OFF renders nothing", () => {
    mockFeatures = { showSpendDashboard: false };
    expect(render()).toBe("");
  });

  test("loading branch renders the loading shell", () => {
    mockSpend = { stats: null, isLoading: true, error: null };
    expect(render()).toContain("Loading spend data");
  });

  test("error branch renders the error message", () => {
    mockSpend = { stats: null, isLoading: false, error: new Error("kaboom") };
    const html = render();
    expect(html).toContain("Failed to load spend data");
    expect(html).toContain("kaboom");
  });

  test("no-stats branch renders the empty state", () => {
    mockSpend = { stats: null, isLoading: false, error: null };
    expect(render()).toContain("No spend data available");
  });

  test("loaded branch renders stat cards, range label, and budget bars", () => {
    mockSpend = { stats: FULL_STATS, isLoading: false, error: null };
    const html = render();
    expect(html).toContain("Spend Dashboard");
    expect(html).toContain("Last 7 Days");
    expect(html).toContain("Total Spent");
    // React SSR inserts a `<!-- -->` marker between adjacent text nodes, so we
    // assert the numeric value and the ETH unit separately rather than as one
    // contiguous "1.25 ETH" string.
    expect(html).toContain("1.25");
    expect(html).toContain("Budget Usage");
    expect(html).toContain("Daily Spend");
    expect(html).toContain("Top Destinations");
    // truncated destination address
    expect(html).toContain("0x1234...5678");
  });

  test("budget bar uses the error color above 90%", () => {
    mockSpend = {
      stats: { ...FULL_STATS, budgetUsage: { ...FULL_STATS.budgetUsage, dailyPercent: 95 } },
      isLoading: false,
      error: null,
    };
    const html = render();
    expect(html).toContain("var(--stwd-error)");
  });

  test("budget bar uses the warning color between 70 and 90%", () => {
    mockSpend = {
      stats: {
        ...FULL_STATS,
        budgetUsage: {
          ...FULL_STATS.budgetUsage,
          dailyPercent: 75,
          weeklyPercent: 10,
        },
      },
      isLoading: false,
      error: null,
    };
    const html = render();
    expect(html).toContain("var(--stwd-warning)");
  });

  test("range label maps each preset", () => {
    for (const [range, label] of [
      ["24h", "Last 24 Hours"],
      ["30d", "Last 30 Days"],
      ["all", "All Time"],
    ] as const) {
      mockSpend = { stats: { ...FULL_STATS, range }, isLoading: false, error: null };
      expect(render()).toContain(label);
    }
  });
});
