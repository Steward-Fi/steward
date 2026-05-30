/**
 * Unit tests for the `utils/format` helpers.
 *
 * These are pure functions (no React, no DOM) so we exercise them directly.
 * `copyToClipboard` is the one exception (it touches `navigator.clipboard`);
 * we cover its failure path here and leave the success path to the browser
 * e2e suite since the test runner has no clipboard API.
 */

import { describe, expect, test } from "bun:test";
import {
  calcPercent,
  copyToClipboard,
  formatBalance,
  formatRelativeTime,
  formatTimestamp,
  formatWei,
  getExplorerAddressUrl,
  getExplorerTxUrl,
  getStatusColor,
  truncateAddress,
} from "../utils/format.js";

describe("truncateAddress", () => {
  test("truncates a full 0x address with default 4 chars each side", () => {
    expect(truncateAddress("0x1234567890abcdef1234567890abcdef12345678")).toBe("0x1234...5678");
  });

  test("respects a custom char count", () => {
    expect(truncateAddress("0x1234567890abcdef1234567890abcdef12345678", 6)).toBe(
      "0x123456...345678",
    );
  });

  test("returns the input unchanged when shorter than the threshold", () => {
    // chars*2 + 2 = 10, so a 10-char string is returned as-is.
    expect(truncateAddress("0x12345678")).toBe("0x12345678");
  });

  test("returns input unchanged for an empty string", () => {
    expect(truncateAddress("")).toBe("");
  });
});

describe("formatWei", () => {
  test("returns '0' for zero or empty input", () => {
    expect(formatWei("0")).toBe("0");
    expect(formatWei("")).toBe("0");
  });

  test("formats one ETH with default 4 decimals", () => {
    expect(formatWei("1000000000000000000")).toBe("1.0000");
  });

  test("formats a fractional value truncating to the requested decimals", () => {
    // 1.5 ETH
    expect(formatWei("1500000000000000000", 2)).toBe("1.50");
  });

  test("decimals=0 drops the fractional component entirely", () => {
    expect(formatWei("2500000000000000000", 0)).toBe("2");
  });

  test("handles sub-one-ETH values (leading zero whole part)", () => {
    // 0.25 ETH
    expect(formatWei("250000000000000000", 4)).toBe("0.2500");
  });
});

describe("formatBalance", () => {
  test("appends the default ETH symbol", () => {
    expect(formatBalance("1000000000000000000")).toBe("1.0000 ETH");
  });

  test("uses a custom symbol", () => {
    expect(formatBalance("1000000000000000000", "BNB", 2)).toBe("1.00 BNB");
  });
});

describe("formatTimestamp", () => {
  test("accepts a Date and produces a non-empty string", () => {
    const out = formatTimestamp(new Date(2026, 0, 15, 13, 30));
    expect(typeof out).toBe("string");
    expect(out.length).toBeGreaterThan(0);
  });

  test("accepts an ISO string", () => {
    const out = formatTimestamp("2026-01-15T13:30:00.000Z");
    expect(typeof out).toBe("string");
    expect(out.length).toBeGreaterThan(0);
  });
});

describe("formatRelativeTime", () => {
  test("returns 'just now' for the current moment", () => {
    expect(formatRelativeTime(new Date())).toBe("just now");
  });

  test("returns minutes for a few minutes ago", () => {
    const d = new Date(Date.now() - 5 * 60 * 1000);
    expect(formatRelativeTime(d)).toBe("5m ago");
  });

  test("returns hours for a few hours ago", () => {
    const d = new Date(Date.now() - 3 * 60 * 60 * 1000);
    expect(formatRelativeTime(d)).toBe("3h ago");
  });

  test("returns days for a few days ago", () => {
    const d = new Date(Date.now() - 4 * 24 * 60 * 60 * 1000);
    expect(formatRelativeTime(d)).toBe("4d ago");
  });

  test("falls back to an absolute timestamp beyond 30 days", () => {
    const d = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000);
    const out = formatRelativeTime(d);
    expect(out).not.toContain("ago");
    expect(out.length).toBeGreaterThan(0);
  });

  test("accepts an ISO string input", () => {
    const iso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    expect(formatRelativeTime(iso)).toBe("10m ago");
  });
});

describe("getExplorerTxUrl", () => {
  test("maps known chain ids to the right explorer", () => {
    expect(getExplorerTxUrl("0xhash", 1)).toBe("https://etherscan.io/tx/0xhash");
    expect(getExplorerTxUrl("0xhash", 56)).toBe("https://bscscan.com/tx/0xhash");
    expect(getExplorerTxUrl("0xhash", 8453)).toBe("https://basescan.org/tx/0xhash");
    expect(getExplorerTxUrl("0xhash", 100)).toBe("https://gnosisscan.io/tx/0xhash");
  });

  test("falls back to etherscan for an unknown chain id", () => {
    expect(getExplorerTxUrl("0xhash", 999999)).toBe("https://etherscan.io/tx/0xhash");
  });
});

describe("getExplorerAddressUrl", () => {
  test("maps known chain ids to the right explorer", () => {
    expect(getExplorerAddressUrl("0xabc", 137)).toBe("https://polygonscan.com/address/0xabc");
    expect(getExplorerAddressUrl("0xabc", 42161)).toBe("https://arbiscan.io/address/0xabc");
  });

  test("falls back to etherscan for an unknown chain id", () => {
    expect(getExplorerAddressUrl("0xabc", 0)).toBe("https://etherscan.io/address/0xabc");
  });
});

describe("getStatusColor", () => {
  test("maps success-ish statuses", () => {
    expect(getStatusColor("confirmed")).toBe("stwd-badge-success");
    expect(getStatusColor("approved")).toBe("stwd-badge-success");
  });

  test("maps error-ish statuses", () => {
    expect(getStatusColor("failed")).toBe("stwd-badge-error");
    expect(getStatusColor("rejected")).toBe("stwd-badge-error");
  });

  test("maps warning-ish statuses", () => {
    expect(getStatusColor("pending")).toBe("stwd-badge-warning");
    expect(getStatusColor("broadcast")).toBe("stwd-badge-warning");
  });

  test("falls back to muted for anything unknown", () => {
    expect(getStatusColor("weird-state")).toBe("stwd-badge-muted");
  });
});

describe("calcPercent", () => {
  test("returns 0 when limit is empty or zero", () => {
    expect(calcPercent("100", "")).toBe(0);
    expect(calcPercent("100", "0")).toBe(0);
  });

  test("computes a mid-range percentage", () => {
    expect(calcPercent("50", "200")).toBe(25);
  });

  test("clamps above 100 down to 100", () => {
    expect(calcPercent("500", "100")).toBe(100);
  });

  test("returns 0 for zero usage", () => {
    expect(calcPercent("0", "100")).toBe(0);
  });
});

describe("copyToClipboard", () => {
  test("resolves false when the clipboard API is unavailable / throws", async () => {
    // The test runner has no jsdom clipboard; navigator.clipboard is undefined
    // so writeText() throws and the helper swallows it, returning false.
    const result = await copyToClipboard("hello");
    expect(result).toBe(false);
  });
});
