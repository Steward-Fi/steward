import { describe, expect, it } from "bun:test";
import { isRecentMfaTimestamp } from "../services/recent-mfa";

describe("isRecentMfaTimestamp", () => {
  const now = 1_800_000_000_000;
  const maxAge = 300_000;

  it("accepts current timestamps and the configured boundaries", () => {
    expect(isRecentMfaTimestamp(now, maxAge, now)).toBe(true);
    expect(isRecentMfaTimestamp(now - maxAge, maxAge, now)).toBe(true);
    expect(isRecentMfaTimestamp(now + 30_000, maxAge, now)).toBe(true);
  });

  it("rejects stale, far-future, and non-finite timestamps", () => {
    expect(isRecentMfaTimestamp(now - maxAge - 1, maxAge, now)).toBe(false);
    expect(isRecentMfaTimestamp(now + 30_001, maxAge, now)).toBe(false);
    expect(isRecentMfaTimestamp(Number.NaN, maxAge, now)).toBe(false);
    expect(isRecentMfaTimestamp(Number.POSITIVE_INFINITY, maxAge, now)).toBe(false);
  });
});
