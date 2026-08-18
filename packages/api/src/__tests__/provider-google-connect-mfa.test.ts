import { describe, expect, it } from "bun:test";
import { hasRecentGoogleConnectMfa } from "../services/provider-google-connect-mfa";

describe("Google provider-connect recent-MFA boundary", () => {
  const now = Date.parse("2026-08-18T01:00:00.000Z");

  it("accepts only a finite verification timestamp from the last five minutes", () => {
    expect(hasRecentGoogleConnectMfa(now, now)).toBe(true);
    expect(hasRecentGoogleConnectMfa(now - 5 * 60_000, now)).toBe(true);
    expect(hasRecentGoogleConnectMfa(now - 5 * 60_000 - 1, now)).toBe(false);
  });

  it("fails closed on absent, malformed, non-finite, or future claims", () => {
    for (const value of [
      undefined,
      null,
      "recent",
      Number.NaN,
      Number.POSITIVE_INFINITY,
      now + 1,
    ]) {
      expect(hasRecentGoogleConnectMfa(value, now)).toBe(false);
    }
  });
});
