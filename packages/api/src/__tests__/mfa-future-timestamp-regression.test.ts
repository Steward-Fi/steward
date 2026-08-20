import { describe, expect, it } from "bun:test";

describe("future-dated MFA timestamps", () => {
  it("the shared audit gate rejects a future timestamp", async () => {
    process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
    process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
    const { hasRecentSessionMfa } = await import("../middleware/audit-gate");
    const future = Date.now() + 24 * 60 * 60_000;
    const context = {
      get(key: string) {
        return key === "sessionMfaVerifiedAt" ? future : undefined;
      },
    };
    expect(hasRecentSessionMfa(context as never)).toBe(false);
  });

  it("enforces the exact age and no-future boundaries", async () => {
    const { isRecentMfaTimestamp } = await import("../services/recent-mfa");
    const now = 1_800_000_000_000;
    const maxAgeMs = 5 * 60_000;

    expect(isRecentMfaTimestamp(now, maxAgeMs, now)).toBe(true);
    expect(isRecentMfaTimestamp(now - maxAgeMs, maxAgeMs, now)).toBe(true);
    expect(isRecentMfaTimestamp(now - maxAgeMs - 1, maxAgeMs, now)).toBe(false);
    expect(isRecentMfaTimestamp(now + 1, maxAgeMs, now)).toBe(false);
    expect(isRecentMfaTimestamp(now + 24 * 60 * 60_000, maxAgeMs, now)).toBe(false);
  });

  it("rejects malformed timestamps and invalid validation windows", async () => {
    const { isRecentMfaTimestamp } = await import("../services/recent-mfa");
    const now = 1_800_000_000_000;

    for (const timestamp of [undefined, null, "recent", Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(isRecentMfaTimestamp(timestamp, 5 * 60_000, now), String(timestamp)).toBe(false);
    }
    expect(isRecentMfaTimestamp(now, -1, now)).toBe(false);
    expect(isRecentMfaTimestamp(now, Number.POSITIVE_INFINITY, now)).toBe(false);
    expect(isRecentMfaTimestamp(now, 5 * 60_000, Number.NaN)).toBe(false);
  });
});
