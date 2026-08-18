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
});
