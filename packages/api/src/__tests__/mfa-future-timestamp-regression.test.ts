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

  it("every local recent-MFA helper has a non-negative age bound", async () => {
    const files = [
      "middleware/idempotency.ts",
      "routes/agents.ts",
      "routes/approvals.ts",
      "routes/condition-sets.ts",
      "routes/dashboard.ts",
      "routes/erc8004.ts",
      "routes/global-wallet.ts",
      "routes/intents.ts",
      "routes/policies-standalone.ts",
      "routes/secrets.ts",
      "routes/session-signers.ts",
      "routes/tenant-config.ts",
      "routes/tenants.ts",
      "routes/user.ts",
      "routes/vault.ts",
      "routes/webhooks.ts",
    ];
    for (const relative of files) {
      const source = await Bun.file(new URL(`../${relative}`, import.meta.url)).text();
      expect(source, relative).toMatch(/(?:Date\.now\(\)|\bnow\b) - [\w.]+ >= 0/);
    }
  });
});
