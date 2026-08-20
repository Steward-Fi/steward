import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");

describe("user account unlink audit atomicity", () => {
  it("keeps the completion audit inside the mutation transaction without snapshot restoration", () => {
    const unlinkStart = routeSource.indexOf(
      'user.delete("/me/accounts/:provider/:providerAccountId"',
    );
    expect(unlinkStart).toBeGreaterThanOrEqual(0);
    const unlinkRoute = routeSource.slice(
      unlinkStart,
      routeSource.indexOf('user.get("/me/account"', unlinkStart),
    );
    expect(unlinkRoute).toContain('action: "user.account.unlink.authorized"');
    expect(unlinkRoute).toContain("revocationStore.revokeUserTokens(userId, issuedBefore)");
    expect(unlinkRoute).toContain("withTenantAuditedTransaction(tenantId");
    expect(unlinkRoute).toContain("await lockUserSession(tx, userId)");
    expect(unlinkRoute).toContain("await appendRequiredAudit({");
    expect(unlinkRoute).toContain('action: "user.account.unlink"');
    expect(unlinkRoute).not.toContain("refreshTokenSnapshot");
    expect(unlinkRoute).not.toContain("restoreUserAccountUnlinkMutation");
    expect(unlinkRoute).toContain("accountUnlinked: false");
    expect(unlinkRoute).toContain("sessionsRevoked: true");
    expect(unlinkRoute.indexOf('action: "user.account.unlink"')).toBeLessThan(
      unlinkRoute.indexOf('dispatchWebhook(tenantId, userId, "user.unlinked_account"'),
    );
  });
});
