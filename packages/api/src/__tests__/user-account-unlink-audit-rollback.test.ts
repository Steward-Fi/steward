import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");
const platformSource = readFileSync(join(import.meta.dir, "..", "routes", "platform.ts"), "utf8");

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

  it("makes tenant wallet remediation atomic without credential restoration", () => {
    const start = routeSource.indexOf("async function remediateTenantWalletPolicyAccount");
    const remediation = routeSource.slice(
      start,
      routeSource.indexOf("async function requireTenantUserDirectoryReaderMfa", start),
    );
    expect(remediation).toContain("withTenantAuditedTransaction(tenantId");
    expect(remediation).toContain("await lockUserSession(tx, targetUserId)");
    expect(remediation).toContain('action: "tenant.wallet_policy.remediation"');
    expect(remediation).not.toContain("refreshTokenSnapshot");
    expect(remediation).not.toContain("insert(accounts)");
    expect(remediation).toContain("accountUnlinked: false");
    expect(remediation).toContain("sessionsRevoked: true");
  });

  it("uses one lock order and audited transaction for platform create, delete, and transfer", () => {
    expect(platformSource).toContain("withPlatformLinkedAccountTransaction");
    expect(platformSource).toContain("withTenantAuditedTransactionOnDb");
    expect(platformSource).not.toContain("set({ userId: fromUserId })");
    for (const route of [
      'platform.post("/users/:userId/accounts"',
      'platform.delete("/users/:userId/accounts/:provider/:providerAccountId"',
      'platform.post("/users/:userId/accounts/:provider/:providerAccountId/transfer"',
    ]) {
      const start = platformSource.indexOf(route);
      expect(start).toBeGreaterThanOrEqual(0);
      const body = platformSource.slice(
        start,
        platformSource.indexOf("\n/**", start + route.length),
      );
      expect(body).toContain("withPlatformLinkedAccountTransaction(");
      expect(body).toContain("lockLinkedAccountIdentity(tx, provider, providerAccountId)");
      expect(body).toContain("appendRequiredAudit({");
    }
  });
});
