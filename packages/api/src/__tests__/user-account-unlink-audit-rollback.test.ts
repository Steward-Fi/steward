import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");

describe("user account unlink audit rollback hardening", () => {
  it("restores linked-account state if the final unlink audit fails", () => {
    expect(routeSource).toContain("type UserAccountUnlinkMutation");
    expect(routeSource).toContain("async function restoreUserAccountUnlinkMutation");
    expect(routeSource).toContain("tx.insert(accounts).values(mutation.deletedAccount)");
    expect(routeSource).toContain("tx.insert(authenticators).values(mutation.deletedPasskey)");
    expect(routeSource).toContain("tx.insert(refreshTokens).values(mutation.deletedRefreshTokens)");

    const unlinkStart = routeSource.indexOf('user.delete("/me/accounts/:provider/:providerAccountId"');
    expect(unlinkStart).toBeGreaterThanOrEqual(0);
    const unlinkRoute = routeSource.slice(
      unlinkStart,
      routeSource.indexOf('user.get("/me/account"', unlinkStart),
    );
    expect(unlinkRoute).toContain('action: "user.account.unlink.authorized"');
    expect(unlinkRoute).toContain("const refreshTokenSnapshot = await tx");
    expect(unlinkRoute).toContain("deletedRefreshTokens: refreshTokenSnapshot");
    expect(unlinkRoute).toContain('action: "user.account.unlink"');
    expect(unlinkRoute).toContain("restoreUserAccountUnlinkMutation(mutation)");
    expect(unlinkRoute.indexOf('action: "user.account.unlink"')).toBeLessThan(
      unlinkRoute.indexOf('dispatchWebhook(tenantId, userId, "user.unlinked_account"'),
    );
  });
});
