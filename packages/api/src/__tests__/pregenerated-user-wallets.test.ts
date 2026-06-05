import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routesDir = join(import.meta.dir, "..", "routes");
const agentsSource = readFileSync(join(routesDir, "agents.ts"), "utf8");
const userSource = readFileSync(join(routesDir, "user.ts"), "utf8");

describe("pregenerated user wallet routes", () => {
  it("creates one-time claim tokens without storing raw tokens", () => {
    const routeStart = agentsSource.indexOf('agentRoutes.post("/pregenerated"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = agentsSource.indexOf('agentRoutes.get("/")', routeStart);
    const route = agentsSource.slice(routeStart, routeEnd);

    expect(route).toContain("generatePregeneratedWalletClaimToken()");
    expect(route).toContain("hashSha256Hex(claimToken)");
    expect(route).toContain("normalizePregeneratedClaimExpiry(body.claimExpiresInSeconds)");
    expect(route).toContain("pregeneratedClaimPlatformId(claimTokenHash, claimExpiresAt)");
    expect(route).toContain("redactPregeneratedClaimPlatformId(identity)");
    expect(route).toContain("claimExpiresAt: claimExpiresAt.toISOString()");
    expect(route).toContain("setNoStoreHeaders(c)");
    expect(route).toContain("claimToken");
    expect(route).not.toContain("platformId = `${PREGENERATED_CLAIM_PREFIX}${claimToken}`");
  });

  it("claims only hashed pregenerated wallets into personal user wallets", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/claim-pregenerated"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/recovery/setup"', routeStart);
    const route = userSource.slice(routeStart, routeEnd);

    expect(route).toContain("requirePersonalUserSession(c)");
    expect(route).toContain("hasRecentMfaStepUp(session)");
    expect(route).toContain("setNoStoreHeaders(c)");
    expect(route).toContain("parseUserWalletIndexSelector(body?.walletIndex, body?.wallet_index)");
    expect(route).toContain('action: "user.wallet.pregenerated_claim.rejected",');
    expect(route).toContain("hashSha256Hex(claimToken)");
    expect(route).toContain("eq(agents.walletType, PREGENERATED_USER_WALLET_TYPE)");
    expect(route).toContain("parsePregeneratedClaimPlatformId");
    expect(route).toContain("Wallet claim token expired");
    expect(route).toContain("EXPIRED_PREGENERATED_CLAIM_PREFIX");
    expect(route).toContain("eq(agents.platformId, claimablePlatformId)");
    expect(route).toContain("User already has an embedded wallet at the selected walletIndex");
    expect(route).toContain("walletIndex.value === 0");
    expect(route).toContain("`user-wallet-${userId}-${walletIndex.value}`");
    expect(route).toContain("getUserWallet(vault, userId, undefined, walletIndex.value)");
    expect(route).toContain("applyUserWalletDefaults(userId, personalTenant)");
    expect(route).toContain("CLAIMED_PREGENERATED_CLAIM_PREFIX");
    expect(route).toContain("throw claimError");
    expect(route).toContain('"user.wallet_created"');
    expect(route).toContain("walletIndex: walletIndex.value");
  });

  it("lists and rotates pregenerated claim tokens without exposing stored hashes", () => {
    expect(agentsSource).toContain("function redactPregeneratedClaimPlatformId");
    expect(agentsSource).toContain('agentRoutes.get("/pregenerated"');
    expect(agentsSource).toContain('agentRoutes.post("/pregenerated/:agentId/claim-token/rotate"');
    expect(agentsSource).toContain("tenantAgents.map(redactPregeneratedClaimPlatformId)");
    expect(agentsSource).toContain("redactPregeneratedClaimPlatformId({");
    expect(agentsSource).toContain(
      'action: "agent.pregenerated_user_wallet.claim_token.rotate.authorized"',
    );
    expect(agentsSource).toContain('action: "agent.pregenerated_user_wallet.claim_token.rotate"');
    expect(agentsSource).not.toContain("metadata: { claimTokenHash");
  });

  it("audits pregenerated claims and keeps raw claim tokens out of webhooks", () => {
    const routeStart = userSource.indexOf('user.post("/me/wallet/claim-pregenerated"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const routeEnd = userSource.indexOf('user.post("/me/wallet/recovery/setup"', routeStart);
    const route = userSource.slice(routeStart, routeEnd);

    expect(route).toContain('action: "user.wallet.pregenerated_claim.authorized"');
    expect(route).toContain('action: "user.wallet.pregenerated_claim"');
    expect(route.indexOf('action: "user.wallet.pregenerated_claim.authorized"')).toBeLessThan(
      route.indexOf("await vault.importKey(personalTenant, targetAgentId, keys.evm.privateKey"),
    );
    expect(route.indexOf('action: "user.wallet.pregenerated_claim"')).toBeLessThan(
      route.indexOf('dispatchWebhook(personalTenant, wallet.id, "user.wallet_created"'),
    );

    const authorizedAuditStart = route.indexOf(
      'action: "user.wallet.pregenerated_claim.authorized"',
    );
    const authorizedAuditEnd = route.indexOf("});", authorizedAuditStart);
    const authorizedAuditPayload = route.slice(authorizedAuditStart, authorizedAuditEnd);
    expect(authorizedAuditPayload).toContain("sourceTenantId");
    expect(authorizedAuditPayload).toContain("sourceAgentId");
    expect(authorizedAuditPayload).toContain("walletIndex: walletIndex.value");
    expect(authorizedAuditPayload).not.toContain("claimToken,");
    expect(authorizedAuditPayload).not.toContain("claimTokenHash");
    expect(authorizedAuditPayload).not.toContain("privateKey");

    const dispatchStart = route.indexOf(
      'dispatchWebhook(personalTenant, wallet.id, "user.wallet_created"',
    );
    expect(dispatchStart).toBeGreaterThanOrEqual(0);
    const dispatchEnd = route.indexOf("});", dispatchStart);
    const dispatchPayload = route.slice(dispatchStart, dispatchEnd);
    expect(dispatchPayload).toContain("pregenerated: true");
    expect(dispatchPayload).not.toContain("claimToken");
    expect(dispatchPayload).not.toContain("claimTokenHash");
    expect(dispatchPayload).not.toContain("privateKey");
    expect(dispatchPayload).not.toContain("keys.");

    const finalAuditStart = route.indexOf('action: "user.wallet.pregenerated_claim"');
    const finalAuditEnd = route.indexOf("});", finalAuditStart);
    const finalAuditPayload = route.slice(finalAuditStart, finalAuditEnd);
    expect(finalAuditPayload).toContain("sourceTenantId");
    expect(finalAuditPayload).toContain("sourceAgentId");
    expect(finalAuditPayload).toContain("walletIndex: walletIndex.value");
    expect(finalAuditPayload).not.toContain("claimToken,");
    expect(finalAuditPayload).not.toContain("claimTokenHash");
    expect(finalAuditPayload).not.toContain("privateKey");
  });
});
