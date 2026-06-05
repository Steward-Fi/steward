import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";

function readFlutter(path: string): string {
  return readFileSync(new URL(`../../../flutter/${path}`, import.meta.url), "utf8");
}

describe("Flutter SDK parity contract", () => {
  it("exposes wallet recovery and pregenerated wallet claim helpers", () => {
    const client = readFlutter("lib/src/client.dart");
    const models = readFlutter("lib/src/models.dart");
    const tests = readFlutter("test/steward_contract_test.dart");

    expect(client).toContain("setupUserWalletRecovery");
    expect(client).toContain("restoreUserWalletRecovery");
    expect(client).toContain("claimPregeneratedUserWallet");
    expect(client).toContain("/user/me/wallet/recovery/setup");
    expect(client).toContain("/user/me/wallet/recovery/restore");
    expect(client).toContain("/user/me/wallet/claim-pregenerated");

    expect(models).toContain("class UserWalletRecoveryRestoreInput");
    expect(models).toContain("class PregeneratedWalletClaimInput");
    expect(models).toContain("'mnemonic': mnemonic");
    expect(models).toContain("'tenantId': tenantId");
    expect(models).toContain("'claimToken': claimToken");

    expect(tests).toContain("wallet recovery and pregenerated wallet payloads match API contract");
  });

  it("exposes global wallet consent, confirmation, scan, and RPC helpers", () => {
    const client = readFlutter("lib/src/client.dart");
    const models = readFlutter("lib/src/models.dart");
    const tests = readFlutter("test/steward_contract_test.dart");

    expect(client).toContain("getGlobalWalletConsentRequest");
    expect(client).toContain("approveGlobalWalletConsent");
    expect(client).toContain("listGlobalWalletConsents");
    expect(client).toContain("revokeGlobalWalletConsent");
    expect(client).toContain("confirmGlobalWalletAction");
    expect(client).toContain("scanGlobalWalletTransaction");
    expect(client).toContain("globalWalletRpc");
    expect(client).toContain("/global-wallet/consent/request");
    expect(client).toContain("/global-wallet/consent/approve");
    expect(client).toContain("/global-wallet/consents");
    expect(client).toContain("/global-wallet/rpc/confirm");
    expect(client).toContain("/global-wallet/rpc/scan");
    expect(client).toContain("/global-wallet/rpc");
    expect(client).toContain("'/global-wallet'");

    expect(models).toContain("class GlobalWalletConsentRequestInput");
    expect(models).toContain("class GlobalWalletConsentApproveInput");
    expect(models).toContain("class GlobalWalletActionInput");
    expect(models).toContain("class GlobalWalletTransactionScanInput");
    expect(models).toContain("class GlobalWalletRpcInput");
    expect(models).toContain("'app_id': appId");
    expect(models).toContain("'redirect_uri': redirectUri");
    expect(models).toContain("'confirmation_id': confirmationId");
    expect(models).toContain("'scope': scopes");
    expect(models).toContain("'scopes': scopes");

    expect(tests).toContain("global wallet payloads match JS SDK wire fields");
  });

  it("exposes wallet external ID platform user helpers", () => {
    const client = readFlutter("lib/src/client.dart");
    const models = readFlutter("lib/src/models.dart");
    const tests = readFlutter("test/steward_contract_test.dart");

    expect(client).toContain("searchPlatformUsers");
    expect(client).toContain("getUserByWalletExternalId");
    expect(client).toContain("assignWalletExternalId");
    expect(client).toContain("resolveWalletExternalId");
    expect(client).toContain("connectOrCreateByWalletExternalId");
    expect(client).toContain("/platform/users/lookup");
    expect(client).toContain("/platform/users/${Uri.encodeComponent(userId)}/wallet/external-id");
    expect(client).toContain("/platform/users/wallet/external-id");
    expect(client).toContain("/platform/users/wallet/external-id/connect-or-create");

    expect(models).toContain("class PlatformUserSearchQuery");
    expect(models).toContain("class WalletExternalIdInput");
    expect(models).toContain("class WalletExternalIdConnectOrCreateInput");
    expect(models).toContain("'walletExternalId': walletExternalId");
    expect(models).toContain("'emailVerified': emailVerified");

    expect(tests).toContain("wallet external ID payloads match platform API contract");
  });

  it("exposes digital asset account resource helpers", () => {
    const client = readFlutter("lib/src/client.dart");
    const models = readFlutter("lib/src/models.dart");
    const tests = readFlutter("test/steward_contract_test.dart");

    expect(client).toContain("listAccounts");
    expect(client).toContain("createAccount");
    expect(client).toContain("getAccount");
    expect(client).toContain("getAccountBalance");
    expect(client).toContain("updateAccount");
    expect(client).toContain("deleteAccount");
    expect(client).toContain("/accounts");
    expect(client).toContain("/accounts/${Uri.encodeComponent(accountId)}");
    expect(client).toContain("/accounts/${Uri.encodeComponent(accountId)}/balance");
    expect(client).toContain("'/accounts'");

    expect(models).toContain("class DigitalAssetAccountWalletConfiguration");
    expect(models).toContain("class DigitalAssetAccountMutationInput");
    expect(models).toContain("'display_name': displayName");
    expect(models).toContain("'wallet_ids': walletIds");
    expect(models).toContain("'wallets_configuration'");
    expect(models).toContain("'chain_type': chainType");
    expect(models).toContain("'wallet_id': walletId");

    expect(tests).toContain("digital asset account payloads match JS SDK wire fields");
  });
});
