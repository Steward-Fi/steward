import { describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { getOpenApiSpec } from "../openapi";

describe("generated OpenAPI contract", () => {
  function expectHardening(operation: Record<string, unknown>, sensitivePrefix: string) {
    expect(operation["x-steward-hardening"]).toMatchObject({
      sensitive: true,
      sensitivePrefix,
      requestExpiry: {
        acceptedHeaders: ["X-Steward-Request-Timestamp", "X-Steward-Request-Expires-At"],
      },
      authorizationSignature: {
        header: "X-Steward-Signature",
        schemes: ["v1=hmac-sha256", "p256=ecdsa-secp256r1"],
      },
      idempotency: {
        header: "Idempotency-Key",
        requiredForSignedRequests: true,
      },
    });
    const parameters = Array.isArray(operation.parameters) ? operation.parameters : [];
    const headerNames = parameters
      .filter((param): param is { in: string; name: string } => {
        return (
          Boolean(param) &&
          typeof param === "object" &&
          "in" in param &&
          "name" in param &&
          param.in === "header" &&
          typeof param.name === "string"
        );
      })
      .map((param) => param.name);
    expect(headerNames).toContain("X-Steward-Request-Timestamp");
    expect(headerNames).toContain("X-Steward-Request-Expires-At");
    expect(headerNames).toContain("X-Steward-Signature");
    expect(headerNames).toContain("X-Steward-Signing-Key-Id");
    expect(headerNames).toContain("Idempotency-Key");
    expect(operation.responses).toHaveProperty("408");
  }

  it("covers the current Privy-parity account and external-id surfaces", () => {
    const spec = getOpenApiSpec();

    expect(spec.openapi).toBe("3.1.0");
    expect(spec.paths).toHaveProperty("/accounts");
    expect(spec.paths).toHaveProperty("/v1/accounts/{accountId}/aggregations/{aggregationId}");
    expect(spec.paths).toHaveProperty("/platform/users/wallet/external-id/connect-or-create");
    expect(spec.paths).toHaveProperty("/platform/apps/gas_spend");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/transactions");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/actions/transfer/quote");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/actions/transfer");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/actions/send-calls");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/actions/{actionId}");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/import/init");
    expect(spec.paths).toHaveProperty("/vault/{agentId}/import/submit");
    expect(spec.paths).toHaveProperty("/user/me/wallet/import/init");
    expect(spec.paths).toHaveProperty("/user/me/wallet/import/submit");
    expect(spec.paths).toHaveProperty("/user/me/wallet/signers");
    expect(spec.paths).toHaveProperty("/user/me/wallet/signers/{signerId}");
    expect(spec.paths).toHaveProperty("/wallets/batch");
    expect(spec.paths).toHaveProperty("/v1/wallets/batch");
    expect(spec.paths).toHaveProperty("/adapters");
    expect(spec.paths).toHaveProperty("/v1/adapters");
    expect(spec.paths).toHaveProperty("/adapters/swap/quote");
    expect(spec.paths).toHaveProperty("/adapters/swap/build");
    expect(spec.paths).toHaveProperty("/adapters/earn/vaults");
    expect(spec.paths).toHaveProperty("/adapters/earn/deposit");
    expect(spec.paths).toHaveProperty("/adapters/earn/withdraw");
    expect(spec.paths).toHaveProperty("/adapters/bridge/quote");
    expect(spec.paths).toHaveProperty("/adapters/bridge/build");
    expect(spec.paths).toHaveProperty("/adapters/exchange/sessions");
    expect(spec.paths).toHaveProperty("/adapters/exchange/accounts/{accountId}");
    expect(spec.paths).toHaveProperty("/v1/apps/{appId}/fiat");
    expect(spec.paths).toHaveProperty("/v1/users/{userId}/fiat/accounts");
    expect(spec.paths).toHaveProperty("/v1/users/{userId}/fiat/kyc_link");
    expect(spec.paths).toHaveProperty("/v1/users/{userId}/fiat/kyc");
    expect(spec.paths).toHaveProperty("/v1/users/{userId}/fiat/onramp");
    expect(spec.paths).toHaveProperty("/v1/users/{userId}/fiat/offramp");
    expect(spec.paths).toHaveProperty("/audit/log");
    expect(spec.paths).toHaveProperty("/audit/summary");
    expect(spec.paths).toHaveProperty("/audit/export");
    expect(spec.paths).toHaveProperty("/audit/events");
    expect(spec.paths).toHaveProperty("/audit/verify");
    expect(spec.paths).toHaveProperty("/intents");
    expect(spec.paths).toHaveProperty("/intents/{intentId}/approve");
    expect(spec.paths).toHaveProperty("/v1/intents/{intentId}/approve");
    expect(spec.paths).toHaveProperty("/secrets");
    expect(spec.paths).toHaveProperty("/secrets/routes");
    expect(spec.paths).toHaveProperty("/secrets/routes/{routeId}");
    expect(spec.paths).toHaveProperty("/secrets/{secretId}/rotate");
    expect(spec.paths).toHaveProperty("/webhooks");
    expect(spec.paths).toHaveProperty("/webhooks/{id}/test");
    expect(spec.paths).toHaveProperty("/webhooks/{id}/deliveries");
    expect(spec.paths).toHaveProperty("/webhooks/{id}/deliveries/export");
    expect(spec.paths).toHaveProperty("/webhooks/deliveries/{id}/retry");
    expect(spec.paths).toHaveProperty("/webhooks/deliveries/{id}/replay");
    expect(spec.paths).toHaveProperty("/approvals");
    expect(spec.paths).toHaveProperty("/approvals/stats");
    expect(spec.paths).toHaveProperty("/approvals/{txId}/approve");
    expect(spec.paths).toHaveProperty("/approvals/{txId}/deny");
    expect(spec.paths).toHaveProperty("/approvals/rules");
    expect(spec.paths).toHaveProperty("/global-wallet/consent/request");
    expect(spec.paths).toHaveProperty("/global-wallet/consent/approve");
    expect(spec.paths).toHaveProperty("/global-wallet/consents");
    expect(spec.paths).toHaveProperty("/global-wallet/consents/{consentId}/revoke");
    expect(spec.paths).toHaveProperty("/global-wallet/rpc/confirm");
    expect(spec.paths).toHaveProperty("/global-wallet/rpc/scan");
    expect(spec.paths).toHaveProperty("/global-wallet/rpc");
    expect(spec.paths).toHaveProperty("/trade/token-status");
    expect(spec.paths).toHaveProperty("/trade/sessions");
    expect(spec.paths).toHaveProperty("/trade/hyperliquid/order");
    expect(spec.paths).toHaveProperty("/trade/{venue}/deposit");
    expect(spec.paths).toHaveProperty("/trade/{venue}/close-all");
    expect(spec.paths).toHaveProperty("/trade/{venue}/leverage");
    expect(spec.paths).toHaveProperty("/trade/{venue}/withdraw");
    expect(spec.paths).toHaveProperty("/v1/trade/{venue}/leverage");
    expect(spec.paths).toHaveProperty("/v1/trade/{venue}/withdraw");
    expect(spec.paths).toHaveProperty("/tenants/config");
    expect(spec.paths).toHaveProperty("/tenants/{id}/config");
    expect(spec.paths).toHaveProperty("/tenants/{id}/config/templates");
    expect(spec.paths).toHaveProperty("/tenants/{id}/config/templates/{name}/apply");
    expect(spec.paths).toHaveProperty("/tenants/{id}/auth-abuse-config");
    expect(spec.paths).toHaveProperty("/tenants/{id}/security-checklist");
    expect(spec.paths).toHaveProperty("/tenants/{id}/idempotency-metrics");
    expect(spec.paths).toHaveProperty("/tenants/{id}/idempotency-metrics/export");
    expect(spec.paths).toHaveProperty("/tenants/{id}/request-signing-keys");
    expect(spec.paths).toHaveProperty("/tenants/{id}/request-signing-keys/{keyId}");
    expect(spec.paths).toHaveProperty("/platform/tenants/{tenantId}/members");
    expect(spec.paths).toHaveProperty("/platform/tenants/{tenantId}/members/{userId}");
    expect(spec.paths).toHaveProperty("/platform/tenants/{tenantId}/invitations");
    expect(spec.paths).toHaveProperty("/platform/tenants/{tenantId}/invitations/{invitationId}");
    expect(spec.paths).toHaveProperty("/user/me/tenants/{tenantId}/users/wallet-policy/violations");
    expect(spec.paths).toHaveProperty(
      "/user/me/tenants/{tenantId}/users/{userId}/wallet-policy/wallets/{accountId}",
    );
    expect(spec.paths).toHaveProperty("/auth/mfa/totp/enroll");
    expect(spec.paths).toHaveProperty("/auth/mfa/totp/verify");
    expect(spec.paths).toHaveProperty("/auth/mfa/totp/complete");
    expect(spec.paths).toHaveProperty("/auth/mfa/totp/step-up");
    expect(spec.paths).toHaveProperty("/auth/mfa/recovery-codes/regenerate");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/enroll");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/verify");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/send");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/complete");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/step-up");
    expect(spec.paths).toHaveProperty("/auth/mfa/sms/unenroll");
    expect(spec.paths).toHaveProperty("/auth/mfa/passkey/options");
    expect(spec.paths).toHaveProperty("/auth/mfa/passkey/complete");
    expect(spec.paths).toHaveProperty("/auth/mfa/passkey/verify");
    expect(spec.paths).toHaveProperty("/auth/logout");
    expect(spec.paths).toHaveProperty("/auth/refresh");
    expect(spec.paths).toHaveProperty("/auth/revoke");
    const totpEnroll = spec.paths["/auth/mfa/totp/enroll"].post;
    expect(totpEnroll.tags).toEqual(["Auth"]);
    expect(totpEnroll.description).toContain("one-time TOTP secret");
    expect(
      totpEnroll.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("otpauthUri");
    const totpComplete = spec.paths["/auth/mfa/totp/complete"].post;
    expect(totpComplete.description).toContain("Consumes exactly one pending TOTP MFA challenge");
    expect(totpComplete.requestBody.content["application/json"].schema.oneOf).toEqual([
      { required: ["code"] },
      { required: ["recoveryCode"] },
    ]);
    const totpStepUp = spec.paths["/auth/mfa/totp/step-up"].post;
    expect(totpStepUp.description).toContain("current MFA freshness claims");
    expect(totpStepUp.requestBody.content["application/json"].schema.oneOf).toEqual([
      { required: ["code"] },
      { required: ["recoveryCode"] },
    ]);
    const recoveryCodes = spec.paths["/auth/mfa/recovery-codes/regenerate"].post;
    expect(recoveryCodes.description).toContain("Returns replacement recovery codes exactly once");
    expect(
      recoveryCodes.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("recoveryCodes");
    const smsEnroll = spec.paths["/auth/mfa/sms/enroll"].post;
    expect(smsEnroll.requestBody.content["application/json"].schema.properties.phone.pattern).toBe(
      "^\\+[1-9]\\d{1,14}$",
    );
    expect(smsEnroll.description).toContain("masked-phone state");
    const smsStepUp = spec.paths["/auth/mfa/sms/step-up"].post;
    expect(smsStepUp.description).toContain("/auth/mfa/sms/send");
    const passkeyComplete = spec.paths["/auth/mfa/passkey/complete"].post;
    expect(passkeyComplete.description).toContain("one-time WebAuthn challenge");
    expect(
      passkeyComplete.responses["200"].content["application/json"].schema.properties,
    ).toHaveProperty("refreshToken");
    const refresh = spec.paths["/auth/refresh"].post;
    expect(refresh.description).toContain("single-use");
    expect(refresh.requestBody.content["application/json"].schema.required).toEqual([
      "refreshToken",
    ]);
    expect(spec.paths["/auth/revoke"].post.description).toContain("idempotent");
    const importInit = spec.paths["/vault/{agentId}/import/init"].post;
    expect(importInit.description).toContain("short-lived X25519 public key");
    expect(
      importInit.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("publicKey");
    const importSubmit = spec.paths["/vault/{agentId}/import/submit"].post;
    expect(importSubmit.description).toContain("Plaintext `privateKey` fields are rejected");
    const importSubmitProperties =
      importSubmit.requestBody.content["application/json"].schema.properties;
    expect(importSubmitProperties).toHaveProperty("ciphertext");
    expect(importSubmitProperties).not.toHaveProperty("privateKey");
    const userWalletImportInit = spec.paths["/user/me/wallet/import/init"].post;
    expect(userWalletImportInit.description).toContain("tenant/app/user/wallet AAD");
    expect(
      userWalletImportInit.responses["200"].content["application/json"].schema.properties.data
        .properties.aad.properties,
    ).toHaveProperty("walletIndex");
    const userWalletImportSubmit = spec.paths["/user/me/wallet/import/submit"].post;
    expect(userWalletImportSubmit.description).toContain(
      "Plaintext `privateKey` fields are rejected",
    );
    const userWalletImportSubmitProperties =
      userWalletImportSubmit.requestBody.content["application/json"].schema.properties;
    expect(userWalletImportSubmitProperties).toHaveProperty("ciphertext");
    expect(userWalletImportSubmitProperties).toHaveProperty("walletIndex");
    expect(userWalletImportSubmitProperties).not.toHaveProperty("privateKey");
    const signerCreateBody =
      spec.paths["/agents/{agentId}/signers"].post.requestBody.content["application/json"].schema;
    expect(signerCreateBody.properties).toHaveProperty("policyIds");
    const signerListItem =
      spec.paths["/agents/{agentId}/signers"].get.responses["200"].content["application/json"]
        .schema.properties.data.properties.signers.items;
    expect(signerListItem.properties).toHaveProperty("policyIds");
    const userWalletSignerCreate =
      spec.paths["/user/me/wallet/signers"].post.requestBody.content["application/json"].schema;
    expect(userWalletSignerCreate.properties).toHaveProperty("walletIndex");
    expect(userWalletSignerCreate.properties.permissions.items.type).toBe("string");
    expect(
      spec.paths["/user/me/wallet/signers"].get.responses["200"].content["application/json"].schema
        .properties.data.properties.signers.items.properties,
    ).not.toHaveProperty("credentialSecret");
    const accountCreateBody =
      spec.paths["/accounts"].post.requestBody.content["application/json"].schema;
    expect(accountCreateBody.properties).toHaveProperty("user_wallet_ids");
    expect(accountCreateBody.properties).toHaveProperty("userWalletIds");
    expect(accountCreateBody.properties).toHaveProperty("owner_user_ids");
    expect(accountCreateBody.properties).toHaveProperty("ownerUserIds");
    expect(accountCreateBody.properties).toHaveProperty("additional_signer_ids");
    expect(accountCreateBody.properties).toHaveProperty("additionalSignerIds");
    expect(accountCreateBody.properties).toHaveProperty("signer_policy_ids");
    expect(accountCreateBody.properties).toHaveProperty("signerPolicyIds");
    expect(accountCreateBody.properties.owner_user_ids.maxItems).toBe(32);
    expect(accountCreateBody.properties.additional_signer_ids.maxItems).toBe(32);
    expect(
      accountCreateBody.properties.wallets_configuration.items.properties.chain_type.enum,
    ).toContain("bitcoin");
    const accountResponseProperties =
      spec.paths["/accounts/{accountId}"].get.responses["200"].content["application/json"].schema
        .properties.data.properties;
    expect(accountResponseProperties).toHaveProperty("ownerUserIds");
    expect(accountResponseProperties).toHaveProperty("owner_user_ids");
    expect(accountResponseProperties).toHaveProperty("additionalSignerIds");
    expect(accountResponseProperties).toHaveProperty("additional_signer_ids");
    expect(accountResponseProperties).toHaveProperty("signerPolicyIds");
    expect(accountResponseProperties).toHaveProperty("signer_policy_ids");
    expect(accountResponseProperties.wallets.items.properties.chainFamily.enum).toContain(
      "bitcoin",
    );
    expect(
      spec.paths["/platform/apps/gas_spend"].get.parameters.some(
        (param) => param.name === "wallet_external_ids",
      ),
    ).toBe(true);
    expect(
      spec.paths["/vault/{agentId}/transactions"].get.parameters.some(
        (param) => param.name === "referenceId",
      ),
    ).toBe(true);
    const walletBatchBody =
      spec.paths["/wallets/batch"].post.requestBody.content["application/json"].schema;
    expect(walletBatchBody.required).toEqual(["wallets"]);
    expect(walletBatchBody.properties.wallets.items.properties).toHaveProperty("externalId");
    expect(
      spec.paths["/wallets/batch"].post.responses["200"].content["application/json"].schema
        .properties.data.properties,
    ).toHaveProperty("created");

    const adapterDiscovery = spec.paths["/adapters"].get;
    expect(adapterDiscovery.tags).toEqual(["Adapters"]);
    expect(adapterDiscovery.description).toContain("unsigned intents gated by policy/spend checks");
    expect(
      adapterDiscovery.responses["200"].content["application/json"].schema.properties.data
        .properties,
    ).toHaveProperty("adapters");

    const swapBuild = spec.paths["/adapters/swap/build"].post;
    expect(swapBuild.description).toContain("unsigned intent");
    expect(
      swapBuild.responses["200"].content["application/json"].schema.properties.data.properties
        .unsignedIntent.properties.signed.const,
    ).toBe(false);
    expect(
      spec.paths["/adapters/earn/vaults"].get.parameters.some((param) => param.name === "chainId"),
    ).toBe(true);
    expect(spec.paths["/v1/adapters/bridge/build"].post.summary).toContain("bridge");

    const auditLog = spec.paths["/audit/log"].get;
    expect(auditLog.security).toEqual([{ bearerAuth: [] }]);
    expect(auditLog.description).toContain("recent MFA");
    expect(auditLog.parameters.some((param) => param.name === "agentId")).toBe(true);
    expect(auditLog.parameters.some((param) => param.name === "status")).toBe(true);
    expect(
      auditLog.responses["200"].content["application/json"].schema.properties.data.properties.data
        .items.properties.action.enum,
    ).toEqual(["sign", "approve", "reject", "proxy"]);

    const auditSummary = spec.paths["/audit/summary"].get;
    expect(auditSummary.security).toEqual([{ bearerAuth: [] }]);
    expect(auditSummary.description).toContain("recent MFA");
    expect(auditSummary.parameters.find((param) => param.name === "range").schema.enum).toEqual([
      "24h",
      "7d",
      "30d",
      "all",
    ]);
    expect(
      auditSummary.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("totalProxyRequests");

    const auditExport = spec.paths["/audit/export"].get;
    expect(auditExport.security).toEqual([{ bearerAuth: [] }]);
    expect(auditExport.description).toContain("recent MFA");
    expect(auditExport.description).toContain("31 days");
    expect(auditExport.responses["200"].content).toHaveProperty("text/csv");
    expect(auditExport.parameters.find((param) => param.name === "dateFrom").required).toBe(true);
    expect(auditExport.parameters.find((param) => param.name === "dateTo").required).toBe(true);

    const auditEvents = spec.paths["/audit/events"].get;
    expect(auditEvents.security).toEqual([{ bearerAuth: [] }]);
    expect(auditEvents.description).toContain("recent MFA");
    expect(auditEvents.description).toContain("metadata.adapter.kind=swap");
    expect(auditEvents.parameters.some((param) => param.name === "actionPrefix")).toBe(true);
    expect(auditEvents.parameters.some((param) => param.name === "metadata.<path>")).toBe(true);
    expect(
      auditEvents.responses["200"].content["application/json"].schema.properties.data.properties
        .pagination.properties.limit.maximum,
    ).toBe(200);

    const auditVerify = spec.paths["/audit/verify"].post;
    expect(auditVerify.security).toEqual([{ bearerAuth: [] }]);
    expect(auditVerify.description).toContain("recent MFA");
    expect(auditVerify.description).toContain("10,000 rows");
    expect(auditVerify.parameters.some((param) => param.name === "fromSeq")).toBe(true);
    expect(auditVerify.parameters.some((param) => param.name === "toSeq")).toBe(true);
    expect(auditVerify.parameters.some((param) => param.name === "requireHead")).toBe(true);
    expect(
      auditVerify.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("verifiedToSeq");

    const walletPolicyReport =
      spec.paths["/user/me/tenants/{tenantId}/users/wallet-policy/violations"].get;
    expect(walletPolicyReport.security).toEqual([{ bearerAuth: [] }]);
    expect(walletPolicyReport.description).toContain("recent MFA");
    expect(
      walletPolicyReport.responses["200"].content["application/json"].schema.properties.data
        .properties.violations.items.properties.wallets.items.properties.provider.enum,
    ).toEqual(["wallet:ethereum", "wallet:solana"]);
    const walletPolicyRemediation =
      spec.paths["/user/me/tenants/{tenantId}/users/{userId}/wallet-policy/wallets/{accountId}"]
        .delete;
    expect(walletPolicyRemediation.security).toEqual([{ bearerAuth: [] }]);
    expect(walletPolicyRemediation.description).toContain("recent MFA");
    expect(walletPolicyRemediation.description).toContain("owner/admin");
    expect(walletPolicyRemediation.description).toContain("last login method");
    expect(walletPolicyRemediation.description).toContain("refresh tokens");
    expect(walletPolicyRemediation.description).toContain("audit events");
    expect(walletPolicyRemediation.description).toContain("user.unlinked_account webhook");
    expect(
      walletPolicyRemediation.responses["200"].content["application/json"].schema.properties.data
        .properties.provider.enum,
    ).toEqual(["wallet:ethereum", "wallet:solana"]);
    expect(
      walletPolicyRemediation.responses["200"].content["application/json"].schema.properties.data
        .properties,
    ).not.toHaveProperty("secret");

    const intentsList = spec.paths["/intents"].get;
    expect(intentsList.tags).toEqual(["Intents"]);
    expect(intentsList.parameters.some((param) => param.name === "intent_type")).toBe(true);
    expect(intentsList.parameters.some((param) => param.name === "wallet_id")).toBe(true);
    expect(
      spec.paths["/intents"].post.requestBody.content["application/json"].schema.properties
        .intent_type.enum,
    ).toContain("policy_rule_create");
    expect(
      spec.paths["/intents"].post.requestBody.content["application/json"].schema.properties
        .intent_type.enum,
    ).toContain("policy_rule_delete");
    expect(spec.paths["/intents/{intentId}/approve"].post.description).toContain(
      "Alias for /intents/{intentId}/authorize",
    );

    const secretsList = spec.paths["/secrets"].get;
    expect(secretsList.security).toEqual([{ bearerAuth: [] }]);
    expect(secretsList.description).toContain("recent MFA");
    expect(
      secretsList.responses["200"].content["application/json"].schema.properties.data.items
        .properties,
    ).not.toHaveProperty("value");
    const secretCreateBody =
      spec.paths["/secrets"].post.requestBody.content["application/json"].schema;
    expect(secretCreateBody.required).toEqual(["name", "value"]);
    expect(spec.paths["/secrets"].post.description).toContain("never returned");
    const routeCreate = spec.paths["/secrets/routes"].post;
    expect(routeCreate.description).toContain("explicit allowlisted upstream host");
    expect(routeCreate.requestBody.content["application/json"].schema.required).toEqual([
      "secretId",
      "agentId",
      "hostPattern",
      "injectAs",
      "injectKey",
    ]);
    expect(
      routeCreate.requestBody.content["application/json"].schema.properties.method.enum,
    ).toContain("HEAD");
    expect(
      spec.paths["/secrets/routes"].get.parameters.some((param) => param.name === "secretId"),
    ).toBe(true);
    expect(spec.paths["/secrets/{secretId}/rotate"].post.description).toContain("recent MFA");

    const webhooksList = spec.paths["/webhooks"].get;
    expect(webhooksList.tags).toEqual(["Webhooks"]);
    expect(webhooksList.security).toEqual([{ bearerAuth: [] }]);
    expect(webhooksList.description).toContain("recent MFA");
    expect(
      webhooksList.responses["200"].content["application/json"].schema.properties.data.items
        .properties,
    ).not.toHaveProperty("secret");
    const webhookCreate = spec.paths["/webhooks"].post;
    expect(webhookCreate.description).toContain("signing secret exactly once");
    expect(
      webhookCreate.responses["201"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("secret");
    const webhookUpdate =
      spec.paths["/webhooks/{id}"].put.requestBody.content["application/json"].schema;
    expect(webhookUpdate.properties.events.items.enum).toContain("intent.executed");
    expect(webhookUpdate.properties.maxRetries.maximum).toBe(10);
    const deliveryHistory = spec.paths["/webhooks/{id}/deliveries"].get;
    expect(deliveryHistory.description).toContain("redact");
    expect(deliveryHistory.parameters.some((param) => param.name === "hasError")).toBe(true);
    const deliveryRow =
      deliveryHistory.responses["200"].content["application/json"].schema.properties.data.items
        .properties;
    expect(deliveryRow).toHaveProperty("hasError");
    expect(deliveryRow).not.toHaveProperty("lastError");
    expect(deliveryRow).not.toHaveProperty("payload");
    expect(deliveryRow).not.toHaveProperty("url");
    expect(spec.paths["/webhooks/deliveries/{id}/retry"].post.description).toContain(
      "without resetting attempts",
    );
    expect(spec.paths["/webhooks/deliveries/{id}/replay"].post.description).toContain(
      "new signed delivery",
    );
    expect(
      spec.paths["/webhooks/{id}/test"].post.responses["202"].content["application/json"].schema
        .properties.data.properties.eventType.const,
    ).toBe("webhook.test");

    const approvalsList = spec.paths["/approvals"].get;
    expect(approvalsList.tags).toEqual(["Approvals"]);
    expect(approvalsList.security).toEqual([{ bearerAuth: [] }]);
    expect(approvalsList.description).toContain("recent MFA");
    expect(approvalsList.description).toContain("Tenant API keys and agent tokens cannot");
    expect(approvalsList.parameters.find((param) => param.name === "status").schema.enum).toEqual([
      "pending",
      "approved",
      "rejected",
      "all",
    ]);
    expect(
      approvalsList.responses["200"].content["application/json"].schema.properties.data.items
        .properties.status.enum,
    ).toEqual(["pending", "approved", "rejected"]);
    const approvalStats = spec.paths["/approvals/stats"].get;
    expect(
      approvalStats.responses["200"].content["application/json"].schema.properties.data.properties,
    ).toHaveProperty("avgWaitSeconds");
    const approvalApprove = spec.paths["/approvals/{txId}/approve"].post;
    expect(approvalApprove.description).toContain("does not execute vault transactions");
    expect(approvalApprove.description).toContain("POST /vault/{agentId}/approve/{txId}");
    expect(
      approvalApprove.requestBody.content["application/json"].schema.properties.comment.maxLength,
    ).toBe(1000);
    const approvalDeny = spec.paths["/approvals/{txId}/deny"].post;
    expect(approvalDeny.requestBody.content["application/json"].schema.required).toEqual([
      "reason",
    ]);
    expect(approvalDeny.description).toContain("dispatches denial webhooks");
    const approvalRules = spec.paths["/approvals/rules"];
    expect(
      approvalRules.get.responses["200"].content["application/json"].schema.properties.data.anyOf,
    ).toEqual([
      expect.objectContaining({ required: ["tenantId", "maxAmountWei", "enabled"] }),
      { type: "null" },
    ]);
    expect(
      approvalRules.put.requestBody.content["application/json"].schema.properties.maxAmountWei
        .pattern,
    ).toBe("^\\d+$");
    expect(approvalRules.put.description).toContain("rolled back if the final audit write fails");

    const consentRequest = spec.paths["/global-wallet/consent/request"].get;
    expect(consentRequest.tags).toEqual(["Global Wallet"]);
    expect(consentRequest.security).toEqual([{ bearerAuth: [] }]);
    expect(consentRequest.description).toContain("allowed Origin/Referer");
    expect(consentRequest.parameters.some((param) => param.name === "app_id")).toBe(true);
    expect(
      consentRequest.responses["200"].content["application/json"].schema.properties.data.properties
        .requestedScopes.items.enum,
    ).toContain("eth_sendTransaction");
    const consentApprove = spec.paths["/global-wallet/consent/approve"].post;
    expect(consentApprove.description).toContain("Requires recent MFA");
    expect(consentApprove.description).toContain("rolled back if the final audit write fails");
    expect(
      consentApprove.requestBody.content["application/json"].schema.properties.scope.anyOf[0].enum,
    ).toContain("personal_sign");
    const consentList = spec.paths["/global-wallet/consents"].get;
    expect(
      consentList.responses["200"].content["application/json"].schema.properties.data.properties
        .consents.items.properties.scopes.items.enum,
    ).toContain("eth_signTypedData_v4");
    expect(spec.paths["/global-wallet/consents/{consentId}/revoke"].post.description).toContain(
      "Requires recent MFA",
    );
    const confirmation = spec.paths["/global-wallet/rpc/confirm"].post;
    expect(confirmation.description).toContain("request hash");
    expect(
      confirmation.responses["200"].content["application/json"].schema.properties.data.properties
        .confirmationId.type,
    ).toBe("string");
    const scan = spec.paths["/global-wallet/rpc/scan"].post;
    expect(scan.description).toContain("contract calldata is blocked");
    expect(
      scan.responses["200"].content["application/json"].schema.properties.data.properties
        .confirmationRequired.const,
    ).toBe(true);
    const rpc = spec.paths["/global-wallet/rpc"].post;
    expect(rpc.description).toContain("fail closed");
    expect(rpc.description).toContain("one-time action confirmation");
    expect(rpc.requestBody.content["application/json"].schema.properties.method.enum).toContain(
      "eth_accounts",
    );

    const tradeTokenStatus = spec.paths["/trade/token-status"].get;
    expect(tradeTokenStatus.tags).toEqual(["Trading"]);
    expect(tradeTokenStatus.description).toContain("without granting trading authority");
    expect(tradeTokenStatus.parameters.some((param) => param.name === "agentId")).toBe(true);
    const tradeSessionCreate = spec.paths["/trade/sessions"].post;
    expect(tradeSessionCreate.description).toContain("policy cap intersection");
    expect(tradeSessionCreate.description).toContain("asset allowlist checks");
    expect(
      tradeSessionCreate.requestBody.content["application/json"].schema.properties.allowedAssets.items
        .anyOf[0].enum,
    ).toContain("HYPE");
    const tradeOrder = spec.paths["/trade/hyperliquid/order"].post;
    expect(tradeOrder.security).toEqual([{ bearerAuth: [] }]);
    expect(tradeOrder.description).toContain("Requires an agent JWT");
    expect(tradeOrder.description).toContain("evaluated against leverage/per-order/daily-spend");
    expect(tradeOrder.responses).toHaveProperty("429");
    expect(tradeOrder.requestBody.content["application/json"].schema.anyOf).toEqual([
      { required: ["coin"] },
      { required: ["asset"] },
    ]);
    const recoveryDeposit = spec.paths["/trade/{venue}/deposit"].post;
    expect(recoveryDeposit.security).toEqual([
      { platformKey: [] },
      { tenantApiKey: [] },
      { bearerAuth: [] },
    ]);
    expect(recoveryDeposit.description).toContain("must not require an agent JWT");
    expect(recoveryDeposit.description).toContain("5-2000 USDC");
    expect(
      recoveryDeposit.requestBody.content["application/json"].schema.properties.amount.anyOf,
    ).toEqual([{ type: "string" }, { type: "number" }]);
    const recoveryCloseAll = spec.paths["/trade/{venue}/close-all"].post;
    expect(recoveryCloseAll.description).toContain("Every per-coin close result is audited");
    const recoveryLeverage = spec.paths["/trade/{venue}/leverage"].post;
    expect(recoveryLeverage.description).toContain("updateLeverage");
    expect(recoveryLeverage.description).toContain("capped at 3x");
    const recoveryWithdraw = spec.paths["/trade/{venue}/withdraw"].post;
    expect(recoveryWithdraw.description).toContain("approved-addresses policy gate");
    expect(recoveryWithdraw.description).toContain("fails closed when unavailable");
    expect(recoveryWithdraw.requestBody.content["application/json"].schema.required).toEqual([
      "agentId",
      "destination",
    ]);
    expect(spec.paths["/v1/trade/hyperliquid/order"].post.description).toContain("agent JWT");

    const publicTenantConfig = spec.paths["/tenants/config"].get;
    expect(publicTenantConfig.tags).toEqual(["Tenant Config"]);
    expect(publicTenantConfig.security).toEqual([]);
    expect(publicTenantConfig.description).toContain("Public discovery endpoint");
    const tenantConfigGet = spec.paths["/tenants/{id}/config"].get;
    expect(tenantConfigGet.security).toEqual([{ tenantApiKey: [] }, { bearerAuth: [] }]);
    expect(
      tenantConfigGet.responses["200"].content["application/json"].schema.properties.data
        .properties,
    ).toHaveProperty("featureFlags");
    const tenantConfigPut = spec.paths["/tenants/{id}/config"].put;
    expect(tenantConfigPut.security).toEqual([{ bearerAuth: [] }]);
    expect(tenantConfigPut.description).toContain("recent MFA");
    expect(tenantConfigPut.description).toContain("allowed origins");
    const authAbuseConfig = spec.paths["/tenants/{id}/auth-abuse-config"].put;
    expect(
      authAbuseConfig.requestBody.content["application/json"].schema.properties,
    ).toHaveProperty("authAbuseConfig");
    expect(authAbuseConfig.description).toContain("MFA");
    const checklist = spec.paths["/tenants/{id}/security-checklist"].get;
    expect(checklist.description).toContain("request-signing-key");
    expect(
      checklist.responses["200"].content["application/json"].schema.properties.data.properties.items
        .items.properties.status.enum,
    ).toEqual(["pass", "warning", "fail"]);
    expect(spec.paths["/tenants/{id}/idempotency-metrics"].get.description).toContain(
      "idempotency counters",
    );
    const idempotencyExport = spec.paths["/tenants/{id}/idempotency-metrics/export"].get;
    expect(idempotencyExport.security).toEqual([{ bearerAuth: [] }]);
    expect(idempotencyExport.description).toContain("recent MFA");
    expect(idempotencyExport.description).toContain("CSV snapshot");
    expect(idempotencyExport.description).toContain("never includes idempotency keys");
    expect(idempotencyExport.responses["200"].content).toHaveProperty("text/csv");
    const signingKeys = spec.paths["/tenants/{id}/request-signing-keys"].get;
    expect(signingKeys.description).toContain("metadata only");
    expect(
      signingKeys.responses["200"].content["application/json"].schema.properties.data.properties
        .keys.items.properties,
    ).not.toHaveProperty("signingSecret");
    const signingKeyCreate = spec.paths["/tenants/{id}/request-signing-keys"].post;
    expect(signingKeyCreate.description).toContain("signingSecret exactly once");
    expect(
      signingKeyCreate.responses["201"].content["application/json"].schema.properties.data
        .properties,
    ).toHaveProperty("signingSecret");
    const templateApply = spec.paths["/tenants/{id}/config/templates/{name}/apply"].post;
    expect(templateApply.description).toContain("customizable fields");
    expect(templateApply.requestBody.content["application/json"].schema.required).toEqual([
      "agentId",
    ]);

    const tenantMembers = spec.paths["/platform/tenants/{tenantId}/members"];
    expect(tenantMembers.get.tags).toEqual(["Platform Tenants"]);
    expect(tenantMembers.get.security).toEqual([{ platformKey: [] }]);
    expect(tenantMembers.get.description).toContain("platform:tenant-member:read");
    expect(
      tenantMembers.get.responses["200"].content["application/json"].schema.properties.data.items
        .properties.role.enum,
    ).toEqual(["owner", "admin", "member"]);
    expect(tenantMembers.post.description).toContain("platform:tenant-member:write");
    expect(tenantMembers.post.description).toContain("audits the membership add");
    expect(
      tenantMembers.post.requestBody.content["application/json"].schema.properties.role.enum,
    ).toEqual(["owner", "admin", "member"]);
    const memberRoleUpdate = spec.paths["/platform/tenants/{tenantId}/members/{userId}"].patch;
    expect(memberRoleUpdate.description).toContain("revoke the member's tenant refresh tokens");
    expect(memberRoleUpdate.description).toContain("sole active owner");

    const tenantInvitations = spec.paths["/platform/tenants/{tenantId}/invitations"];
    expect(tenantInvitations.get.description).toContain("token hashes are never returned");
    expect(
      tenantInvitations.get.parameters.find((param) => param.name === "status").schema.enum,
    ).toEqual(["pending", "accepted", "revoked", "expired", "all"]);
    const invitationListItem =
      tenantInvitations.get.responses["200"].content["application/json"].schema.properties.data
        .properties.invitations.items.properties;
    expect(invitationListItem).not.toHaveProperty("token");
    expect(invitationListItem).not.toHaveProperty("tokenHash");
    const invitationCreate = tenantInvitations.post;
    expect(invitationCreate.description).toContain("single-use invitation token exactly once");
    expect(invitationCreate.description).toContain("no-store");
    expect(
      invitationCreate.responses["201"].content["application/json"].schema.properties.data
        .properties,
    ).toHaveProperty("token");
    expect(
      spec.paths["/platform/tenants/{tenantId}/invitations/{invitationId}"].delete.description,
    ).toContain("rolls the status back");
  });

  it("marks sensitive mutating operations with request-hardening inventory", () => {
    const spec = getOpenApiSpec();

    expect(spec["x-steward-sensitive-prefixes"]).toContain("/vault");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/accounts");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/v1/accounts");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/auth");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/wallets/batch");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/v1/adapters");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/v1/users");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/secrets");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/trade");
    expect(spec["x-steward-sensitive-prefixes"]).toContain("/v1/trade");

    expectHardening(spec.paths["/platform/users"].post, "/platform");
    expectHardening(spec.paths["/auth/mfa/totp/enroll"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/totp/complete"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/totp/step-up"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/recovery-codes/regenerate"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/sms/enroll"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/sms/complete"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/sms/step-up"].post, "/auth");
    expectHardening(spec.paths["/auth/mfa/passkey/complete"].post, "/auth");
    expectHardening(spec.paths["/auth/logout"].post, "/auth");
    expectHardening(spec.paths["/auth/refresh"].post, "/auth");
    expectHardening(spec.paths["/auth/revoke"].post, "/auth");
    expectHardening(spec.paths["/platform/users/{userId}/wallet/external-id"].post, "/platform");
    expectHardening(spec.paths["/accounts"].post, "/accounts");
    expectHardening(spec.paths["/v1/accounts/{accountId}"].patch, "/v1/accounts");
    expectHardening(spec.paths["/wallets/batch"].post, "/wallets/batch");
    expectHardening(spec.paths["/v1/wallets/batch"].post, "/v1/wallets/batch");
    expectHardening(spec.paths["/user/me/wallet/signers"].post, "/user");
    expectHardening(spec.paths["/user/me/wallet/signers/{signerId}"].delete, "/user");
    expectHardening(spec.paths["/vault/{agentId}/actions/transfer"].post, "/vault");
    expectHardening(spec.paths["/vault/{agentId}/actions/send-calls"].post, "/vault");
    expectHardening(spec.paths["/adapters/swap/build"].post, "/adapters");
    expectHardening(spec.paths["/v1/adapters/bridge/build"].post, "/v1/adapters");
    expectHardening(spec.paths["/v1/users/{userId}/fiat/kyc"].post, "/v1/users");
    expectHardening(spec.paths["/v1/users/{userId}/fiat/kyc"].patch, "/v1/users");
    expectHardening(spec.paths["/v1/users/{userId}/fiat/onramp"].post, "/v1/users");
    expectHardening(spec.paths["/v1/users/{userId}/fiat/offramp"].post, "/v1/users");
    expectHardening(spec.paths["/audit/verify"].post, "/audit");
    expectHardening(spec.paths["/secrets"].post, "/secrets");
    expectHardening(spec.paths["/secrets/routes"].post, "/secrets");
    expectHardening(spec.paths["/secrets/routes/{routeId}"].put, "/secrets");
    expectHardening(spec.paths["/secrets/{secretId}/rotate"].post, "/secrets");
    expectHardening(spec.paths["/webhooks"].post, "/webhooks");
    expectHardening(spec.paths["/webhooks/{id}"].put, "/webhooks");
    expectHardening(spec.paths["/webhooks/{id}"].delete, "/webhooks");
    expectHardening(spec.paths["/webhooks/deliveries/{id}/retry"].post, "/webhooks");
    expectHardening(spec.paths["/webhooks/deliveries/{id}/replay"].post, "/webhooks");
    expectHardening(spec.paths["/approvals/{txId}/approve"].post, "/approvals");
    expectHardening(spec.paths["/approvals/{txId}/deny"].post, "/approvals");
    expectHardening(spec.paths["/approvals/rules"].put, "/approvals");
    expectHardening(spec.paths["/global-wallet/consent/approve"].post, "/global-wallet");
    expectHardening(
      spec.paths["/global-wallet/consents/{consentId}/revoke"].post,
      "/global-wallet",
    );
    expectHardening(spec.paths["/global-wallet/rpc/confirm"].post, "/global-wallet");
    expectHardening(spec.paths["/global-wallet/rpc/scan"].post, "/global-wallet");
    expectHardening(spec.paths["/global-wallet/rpc"].post, "/global-wallet");
    expectHardening(spec.paths["/trade/sessions"].post, "/trade");
    expectHardening(spec.paths["/trade/hyperliquid/order"].post, "/trade");
    expectHardening(spec.paths["/trade/{venue}/deposit"].post, "/trade");
    expectHardening(spec.paths["/trade/{venue}/close-all"].post, "/trade");
    expectHardening(spec.paths["/trade/{venue}/leverage"].post, "/trade");
    expectHardening(spec.paths["/trade/{venue}/withdraw"].post, "/trade");
    expectHardening(spec.paths["/v1/trade/hyperliquid/order"].post, "/v1/trade");
    expectHardening(spec.paths["/v1/trade/{venue}/leverage"].post, "/v1/trade");
    expectHardening(spec.paths["/v1/trade/{venue}/withdraw"].post, "/v1/trade");
    expectHardening(spec.paths["/tenants/{id}/config"].put, "/tenants");
    expectHardening(spec.paths["/tenants/{id}/config/templates/{name}/apply"].post, "/tenants");
    expectHardening(spec.paths["/tenants/{id}/auth-abuse-config"].put, "/tenants");
    expectHardening(spec.paths["/tenants/{id}/request-signing-keys"].post, "/tenants");
    expectHardening(spec.paths["/tenants/{id}/request-signing-keys/{keyId}"].delete, "/tenants");
    expectHardening(spec.paths["/platform/tenants/{tenantId}/members"].post, "/platform");
    expectHardening(spec.paths["/platform/tenants/{tenantId}/members/{userId}"].patch, "/platform");
    expectHardening(
      spec.paths["/platform/tenants/{tenantId}/members/{userId}"].delete,
      "/platform",
    );
    expectHardening(spec.paths["/platform/tenants/{tenantId}/invitations"].post, "/platform");
    expectHardening(
      spec.paths["/platform/tenants/{tenantId}/invitations/{invitationId}"].delete,
      "/platform",
    );
    expectHardening(spec.paths["/condition-sets"].post, "/condition-sets");
    expectHardening(
      spec.paths["/v1/condition-sets/{conditionSetId}/items/{itemId}"].delete,
      "/v1/condition-sets",
    );
    expectHardening(spec.paths["/agents/{agentId}/signers"].post, "/agents");
    expectHardening(spec.paths["/v1/agents/{agentId}/key-quorums/{quorumId}"].delete, "/v1/agents");

    expect(spec.paths["/vault/{agentId}/transactions"].get["x-steward-hardening"]).toBeUndefined();
    expect(spec.paths["/platform/apps/gas_spend"].get["x-steward-hardening"]).toBeUndefined();
  });

  it("documents wallet action status and error parity", () => {
    const spec = getOpenApiSpec();
    const quote = spec.paths["/vault/{agentId}/actions/transfer/quote"].post;
    const transfer = spec.paths["/vault/{agentId}/actions/transfer"].post;
    const sendCalls = spec.paths["/vault/{agentId}/actions/send-calls"].post;
    const status = spec.paths["/vault/{agentId}/actions/{actionId}"].get;

    const transferBody = transfer.requestBody.content["application/json"].schema;
    expect(quote.requestBody.content["application/json"].schema).toBe(transferBody);
    expect(transferBody.anyOf).toEqual([{ required: ["value"] }, { required: ["amountWei"] }]);
    expect(transferBody.properties).toHaveProperty("referenceId");
    expect(transferBody.properties).toHaveProperty("sponsor");

    const transferData =
      transfer.responses["200"].content["application/json"].schema.properties.data;
    expect(transferData.properties.status.enum).toEqual([
      "pending_approval",
      "rejected",
      "signed",
      "broadcast",
      "confirmed",
      "failed",
    ]);
    expect(transfer.responses).toHaveProperty("202");
    expect(transfer.responses).toHaveProperty("429");
    expect(transfer.responses).toHaveProperty("502");
    expect(transfer.description).toContain("selector-gated ERC20 transfer");
    expect(transfer.description).toContain("zero native value");
    expect(transfer.description).toContain("contract-allowlist");
    expect(transfer.description).toContain("Policy-denied actions return 403");
    expect(transfer.description).toContain("Broadcast actions require idempotency");
    expect(quote.description).toContain("ERC20 execution requires");

    const sendCallsData =
      sendCalls.responses["202"].content["application/json"].schema.properties.data;
    expect(sendCalls.requestBody.content["application/json"].schema.properties.calls.maxItems).toBe(
      25,
    );
    expect(sendCallsData.properties.status.enum).toEqual(["pending_approval", "rejected"]);
    expect(sendCalls.description).toContain("approval/intents workflow");

    const statusData = status.responses["200"].content["application/json"].schema.properties.data;
    expect(statusData.properties.type.const).toBe("transfer");
    expect(status.description).toContain("transfer-only status endpoint");
  });

  it("covers condition-set resources and item lifecycle surfaces", () => {
    const spec = getOpenApiSpec();
    const conditionSets = spec.paths["/condition-sets"];
    const conditionSet = spec.paths["/condition-sets/{conditionSetId}"];
    const items = spec.paths["/condition-sets/{conditionSetId}/items"];
    const item = spec.paths["/condition-sets/{conditionSetId}/items/{itemId}"];

    expect(conditionSets).toHaveProperty("get");
    expect(conditionSets).toHaveProperty("post");
    expect(conditionSet).toHaveProperty("get");
    expect(conditionSet).toHaveProperty("patch");
    expect(conditionSet).toHaveProperty("delete");
    expect(items).toHaveProperty("get");
    expect(items).toHaveProperty("post");
    expect(items).toHaveProperty("put");
    expect(item).toHaveProperty("get");
    expect(item).toHaveProperty("patch");
    expect(item).toHaveProperty("delete");
    expect(spec.paths).toHaveProperty("/v1/condition-sets/{conditionSetId}/items/{itemId}");

    const itemListSchema =
      items.get.responses["200"].content["application/json"].schema.properties.data;
    expect(itemListSchema.required).toEqual(["items", "limit", "offset"]);
    expect(itemListSchema.properties.items.type).toBe("array");
    expect(itemListSchema.properties.limit.type).toBe("integer");
    expect(itemListSchema.properties.offset.type).toBe("integer");
  });

  it("covers policy template and simulation schemas that reference condition sets", () => {
    const spec = getOpenApiSpec();

    expect(spec.paths["/policies"]).toHaveProperty("get");
    expect(spec.paths["/policies"]).toHaveProperty("post");
    expect(spec.paths["/policies/{templateId}"]).toHaveProperty("get");
    expect(spec.paths["/policies/{templateId}"]).toHaveProperty("put");
    expect(spec.paths["/policies/{templateId}"]).toHaveProperty("delete");
    expect(spec.paths["/policies/{templateId}/assign"]).toHaveProperty("post");
    expect(spec.paths["/policies/simulate"]).toHaveProperty("post");
    expect(spec.paths).toHaveProperty("/v1/policies/simulate");

    const simulateBody =
      spec.paths["/policies/simulate"].post.requestBody.content["application/json"].schema;
    expect(simulateBody.properties).toHaveProperty("rules");
    expect(simulateBody.properties).toHaveProperty("policyId");
    expect(simulateBody.properties).toHaveProperty("request");
  });

  it("serves the generated contract at /openapi.json", async () => {
    process.env.DATABASE_URL ??= "postgres://openapi-contract.invalid/steward";
    process.env.STEWARD_MASTER_PASSWORD ??= "openapi-contract-master-password";
    const { default: app } = await import("../app");
    const response = await app.request("/openapi.json");

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual(getOpenApiSpec());
  });

  it("keeps docs/openapi.json in sync with the generator", async () => {
    const generated = `${JSON.stringify(getOpenApiSpec(), null, 2)}\n`;
    const committed = await readFile(
      resolve(import.meta.dir, "../../../../docs/openapi.json"),
      "utf8",
    );

    expect(committed).toBe(generated);
  });
});
