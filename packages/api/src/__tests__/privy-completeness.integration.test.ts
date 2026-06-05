import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import { randomUUID } from "node:crypto";
import { generateTotp, hashSha256Hex } from "@stwd/auth";
import { agents, closeDb, getDb, tenantConfigs, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { isValidMnemonic } from "@stwd/vault";
import { eq } from "drizzle-orm";

const webhookDispatches: Array<{
  event: { type: string; deliveryId?: string; data?: unknown };
  webhook: { url: string; secret: string };
}> = [];

mock.module("@stwd/webhooks", () => ({
  encryptWebhookSecret: (secret: string) => `enc:${secret}`,
  decryptWebhookSecret: (secret: string) => secret.replace(/^enc:/, ""),
  isEncryptedWebhookSecret: (secret: string) => secret.startsWith("enc:"),
  WebhookDispatcher: class {
    async dispatch(
      event: { type: string; deliveryId?: string },
      webhook: { url: string; secret: string },
    ) {
      webhookDispatches.push({ event, webhook });
      return {
        success: true,
        attempts: 1,
        deliveredAt: new Date(),
        deliveryId: event.deliveryId,
      };
    }
  },
}));

const TEST_ID = randomUUID();
const USER_ID = TEST_ID;
const TENANT_ID = `personal-${USER_ID}`;
const EMAIL = `privy-completeness-${TEST_ID}@example.test`;
const USER_ADDRESS = "0x00000000000000000000000000000000000000cd";
const RESTORE_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("Privy-competitor integration completeness", () => {
  let app: Awaited<typeof import("../app")>["app"];
  let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "privy-completeness-master-password";
    process.env.STEWARD_JWT_SECRET = "privy-completeness-jwt-secret-with-enough-entropy";
    process.env.JWT_SECRET = "privy-completeness-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "privy-completeness-audit-hmac-key-with-enough-entropy";
    process.env.NODE_ENV = "test";
    process.env.EMAIL_PROVIDER = "mock";
    process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(users).values({
      id: USER_ID,
      email: EMAIL,
      emailVerified: true,
      walletAddress: null,
      walletChain: null,
    });
    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Privy Completeness", apiKeyHash: `hash-${TENANT_ID}` });
    await getDb()
      .insert(userTenants)
      .values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });

    ({ app } = await import("../app"));
    ({ createSessionToken } = await import("../routes/auth"));
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.NODE_ENV;
    delete process.env.EMAIL_PROVIDER;
    delete process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING;
    delete process.env.STEWARD_ALLOW_USER_UNSAFE_MESSAGE_SIGNING;
  });

  async function sessionTokenFor(
    userId: string,
    tenantId: string,
    email: string,
    options: { factorEnrollment?: boolean; mfa?: boolean } = {},
  ) {
    return createSessionToken(USER_ADDRESS, tenantId, {
      userId,
      email,
      authMethod: "email",
      ...(options.factorEnrollment ? { factorEnrollmentVerifiedAt: Date.now() } : {}),
      ...(options.mfa ? { mfaVerifiedAt: Date.now(), mfaMethod: "totp" } : {}),
    });
  }

  async function sessionToken(options: { factorEnrollment?: boolean; mfa?: boolean } = {}) {
    return sessionTokenFor(USER_ID, TENANT_ID, EMAIL, options);
  }

  async function createPersonalUser(label: string) {
    const userId = randomUUID();
    const tenantId = `personal-${userId}`;
    const email = `privy-${label}-${userId}@example.test`;
    await getDb().insert(users).values({
      id: userId,
      email,
      emailVerified: true,
      walletAddress: null,
      walletChain: null,
    });
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: `Privy ${label}`, apiKeyHash: `hash-${tenantId}` });
    await getDb().insert(userTenants).values({ userId, tenantId, role: "owner" });
    return { userId, tenantId, email };
  }

  async function json<T>(response: Response): Promise<T> {
    return (await response.json()) as T;
  }

  async function waitForWebhookEvent(type: string) {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const dispatch = webhookDispatches.find((item) => item.event.type === type);
      if (dispatch) return dispatch;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Timed out waiting for webhook event ${type}`);
  }

  it("covers session MFA step-up, recovery setup one-time secret, wallet-action MFA denial, webhook dispatch, and audit filters", async () => {
    const factorEnrollmentToken = await sessionToken({ factorEnrollment: true });

    const deniedRecovery = await app.request("/user/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${factorEnrollmentToken}` },
    });
    expect(deniedRecovery.status).toBe(403);
    await expect(json<{ error: string }>(deniedRecovery)).resolves.toMatchObject({
      error: expect.stringContaining("recent MFA"),
    });

    const enroll = await app.request("/auth/mfa/totp/enroll", {
      method: "POST",
      headers: { Authorization: `Bearer ${factorEnrollmentToken}` },
    });
    expect(enroll.status).toBe(200);
    const enrolled = await json<{ ok: true; secret: string }>(enroll);
    const code = await generateTotp(enrolled.secret);

    const verify = await app.request("/auth/mfa/totp/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${factorEnrollmentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    expect(verify.status).toBe(200);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const mfaToken = await sessionToken({ mfa: true });
    const recovery = await app.request("/user/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${mfaToken}` },
    });
    expect(recovery.status).toBe(201);
    expect(recovery.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(recovery.headers.get("Pragma")).toBe("no-cache");
    expect(recovery.headers.get("Expires")).toBe("0");
    const recoveryBody = await json<{
      ok: boolean;
      data: {
        wallet: { agentId: string; walletAddress: string; recoverable: true };
        recovery: { type: "bip39"; mnemonic: string; warning: string };
      };
    }>(recovery);
    expect(recoveryBody.ok).toBe(true);
    expect(recoveryBody.data.wallet).toMatchObject({
      agentId: `user-wallet-${USER_ID}`,
      recoverable: true,
    });
    expect(isValidMnemonic(recoveryBody.data.recovery.mnemonic)).toBe(true);
    expect(recoveryBody.data.recovery.warning).toContain("shown once");

    const recoveryReplay = await app.request("/user/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${mfaToken}` },
    });
    expect(recoveryReplay.status).toBe(409);
    expect(await recoveryReplay.text()).not.toContain(recoveryBody.data.recovery.mnemonic);

    const aliasUser = await createPersonalUser("aggregation");
    const aliasToken = await sessionTokenFor(aliasUser.userId, aliasUser.tenantId, aliasUser.email);
    const account = await app.request("/user/me/account", {
      headers: { Authorization: `Bearer ${aliasToken}` },
    });
    const aggregation = await app.request("/user/me/aggregation", {
      headers: { Authorization: `Bearer ${aliasToken}` },
    });
    const accountsAggregation = await app.request("/user/me/accounts/aggregation", {
      headers: { Authorization: `Bearer ${aliasToken}` },
    });
    expect(account.status).toBe(200);
    expect(aggregation.status).toBe(200);
    expect(accountsAggregation.status).toBe(200);
    const accountBody = await json<{
      ok: boolean;
      data: { id: string; type: string; wallet: null; capabilities: string[] };
    }>(account);
    const aggregationBody = await json<typeof accountBody>(aggregation);
    const accountsAggregationBody = await json<typeof accountBody>(accountsAggregation);
    expect(aggregationBody.data).toMatchObject({
      id: accountBody.data.id,
      type: "user",
      wallet: null,
      capabilities: [],
    });
    expect(accountsAggregationBody.data).toMatchObject(aggregationBody.data);

    const createdAgent = await app.request("/agents", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        "Content-Type": "application/json",
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ name: "Privy aggregation agent" }),
    });
    expect(createdAgent.status).toBe(200);
    const createdAgentBody = await json<{
      ok: boolean;
      data: { id: string; walletAddress: string };
    }>(createdAgent);
    const agentAccount = await app.request(`/agents/${createdAgentBody.data.id}/account`, {
      headers: { Authorization: `Bearer ${mfaToken}`, "X-Steward-Tenant": TENANT_ID },
    });
    const agentAggregation = await app.request(`/agents/${createdAgentBody.data.id}/aggregation`, {
      headers: { Authorization: `Bearer ${mfaToken}`, "X-Steward-Tenant": TENANT_ID },
    });
    expect(agentAccount.status).toBe(200);
    expect(agentAggregation.status).toBe(200);
    const agentAccountBody = await json<{
      ok: boolean;
      data: { id: string; type: string; walletAddress: string; capabilities: string[] };
    }>(agentAccount);
    const agentAggregationBody = await json<typeof agentAccountBody>(agentAggregation);
    expect(agentAggregationBody.data).toMatchObject({
      id: agentAccountBody.data.id,
      type: "agent",
      walletAddress: createdAgentBody.data.walletAddress,
      capabilities: agentAccountBody.data.capabilities,
    });

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const noMfaToken = await sessionToken();

    const deniedConsent = await app.request("/global-wallet/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${noMfaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ appId: `${TENANT_ID}/web`, origin: "https://app.example.com" }),
    });
    expect(deniedConsent.status).toBe(403);
    await expect(json<{ error: string }>(deniedConsent)).resolves.toMatchObject({
      error: expect.stringContaining("Recent MFA"),
    });

    const deniedSign = await app.request("/user/me/wallet/sign-message", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${noMfaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ message: "Compatibility signing should still require MFA" }),
    });
    expect(deniedSign.status).toBe(403);
    const deniedSignBody = await json<{ ok: boolean; error: string; data?: unknown }>(deniedSign);
    expect(deniedSignBody.ok).toBe(false);
    expect(deniedSignBody.error).toContain("recent MFA");
    expect(deniedSignBody.data).toBeUndefined();

    const webhookCreate = await app.request("/webhooks", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: "https://example.com/steward-webhook",
        events: ["wallet.recovery_setup", "wallet_action.transfer.succeeded"],
        maxRetries: 0,
        retryBackoffMs: 1000,
      }),
    });
    expect(webhookCreate.status).toBe(201);
    const createdWebhook = await json<{
      ok: boolean;
      data: { id: string; secret: string; events: string[] };
    }>(webhookCreate);
    expect(createdWebhook.ok).toBe(true);
    expect(createdWebhook.data.secret).toMatch(/^whsec_/);
    expect(createdWebhook.data.events).toEqual([
      "wallet.recovery_setup",
      "wallet_action.transfer.succeeded",
    ]);

    const listedWebhooks = await app.request("/webhooks", {
      headers: { Authorization: `Bearer ${mfaToken}` },
    });
    expect(listedWebhooks.status).toBe(200);
    expect(await listedWebhooks.text()).not.toContain(createdWebhook.data.secret);

    const testDispatch = await app.request(`/webhooks/${createdWebhook.data.id}/test`, {
      method: "POST",
      headers: { Authorization: `Bearer ${mfaToken}` },
    });
    expect(testDispatch.status).toBe(202);
    const dispatchBody = await json<{ ok: boolean; data: { eventType: string; status: string } }>(
      testDispatch,
    );
    expect(dispatchBody.ok).toBe(true);
    expect(dispatchBody.data).toMatchObject({ eventType: "webhook.test", status: "delivered" });
    expect(webhookDispatches.at(-1)?.event.type).toBe("webhook.test");

    const webhookRecoveryUser = await createPersonalUser("webhook-recovery");
    const webhookRecoveryToken = await sessionTokenFor(
      webhookRecoveryUser.userId,
      webhookRecoveryUser.tenantId,
      webhookRecoveryUser.email,
      { mfa: true },
    );
    const webhookRecoveryConfig = await app.request("/webhooks", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${webhookRecoveryToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: "https://example.com/recovery-webhook",
        events: ["wallet.recovery_setup"],
        maxRetries: 0,
      }),
    });
    expect(webhookRecoveryConfig.status).toBe(201);
    const webhookRecovery = await app.request("/user/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${webhookRecoveryToken}` },
    });
    expect(webhookRecovery.status).toBe(201);
    const webhookRecoveryBody = await json<{
      data: {
        wallet: { agentId: string; recoverable: true };
        recovery: { mnemonic: string };
      };
    }>(webhookRecovery);
    const recoverySetupDispatch = await waitForWebhookEvent("wallet.recovery_setup");
    expect(recoverySetupDispatch.webhook.url).toBe("https://example.com/recovery-webhook");
    expect(recoverySetupDispatch.event.deliveryId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );
    expect(recoverySetupDispatch.event.data).toMatchObject({
      walletId: webhookRecoveryBody.data.wallet.agentId,
      method: "bip39",
    });
    const recoveryDispatchJson = JSON.stringify(recoverySetupDispatch.event);
    expect(recoveryDispatchJson).not.toContain(webhookRecoveryBody.data.recovery.mnemonic);
    expect(recoveryDispatchJson).not.toContain("mnemonic");
    expect(recoveryDispatchJson).not.toContain("recoveryPhrase");
    expect(recoveryDispatchJson).not.toContain("privateKey");

    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { user: { allowedUserIds: [randomUUID()] } },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: { user: { allowedUserIds: [randomUUID()] } } },
      });
    const sendAllowedUserBlocked = await app.request("/auth/email/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_ID, email: EMAIL }),
    });
    expect(sendAllowedUserBlocked.status).toBe(200);
    const inbox = await app.request(`/auth/test/inbox/${encodeURIComponent(EMAIL)}`);
    expect(inbox.status).toBe(200);
    const { token: magicToken } = await json<{ token: string }>(inbox);
    const deniedByUserAllowlist = await app.request("/auth/email/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_ID, email: EMAIL, token: magicToken }),
    });
    expect(deniedByUserAllowlist.status).toBe(403);
    await expect(json<{ error: string }>(deniedByUserAllowlist)).resolves.toMatchObject({
      error: "user id is not allowed",
    });
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId: TENANT_ID, authAbuseConfig: {} })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: {} },
      });

    const pregenerated = await app.request("/agents/pregenerated", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        "Content-Type": "application/json",
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({ count: 1, namePrefix: "Privy E2E pregenerated" }),
    });
    expect(pregenerated.status).toBe(201);
    expect(pregenerated.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const pregeneratedBody = await json<{
      ok: boolean;
      data: {
        wallets: Array<{
          agent: { id: string; walletAddress: string };
          claimToken: string;
          claimExpiresAt: string;
        }>;
        warning: string;
      };
    }>(pregenerated);
    expect(pregeneratedBody.ok).toBe(true);
    expect(pregeneratedBody.data.warning).toContain("shown once");
    const claimToken = pregeneratedBody.data.wallets[0]?.claimToken;
    expect(claimToken).toMatch(/^stwd_claim_/);
    const claimTokenHash = hashSha256Hex(claimToken ?? "");
    expect(Date.parse(pregeneratedBody.data.wallets[0]?.claimExpiresAt ?? "")).toBeGreaterThan(
      Date.now(),
    );
    expect(pregeneratedBody.data.wallets[0]?.agent.platformId).toBeUndefined();
    const agentList = await app.request("/agents", {
      headers: { Authorization: `Bearer ${mfaToken}`, "X-Steward-Tenant": TENANT_ID },
    });
    expect(agentList.status).toBe(200);
    const agentListText = await agentList.text();
    expect(agentListText).not.toContain(claimToken);
    expect(agentListText).not.toContain(claimTokenHash);
    const pregeneratedAgentDetail = await app.request(
      `/agents/${encodeURIComponent(pregeneratedBody.data.wallets[0]?.agent.id ?? "")}`,
      {
        headers: { Authorization: `Bearer ${mfaToken}`, "X-Steward-Tenant": TENANT_ID },
      },
    );
    expect(pregeneratedAgentDetail.status).toBe(200);
    const pregeneratedAgentDetailText = await pregeneratedAgentDetail.text();
    expect(pregeneratedAgentDetailText).not.toContain(claimTokenHash);

    const pregeneratedInventory = await app.request("/agents/pregenerated", {
      headers: { Authorization: `Bearer ${mfaToken}`, "X-Steward-Tenant": TENANT_ID },
    });
    expect(pregeneratedInventory.status).toBe(200);
    const pregeneratedInventoryBody = await json<{
      ok: boolean;
      data: {
        wallets: Array<{
          agent: { id: string; platformId?: string };
          status: "claimable" | "claimed" | "expired" | "unknown";
          claimExpiresAt: string | null;
        }>;
      };
    }>(pregeneratedInventory);
    expect(pregeneratedInventoryBody.data.wallets[0]?.agent.platformId).toBeUndefined();
    expect(pregeneratedInventoryBody.data.wallets[0]?.status).toBe("claimable");
    expect(pregeneratedInventoryBody.data.wallets[0]?.claimExpiresAt).toBe(
      pregeneratedBody.data.wallets[0]?.claimExpiresAt,
    );

    const claimUser = await createPersonalUser("claim");
    const claimTokenSession = await sessionTokenFor(
      claimUser.userId,
      claimUser.tenantId,
      claimUser.email,
      { mfa: true },
    );
    const claimed = await app.request("/user/me/wallet/claim-pregenerated", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${claimTokenSession}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tenantId: TENANT_ID, claimToken }),
    });
    expect(claimed.status).toBe(201);
    expect(claimed.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const claimedBody = await json<{
      ok: boolean;
      data: { agentId: string; walletAddress: string; claimed: true };
    }>(claimed);
    expect(claimedBody.data).toMatchObject({
      agentId: `user-wallet-${claimUser.userId}`,
      claimed: true,
      walletAddress: pregeneratedBody.data.wallets[0]?.agent.walletAddress,
    });

    const replayUser = await createPersonalUser("claim-replay");
    const replayTokenSession = await sessionTokenFor(
      replayUser.userId,
      replayUser.tenantId,
      replayUser.email,
      { mfa: true },
    );
    const replayClaim = await app.request("/user/me/wallet/claim-pregenerated", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${replayTokenSession}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tenantId: TENANT_ID, claimToken }),
    });
    expect(replayClaim.status).toBe(404);
    await expect(json<{ error: string }>(replayClaim)).resolves.toMatchObject({
      error: "Invalid or already claimed wallet token",
    });

    const expiringPregenerated = await app.request("/agents/pregenerated", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${mfaToken}`,
        "Content-Type": "application/json",
        "X-Steward-Tenant": TENANT_ID,
      },
      body: JSON.stringify({
        count: 1,
        namePrefix: "Privy E2E expired pregenerated",
        claimExpiresInSeconds: 300,
      }),
    });
    expect(expiringPregenerated.status).toBe(201);
    const expiringBody = await json<typeof pregeneratedBody>(expiringPregenerated);
    const expiredAgentId = expiringBody.data.wallets[0]?.agent.id;
    const rotatedClaim = await app.request(
      `/agents/pregenerated/${encodeURIComponent(expiredAgentId ?? "")}/claim-token/rotate`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${mfaToken}`,
          "Content-Type": "application/json",
          "X-Steward-Tenant": TENANT_ID,
        },
        body: JSON.stringify({ claimExpiresInSeconds: 600 }),
      },
    );
    expect(rotatedClaim.status).toBe(200);
    expect(rotatedClaim.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const rotatedClaimBody = await json<{
      ok: boolean;
      data: { agent: { platformId?: string }; claimToken: string; claimExpiresAt: string };
    }>(rotatedClaim);
    expect(rotatedClaimBody.data.agent.platformId).toBeUndefined();
    expect(rotatedClaimBody.data.claimToken).toMatch(/^stwd_claim_/);
    expect(Date.parse(rotatedClaimBody.data.claimExpiresAt)).toBeGreaterThan(Date.now());
    const expiredClaimToken = rotatedClaimBody.data.claimToken;
    await getDb()
      .update(agents)
      .set({
        platformId: `pregenerated:${hashSha256Hex(expiredClaimToken ?? "")}:${Date.now() - 1_000}`,
      })
      .where(eq(agents.id, expiredAgentId ?? ""));

    const expiredClaimUser = await createPersonalUser("claim-expired");
    const expiredClaimSession = await sessionTokenFor(
      expiredClaimUser.userId,
      expiredClaimUser.tenantId,
      expiredClaimUser.email,
      { mfa: true },
    );
    const expiredClaim = await app.request("/user/me/wallet/claim-pregenerated", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${expiredClaimSession}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tenantId: TENANT_ID, claimToken: expiredClaimToken }),
    });
    expect(expiredClaim.status).toBe(410);
    await expect(json<{ error: string }>(expiredClaim)).resolves.toMatchObject({
      error: "Wallet claim token expired",
    });

    const restoreUser = await createPersonalUser("restore");
    const restoreNoMfa = await sessionTokenFor(
      restoreUser.userId,
      restoreUser.tenantId,
      restoreUser.email,
    );
    const deniedRestore = await app.request("/user/me/wallet/recovery/restore", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${restoreNoMfa}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mnemonic: RESTORE_MNEMONIC }),
    });
    expect(deniedRestore.status).toBe(403);

    const restoreMfa = await sessionTokenFor(
      restoreUser.userId,
      restoreUser.tenantId,
      restoreUser.email,
      {
        mfa: true,
      },
    );
    const restored = await app.request("/user/me/wallet/recovery/restore", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${restoreMfa}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mnemonic: RESTORE_MNEMONIC }),
    });
    expect(restored.status).toBe(201);
    expect(restored.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const restoredText = await restored.text();
    expect(restoredText).not.toContain(RESTORE_MNEMONIC);
    const restoredBody = JSON.parse(restoredText) as {
      ok: boolean;
      data: {
        wallet: {
          agentId: string;
          walletAddress: string;
          recoverable: true;
          restoredExisting: boolean;
        };
        recovery: { type: "bip39"; restored: true };
      };
    };
    expect(restoredBody.data.wallet).toMatchObject({
      agentId: `user-wallet-${restoreUser.userId}`,
      walletAddress: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
      recoverable: true,
      restoredExisting: false,
    });
    expect(restoredBody.data.recovery).toEqual({ type: "bip39", restored: true });

    const restoredAgain = await app.request("/user/me/wallet/recovery/restore", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${restoreMfa}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ mnemonic: RESTORE_MNEMONIC }),
    });
    expect(restoredAgain.status).toBe(200);
    await expect(
      json<{
        data: { wallet: { walletAddress: string; restoredExisting: boolean } };
      }>(restoredAgain),
    ).resolves.toMatchObject({
      data: {
        wallet: {
          walletAddress: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
          restoredExisting: true,
        },
      },
    });

    const audit = await app.request(
      "/audit/events?action=user.wallet.recovery_setup&actorType=user&resourceType=wallet&resourceId=" +
        encodeURIComponent(recoveryBody.data.wallet.agentId),
      { headers: { Authorization: `Bearer ${mfaToken}` } },
    );
    expect(audit.status).toBe(200);
    expect(audit.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const auditBody = await json<{
      ok: boolean;
      data: {
        data: Array<{
          action: string;
          actor_type: string;
          resource_type: string;
          resource_id: string;
        }>;
        pagination: { total: number };
      };
    }>(audit);
    expect(auditBody.ok).toBe(true);
    expect(auditBody.data.pagination.total).toBe(1);
    expect(auditBody.data.data).toEqual([
      expect.objectContaining({
        action: "user.wallet.recovery_setup",
        actor_type: "user",
        resource_type: "wallet",
        resource_id: recoveryBody.data.wallet.agentId,
      }),
    ]);
  }, 120_000);
});
