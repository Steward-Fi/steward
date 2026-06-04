import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { generateTotp, hashSha256Hex } from "@stwd/auth";
import { closeDb, getDb, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

type WebhookDispatch = {
  tenantId: string;
  agentId: string;
  type: string;
  data: Record<string, unknown>;
};

const webhookDispatches: WebhookDispatch[] = [];

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: mock(
    (tenantId: string, agentId: string, type: string, data: Record<string, unknown>) => {
      webhookDispatches.push({ tenantId, agentId, type, data });
    },
  ),
}));

// Env must be set before the route module is imported (it reads secrets at
// module load). Shaw's hardening default-denies missing audit/jwt secrets, so
// these have to exist up front, not in beforeAll.
process.env.NODE_ENV = "test";
process.env.SMS_PROVIDER = "mock";
process.env.STEWARD_MASTER_PASSWORD = "mfa-sms-test-master-password";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_JWT_SECRET =
  process.env.STEWARD_JWT_SECRET ?? "mfa-sms-test-jwt-secret-with-enough-entropy-32b";
process.env.STEWARD_AUDIT_HMAC_KEY =
  process.env.STEWARD_AUDIT_HMAC_KEY ?? "mfa-sms-test-audit-hmac-key-with-enough-entropy-32b";

const { authRoutes, verifySessionToken } = await import("../routes/auth");

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

beforeEach(() => {
  webhookDispatches.length = 0;
});

async function fetchSiweNonce(): Promise<string> {
  const nonceRes = await authRoutes.request("/nonce", {
    headers: { Origin: "https://steward.fi" },
  });
  expect(nonceRes.status).toBe(200);
  const nonceJson = (await nonceRes.json()) as { nonce: string };
  return nonceJson.nonce;
}

function buildSiweMessage(address: string, nonce: string): string {
  return [
    "steward.fi wants you to sign in with your Ethereum account:",
    address,
    "",
    "Sign in to Steward",
    "",
    "URI: https://steward.fi",
    "Version: 1",
    "Chain ID: 1",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}

describe("SMS OTP auth and TOTP MFA routes", () => {
  it("dispatches webhooks for TOTP MFA enable and disable", async () => {
    const phone = "+14155550777";

    const sendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(sendRes.status).toBe(200);
    const inboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const inbox = (await inboxRes.json()) as { code: string };
    const verifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(verifyRes.status).toBe(200);
    const auth = (await verifyRes.json()) as { token: string; user: { id: string } };

    const enrollRes = await authRoutes.request("/mfa/totp/enroll", {
      method: "POST",
      headers: { Authorization: `Bearer ${auth.token}` },
    });
    expect(enrollRes.status).toBe(200);
    const enrollment = (await enrollRes.json()) as { secret: string };
    webhookDispatches.length = 0;

    const code = await generateTotp(enrollment.secret);
    const invalidCode = code === "000000" ? "000001" : "000000";
    const invalidVerifyRes = await authRoutes.request("/mfa/totp/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code: invalidCode }),
    });
    expect(invalidVerifyRes.status).toBe(401);
    expect(webhookDispatches).toHaveLength(0);

    const verifyMfaRes = await authRoutes.request("/mfa/totp/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    expect(verifyMfaRes.status).toBe(200);
    const verifyMfa = (await verifyMfaRes.json()) as { recoveryCodes: string[] };
    expect(webhookDispatches).toEqual([
      expect.objectContaining({
        agentId: auth.user.id,
        type: "mfa.enabled",
        data: {
          userId: auth.user.id,
          factor: "totp",
          recoveryCodesIssued: 10,
        },
      }),
      expect.objectContaining({
        agentId: auth.user.id,
        type: "wallet.recovery_setup",
        data: {
          userId: auth.user.id,
          source: "totp_enable",
          recoveryCodesIssued: 10,
        },
      }),
    ]);

    const secondSendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(secondSendRes.status).toBe(200);
    const secondInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const secondInbox = (await secondInboxRes.json()) as { code: string };
    const secondVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: secondInbox.code }),
    });
    expect(secondVerifyRes.status).toBe(200);
    const mfaRequired = (await secondVerifyRes.json()) as { mfa: { challengeId: string } };
    await Bun.sleep(1100);
    const completeRes = await authRoutes.request("/mfa/totp/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: mfaRequired.mfa.challengeId,
        recoveryCode: verifyMfa.recoveryCodes[0],
      }),
    });
    expect(completeRes.status).toBe(200);
    const freshToken = ((await completeRes.json()) as { token: string }).token;
    webhookDispatches.splice(2);

    const invalidUnenrollRes = await authRoutes.request("/mfa/totp/unenroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${freshToken!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: await generateTotp(enrollment.secret, { time: Date.now() + 10 * 30_000 }),
      }),
    });
    expect(invalidUnenrollRes.status).toBe(401);
    expect(webhookDispatches).toHaveLength(2);

    const originalNow = Date.now;
    const unenrollTime = originalNow() + 360_000;
    const unenrollCode = await generateTotp(enrollment.secret, { time: unenrollTime });
    Date.now = () => unenrollTime;
    try {
      const unenrollRes = await authRoutes.request("/mfa/totp/unenroll", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${freshToken!}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code: unenrollCode }),
      });
      expect(unenrollRes.status).toBe(200);
    } finally {
      Date.now = originalNow;
    }
    expect(webhookDispatches).toEqual([
      expect.objectContaining({ type: "mfa.enabled" }),
      expect.objectContaining({ type: "wallet.recovery_setup" }),
      expect.objectContaining({
        agentId: auth.user.id,
        type: "mfa.disabled",
        data: {
          userId: auth.user.id,
          factor: "totp",
        },
      }),
    ]);
  });

  it("signs in with SMS OTP and manages TOTP enrollment", async () => {
    const phone = "+14155550123";

    const sendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(sendRes.status).toBe(200);

    const inboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    expect(inboxRes.status).toBe(200);
    const inbox = (await inboxRes.json()) as { code: string };
    expect(inbox.code).toMatch(/^\d{6}$/);

    const verifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(verifyRes.status).toBe(200);
    const auth = (await verifyRes.json()) as {
      token: string;
      refreshToken: string;
      user: { id: string };
    };
    expect(auth.refreshToken).toBeTruthy();
    expect(await verifySessionToken(auth.token)).toMatchObject({ userId: auth.user.id });

    const enrollRes = await authRoutes.request("/mfa/totp/enroll", {
      method: "POST",
      headers: { Authorization: `Bearer ${auth.token}` },
    });
    expect(enrollRes.status).toBe(200);
    const enrollment = (await enrollRes.json()) as { secret: string; otpauthUri: string };
    expect(enrollment.otpauthUri).toContain("otpauth://totp/");

    const code = await generateTotp(enrollment.secret);
    const mfaVerifyRes = await authRoutes.request("/mfa/totp/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    expect(mfaVerifyRes.status).toBe(200);
    const mfaVerify = (await mfaVerifyRes.json()) as { enabled: boolean; recoveryCodes: string[] };
    expect(mfaVerify.enabled).toBe(true);
    expect(mfaVerify.recoveryCodes).toHaveLength(10);

    const blockedSmsEnroll = await authRoutes.request("/mfa/sms/enroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ phone: "+14155550124" }),
    });
    expect(blockedSmsEnroll.status).toBe(401);

    const account = privateKeyToAccount(generatePrivateKey());
    await getDb()
      .update(users)
      .set({ walletAddress: account.address.toLowerCase(), walletChain: "ethereum" })
      .where(eq(users.id, auth.user.id));
    const siweNonce = await fetchSiweNonce();
    const siweMessage = buildSiweMessage(account.address, siweNonce);
    const siweSignature = await account.signMessage({ message: siweMessage });
    const siweRes = await authRoutes.request("/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://steward.fi" },
      body: JSON.stringify({ message: siweMessage, signature: siweSignature }),
    });
    expect(siweRes.status).toBe(200);
    const siweMfaRequired = (await siweRes.json()) as {
      token?: string;
      refreshToken?: string;
      mfaRequired: boolean;
      mfa: { type: string; challengeId: string };
    };
    expect(siweMfaRequired.mfaRequired).toBe(true);
    expect(siweMfaRequired.mfa.type).toBe("totp");
    expect(siweMfaRequired.token).toBeUndefined();
    expect(siweMfaRequired.refreshToken).toBeUndefined();

    await Bun.sleep(1100);
    const siweCompleteRes = await authRoutes.request("/mfa/totp/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: siweMfaRequired.mfa.challengeId,
        recoveryCode: mfaVerify.recoveryCodes[1],
      }),
    });
    expect(siweCompleteRes.status).toBe(200);
    const siweCompletedToken = ((await siweCompleteRes.json()) as { token: string }).token;

    const recoveryStatusRes = await authRoutes.request("/mfa/recovery-codes/status", {
      headers: { Authorization: `Bearer ${siweCompletedToken!}` },
    });
    expect(recoveryStatusRes.status).toBe(200);
    const recoveryStatus = (await recoveryStatusRes.json()) as {
      enabled: boolean;
      remaining: number;
    };
    expect(recoveryStatus).toMatchObject({ enabled: true, remaining: 9 });

    const replayRes = await authRoutes.request("/mfa/totp/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${siweCompletedToken!}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    expect(replayRes.status).toBe(401);

    await getDb()
      .update(users)
      .set({ walletAddress: `phone:${hashSha256Hex(phone)}`, walletChain: "ethereum" })
      .where(eq(users.id, auth.user.id));

    const secondSendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(secondSendRes.status).toBe(200);
    const secondInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const secondInbox = (await secondInboxRes.json()) as { code: string };

    const secondVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: secondInbox.code }),
    });
    expect(secondVerifyRes.status).toBe(200);
    const mfaRequired = (await secondVerifyRes.json()) as {
      token?: string;
      refreshToken?: string;
      mfaRequired: boolean;
      mfa: { challengeId: string };
    };
    expect(mfaRequired.mfaRequired).toBe(true);
    expect(mfaRequired.token).toBeUndefined();
    expect(mfaRequired.refreshToken).toBeUndefined();

    const completeRes = await authRoutes.request("/mfa/totp/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: mfaRequired.mfa.challengeId,
        recoveryCode: mfaVerify.recoveryCodes[0],
      }),
    });
    expect(completeRes.status).toBe(200);
    const completed = (await completeRes.json()) as { token: string; refreshToken: string };
    expect(completed.refreshToken).toBeTruthy();
    expect(await verifySessionToken(completed.token)).toMatchObject({
      userId: auth.user.id,
      mfaMethod: "recovery_code",
    });

    const reusedRecoveryRes = await authRoutes.request("/mfa/totp/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: mfaRequired.mfa.challengeId,
        recoveryCode: mfaVerify.recoveryCodes[0],
      }),
    });
    expect(reusedRecoveryRes.status).toBe(401);

    const recoveryStatusAfterUseRes = await authRoutes.request("/mfa/recovery-codes/status", {
      headers: { Authorization: `Bearer ${completed.token}` },
    });
    const recoveryStatusAfterUse = (await recoveryStatusAfterUseRes.json()) as {
      remaining: number;
    };
    expect(recoveryStatusAfterUse.remaining).toBe(8);

    const regenerateTime = Date.now() + 120_000;
    const regenerateCode = await generateTotp(enrollment.secret, { time: regenerateTime });
    const originalNowForRegenerate = Date.now;
    Date.now = () => regenerateTime;
    let regeneratedCodes: string[];
    try {
      const regenerateRes = await authRoutes.request("/mfa/recovery-codes/regenerate", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${completed.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code: regenerateCode }),
      });
      expect(regenerateRes.status).toBe(200);
      const regenerate = (await regenerateRes.json()) as { recoveryCodes: string[] };
      expect(regenerate.recoveryCodes).toHaveLength(10);
      regeneratedCodes = regenerate.recoveryCodes;
    } finally {
      Date.now = originalNowForRegenerate;
    }
    expect(regeneratedCodes![0]).not.toBe(mfaVerify.recoveryCodes[0]);

    const challengeIds: string[] = [];
    for (let i = 0; i < 2; i++) {
      const sendConcurrentRes = await authRoutes.request("/sms/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone }),
      });
      expect(sendConcurrentRes.status).toBe(200);
      const inboxConcurrentRes = await authRoutes.request(
        `/test/sms-inbox/${encodeURIComponent(phone)}`,
      );
      const inboxConcurrent = (await inboxConcurrentRes.json()) as { code: string };
      const verifyConcurrentRes = await authRoutes.request("/sms/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, code: inboxConcurrent.code }),
      });
      expect(verifyConcurrentRes.status).toBe(200);
      const verifyConcurrent = (await verifyConcurrentRes.json()) as {
        mfa: { challengeId: string };
      };
      challengeIds.push(verifyConcurrent.mfa.challengeId);
    }
    const concurrentRecoveryResults = await Promise.all(
      challengeIds.map((challengeId) =>
        authRoutes.request("/mfa/totp/complete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ challengeId, recoveryCode: regeneratedCodes![0] }),
        }),
      ),
    );
    expect(concurrentRecoveryResults.map((res) => res.status).sort()).toEqual([200, 401]);

    const originalNow = Date.now;
    const unenrollTime = originalNow() + 180_000;
    const nextCode = await generateTotp(enrollment.secret, { time: unenrollTime });
    Date.now = () => unenrollTime;
    try {
      const unenrollRes = await authRoutes.request("/mfa/totp/unenroll", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${completed.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code: nextCode }),
      });
      expect(unenrollRes.status).toBe(200);
    } finally {
      Date.now = originalNow;
    }
  });

  it("enrolls and completes SMS MFA challenges", async () => {
    const phone = "+14155550999";

    const sendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(sendRes.status).toBe(200);
    const inboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const inbox = (await inboxRes.json()) as { code: string };

    const verifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(verifyRes.status).toBe(200);
    const auth = (await verifyRes.json()) as {
      token: string;
      user: { id: string };
    };

    const statusRes = await authRoutes.request("/mfa/sms/status", {
      headers: { Authorization: `Bearer ${auth.token}` },
    });
    expect(statusRes.status).toBe(200);
    expect(await statusRes.json()).toMatchObject({ enabled: false, pending: false });

    const enrollRes = await authRoutes.request("/mfa/sms/enroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ phone }),
    });
    expect(enrollRes.status).toBe(200);
    expect(await enrollRes.json()).toMatchObject({ phone: "***0999" });
    const enrollInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const enrollInbox = (await enrollInboxRes.json()) as { code: string };
    const invalidEnrollCode = enrollInbox.code === "000000" ? "000001" : "000000";
    webhookDispatches.length = 0;

    const invalidVerifyMfaRes = await authRoutes.request("/mfa/sms/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code: invalidEnrollCode }),
    });
    expect(invalidVerifyMfaRes.status).toBe(401);
    expect(webhookDispatches).toHaveLength(0);

    const verifyMfaRes = await authRoutes.request("/mfa/sms/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${auth.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code: enrollInbox.code }),
    });
    expect(verifyMfaRes.status).toBe(200);
    expect(await verifyMfaRes.json()).toMatchObject({ enabled: true, phone: "***0999" });
    expect(webhookDispatches).toEqual([
      expect.objectContaining({
        agentId: auth.user.id,
        type: "mfa.enabled",
        data: {
          userId: auth.user.id,
          factor: "sms",
          phoneHash: hashSha256Hex(phone),
        },
      }),
    ]);

    const secondSendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(secondSendRes.status).toBe(200);
    const secondInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const secondInbox = (await secondInboxRes.json()) as { code: string };

    const secondVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: secondInbox.code }),
    });
    expect(secondVerifyRes.status).toBe(200);
    const mfaRequired = (await secondVerifyRes.json()) as {
      token?: string;
      mfaRequired: boolean;
      mfa: { type: string; challengeId: string };
    };
    expect(mfaRequired.token).toBeUndefined();
    expect(mfaRequired).toMatchObject({ mfaRequired: true, mfa: { type: "sms" } });

    const mfaInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const mfaInbox = (await mfaInboxRes.json()) as { code: string };
    const unrelatedLoginOtpRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(unrelatedLoginOtpRes.status).toBe(200);
    const unrelatedInboxRes = await authRoutes.request(
      `/test/sms-inbox/${encodeURIComponent(phone)}`,
    );
    const unrelatedInbox = (await unrelatedInboxRes.json()) as { code: string };
    const wrongPurposeRes = await authRoutes.request("/mfa/sms/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: mfaRequired.mfa.challengeId,
        code: unrelatedInbox.code,
      }),
    });
    expect(wrongPurposeRes.status).toBe(401);

    const repeatSendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(repeatSendRes.status).toBe(200);
    const repeatInboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    const repeatInbox = (await repeatInboxRes.json()) as { code: string };
    const repeatVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: repeatInbox.code }),
    });
    const repeatMfaRequired = (await repeatVerifyRes.json()) as {
      mfa: { challengeId: string };
    };
    const completeRes = await authRoutes.request("/mfa/sms/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: repeatMfaRequired.mfa.challengeId,
        code: mfaInbox.code,
      }),
    });
    expect(completeRes.status).toBe(401);

    const validSendRes = await authRoutes.request("/sms/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(validSendRes.status).toBe(200);
    const validLoginInboxRes = await authRoutes.request(
      `/test/sms-inbox/${encodeURIComponent(phone)}`,
    );
    const validLoginInbox = (await validLoginInboxRes.json()) as { code: string };
    const validVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: validLoginInbox.code }),
    });
    expect(validVerifyRes.status).toBe(200);
    const validMfaRequired = (await validVerifyRes.json()) as {
      mfa: { challengeId: string };
    };
    const validMfaInboxRes = await authRoutes.request(
      `/test/sms-inbox/${encodeURIComponent(phone)}`,
    );
    const validMfaInbox = (await validMfaInboxRes.json()) as { code: string };
    await Bun.sleep(1100);
    const validCompleteRes = await authRoutes.request("/mfa/sms/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: validMfaRequired.mfa.challengeId,
        code: validMfaInbox.code,
      }),
    });
    expect(validCompleteRes.status).toBe(200);
    const completed = (await validCompleteRes.json()) as { token: string; refreshToken: string };
    expect(await verifySessionToken(completed.token)).toMatchObject({
      userId: auth.user.id,
      mfaMethod: "sms",
    });

    const refreshRes = await authRoutes.request("/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: completed.refreshToken }),
    });
    expect(refreshRes.status).toBe(200);
    const refreshed = (await refreshRes.json()) as { token: string };
    expect(await verifySessionToken(refreshed.token)).toMatchObject({
      userId: auth.user.id,
      mfaMethod: "sms",
    });
    webhookDispatches.splice(1);

    const replayRes = await authRoutes.request("/mfa/sms/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challengeId: validMfaRequired.mfa.challengeId,
        code: validMfaInbox.code,
      }),
    });
    expect(replayRes.status).toBe(401);

    const unenrollSendRes = await authRoutes.request("/mfa/sms/send", {
      method: "POST",
      headers: { Authorization: `Bearer ${completed.token}` },
    });
    expect(unenrollSendRes.status).toBe(200);
    const unenrollInboxRes = await authRoutes.request(
      `/test/sms-inbox/${encodeURIComponent(phone)}`,
    );
    const unenrollInbox = (await unenrollInboxRes.json()) as { code: string };
    const invalidUnenrollCode = unenrollInbox.code === "000000" ? "000001" : "000000";
    const invalidUnenrollRes = await authRoutes.request("/mfa/sms/unenroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${completed.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code: invalidUnenrollCode }),
    });
    expect(invalidUnenrollRes.status).toBe(401);
    expect(webhookDispatches).toHaveLength(1);

    const unenrollRes = await authRoutes.request("/mfa/sms/unenroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${completed.token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code: unenrollInbox.code }),
    });
    expect(unenrollRes.status).toBe(200);
    expect(webhookDispatches).toEqual([
      expect.objectContaining({ type: "mfa.enabled" }),
      expect.objectContaining({
        agentId: auth.user.id,
        type: "mfa.disabled",
        data: {
          userId: auth.user.id,
          factor: "sms",
          phoneHash: hashSha256Hex(phone),
        },
      }),
    ]);
  });
});
