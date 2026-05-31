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

const { authRoutes, verifySessionToken, createSessionToken } = await import("../routes/auth");

/**
 * Decode a JWT's claims WITHOUT running the revocation/membership checks that
 * `verifySessionToken` performs. Enabling MFA revokes the SMS-login session, so
 * `verifySessionToken` would return null for it — but the token's claims
 * (userId, tenantId, address) are still the values we want to carry into the
 * fresh, MFA-verified session below.
 */
function decodeTokenClaims(token: string): {
  userId: string;
  tenantId: string;
  address?: string;
  email?: string;
} {
  const [, payloadB64] = token.split(".");
  return JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
}

/**
 * Advance the global clock by `offsetMs` and return a restore function.
 *
 * Why this is needed: enabling/disabling an MFA factor calls
 * `revokeUserRefreshSessions`, which sets the user revocation line to
 * `floor(Date.now()/1000)`. JWT `iat` is second-grained and same-second tokens
 * are intentionally treated as revoked (`iat <= issuedBefore`) — a deliberate
 * security property so logout/compromise kills tokens minted in the same second.
 * In a real flow the user re-authenticates seconds after enabling MFA, so any
 * session the server subsequently issues (e.g. via /mfa/totp/complete) has an
 * `iat` past the revocation line. These in-process tests run in well under a
 * second, so we advance the clock to model that realistic gap. jose's
 * `setIssuedAt()` reads `new Date()`, so we override the Date class (not just
 * Date.now); `revokeUserTokens` reads `Date.now()`, which the override covers too.
 */
function installClockShift(offsetMs: number): () => void {
  const OriginalDate = Date;
  class ShiftedDate extends OriginalDate {
    constructor(...args: ConstructorParameters<typeof Date>) {
      super(...(args.length ? args : [OriginalDate.now() + offsetMs]));
    }
    static now(): number {
      return OriginalDate.now() + offsetMs;
    }
  }
  globalThis.Date = ShiftedDate as DateConstructor;
  return () => {
    globalThis.Date = OriginalDate;
  };
}

async function mintFreshSession(
  address: string,
  tenantId: string,
  claims: Record<string, unknown>,
): Promise<string> {
  const restore = installClockShift(5_000);
  try {
    return await createSessionToken(address, tenantId, claims);
  } finally {
    restore();
  }
}

/**
 * Enabling/managing MFA factors revokes sessions issued before the change and
 * MFA-management routes require a recent MFA step-up. Mint a fresh, MFA-verified
 * session for the user so post-enable management calls reflect a real re-auth.
 */
async function freshMfaToken(token: string): Promise<string> {
  const payload = decodeTokenClaims(token);
  return mintFreshSession(payload.address ?? "", payload.tenantId, {
    userId: payload.userId,
    ...(payload.email ? { email: payload.email } : {}),
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
    factorEnrollmentVerifiedAt: Date.now(),
  });
}

/**
 * Mint a fresh (non-revoked) SMS-login-style session that carries the same
 * claims an SMS OTP login issues — notably a recent `factorEnrollmentVerifiedAt`
 * but NO `mfaVerifiedAt`. Enabling TOTP revokes the original login token (so it
 * would 401), but the security boundary under test is the factor-enrollment
 * step-up: once a durable factor exists, that login-grade step-up is no longer
 * sufficient, so the route must respond 403 (not 401).
 */
async function freshLoginToken(token: string): Promise<string> {
  const payload = decodeTokenClaims(token);
  return mintFreshSession(payload.address ?? "", payload.tenantId, {
    userId: payload.userId,
    ...(payload.email ? { email: payload.email } : {}),
    authMethod: "sms",
    factorEnrollmentVerifiedAt: Date.now(),
  });
}

beforeAll(async () => {
  process.env.NODE_ENV = "test";
  process.env.SMS_PROVIDER = "mock";
  process.env.STEWARD_MASTER_PASSWORD = "mfa-sms-test-master-password";
  process.env.STEWARD_PGLITE_MEMORY = "true";
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
  // /nonce binds the issued nonce to an allowed request Origin; SIWE verify
  // cross-checks the message domain against it. Send an allowlisted Origin.
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

    // Enabling TOTP revokes the prior SMS-login session; re-auth with a fresh
    // MFA-verified session to manage the factor.
    const manageToken = await freshMfaToken(auth.token);

    const invalidUnenrollRes = await authRoutes.request("/mfa/totp/unenroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${manageToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: await generateTotp(enrollment.secret, { time: Date.now() + 10 * 30_000 }),
      }),
    });
    expect(invalidUnenrollRes.status).toBe(401);
    expect(webhookDispatches).toHaveLength(2);

    const originalNow = Date.now;
    const unenrollTime = originalNow() + 120_000;
    const unenrollCode = await generateTotp(enrollment.secret, { time: unenrollTime });
    Date.now = () => unenrollTime;
    try {
      const unenrollRes = await authRoutes.request("/mfa/totp/unenroll", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${manageToken}`,
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

    // Enabling TOTP revoked the SMS-login session. Re-mint a fresh login-grade
    // session (recent factor-enrollment step-up, but NOT an MFA step-up). Now
    // that a durable factor (TOTP) exists, login-grade step-up is insufficient
    // for enrolling another factor, so the route must respond 403.
    const loginToken = await freshLoginToken(auth.token);
    const manageToken = await freshMfaToken(auth.token);
    const blockedSmsEnroll = await authRoutes.request("/mfa/sms/enroll", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${loginToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ phone: "+14155550124" }),
    });
    expect(blockedSmsEnroll.status).toBe(403);

    // From here the test re-authenticates (SIWE, second SMS login + MFA
    // complete, recovery regenerate, etc.). Each issues a NEW session whose
    // `iat` must land past the revocation line set by the TOTP enable above.
    // In real usage that re-auth happens seconds later; advance the clock to
    // model it. Restored in the finally so it never leaks to other tests.
    const restoreClock = installClockShift(2_000);
    try {
      // Phone-login users are keyed on a `phone:<hash>` walletAddress. The SIWE
      // check below temporarily attaches a real wallet to assert that a SIWE login
      // for a TOTP-enabled user requires MFA — capture the phone subject so we can
      // restore it afterwards, otherwise later phone logins would resolve to a
      // brand-new (TOTP-less) user.
      const [{ walletAddress: phoneSubject }] = await getDb()
        .select({ walletAddress: users.walletAddress })
        .from(users)
        .where(eq(users.id, auth.user.id));
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
        headers: { "Content-Type": "application/json" },
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

      // Restore the phone subject so subsequent SMS logins resolve the same user.
      await getDb()
        .update(users)
        .set({ walletAddress: phoneSubject })
        .where(eq(users.id, auth.user.id));

      const recoveryStatusRes = await authRoutes.request("/mfa/recovery-codes/status", {
        headers: { Authorization: `Bearer ${manageToken}` },
      });
      expect(recoveryStatusRes.status).toBe(200);
      const recoveryStatus = (await recoveryStatusRes.json()) as {
        enabled: boolean;
        remaining: number;
      };
      expect(recoveryStatus).toMatchObject({ enabled: true, remaining: 10 });

      const replayRes = await authRoutes.request("/mfa/totp/verify", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${manageToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });
      expect(replayRes.status).toBe(401);

      const secondSendRes = await authRoutes.request("/sms/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone }),
      });
      expect(secondSendRes.status).toBe(200);
      const secondInboxRes = await authRoutes.request(
        `/test/sms-inbox/${encodeURIComponent(phone)}`,
      );
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
      expect(recoveryStatusAfterUse.remaining).toBe(9);

      const regenerateTime = Date.now() + 60_000;
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
      const unenrollTime = originalNow() + 120_000;
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
    } finally {
      restoreClock();
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

    // Drop the user.created / user.authenticated webhooks emitted by the SMS
    // login above so the assertions below isolate MFA-enable webhooks: a FAILED
    // SMS MFA verify must dispatch nothing.
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

    // Enabling SMS MFA above revoked prior sessions. Subsequent MFA-completed
    // logins must issue tokens whose `iat` is past that revocation line; advance
    // the clock to model the realistic re-auth gap. Restored in the finally.
    const restoreClock = installClockShift(2_000);
    try {
      const secondSendRes = await authRoutes.request("/sms/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone }),
      });
      expect(secondSendRes.status).toBe(200);
      const secondInboxRes = await authRoutes.request(
        `/test/sms-inbox/${encodeURIComponent(phone)}`,
      );
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
      const repeatInboxRes = await authRoutes.request(
        `/test/sms-inbox/${encodeURIComponent(phone)}`,
      );
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
      // Drop the user.authenticated/user.created webhooks emitted by the SMS
      // logins above so the assertions below isolate the MFA factor lifecycle
      // (enable then disable). An invalid unenroll must add no MFA webhook.
      {
        const mfaLifecycle = webhookDispatches.filter((d) => d.type.startsWith("mfa."));
        webhookDispatches.length = 0;
        webhookDispatches.push(...mfaLifecycle);
      }
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
    } finally {
      restoreClock();
    }
  });
});
