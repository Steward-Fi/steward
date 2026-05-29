import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

import { MockSmsInbox, signTelegramLoginPayload } from "@stwd/auth";
import {
  accounts,
  agents,
  agentWallets,
  auditEvents,
  authenticators,
  closeDb,
  getDb,
  refreshTokens,
  tenantConfigs,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import bs58 from "bs58";
import { and, eq } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const TENANT_ID = "user-linked-accounts";
const SOLANA_TEST_KEYPAIR = {
  d: "_AcsmFehfd3TZ-8I5f7TgoiFLcjrclBONqMMnX2Zeew",
  x: "DtNuOw6T7fPESIGzt_Qp6V0Q5d2a1-mUks5zrxPIoeE",
  publicKey: "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct",
};
const TELEGRAM_BOT_TOKEN = "123456:user-linked-telegram-test-token";

function signedTelegramPayload(overrides: Record<string, unknown> = {}) {
  const payload = {
    id: "424242",
    first_name: "Ada",
    username: "ada",
    auth_date: Math.floor(Date.now() / 1000),
    ...overrides,
  };
  return { ...payload, hash: signTelegramLoginPayload(payload, TELEGRAM_BOT_TOKEN) };
}

function buildSiwfMessage(address: string, nonce: string, fid = "4242") {
  return [
    "steward.fi wants you to sign in with your Ethereum account:",
    address,
    "",
    "Sign in with Farcaster.",
    "",
    "URI: https://steward.fi/auth/farcaster",
    "Version: 1",
    "Chain ID: 10",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
    `Expiration Time: ${new Date(Date.now() + 5 * 60_000).toISOString()}`,
    "Resources:",
    `- farcaster://fid/${fid}`,
  ].join("\n");
}

function signSolanaMessage(message: string): string {
  const keyObject = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: SOLANA_TEST_KEYPAIR.d,
      x: SOLANA_TEST_KEYPAIR.x,
    },
    format: "jwk",
  });

  return bs58.encode(cryptoSign(null, Buffer.from(message, "utf8"), keyObject));
}

describe("user linked account routes", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let userId = "";
  let accountOnlyUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-linked-accounts-master-password";
    process.env.STEWARD_JWT_SECRET = "user-linked-accounts-jwt-secret-32chars";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "User Linked Accounts",
      apiKeyHash: "hash",
    });
    const [user] = await getDb()
      .insert(users)
      .values({
        email: "linked@example.test",
        emailVerified: true,
        walletAddress: "0x1111111111111111111111111111111111111111",
      })
      .returning({ id: users.id });
    const [accountOnlyUser] = await getDb()
      .insert(users)
      .values({ email: null, emailVerified: false, walletAddress: null })
      .returning({ id: users.id });
    userId = user.id;
    accountOnlyUserId = accountOnlyUser.id;
    await getDb()
      .insert(userTenants)
      .values([
        { userId, tenantId: TENANT_ID, role: "member" },
        { userId: accountOnlyUserId, tenantId: TENANT_ID, role: "member" },
      ]);
    await getDb()
      .insert(tenants)
      .values([
        {
          id: `personal-${userId}`,
          name: "Linked Account Personal Tenant",
          apiKeyHash: "personal-hash",
        },
        {
          id: `personal-${accountOnlyUserId}`,
          name: "Account Only Personal Tenant",
          apiKeyHash: "personal-account-only-hash",
        },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId, tenantId: `personal-${userId}`, role: "owner" },
        { userId: accountOnlyUserId, tenantId: `personal-${accountOnlyUserId}`, role: "owner" },
      ]);
    await getDb()
      .insert(tenantConfigs)
      .values([
        {
          tenantId: `personal-${userId}`,
          allowedOrigins: ["https://app.example.test/auth/callback"],
        },
        {
          tenantId: `personal-${accountOnlyUserId}`,
          allowedOrigins: ["https://app.example.test/auth/callback"],
        },
      ]);
    await getDb()
      .insert(accounts)
      .values([
        { userId, provider: "google", providerAccountId: "google-linked" },
        { userId: accountOnlyUserId, provider: "github", providerAccountId: "github-only" },
      ]);
    await getDb()
      .insert(authenticators)
      .values({
        userId,
        credentialId: "passkey-linked",
        credentialPublicKey: "passkey-public-key",
        counter: 0,
        credentialDeviceType: "platform",
        credentialBackedUp: true,
        transports: ["internal"],
      });
    await getDb()
      .insert(agents)
      .values({
        id: `user-wallet-${userId}`,
        tenantId: `personal-${userId}`,
        name: "Linked User Wallet",
        walletAddress: "0x1111111111111111111111111111111111111111",
      });
    await getDb()
      .insert(agentWallets)
      .values({
        agentId: `user-wallet-${userId}`,
        chainFamily: "evm",
        address: "0x1111111111111111111111111111111111111111",
        purpose: "primary",
      });
    await getDb()
      .insert(transactions)
      .values({
        id: "linked-user-wallet-spend",
        agentId: `user-wallet-${userId}`,
        status: "confirmed",
        toAddress: "0x0000000000000000000000000000000000000001",
        value: "123",
        chainId: 8453,
        policyResults: [],
      });

    ({ userRoutes } = await import("../routes/user"));
    ({ createSessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
  });

  async function tokenFor(id: string): Promise<string> {
    const tenantId = `personal-${id}`;
    return createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId: id,
      tenantId,
      mfaVerifiedAt: Date.now(),
    });
  }

  async function staleTokenFor(id: string): Promise<string> {
    const tenantId = `personal-${id}`;
    return createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId: id,
      tenantId,
    });
  }

  it("lists only the authenticated user's linked accounts and primary login methods", async () => {
    const response = await userRoutes.request("/me/accounts", {
      headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        accounts: Array<{ provider: string; providerAccountId: string }>;
        primaryLoginMethods: Array<{ provider: string; providerAccountId: string }>;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.accounts).toEqual([
      expect.objectContaining({ provider: "google", providerAccountId: "google-linked" }),
      expect.objectContaining({ provider: "passkey", providerAccountId: "passkey-linked" }),
    ]);
    expect(body.data.primaryLoginMethods).toEqual([
      { provider: "email", providerAccountId: "linked@example.test" },
      {
        provider: "wallet",
        providerAccountId: "0x1111111111111111111111111111111111111111",
      },
    ]);
  });

  it("returns the authenticated user's account, wallet, portfolio, and spend summary", async () => {
    const response = await userRoutes.request("/me/account?chainId=8453", {
      headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        id: string;
        type: "user";
        userId: string;
        tenantId: string;
        email: string | null;
        linkedAccounts: Array<{ provider: string; providerAccountId: string }>;
        primaryLoginMethods: Array<{ provider: string; providerAccountId: string }>;
        wallet: null | { id: string; walletAddress: string };
        walletAddresses: { evm?: string };
        wallets: Array<{ chainFamily: string; address: string; purpose: string | null }>;
        balances: { evm: null | { native: string }; unavailableReason?: string };
        portfolio: {
          chainId: number | null;
          walletAddress: string | null;
          native: null | { token: string; balance: string };
          tokens: Array<{ token: string; balance: string }>;
          totalUsd: number | null;
          totalUsdText: string | null;
          unavailableReason?: string;
        };
        spend: { todayWei: string; weekWei: string; monthWei: string };
        capabilities: string[];
        sponsorship: { enabled: boolean; provider: string | null };
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.id).toBe(userId);
    expect(body.data.type).toBe("user");
    expect(body.data.tenantId).toBe(`personal-${userId}`);
    expect(body.data.email).toBe("linked@example.test");
    expect(body.data.linkedAccounts).toEqual([
      expect.objectContaining({ provider: "google", providerAccountId: "google-linked" }),
      expect.objectContaining({ provider: "passkey", providerAccountId: "passkey-linked" }),
    ]);
    expect(body.data.primaryLoginMethods).toContainEqual({
      provider: "email",
      providerAccountId: "linked@example.test",
    });
    expect(body.data.wallet).toEqual(
      expect.objectContaining({
        id: `user-wallet-${userId}`,
        walletAddress: "0x1111111111111111111111111111111111111111",
      }),
    );
    expect(body.data.walletAddresses.evm).toBe("0x1111111111111111111111111111111111111111");
    expect(body.data.wallets).toEqual([
      expect.objectContaining({
        chainFamily: "evm",
        address: "0x1111111111111111111111111111111111111111",
        purpose: "primary",
      }),
    ]);
    if (body.data.balances.evm) {
      expect(typeof body.data.balances.evm.native).toBe("string");
    } else {
      expect(typeof body.data.balances.unavailableReason).toBe("string");
    }
    expect(body.data.portfolio.walletAddress).toBe("0x1111111111111111111111111111111111111111");
    expect(Array.isArray(body.data.portfolio.tokens)).toBe(true);
    expect(body.data.spend).toEqual({ todayWei: "123", weekWei: "123", monthWei: "123" });
    expect(body.data.capabilities).toContain("sign_transaction");
    expect(body.data.sponsorship).toEqual(
      expect.objectContaining({ enabled: false, provider: null }),
    );
  });

  it("links an Ethereum wallet with a one-time user proof and blocks replay/cross-user reuse", async () => {
    const wallet = privateKeyToAccount(
      "0x59c6995e998f97a5a004497e5da4e4f70f0a2824f8d53192d4dbf84d6b6d6e04",
    );
    const nonceResponse = await userRoutes.request("/me/accounts/wallet/ethereum/nonce", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ address: wallet.address }),
    });
    expect(nonceResponse.status).toBe(200);
    const nonceBody = (await nonceResponse.json()) as {
      data: { message: string; nonce: string; address: string };
    };
    expect(nonceBody.data.address).toBe(wallet.address);
    const signature = await wallet.signMessage({ message: nonceBody.data.message });

    const invalidSignature = await wallet.signMessage({
      message: `${nonceBody.data.message}\nnope`,
    });
    const invalidAttempt = await userRoutes.request("/me/accounts/wallet/ethereum", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        address: wallet.address,
        message: nonceBody.data.message,
        signature: invalidSignature,
      }),
    });
    expect(invalidAttempt.status).toBe(401);

    const linkResponse = await userRoutes.request("/me/accounts/wallet/ethereum", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ address: wallet.address, message: nonceBody.data.message, signature }),
    });
    expect(linkResponse.status).toBe(200);
    const linkBody = (await linkResponse.json()) as {
      data: { isNew: boolean; account: { provider: string; providerAccountId: string } };
    };
    expect(linkBody.data.isNew).toBe(true);
    expect(linkBody.data.account).toMatchObject({
      provider: "wallet:ethereum",
      providerAccountId: wallet.address.toLowerCase(),
    });

    const replay = await userRoutes.request("/me/accounts/wallet/ethereum", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ address: wallet.address, message: nonceBody.data.message, signature }),
    });
    expect(replay.status).toBe(401);

    const otherNonceResponse = await userRoutes.request("/me/accounts/wallet/ethereum/nonce", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ address: wallet.address }),
    });
    const otherNonceBody = (await otherNonceResponse.json()) as { data: { message: string } };
    const otherSignature = await wallet.signMessage({ message: otherNonceBody.data.message });
    const crossUser = await userRoutes.request("/me/accounts/wallet/ethereum", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        address: wallet.address,
        message: otherNonceBody.data.message,
        signature: otherSignature,
      }),
    });
    expect(crossUser.status).toBe(409);
  });

  it("links a Solana wallet with a one-time user proof and blocks replay/cross-user reuse", async () => {
    const nonceResponse = await userRoutes.request("/me/accounts/wallet/solana/nonce", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ publicKey: SOLANA_TEST_KEYPAIR.publicKey }),
    });
    expect(nonceResponse.status).toBe(200);
    const nonceBody = (await nonceResponse.json()) as {
      data: { message: string; nonce: string; publicKey: string };
    };
    expect(nonceBody.data.publicKey).toBe(SOLANA_TEST_KEYPAIR.publicKey);
    const signature = signSolanaMessage(nonceBody.data.message);
    const invalidSignature = signSolanaMessage(`${nonceBody.data.message}\nnope`);

    const invalidAttempt = await userRoutes.request("/me/accounts/wallet/solana", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        publicKey: SOLANA_TEST_KEYPAIR.publicKey,
        message: nonceBody.data.message,
        signature: invalidSignature,
      }),
    });
    expect(invalidAttempt.status).toBe(401);

    const linkResponse = await userRoutes.request("/me/accounts/wallet/solana", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        publicKey: SOLANA_TEST_KEYPAIR.publicKey,
        message: nonceBody.data.message,
        signature,
      }),
    });
    expect(linkResponse.status).toBe(200);
    const linkBody = (await linkResponse.json()) as {
      data: { isNew: boolean; account: { provider: string; providerAccountId: string } };
    };
    expect(linkBody.data.isNew).toBe(true);
    expect(linkBody.data.account).toMatchObject({
      provider: "wallet:solana",
      providerAccountId: SOLANA_TEST_KEYPAIR.publicKey,
    });

    const replay = await userRoutes.request("/me/accounts/wallet/solana", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        publicKey: SOLANA_TEST_KEYPAIR.publicKey,
        message: nonceBody.data.message,
        signature,
      }),
    });
    expect(replay.status).toBe(401);

    const otherNonceResponse = await userRoutes.request("/me/accounts/wallet/solana/nonce", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ publicKey: SOLANA_TEST_KEYPAIR.publicKey }),
    });
    const otherNonceBody = (await otherNonceResponse.json()) as { data: { message: string } };
    const otherSignature = signSolanaMessage(otherNonceBody.data.message);
    const crossUser = await userRoutes.request("/me/accounts/wallet/solana", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        publicKey: SOLANA_TEST_KEYPAIR.publicKey,
        message: otherNonceBody.data.message,
        signature: otherSignature,
      }),
    });
    expect(crossUser.status).toBe(409);
  });

  it("links an OAuth account to the authenticated user and blocks cross-user reuse", async () => {
    const originalFetch = globalThis.fetch;
    process.env.GOOGLE_CLIENT_ID = "google-client";
    process.env.GOOGLE_CLIENT_SECRET = "google-secret";
    process.env.GOOGLE_TOKEN_URL = "https://oauth.example.test/token";
    process.env.GOOGLE_USERINFO_URL = "https://oauth.example.test/user";
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url === "https://oauth.example.test/token") {
        return new Response(
          JSON.stringify({
            access_token: "provider-access-token",
            refresh_token: "provider-refresh-token",
            token_type: "bearer",
            expires_in: 3600,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url === "https://oauth.example.test/user") {
        return new Response(
          JSON.stringify({
            id: "google-linked-user",
            email: "oauth-linked@example.test",
            verified_email: true,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return originalFetch(input);
    }) as typeof fetch;

    try {
      const challengeResponse = await userRoutes.request("/me/accounts/oauth/google/challenge", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          redirectUri: "https://app.example.test/auth/callback",
        }),
      });
      expect(challengeResponse.status).toBe(200);
      const challengeBody = (await challengeResponse.json()) as {
        data: { state: string; redirectUri: string };
      };

      const linkResponse = await userRoutes.request("/me/accounts/oauth/google/token", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: "oauth-code",
          redirectUri: "https://app.example.test/auth/callback",
          state: challengeBody.data.state,
          codeVerifier: "verifier",
        }),
      });
      expect(linkResponse.status).toBe(200);
      const linkBody = (await linkResponse.json()) as {
        data: { isNew: boolean; account: { provider: string; providerAccountId: string } };
      };
      expect(linkBody.data.isNew).toBe(true);
      expect(linkBody.data.account).toMatchObject({
        provider: "google",
        providerAccountId: "google-linked-user",
      });

      const missingState = await userRoutes.request("/me/accounts/oauth/google/token", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: "oauth-code-missing-state",
          redirectUri: "https://app.example.test/auth/callback",
          codeVerifier: "verifier",
        }),
      });
      expect(missingState.status).toBe(400);

      const badRedirectChallenge = await userRoutes.request("/me/accounts/oauth/google/challenge", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          redirectUri: "https://evil.example.test/auth/callback",
        }),
      });
      expect(badRedirectChallenge.status).toBe(400);

      const userBoundChallenge = await userRoutes.request("/me/accounts/oauth/google/challenge", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          redirectUri: "https://app.example.test/auth/callback",
        }),
      });
      expect(userBoundChallenge.status).toBe(200);
      const userBoundChallengeBody = (await userBoundChallenge.json()) as {
        data: { state: string };
      };
      const wrongUserState = await userRoutes.request("/me/accounts/oauth/google/token", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: "oauth-code-wrong-user",
          redirectUri: "https://app.example.test/auth/callback",
          state: userBoundChallengeBody.data.state,
          codeVerifier: "verifier",
        }),
      });
      expect(wrongUserState.status).toBe(401);

      const otherChallengeResponse = await userRoutes.request(
        "/me/accounts/oauth/google/challenge",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            redirectUri: "https://app.example.test/auth/callback",
          }),
        },
      );
      expect(otherChallengeResponse.status).toBe(200);
      const otherChallengeBody = (await otherChallengeResponse.json()) as {
        data: { state: string };
      };
      const crossUser = await userRoutes.request("/me/accounts/oauth/google/token", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          code: "oauth-code-2",
          redirectUri: "https://app.example.test/auth/callback",
          state: otherChallengeBody.data.state,
          codeVerifier: "verifier",
        }),
      });
      expect(crossUser.status).toBe(409);
    } finally {
      globalThis.fetch = originalFetch;
      delete process.env.GOOGLE_CLIENT_ID;
      delete process.env.GOOGLE_CLIENT_SECRET;
      delete process.env.GOOGLE_TOKEN_URL;
      delete process.env.GOOGLE_USERINFO_URL;
    }
  });

  it("links a phone account with a one-time OTP and blocks cross-user reuse", async () => {
    process.env.SMS_PROVIDER = "mock";
    process.env.STEWARD_TEST_INBOX = "true";
    MockSmsInbox.clear();
    try {
      const phone = "+14155550123";
      const sendResponse = await userRoutes.request("/me/accounts/phone/sms/send", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone }),
      });
      expect(sendResponse.status).toBe(200);
      const message = MockSmsInbox.last(phone);
      expect(message?.code).toMatch(/^\d{6}$/);

      const invalidAttempt = await userRoutes.request("/me/accounts/phone/sms/verify", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone, code: "000000" }),
      });
      expect(invalidAttempt.status).toBe(401);

      const linkResponse = await userRoutes.request("/me/accounts/phone/sms/verify", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone, code: message?.code }),
      });
      expect(linkResponse.status).toBe(200);
      const linkBody = (await linkResponse.json()) as {
        data: { isNew: boolean; account: { provider: string; providerAccountId: string } };
      };
      expect(linkBody.data.isNew).toBe(true);
      expect(linkBody.data.account.provider).toBe("phone");
      expect(linkBody.data.account.providerAccountId).toMatch(/^phone:/);

      const replay = await userRoutes.request("/me/accounts/phone/sms/verify", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone, code: message?.code }),
      });
      expect(replay.status).toBe(401);

      const otherSend = await userRoutes.request("/me/accounts/phone/sms/send", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone }),
      });
      expect(otherSend.status).toBe(200);
      const otherMessage = MockSmsInbox.last(phone);
      const crossUser = await userRoutes.request("/me/accounts/phone/sms/verify", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ phone, code: otherMessage?.code }),
      });
      expect(crossUser.status).toBe(409);
    } finally {
      MockSmsInbox.clear();
      delete process.env.SMS_PROVIDER;
      delete process.env.STEWARD_TEST_INBOX;
    }
  });

  it("links Telegram and Farcaster accounts with one-time proofs and blocks cross-user reuse", async () => {
    process.env.TELEGRAM_BOT_TOKEN = TELEGRAM_BOT_TOKEN;
    process.env.FARCASTER_LOGIN_ENABLED = "true";
    process.env.SIWE_ALLOWED_DOMAINS = "steward.fi";
    try {
      const telegramChallengeResponse = await userRoutes.request(
        "/me/accounts/telegram/challenge",
        {
          method: "POST",
          headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
        },
      );
      expect(telegramChallengeResponse.status).toBe(200);
      const telegramChallenge = (await telegramChallengeResponse.json()) as {
        data: { challengeId: string };
      };
      const telegramPayload = signedTelegramPayload();
      const telegramLink = await userRoutes.request("/me/accounts/telegram", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...telegramPayload,
          challengeId: telegramChallenge.data.challengeId,
        }),
      });
      expect(telegramLink.status).toBe(200);
      const telegramBody = (await telegramLink.json()) as {
        data: { account: { provider: string; providerAccountId: string } };
      };
      expect(telegramBody.data.account).toMatchObject({
        provider: "telegram",
        providerAccountId: "424242",
      });

      const telegramReplay = await userRoutes.request("/me/accounts/telegram", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...telegramPayload,
          challengeId: telegramChallenge.data.challengeId,
        }),
      });
      expect(telegramReplay.status).toBe(401);

      const otherTelegramChallengeResponse = await userRoutes.request(
        "/me/accounts/telegram/challenge",
        {
          method: "POST",
          headers: { Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}` },
        },
      );
      const otherTelegramChallenge = (await otherTelegramChallengeResponse.json()) as {
        data: { challengeId: string };
      };
      const telegramCrossUser = await userRoutes.request("/me/accounts/telegram", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          ...signedTelegramPayload({ auth_date: Math.floor(Date.now() / 1000) + 1 }),
          challengeId: otherTelegramChallenge.data.challengeId,
        }),
      });
      expect(telegramCrossUser.status).toBe(409);

      const farcasterNonceResponse = await userRoutes.request("/me/accounts/farcaster/nonce", {
        method: "POST",
        headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
      });
      expect(farcasterNonceResponse.status).toBe(200);
      const farcasterNonce = (await farcasterNonceResponse.json()) as { data: { nonce: string } };
      const farcasterAccount = privateKeyToAccount(generatePrivateKey());
      const farcasterMessage = buildSiwfMessage(
        farcasterAccount.address,
        farcasterNonce.data.nonce,
      );
      const farcasterSignature = await farcasterAccount.signMessage({ message: farcasterMessage });
      const farcasterLink = await userRoutes.request("/me/accounts/farcaster", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: farcasterMessage,
          signature: farcasterSignature,
          custodyAddress: farcasterAccount.address,
          fid: "4242",
        }),
      });
      expect(farcasterLink.status).toBe(200);
      const farcasterBody = (await farcasterLink.json()) as {
        data: { account: { provider: string; providerAccountId: string } };
      };
      expect(farcasterBody.data.account).toMatchObject({
        provider: "farcaster",
        providerAccountId: `address:${farcasterAccount.address.toLowerCase()}`,
      });

      const farcasterReplay = await userRoutes.request("/me/accounts/farcaster", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(userId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: farcasterMessage,
          signature: farcasterSignature,
          custodyAddress: farcasterAccount.address,
          fid: "4242",
        }),
      });
      expect(farcasterReplay.status).toBe(401);

      const otherFarcasterNonceResponse = await userRoutes.request("/me/accounts/farcaster/nonce", {
        method: "POST",
        headers: { Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}` },
      });
      const otherFarcasterNonce = (await otherFarcasterNonceResponse.json()) as {
        data: { nonce: string };
      };
      const otherFarcasterMessage = buildSiwfMessage(
        farcasterAccount.address,
        otherFarcasterNonce.data.nonce,
      );
      const otherFarcasterSignature = await farcasterAccount.signMessage({
        message: otherFarcasterMessage,
      });
      const farcasterCrossUser = await userRoutes.request("/me/accounts/farcaster", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: otherFarcasterMessage,
          signature: otherFarcasterSignature,
          custodyAddress: farcasterAccount.address,
          fid: "4242",
        }),
      });
      expect(farcasterCrossUser.status).toBe(409);
    } finally {
      delete process.env.TELEGRAM_BOT_TOKEN;
      delete process.env.FARCASTER_LOGIN_ENABLED;
      delete process.env.SIWE_ALLOWED_DOMAINS;
    }
  });

  it("unlinks an owned account, deletes refresh tokens, and rejects cross-user unlink", async () => {
    const [account] = await getDb()
      .select({ id: accounts.id })
      .from(accounts)
      .where(and(eq(accounts.provider, "google"), eq(accounts.providerAccountId, "google-linked")));
    expect(account).toBeDefined();
    await getDb()
      .insert(refreshTokens)
      .values({
        id: "linked-refresh-token",
        userId,
        tenantId: TENANT_ID,
        tokenHash: "refresh-hash",
        expiresAt: new Date(Date.now() + 60_000),
      });

    const crossUser = await userRoutes.request("/me/accounts/github/github-only", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
    });
    expect(crossUser.status).toBe(404);

    const noMfa = await userRoutes.request("/me/accounts/google/google-linked", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${await staleTokenFor(userId)}` },
    });
    expect(noMfa.status).toBe(403);
    const noMfaBody = (await noMfa.json()) as { error: string };
    expect(noMfaBody.error).toContain("recent MFA");

    const response = await userRoutes.request("/me/accounts/google/google-linked", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { ok: boolean; data: { deleted: boolean } };
    expect(body.ok).toBe(true);
    expect(body.data.deleted).toBe(true);

    const [deletedAccount] = await getDb()
      .select()
      .from(accounts)
      .where(and(eq(accounts.provider, "google"), eq(accounts.providerAccountId, "google-linked")));
    expect(deletedAccount).toBeUndefined();
    const remainingRefreshTokens = await getDb()
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, userId));
    expect(remainingRefreshTokens).toHaveLength(0);

    const [audit] = await getDb()
      .select()
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, `personal-${userId}`),
          eq(auditEvents.action, "user.account.unlink"),
        ),
      )
      .orderBy(auditEvents.createdAt);
    expect(audit?.metadata).toMatchObject({
      accountId: account.id,
      provider: "google",
      providerAccountId: "google-linked",
    });
  });

  it("unlinks an owned passkey account and revokes sessions", async () => {
    await new Promise((resolve) => setTimeout(resolve, 2500));
    await getDb()
      .insert(refreshTokens)
      .values({
        id: "passkey-linked-refresh-token",
        userId,
        tenantId: TENANT_ID,
        tokenHash: "passkey-refresh-hash",
        expiresAt: new Date(Date.now() + 60_000),
      });

    const response = await userRoutes.request("/me/accounts/passkey/passkey-linked", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${await tokenFor(userId)}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { deleted: boolean } };
    expect(body.data.deleted).toBe(true);
    const [passkey] = await getDb()
      .select({ id: authenticators.id })
      .from(authenticators)
      .where(
        and(eq(authenticators.userId, userId), eq(authenticators.credentialId, "passkey-linked")),
      );
    expect(passkey).toBeUndefined();
    const remainingRefreshTokens = await getDb()
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, userId));
    expect(remainingRefreshTokens).toHaveLength(0);
  });

  it("does not unlink a user's last login method", async () => {
    const response = await userRoutes.request("/me/accounts/github/github-only", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${await tokenFor(accountOnlyUserId)}` },
    });
    expect(response.status).toBe(409);
    const body = (await response.json()) as { error: string };
    expect(body.error).toBe("Cannot unlink the user's last login method");
  });
});
