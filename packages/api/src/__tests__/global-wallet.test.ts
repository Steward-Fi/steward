import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  agentWallets,
  closeDb,
  getDb,
  tenantAppClients,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Vault } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { verifyTypedData } from "viem";

const APP_TENANT_ID = "global-wallet-app";
const CLIENT_ID = "client";
const ORIGIN = "https://wallet.example.test";
const ALT_ORIGIN = "https://wallet-alt.example.test";
const REDIRECT_URI = "https://wallet.example.test/callback";
let walletAddress = "0x1111111111111111111111111111111111111111";

describe("global wallet routes", () => {
  let routes: typeof import("../routes/global-wallet").globalWalletRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let userId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_JWT_SECRET = "global-wallet-test-jwt-secret-32chars";
    process.env.STEWARD_MASTER_PASSWORD = "global-wallet-test-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "global-wallet-test-audit-hmac-key-32chars";
    process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING = "true";
    process.env.STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN = "true";
    process.env.STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING = "true";
    process.env.STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION = "true";
    process.env.CHAIN_ID = "8453";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values([
        { id: APP_TENANT_ID, name: "Global Wallet App", apiKeyHash: "hash-app" },
        {
          id: "disabled-global-wallet-app",
          name: "Disabled Global Wallet",
          apiKeyHash: "hash-disabled",
        },
      ]);
    const [user] = await getDb()
      .insert(users)
      .values({ email: "global-wallet@example.test", walletAddress })
      .returning({ id: users.id });
    userId = user.id;

    await getDb()
      .insert(tenants)
      .values({ id: `personal-${userId}`, name: "Personal", apiKeyHash: "personal-hash" });
    await getDb()
      .insert(userTenants)
      .values({
        userId,
        tenantId: `personal-${userId}`,
        role: "owner",
      });
    const vault = new Vault({
      masterPassword: process.env.STEWARD_MASTER_PASSWORD,
      rpcUrl: "https://sepolia.base.org",
      chainId: 8453,
    });
    const wallet = await vault.createAgent(
      `personal-${userId}`,
      `user-wallet-${userId}`,
      "User Wallet",
    );
    walletAddress = wallet.walletAddress;
    await getDb().update(users).set({ walletAddress }).where(eq(users.id, userId));
    await getDb()
      .insert(tenantAppClients)
      .values([
        {
          tenantId: APP_TENANT_ID,
          id: CLIENT_ID,
          name: "Wallet App",
          enabled: true,
          isDefault: true,
          allowedOrigins: [ORIGIN],
          allowedRedirectUrls: [REDIRECT_URI],
          globalWalletEnabled: true,
          globalWalletAllowedScopes: [
            "eth_accounts",
            "personal_sign",
            "eth_signTypedData_v4",
            "eth_sendTransaction",
          ],
        },
        {
          tenantId: "disabled-global-wallet-app",
          id: CLIENT_ID,
          name: "Disabled Wallet App",
          enabled: true,
          isDefault: true,
          allowedOrigins: [ORIGIN],
          allowedRedirectUrls: [REDIRECT_URI],
          globalWalletEnabled: false,
        },
      ]);

    ({ globalWalletRoutes: routes } = await import("../routes/global-wallet"));
    ({ createSessionToken } = await import("../routes/auth"));
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING;
    delete process.env.STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN;
    delete process.env.STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING;
    delete process.env.STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION;
    delete process.env.CHAIN_ID;
  });

  function appId(tenantId = APP_TENANT_ID) {
    return `${tenantId}/${CLIENT_ID}`;
  }

  async function token(mfa = true) {
    return createSessionToken(walletAddress, `personal-${userId}`, {
      userId,
      tenantId: `personal-${userId}`,
      ...(mfa ? { mfaVerifiedAt: Date.now(), mfaMethod: "totp" } : {}),
    });
  }

  it("returns request metadata only for enabled app clients with exact allowlists", async () => {
    const response = await routes.request(
      `/consent/request?app_id=${encodeURIComponent(appId())}&redirect_uri=${encodeURIComponent(
        REDIRECT_URI,
      )}&scope=eth_accounts`,
      { headers: { Authorization: `Bearer ${await token()}`, Origin: ORIGIN } },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { app: { appId: string }; wallet: { address: string }; requestedScopes: string[] };
    };
    expect(body.ok).toBe(true);
    expect(body.data.app.appId).toBe(appId());
    expect(body.data.wallet.address).toBe(walletAddress);
    expect(body.data.requestedScopes).toEqual(["eth_accounts"]);

    const badOrigin = await routes.request(
      `/consent/request?app_id=${encodeURIComponent(appId())}`,
      {
        headers: { Authorization: `Bearer ${await token()}`, Origin: "https://evil.example.test" },
      },
    );
    expect(badOrigin.status).toBe(400);

    const disabled = await routes.request(
      `/consent/request?app_id=${encodeURIComponent(appId("disabled-global-wallet-app"))}`,
      { headers: { Authorization: `Bearer ${await token()}`, Origin: ORIGIN } },
    );
    expect(disabled.status).toBe(404);
  });

  it("source rolls back consent approval if final audit fails", () => {
    const source = readFileSync(join(import.meta.dir, "..", "routes", "global-wallet.ts"), "utf8");
    const routeStart = source.indexOf('globalWalletRoutes.post("/consent/approve"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const route = source.slice(
      routeStart,
      source.indexOf('globalWalletRoutes.get("/consents"', routeStart),
    );
    const authorized = route.indexOf('action: "global_wallet.consent.approve.authorized"');
    const insert = route.indexOf(".insert(userWalletAppConsents)", authorized);
    const finalAudit = route.indexOf('action: "global_wallet.consent.approved"', insert);
    const rollbackDelete = route.indexOf(".delete(userWalletAppConsents)", finalAudit);
    const restoreActive = route.indexOf('status: "active"', rollbackDelete);

    expect(authorized).toBeGreaterThanOrEqual(0);
    expect(insert).toBeGreaterThan(authorized);
    expect(finalAudit).toBeGreaterThan(insert);
    expect(rollbackDelete).toBeGreaterThan(finalAudit);
    expect(restoreActive).toBeGreaterThan(rollbackDelete);
  });

  it("uses browser Origin as authoritative over explicit origin parameters", async () => {
    const spoofed = await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: "https://evil.example.test",
      },
      body: JSON.stringify({
        app_id: appId(),
        origin: ORIGIN,
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    expect(spoofed.status).toBe(400);
  });

  it("treats an empty app-client global wallet scope allowlist as deny-all", async () => {
    await getDb()
      .update(tenantAppClients)
      .set({ globalWalletAllowedScopes: [] })
      .where(eq(tenantAppClients.id, CLIENT_ID));
    const denied = await routes.request(
      `/consent/request?app_id=${encodeURIComponent(appId())}&scope=eth_accounts`,
      { headers: { Authorization: `Bearer ${await token()}`, Origin: ORIGIN } },
    );
    expect(denied.status).toBe(400);
    await getDb()
      .update(tenantAppClients)
      .set({
        globalWalletAllowedScopes: [
          "eth_accounts",
          "personal_sign",
          "eth_signTypedData_v4",
          "eth_sendTransaction",
        ],
      })
      .where(eq(tenantAppClients.id, CLIENT_ID));
  });

  it("requires recent MFA to approve and revoke consent", async () => {
    const stale = await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token(false)}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    expect(stale.status).toBe(403);

    const approved = await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    expect(approved.status).toBe(200);
    const approvedBody = (await approved.json()) as {
      ok: boolean;
      data: { consent: { id: string; status: string }; wallet: { address: string } };
    };
    expect(approvedBody.data.consent.status).toBe("active");
    expect(approvedBody.data.wallet.address).toBe(walletAddress);

    const staleRevoke = await routes.request(`/consents/${approvedBody.data.consent.id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${await token(false)}` },
    });
    expect(staleRevoke.status).toBe(403);

    const revoked = await routes.request(`/consents/${approvedBody.data.consent.id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
    });
    expect(revoked.status).toBe(200);
  });

  it("binds RPC to active consent and blocks signing methods", async () => {
    const noConsent = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({ app_id: appId(), method: "eth_accounts", id: 1 }),
    });
    expect(noConsent.status).toBe(403);

    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });

    const accountsResponse = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({ app_id: appId(), method: "eth_accounts", id: 1 }),
    });
    expect(accountsResponse.status).toBe(200);
    const accountsBody = (await accountsResponse.json()) as {
      data: { id: number; result: string[] };
    };
    expect(accountsBody.data.result).toEqual([walletAddress]);

    const chainIdResponse = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({ app_id: appId(), method: "eth_chainId", id: 2 }),
    });
    const chainIdBody = (await chainIdResponse.json()) as { data: { result: string } };
    expect(chainIdBody.data.result).toBe("0x2105");

    await getDb()
      .update(agentWallets)
      .set({ address: "0x3333333333333333333333333333333333333333" })
      .where(eq(agentWallets.agentId, `user-wallet-${userId}`));
    const rotatedWallet = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({ app_id: appId(), method: "eth_accounts", id: 3 }),
    });
    expect(rotatedWallet.status).toBe(403);
    await getDb()
      .update(agentWallets)
      .set({ address: walletAddress })
      .where(eq(agentWallets.agentId, `user-wallet-${userId}`));

    const unsupportedSigning = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({ app_id: appId(), method: "eth_signTypedData_v3", params: [] }),
    });
    expect(unsupportedSigning.status).toBe(403);
  });

  it("requires personal_sign scope and recent MFA before signing global wallet messages", async () => {
    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    const missingScope = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
      }),
    });
    expect(missingScope.status).toBe(403);

    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts", "personal_sign"],
      }),
    });

    const staleMfa = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token(false)}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
      }),
    });
    expect(staleMfa.status).toBe(403);

    const authLike = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["example.com wants you to sign in with your Ethereum account", walletAddress],
      }),
    });
    expect(authLike.status).toBe(403);

    const unconfirmed = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
        id: 3,
      }),
    });
    expect(unconfirmed.status).toBe(403);

    const confirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
      }),
    });
    expect(confirmation.status).toBe(200);
    const confirmationBody = (await confirmation.json()) as {
      data: { confirmationId: string; method: string };
    };
    expect(confirmationBody.data.method).toBe("personal_sign");

    const signed = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
        confirmation_id: confirmationBody.data.confirmationId,
        id: 3,
      }),
    });
    expect(signed.status).toBe(200);
    const signedBody = (await signed.json()) as { data: { id: number; result: string } };
    expect(signedBody.data.id).toBe(3);
    expect(signedBody.data.result).toMatch(/^0x[0-9a-fA-F]{130}$/);

    const reused = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["hello steward", walletAddress],
        confirmation_id: confirmationBody.data.confirmationId,
      }),
    });
    expect(reused.status).toBe(403);
  });

  it("source writes global wallet RPC authorization audits before sensitive execution", () => {
    const source = readFileSync(join(import.meta.dir, "..", "routes", "global-wallet.ts"), "utf8");
    const rpcStart = source.indexOf('globalWalletRoutes.post("/rpc",');
    expect(rpcStart).toBeGreaterThanOrEqual(0);

    for (const [methodMarker, auditAction, executionMarker] of [
      ['method === "personal_sign"', "global_wallet.rpc.sign.authorized", "signMessage("],
      [
        'method === "eth_signTypedData_v4"',
        "global_wallet.rpc.typed_data_sign.authorized",
        "signTypedData({",
      ],
      [
        'method === "eth_sendTransaction"',
        "global_wallet.rpc.transaction_submit.authorized",
        "signTransaction({",
      ],
    ] as const) {
      const methodStart = source.indexOf(methodMarker, rpcStart);
      expect(methodStart).toBeGreaterThan(rpcStart);
      const audit = source.indexOf(auditAction, methodStart);
      const execution = source.indexOf(executionMarker, methodStart);
      expect(audit).toBeGreaterThan(methodStart);
      expect(audit).toBeLessThan(execution);
    }
  });

  it("requires eth_signTypedData_v4 scope and recent MFA before signing global wallet typed data", async () => {
    const typedData = {
      domain: {
        name: "Steward Test",
        version: "1",
        chainId: 8453,
        verifyingContract: "0x0000000000000000000000000000000000000001",
      },
      types: {
        Message: [
          { name: "contents", type: "string" },
          { name: "nonce", type: "uint256" },
        ],
      },
      primaryType: "Message",
      message: { contents: "hello steward", nonce: 1 },
    };

    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    const missingScope = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
      }),
    });
    expect(missingScope.status).toBe(403);

    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts", "eth_signTypedData_v4"],
      }),
    });

    const staleMfa = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token(false)}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
      }),
    });
    expect(staleMfa.status).toBe(403);

    const mismatchedAddress = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: ["0x2222222222222222222222222222222222222222", typedData],
      }),
    });
    expect(mismatchedAddress.status).toBe(403);

    const permitLike = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [
          walletAddress,
          {
            ...typedData,
            types: { PermitSingle: [{ name: "spender", type: "address" }] },
            primaryType: "PermitSingle",
            message: { spender: "0x0000000000000000000000000000000000000001" },
          },
        ],
      }),
    });
    expect(permitLike.status).toBe(403);

    const unconfirmed = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
        id: 4,
      }),
    });
    expect(unconfirmed.status).toBe(403);

    const confirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
      }),
    });
    expect(confirmation.status).toBe(200);
    expect(confirmation.headers.get("Cache-Control")).toContain("no-store");
    const confirmationBody = (await confirmation.json()) as {
      data: { confirmationId: string; method: string };
    };
    expect(confirmationBody.data.method).toBe("eth_signTypedData_v4");

    const signed = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
        confirmationId: confirmationBody.data.confirmationId,
        id: 4,
      }),
    });
    expect(signed.status).toBe(200);
    const signedBody = (await signed.json()) as { data: { id: number; result: `0x${string}` } };
    expect(signedBody.data.id).toBe(4);
    expect(signedBody.data.result).toMatch(/^0x[0-9a-fA-F]{130}$/);
    await expect(
      verifyTypedData({
        address: walletAddress as `0x${string}`,
        domain: typedData.domain,
        types: typedData.types,
        primaryType: typedData.primaryType,
        message: typedData.message,
        signature: signedBody.data.result,
      }),
    ).resolves.toBe(true);

    const reused = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_signTypedData_v4",
        params: [walletAddress, typedData],
        confirmationId: confirmationBody.data.confirmationId,
      }),
    });
    expect(reused.status).toBe(403);
  });

  it("rejects global wallet confirmations after consent revocation", async () => {
    const approved = await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts", "personal_sign"],
      }),
    });
    expect(approved.status).toBe(200);
    const approvedBody = (await approved.json()) as {
      data: { consent: { id: string } };
    };

    const confirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["revoked consent confirmation", walletAddress],
      }),
    });
    expect(confirmation.status).toBe(200);
    const confirmationBody = (await confirmation.json()) as {
      data: { confirmationId: string };
    };

    const revoked = await routes.request(`/consents/${approvedBody.data.consent.id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
    });
    expect(revoked.status).toBe(200);

    const revokedConsentUse = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["revoked consent confirmation", walletAddress],
        confirmation_id: confirmationBody.data.confirmationId,
      }),
    });
    expect(revokedConsentUse.status).toBe(403);

    const reapproved = await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts", "personal_sign"],
      }),
    });
    expect(reapproved.status).toBe(200);

    const reapprovedConsentUse = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "personal_sign",
        params: ["revoked consent confirmation", walletAddress],
        confirmation_id: confirmationBody.data.confirmationId,
      }),
    });
    expect(reapprovedConsentUse.status).toBe(403);
  });

  it("binds global wallet confirmations to origin and wallet", async () => {
    await getDb()
      .update(tenantAppClients)
      .set({ allowedOrigins: [ORIGIN, ALT_ORIGIN] })
      .where(eq(tenantAppClients.id, CLIENT_ID));

    try {
      await routes.request("/consent/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          redirect_uri: REDIRECT_URI,
          scopes: ["eth_accounts", "personal_sign"],
        }),
      });

      const confirmation = await routes.request("/rpc/confirm", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          method: "personal_sign",
          params: ["origin and wallet bound", walletAddress],
        }),
      });
      expect(confirmation.status).toBe(200);
      const confirmationBody = (await confirmation.json()) as {
        data: { confirmationId: string };
      };

      await routes.request("/consent/approve", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ALT_ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          scopes: ["eth_accounts", "personal_sign"],
        }),
      });

      const wrongOrigin = await routes.request("/rpc", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ALT_ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          method: "personal_sign",
          params: ["origin and wallet bound", walletAddress],
          confirmation_id: confirmationBody.data.confirmationId,
        }),
      });
      expect(wrongOrigin.status).toBe(403);

      await getDb()
        .update(agentWallets)
        .set({ address: "0x4444444444444444444444444444444444444444" })
        .where(eq(agentWallets.agentId, `user-wallet-${userId}`));
      const wrongWallet = await routes.request("/rpc", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          method: "personal_sign",
          params: ["origin and wallet bound", walletAddress],
          confirmation_id: confirmationBody.data.confirmationId,
        }),
      });
      expect(wrongWallet.status).toBe(403);
    } finally {
      await getDb()
        .update(agentWallets)
        .set({ address: walletAddress })
        .where(eq(agentWallets.agentId, `user-wallet-${userId}`));
      await getDb()
        .update(tenantAppClients)
        .set({ allowedOrigins: [ORIGIN] })
        .where(eq(tenantAppClients.id, CLIENT_ID));
    }
  });

  it("scans and executes native eth_sendTransaction requests behind confirmation", async () => {
    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts"],
      }),
    });
    const missingScope = await routes.request("/rpc/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          { from: walletAddress, to: "0x0000000000000000000000000000000000000001", value: "0x1" },
        ],
      }),
    });
    expect(missingScope.status).toBe(403);

    await routes.request("/consent/approve", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        redirect_uri: REDIRECT_URI,
        scopes: ["eth_accounts", "eth_sendTransaction"],
      }),
    });

    const mismatch = await routes.request("/rpc/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: "0x2222222222222222222222222222222222222222",
            to: "0x0000000000000000000000000000000000000001",
            value: "0x1",
          },
        ],
      }),
    });
    expect(mismatch.status).toBe(403);

    const scanned = await routes.request("/rpc/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token(false)}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x0000000000000000000000000000000000000001",
            value: "0x1",
            chainId: "0x2105",
          },
        ],
      }),
    });
    expect(scanned.status).toBe(200);
    const scannedBody = (await scanned.json()) as {
      data: {
        blocked: boolean;
        riskLevel: string;
        confirmationRequired: boolean;
        executionSupported: boolean;
        transaction: { valueWei: string; chainId: number };
      };
    };
    expect(scannedBody.data.blocked).toBe(false);
    expect(scannedBody.data.riskLevel).toBe("medium");
    expect(scannedBody.data.confirmationRequired).toBe(true);
    expect(scannedBody.data.executionSupported).toBe(true);
    expect(scannedBody.data.transaction.valueWei).toBe("1");
    expect(scannedBody.data.transaction.chainId).toBe(8453);

    const staleConfirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token(false)}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x0000000000000000000000000000000000000001",
            value: "0x1",
            chainId: "0x2105",
          },
        ],
      }),
    });
    expect(staleConfirmation.status).toBe(403);

    const confirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x0000000000000000000000000000000000000001",
            value: "0x1",
            chainId: "0x2105",
          },
        ],
      }),
    });
    expect(confirmation.status).toBe(200);
    const confirmationBody = (await confirmation.json()) as {
      data: { confirmationId: string; method: string };
    };
    expect(confirmationBody.data.method).toBe("eth_sendTransaction");

    const calldataConfirmation = await routes.request("/rpc/confirm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x0000000000000000000000000000000000000001",
            value: "0",
            data: "0xabcdef01",
          },
        ],
      }),
    });
    expect(calldataConfirmation.status).toBe(403);

    const calldata = await routes.request("/rpc/scan", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          {
            from: walletAddress,
            to: "0x0000000000000000000000000000000000000001",
            value: "0",
            data: "0xabcdef01",
          },
        ],
      }),
    });
    expect(calldata.status).toBe(200);
    const calldataBody = (await calldata.json()) as {
      data: { blocked: boolean; warnings: Array<{ code: string; severity: string }> };
    };
    expect(calldataBody.data.blocked).toBe(true);
    expect(calldataBody.data.warnings).toContainEqual(
      expect.objectContaining({ code: "contract_call_blocked", severity: "error" }),
    );

    const missingConfirmation = await routes.request("/rpc", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "Content-Type": "application/json",
        Origin: ORIGIN,
      },
      body: JSON.stringify({
        app_id: appId(),
        method: "eth_sendTransaction",
        params: [
          { from: walletAddress, to: "0x0000000000000000000000000000000000000001", value: "0x1" },
        ],
      }),
    });
    expect(missingConfirmation.status).toBe(403);

    const txHash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const signSpy = spyOn(Vault.prototype, "signTransaction").mockResolvedValue(txHash);
    try {
      const execution = await routes.request("/rpc", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          method: "eth_sendTransaction",
          params: [
            {
              from: walletAddress,
              to: "0x0000000000000000000000000000000000000001",
              value: "0x1",
              chainId: "0x2105",
            },
          ],
          confirmation_id: confirmationBody.data.confirmationId,
        }),
      });
      expect(execution.status).toBe(200);
      const executionBody = (await execution.json()) as {
        data: { result: string; jsonrpc: string; id: null };
      };
      expect(executionBody.data.result).toBe(txHash);
      expect(signSpy).toHaveBeenCalledWith({
        agentId: `user-wallet-${userId}`,
        tenantId: `personal-${userId}`,
        to: "0x0000000000000000000000000000000000000001",
        value: "1",
        data: undefined,
        chainId: 8453,
        walletAddress,
        broadcast: true,
      });

      const replay = await routes.request("/rpc", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${await token()}`,
          "Content-Type": "application/json",
          Origin: ORIGIN,
        },
        body: JSON.stringify({
          app_id: appId(),
          method: "eth_sendTransaction",
          params: [
            {
              from: walletAddress,
              to: "0x0000000000000000000000000000000000000001",
              value: "0x1",
              chainId: "0x2105",
            },
          ],
          confirmation_id: confirmationBody.data.confirmationId,
        }),
      });
      expect(replay.status).toBe(403);
    } finally {
      signSpy.mockRestore();
    }
  });
});
