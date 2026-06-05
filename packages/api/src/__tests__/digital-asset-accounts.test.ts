import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  agentKeyQuorums,
  agentSigners,
  agents,
  agentWallets,
  closeDb,
  digitalAssetAccountAggregations,
  digitalAssetAccounts,
  digitalAssetAccountWallets,
  getDb,
  policies,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `digital-account-tenant-${Date.now()}`;
const OTHER_TENANT_ID = `digital-account-other-${Date.now()}`;
const WALLET_A = `digital-account-wallet-a-${Date.now()}`;
const WALLET_B = `digital-account-wallet-b-${Date.now()}`;
const WALLET_BTC = `digital-account-wallet-btc-${Date.now()}`;
const OTHER_WALLET = `digital-account-other-wallet-${Date.now()}`;
const ACCOUNT_OWNER_USER_ID = "11111111-1111-4111-8111-111111111111";
const WALLET_A_OWNER_SIGNER_ID = "22222222-2222-4222-8222-222222222222";
const WALLET_A_AUTH_KEY_SIGNER_ID = "33333333-3333-4333-8333-333333333333";
const WALLET_A_REVOKED_SIGNER_ID = "55555555-5555-4555-8555-555555555555";
const OTHER_TENANT_SIGNER_ID = "44444444-4444-4444-8444-444444444444";

setDefaultTimeout(30000);

async function makeApp(tenantId = TENANT_ID) {
  const { accountRoutes } = await import("../routes/accounts");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "api-key");
    await next();
  });
  app.route("/accounts", accountRoutes);
  return app;
}

async function seedWallet(tenantId: string, id: string, evmAddress: string, solanaAddress: string) {
  await getDb().insert(agents).values({
    id,
    tenantId,
    name: id,
    walletAddress: evmAddress,
  });
  await getDb()
    .insert(agentWallets)
    .values([
      { agentId: id, chainFamily: "evm", address: evmAddress, purpose: "primary" },
      { agentId: id, chainFamily: "solana", address: solanaAddress, purpose: "primary" },
    ]);
}

describe("digital asset account resources", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "digital-account-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "digital-account-audit-hmac-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Digital Account Tenant", apiKeyHash: "hash" },
        { id: OTHER_TENANT_ID, name: "Other Digital Account Tenant", apiKeyHash: "other-hash" },
      ]);
    await getDb().insert(users).values({
      id: ACCOUNT_OWNER_USER_ID,
      walletAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      walletChain: "ethereum",
    });
    await getDb()
      .insert(userTenants)
      .values({ userId: ACCOUNT_OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" });
    await seedWallet(
      TENANT_ID,
      WALLET_A,
      "0x1111111111111111111111111111111111111111",
      "7cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
    );
    await getDb()
      .update(agents)
      .set({
        ownerUserId: ACCOUNT_OWNER_USER_ID,
        walletType: "recoverable_user",
      })
      .where(and(eq(agents.tenantId, TENANT_ID), eq(agents.id, WALLET_A)));
    await getDb()
      .insert(agentSigners)
      .values([
        {
          id: WALLET_A_OWNER_SIGNER_ID,
          tenantId: TENANT_ID,
          agentId: WALLET_A,
          signerType: "owner",
          subjectType: "user",
          subjectId: ACCOUNT_OWNER_USER_ID,
          status: "active",
        },
        {
          id: WALLET_A_AUTH_KEY_SIGNER_ID,
          tenantId: TENANT_ID,
          agentId: WALLET_A,
          signerType: "service",
          subjectType: "authorization_key",
          subjectId: "key_active",
          status: "active",
        },
        {
          id: WALLET_A_REVOKED_SIGNER_ID,
          tenantId: TENANT_ID,
          agentId: WALLET_A,
          signerType: "service",
          subjectType: "authorization_key",
          subjectId: "key_retired",
          status: "revoked",
        },
      ]);
    await getDb()
      .insert(policies)
      .values({
        id: "policy_tx_review",
        agentId: WALLET_A,
        type: "spending-limit",
        enabled: true,
        config: { maxPerTx: "100" },
      });
    await getDb()
      .insert(agentKeyQuorums)
      .values([
        {
          id: crypto.randomUUID(),
          tenantId: TENANT_ID,
          agentId: WALLET_A,
          name: "Owner quorum",
          threshold: 1,
          status: "active",
        },
        {
          id: crypto.randomUUID(),
          tenantId: TENANT_ID,
          agentId: WALLET_A,
          name: "Retired quorum",
          threshold: 1,
          status: "revoked",
        },
      ]);
    await seedWallet(
      TENANT_ID,
      WALLET_B,
      "0x2222222222222222222222222222222222222222",
      "8cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
    );
    await getDb().insert(agents).values({
      id: WALLET_BTC,
      tenantId: TENANT_ID,
      name: "Bitcoin Account Wallet",
      walletAddress: "0x0000000000000000000000000000000000000000",
    });
    await getDb()
      .insert(agentWallets)
      .values({
        agentId: WALLET_BTC,
        chainFamily: "bitcoin",
        address: "tb1q9x5p7m6d3l0q8s2e4r6t8y0u2i4o6p8a0s2d4f",
        purpose: "primary",
        venue: "bitcoin:testnet:p2wpkh:0:0:0",
        metadata: {
          bitcoin: {
            network: "testnet",
            addressType: "p2wpkh",
            path: "m/84'/1'/0'/0/0",
            publicKey: "0x" + "02".repeat(33),
            privateKey: "0x" + "aa".repeat(32),
            mnemonic:
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            account: 0,
            change: 0,
            index: 0,
            caip2: "bip122:000000000933ea01ad0ee984209779ba",
          },
        },
      });
    await seedWallet(
      OTHER_TENANT_ID,
      OTHER_WALLET,
      "0x3333333333333333333333333333333333333333",
      "9cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
    );
    await getDb().insert(agentSigners).values({
      id: OTHER_TENANT_SIGNER_ID,
      tenantId: OTHER_TENANT_ID,
      agentId: OTHER_WALLET,
      signerType: "service",
      subjectType: "authorization_key",
      subjectId: "other-tenant-key",
      status: "active",
    });
    await getDb().insert(agentKeyQuorums).values({
      id: crypto.randomUUID(),
      tenantId: OTHER_TENANT_ID,
      agentId: OTHER_WALLET,
      name: "Other tenant quorum",
      threshold: 1,
      status: "active",
    });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("creates, lists, gets, updates, and deletes an account over existing wallet ids", async () => {
    const create = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_existing_wallets",
        display_name: "Treasury",
        wallet_ids: [WALLET_A],
        metadata: { env: "test" },
      }),
    });
    const createBody = await create.clone().json();
    expect(create.status, JSON.stringify(createBody)).toBe(201);
    const created = createBody as {
      ok: boolean;
      data: {
        id: string;
        display_name: string;
        wallet_ids: string[];
        wallets: Array<{
          walletId: string;
          chainFamily: string;
          address: string;
          ownerUserId: string | null;
          walletType: string | null;
          custody: { type: string; ownerUserId: string | null };
          capabilities: string[];
          capabilityMetadata: {
            custody: { type: string; userOwned: boolean; serverManaged: boolean };
            signing: {
              signerCount: number;
              activeSignerCount: number;
              quorumCount: number;
              activeQuorumCount: number;
              mode: string;
            };
            operations: {
              signTransaction: boolean;
              signTypedData: boolean;
              exportPrivateKey: boolean;
              solanaTransaction: boolean;
            };
          };
          signing: {
            signerCount: number;
            activeSignerCount: number;
            quorumCount: number;
            activeQuorumCount: number;
          };
        }>;
        metadata: Record<string, unknown>;
        capabilities: string[];
        capabilityMetadata: {
          walletCount: number;
          walletIds: string[];
          chainFamilies: string[];
          custodyTypes: string[];
          hasUserEmbeddedWallets: boolean;
          hasActiveDelegatedSigners: boolean;
          hasActiveKeyQuorums: boolean;
        };
      };
    };
    expect(created.ok).toBe(true);
    expect(created.data.id).toBe("acct_existing_wallets");
    expect(created.data.display_name).toBe("Treasury");
    expect(created.data.wallet_ids).toEqual([WALLET_A]);
    expect(created.data.wallets.map((wallet) => wallet.chainFamily).sort()).toEqual([
      "evm",
      "solana",
    ]);
    expect(created.data.wallets[0]).toMatchObject({
      ownerUserId: "11111111-1111-4111-8111-111111111111",
      walletType: "recoverable_user",
      custody: {
        type: "user_embedded",
        ownerUserId: "11111111-1111-4111-8111-111111111111",
      },
      signing: {
        signerCount: 3,
        activeSignerCount: 2,
        quorumCount: 2,
        activeQuorumCount: 1,
      },
    });
    expect(created.data.capabilities).toEqual([
      "export_private_key",
      "sign_message",
      "sign_transaction",
      "solana_transaction",
      "transfer",
    ]);
    expect(created.data.capabilityMetadata).toMatchObject({
      walletCount: 2,
      walletIds: [WALLET_A],
      chainFamilies: ["evm", "solana"],
      custodyTypes: ["user_embedded"],
      hasUserEmbeddedWallets: true,
      hasActiveDelegatedSigners: true,
      hasActiveKeyQuorums: true,
    });
    const evmWallet = created.data.wallets.find((wallet) => wallet.chainFamily === "evm");
    expect(evmWallet).toMatchObject({
      capabilities: ["export_private_key", "sign_message", "sign_transaction", "transfer"],
      capabilityMetadata: {
        custody: { type: "user_embedded", userOwned: true, serverManaged: false },
        signing: {
          mode: "quorum",
          signerCount: 3,
          activeSignerCount: 2,
          quorumCount: 2,
          activeQuorumCount: 1,
        },
        operations: {
          signTransaction: true,
          signTypedData: false,
          exportPrivateKey: true,
          solanaTransaction: false,
        },
      },
    });
    expect(created.data.metadata).toEqual({ env: "test" });

    const list = await app.request("/accounts");
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { data: { accounts: Array<{ id: string }> } };
    expect(listed.data.accounts.map((account) => account.id)).toContain("acct_existing_wallets");

    const patch = await app.request("/accounts/acct_existing_wallets", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        display_name: "Ops Treasury",
        wallet_ids: [WALLET_B],
      }),
    });
    expect(patch.status).toBe(200);
    const patched = (await patch.json()) as {
      data: { display_name: string; wallet_ids: string[]; wallets: Array<{ walletId: string }> };
    };
    expect(patched.data.display_name).toBe("Ops Treasury");
    expect(patched.data.wallet_ids).toEqual([WALLET_B]);
    expect(new Set(patched.data.wallets.map((wallet) => wallet.walletId))).toEqual(
      new Set([WALLET_B]),
    );

    const get = await app.request("/accounts/acct_existing_wallets");
    expect(get.status).toBe(200);
    const context = await import("../services/context");
    const originalGetBalance = context.vault.getBalance.bind(context.vault);
    const originalGetTokenBalances = context.vault.getTokenBalances.bind(context.vault);
    const originalGetSplTokenBalances = context.vault.getSplTokenBalances.bind(context.vault);
    context.vault.getBalance = async (_tenantId: string, agentId: string, chainId?: number) => ({
      native: agentId === WALLET_B && chainId === 101 ? 2_000_000_000n : 1_000_000_000n,
      nativeFormatted: agentId === WALLET_B && chainId === 101 ? "2" : "1",
      chainId: chainId ?? 84532,
      symbol: chainId === 101 ? "SOL" : "ETH",
      walletAddress:
        chainId === 101
          ? "8cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx"
          : "0x2222222222222222222222222222222222222222",
    });
    context.vault.getTokenBalances = async (
      _tenantId: string,
      _agentId: string,
      chainId?: number,
      tokens?: string[],
    ) => [
      {
        token: tokens?.[0] ?? "0x9999999999999999999999999999999999999999",
        symbol: "MOCK",
        balance: "1500",
        formatted: "1.5",
        decimals: 3,
        chainId,
      } as never,
    ];
    context.vault.getSplTokenBalances = async () => [
      {
        mint: "So11111111111111111111111111111111111111112",
        token: "So11111111111111111111111111111111111111112",
        symbol: "SPL",
        balance: "2500000",
        formatted: "2.5",
        decimals: 6,
      },
    ];
    try {
      const balance = await app.request(
        "/accounts/acct_existing_wallets/balance?tokens=0x9999999999999999999999999999999999999999",
      );
      expect(balance.status).toBe(200);
      const balanceBody = (await balance.json()) as {
        data: {
          capabilities: string[];
          capabilityMetadata: {
            walletCount: number;
            hasServerWallets: boolean;
            hasUserEmbeddedWallets: boolean;
            hasActiveDelegatedSigners: boolean;
            hasActiveKeyQuorums: boolean;
          };
          wallets: unknown[];
          balances: Array<{ walletId: string; chainId: number; symbol: string; native: string }>;
          tokenBalances: Array<{
            walletId: string;
            chainId: number;
            token: string;
            symbol: string;
            balance: string;
            decimals: number;
          }>;
          rollups: {
            native: Array<{ chainId: number; symbol: string; native: string }>;
            tokens: Array<{
              chainId: number;
              token: string;
              symbol: string;
              balance: string;
              decimals: number;
            }>;
          };
        };
      };
      expect(balanceBody.data.capabilities).toEqual([
        "send_calls",
        "sign_authorization",
        "sign_message",
        "sign_transaction",
        "sign_typed_data",
        "sign_user_operation",
        "solana_transaction",
        "transfer",
      ]);
      expect(balanceBody.data.capabilityMetadata).toMatchObject({
        walletCount: 2,
        hasServerWallets: true,
        hasUserEmbeddedWallets: false,
        hasActiveDelegatedSigners: false,
        hasActiveKeyQuorums: false,
      });
      expect(balanceBody.data.wallets).toHaveLength(2);
      expect(balanceBody.data.balances).toMatchObject([
        {
          walletId: WALLET_B,
          chainFamily: "evm",
          chainId: 84532,
          symbol: "ETH",
          native: "1000000000",
          nativeFormatted: "1",
          walletAddress: "0x2222222222222222222222222222222222222222",
        },
        {
          walletId: WALLET_B,
          chainFamily: "solana",
          chainId: 101,
          symbol: "SOL",
          native: "2000000000",
          nativeFormatted: "2",
          walletAddress: "8cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
        },
      ]);
      expect(balanceBody.data.tokenBalances).toEqual([
        {
          walletId: WALLET_B,
          chainId: 84532,
          token: "0x9999999999999999999999999999999999999999",
          symbol: "MOCK",
          balance: "1500",
          formatted: "1.5",
          decimals: 3,
        },
        {
          walletId: WALLET_B,
          chainId: 101,
          token: "So11111111111111111111111111111111111111112",
          symbol: "SPL",
          balance: "2500000",
          formatted: "2.5",
          decimals: 6,
        },
      ]);
      expect(balanceBody.data.rollups.native).toEqual([
        { chainId: 84532, symbol: "ETH", native: "1000000000" },
        { chainId: 101, symbol: "SOL", native: "2000000000" },
      ]);
      expect(balanceBody.data.rollups.tokens).toEqual([
        {
          chainId: 84532,
          token: "0x9999999999999999999999999999999999999999",
          symbol: "MOCK",
          balance: "1500",
          decimals: 3,
        },
        {
          chainId: 101,
          token: "So11111111111111111111111111111111111111112",
          symbol: "SPL",
          balance: "2500000",
          decimals: 6,
        },
      ]);
    } finally {
      context.vault.getBalance = originalGetBalance;
      context.vault.getTokenBalances = originalGetTokenBalances;
      context.vault.getSplTokenBalances = originalGetSplTokenBalances;
    }

    const deleted = await app.request("/accounts/acct_existing_wallets", { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect((await app.request("/accounts/acct_existing_wallets")).status).toBe(404);
  });

  it("accepts explicit user wallet membership ids and rejects server wallets in that field", async () => {
    const createResponse = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_user_wallet_ids",
        display_name: "User Wallet Account",
        user_wallet_ids: [WALLET_A],
      }),
    });

    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      data: {
        wallet_ids: string[];
        wallets: Array<{
          walletId: string;
          ownerUserId: string | null;
          walletType: string | null;
          custody: { type: string; ownerUserId: string | null };
        }>;
      };
    };
    expect(created.data.wallet_ids).toEqual([WALLET_A]);
    expect(created.data.wallets[0]).toMatchObject({
      walletId: WALLET_A,
      ownerUserId: "11111111-1111-4111-8111-111111111111",
      walletType: "recoverable_user",
      custody: {
        type: "user_embedded",
        ownerUserId: "11111111-1111-4111-8111-111111111111",
      },
    });
    const deleteResponse = await app.request("/accounts/acct_user_wallet_ids", {
      method: "DELETE",
    });
    expect(deleteResponse.status).toBe(200);

    const serverWalletResponse = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_user_wallet_ids_reject",
        display_name: "Rejected Server Wallet",
        user_wallet_ids: [WALLET_B],
      }),
    });

    expect(serverWalletResponse.status).toBe(400);
    expect(((await serverWalletResponse.json()) as { error: string }).error).toContain(
      "user_wallet_ids must reference user-owned wallets",
    );
  });

  it("stores account-level owners and additional signer assignments with tenant scoping", async () => {
    const create = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_authorization_assignments",
        display_name: "Signer assigned account",
        wallet_ids: [WALLET_A],
        owner_user_ids: [ACCOUNT_OWNER_USER_ID],
        additional_signer_ids: [WALLET_A_AUTH_KEY_SIGNER_ID],
        signer_policy_ids: ["policy_tx_review"],
        metadata: { env: "authz-test" },
      }),
    });
    const created = (await create.json()) as {
      data: {
        ownerUserIds: string[];
        owner_user_ids: string[];
        additionalSignerIds: string[];
        additional_signer_ids: string[];
        signerPolicyIds: string[];
        signer_policy_ids: string[];
        metadata: Record<string, unknown>;
      };
    };
    expect(create.status).toBe(201);
    expect(created.data.ownerUserIds).toEqual([ACCOUNT_OWNER_USER_ID]);
    expect(created.data.owner_user_ids).toEqual([ACCOUNT_OWNER_USER_ID]);
    expect(created.data.additionalSignerIds).toEqual([WALLET_A_AUTH_KEY_SIGNER_ID]);
    expect(created.data.additional_signer_ids).toEqual([WALLET_A_AUTH_KEY_SIGNER_ID]);
    expect(created.data.signerPolicyIds).toEqual(["policy_tx_review"]);
    expect(created.data.signer_policy_ids).toEqual(["policy_tx_review"]);
    expect(created.data.metadata.authorization).toMatchObject({
      ownerUserIds: [ACCOUNT_OWNER_USER_ID],
      additionalSignerIds: [WALLET_A_AUTH_KEY_SIGNER_ID],
      signerPolicyIds: ["policy_tx_review"],
    });

    const rawMetadataAuthorization = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_raw_authorization_bypass",
        wallet_ids: [WALLET_A],
        metadata: {
          authorization: {
            additionalSignerIds: [OTHER_TENANT_SIGNER_ID],
          },
        },
      }),
    });
    expect(rawMetadataAuthorization.status).toBe(400);
    expect(((await rawMetadataAuthorization.json()) as { error?: string }).error).toContain(
      "metadata.authorization is reserved",
    );

    const patch = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        metadata: { env: "metadata-replaced" },
        additional_signer_ids: [WALLET_A_OWNER_SIGNER_ID],
      }),
    });
    const patched = (await patch.json()) as {
      data: {
        ownerUserIds: string[];
        additionalSignerIds: string[];
        signerPolicyIds: string[];
        metadata: Record<string, unknown>;
      };
    };
    expect(patch.status).toBe(200);
    expect(patched.data.ownerUserIds).toEqual([ACCOUNT_OWNER_USER_ID]);
    expect(patched.data.additionalSignerIds).toEqual([WALLET_A_OWNER_SIGNER_ID]);
    expect(patched.data.signerPolicyIds).toEqual(["policy_tx_review"]);
    expect(patched.data.metadata.env).toBe("metadata-replaced");
    expect(patched.data.metadata.authorization).toMatchObject({
      additionalSignerIds: [WALLET_A_OWNER_SIGNER_ID],
    });

    const rawMetadataPatch = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        metadata: {
          authorization: {
            additionalSignerIds: [OTHER_TENANT_SIGNER_ID],
          },
        },
      }),
    });
    expect(rawMetadataPatch.status).toBe(400);
    expect(((await rawMetadataPatch.json()) as { error?: string }).error).toContain(
      "metadata.authorization is reserved",
    );

    const crossTenant = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ additional_signer_ids: [OTHER_TENANT_SIGNER_ID] }),
    });
    expect(crossTenant.status).toBe(400);
    expect(((await crossTenant.json()) as { error?: string }).error).toContain(
      "outside this account",
    );

    const revokedSigner = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ additional_signer_ids: [WALLET_A_REVOKED_SIGNER_ID] }),
    });
    expect(revokedSigner.status).toBe(400);
    expect(((await revokedSigner.json()) as { error?: string }).error).toContain(
      "outside this account",
    );

    const missingPolicy = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ signer_policy_ids: ["policy_other_wallet"] }),
    });
    expect(missingPolicy.status).toBe(400);
    expect(((await missingPolicy.json()) as { error?: string }).error).toContain(
      "policy outside this account",
    );

    const staleSignerAfterWalletReplacement = await app.request(
      "/accounts/acct_authorization_assignments",
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ wallet_ids: [WALLET_B] }),
      },
    );
    expect(staleSignerAfterWalletReplacement.status).toBe(400);
    expect(
      ((await staleSignerAfterWalletReplacement.json()) as { error?: string }).error,
    ).toContain("outside this account");

    const nonMemberOwner = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_user_ids: [crypto.randomUUID()] }),
    });
    expect(nonMemberOwner.status).toBe(400);
    expect(((await nonMemberOwner.json()) as { error?: string }).error).toContain(
      "not an active tenant member",
    );

    const deactivatedUserId = crypto.randomUUID();
    await getDb()
      .insert(users)
      .values({
        id: deactivatedUserId,
        walletAddress: `0x${"12".repeat(20)}`,
        walletChain: "ethereum",
        deactivatedAt: new Date(),
      });
    await getDb()
      .insert(userTenants)
      .values({ userId: deactivatedUserId, tenantId: TENANT_ID, role: "member" });
    const deactivatedOwner = await app.request("/accounts/acct_authorization_assignments", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_user_ids: [deactivatedUserId] }),
    });
    expect(deactivatedOwner.status).toBe(400);
    expect(((await deactivatedOwner.json()) as { error?: string }).error).toContain(
      "not an active tenant member",
    );

    const cleanup = await app.request("/accounts/acct_authorization_assignments", {
      method: "DELETE",
    });
    expect(cleanup.status).toBe(200);
  });

  it("provisions configured wallets and stores only requested chain memberships", async () => {
    const response = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_configured_wallets",
        wallets_configuration: [
          { chain_type: "ethereum", wallet_id: "acct_configured_evm", name: "Account EVM" },
          { chain_type: "solana", wallet_id: "acct_configured_sol", name: "Account Solana" },
        ],
      }),
    });
    const responseBody = await response.clone().json();
    expect(response.status, JSON.stringify(responseBody)).toBe(201);
    const body = responseBody as {
      data: { wallet_ids: string[]; wallets: Array<{ walletId: string; chainFamily: string }> };
    };
    expect(new Set(body.data.wallet_ids)).toEqual(
      new Set(["acct_configured_evm", "acct_configured_sol"]),
    );
    expect(body.data.wallets).toHaveLength(2);
    expect(body.data.wallets.map((wallet) => wallet.chainFamily).sort()).toEqual(["evm", "solana"]);

    const memberships = await getDb()
      .select({
        walletAgentId: digitalAssetAccountWallets.walletAgentId,
        chainFamily: digitalAssetAccountWallets.chainFamily,
      })
      .from(digitalAssetAccountWallets)
      .where(
        and(
          eq(digitalAssetAccountWallets.tenantId, TENANT_ID),
          eq(digitalAssetAccountWallets.accountId, "acct_configured_wallets"),
        ),
      );
    expect(memberships).toEqual([
      { walletAgentId: "acct_configured_evm", chainFamily: "evm" },
      { walletAgentId: "acct_configured_sol", chainFamily: "solana" },
    ]);
  });

  it("serializes Bitcoin account metadata without private key material", async () => {
    const response = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_bitcoin_metadata",
        wallet_ids: [WALLET_BTC],
      }),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      data: {
        wallets: Array<{
          chainFamily: string;
          capabilities: string[];
          capabilityMetadata: { operations: { exportPrivateKey: boolean } };
          metadata: { bitcoin?: Record<string, unknown> };
        }>;
      };
    };
    const serialized = JSON.stringify(body.data);
    expect(body.data.wallets[0]).toMatchObject({
      chainFamily: "bitcoin",
      capabilities: [],
      capabilityMetadata: { operations: { exportPrivateKey: false } },
      metadata: {
        bitcoin: {
          network: "testnet",
          addressType: "p2wpkh",
          path: "m/84'/1'/0'/0/0",
        },
      },
    });
    expect(serialized).not.toContain("privateKey");
    expect(serialized).not.toContain("mnemonic");
    expect(serialized).not.toContain(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
  });

  it("rolls back account field updates when membership replacement fails", async () => {
    const owner = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_conflict_owner",
        display_name: "Conflict owner",
        wallet_ids: [WALLET_B],
      }),
    });
    expect(owner.status).toBe(201);

    const victim = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_conflict_victim",
        display_name: "Original victim",
        metadata: { version: 1 },
        wallet_ids: [WALLET_A],
      }),
    });
    expect(victim.status).toBe(201);

    const patch = await app.request("/accounts/acct_conflict_victim", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        display_name: "Should not persist",
        metadata: { version: 2 },
        wallet_ids: [WALLET_B],
      }),
    });
    expect(patch.status).toBe(400);

    const get = await app.request("/accounts/acct_conflict_victim");
    expect(get.status).toBe(200);
    const body = (await get.json()) as {
      data: { display_name: string; metadata: Record<string, unknown>; wallet_ids: string[] };
    };
    expect(body.data.display_name).toBe("Original victim");
    expect(body.data.metadata).toEqual({ version: 1 });
    expect(body.data.wallet_ids).toEqual([WALLET_A]);

    expect((await app.request("/accounts/acct_conflict_victim", { method: "DELETE" })).status).toBe(
      200,
    );
    expect((await app.request("/accounts/acct_conflict_owner", { method: "DELETE" })).status).toBe(
      200,
    );
  });

  it("persists account aggregation resources as snapshots of account wallet membership", async () => {
    const createAccount = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_aggregation_source",
        display_name: "Aggregation Source",
        wallet_ids: [WALLET_A],
      }),
    });
    expect(createAccount.status).toBe(201);

    const createAggregation = await app.request("/accounts/acct_aggregation_source/aggregations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_agg_snapshot",
        display_name: "Daily snapshot",
        metadata: { window: "day" },
      }),
    });
    expect(createAggregation.status).toBe(201);
    const created = (await createAggregation.json()) as {
      data: {
        id: string;
        account_id: string;
        display_name: string;
        wallet_ids: string[];
        chain_families: string[];
        metadata: Record<string, unknown>;
      };
    };
    expect(created.data).toMatchObject({
      id: "acct_agg_snapshot",
      account_id: "acct_aggregation_source",
      display_name: "Daily snapshot",
      metadata: { window: "day" },
    });
    expect(created.data.wallet_ids).toEqual([WALLET_A]);
    expect(created.data.chain_families.sort()).toEqual(["evm", "solana"]);

    const list = await app.request("/accounts/acct_aggregation_source/aggregations");
    expect(list.status).toBe(200);
    const listed = (await list.json()) as { data: { aggregations: Array<{ id: string }> } };
    expect(listed.data.aggregations.map((aggregation) => aggregation.id)).toContain(
      "acct_agg_snapshot",
    );

    await app.request("/accounts/acct_aggregation_source", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ wallet_ids: [WALLET_B] }),
    });
    const getSnapshot = await app.request(
      "/accounts/acct_aggregation_source/aggregations/acct_agg_snapshot",
    );
    expect(getSnapshot.status).toBe(200);
    const snapshot = (await getSnapshot.json()) as { data: { wallet_ids: string[] } };
    expect(snapshot.data.wallet_ids).toEqual([WALLET_A]);

    const deleted = await app.request(
      "/accounts/acct_aggregation_source/aggregations/acct_agg_snapshot",
      { method: "DELETE" },
    );
    expect(deleted.status).toBe(200);
    expect(
      (await app.request("/accounts/acct_aggregation_source/aggregations/acct_agg_snapshot"))
        .status,
    ).toBe(404);
  });

  it("rejects unknown wallets, over-cap memberships, and cross-tenant reads", async () => {
    const unknown = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "acct_unknown", wallet_ids: ["missing-wallet"] }),
    });
    expect(unknown.status).toBe(400);
    expect(((await unknown.json()) as { error: string }).error).toContain("Unknown wallet_ids");

    const tooMany = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_too_many",
        wallets_configuration: [
          { chain_type: "ethereum", wallet_id: "acct_cap_1" },
          { chain_type: "ethereum", wallet_id: "acct_cap_2" },
          { chain_type: "ethereum", wallet_id: "acct_cap_3" },
          { chain_type: "ethereum", wallet_id: "acct_cap_4" },
          { chain_type: "ethereum", wallet_id: "acct_cap_5" },
          { chain_type: "ethereum", wallet_id: "acct_cap_6" },
        ],
      }),
    });
    expect(tooMany.status).toBe(400);
    expect(((await tooMany.json()) as { error: string }).error).toContain("at most 5");

    await getDb().insert(digitalAssetAccounts).values({
      id: "acct_other_tenant",
      tenantId: OTHER_TENANT_ID,
      displayName: "Other",
      metadata: {},
    });
    const otherTenantApp = await makeApp(OTHER_TENANT_ID);
    expect((await otherTenantApp.request("/accounts/acct_other_tenant")).status).toBe(200);
    expect((await app.request("/accounts/acct_other_tenant")).status).toBe(404);
  });

  it("keeps capability metadata tenant scoped", async () => {
    const otherTenantApp = await makeApp(OTHER_TENANT_ID);
    const create = await otherTenantApp.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "acct_other_capabilities", wallet_ids: [OTHER_WALLET] }),
    });
    expect(create.status).toBe(201);

    const otherAccount = (await create.json()) as {
      data: {
        capabilities: string[];
        capabilityMetadata: {
          walletIds: string[];
          hasActiveDelegatedSigners: boolean;
          hasActiveKeyQuorums: boolean;
        };
        wallets: Array<{
          walletId: string;
          signing: { activeSignerCount: number; activeQuorumCount: number };
          capabilityMetadata: { signing: { activeSignerCount: number; activeQuorumCount: number } };
        }>;
      };
    };
    expect(otherAccount.data.capabilityMetadata).toMatchObject({
      walletIds: [OTHER_WALLET],
      hasActiveDelegatedSigners: true,
      hasActiveKeyQuorums: true,
    });
    expect(otherAccount.data.wallets[0]).toMatchObject({
      walletId: OTHER_WALLET,
      signing: { activeSignerCount: 1, activeQuorumCount: 1 },
      capabilityMetadata: { signing: { activeSignerCount: 1, activeQuorumCount: 1 } },
    });
    expect(otherAccount.data.capabilities).toContain("sign_typed_data");

    expect((await app.request("/accounts/acct_other_capabilities")).status).toBe(404);
    expect((await app.request("/accounts/acct_other_capabilities/balance")).status).toBe(404);
  });

  it("keeps account aggregations tenant scoped and cascades them on account delete", async () => {
    await getDb().insert(digitalAssetAccounts).values({
      id: "acct_other_with_aggregation",
      tenantId: OTHER_TENANT_ID,
      displayName: "Other aggregation account",
      metadata: {},
    });
    await getDb().insert(digitalAssetAccountAggregations).values({
      id: "acct_agg_other",
      tenantId: OTHER_TENANT_ID,
      accountId: "acct_other_with_aggregation",
      displayName: "Other aggregation",
      walletAgentIds: [],
      chainFamilies: [],
      metadata: {},
    });
    expect(
      (await app.request("/accounts/acct_other_with_aggregation/aggregations/acct_agg_other"))
        .status,
    ).toBe(404);

    const account = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "acct_delete_cascade", wallet_ids: [WALLET_A] }),
    });
    expect(account.status).toBe(201);
    const aggregation = await app.request("/accounts/acct_delete_cascade/aggregations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: "acct_agg_delete_cascade" }),
    });
    expect(aggregation.status).toBe(201);
    expect((await app.request("/accounts/acct_delete_cascade", { method: "DELETE" })).status).toBe(
      200,
    );
    const rows = await getDb()
      .select({ id: digitalAssetAccountAggregations.id })
      .from(digitalAssetAccountAggregations)
      .where(eq(digitalAssetAccountAggregations.id, "acct_agg_delete_cascade"));
    expect(rows).toHaveLength(0);
  });

  it("cleans up configured wallet agents when account creation fails", async () => {
    await getDb().insert(digitalAssetAccounts).values({
      id: "acct_cleanup_duplicate",
      tenantId: TENANT_ID,
      displayName: "Existing",
      metadata: {},
    });

    const response = await app.request("/accounts", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        id: "acct_cleanup_duplicate",
        wallets_configuration: [
          {
            chain_type: "ethereum",
            wallet_id: "acct_cleanup_orphan_candidate",
            name: "Should Be Rolled Back",
          },
        ],
      }),
    });

    expect(response.status).toBe(400);
    const orphaned = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(and(eq(agents.tenantId, TENANT_ID), eq(agents.id, "acct_cleanup_orphan_candidate")));
    expect(orphaned).toHaveLength(0);
  });
});
