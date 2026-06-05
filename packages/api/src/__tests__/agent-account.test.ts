import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, agentWallets, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `agent-account-tenant-${Date.now()}`;
const AGENT_ID = `agent-account-agent-${Date.now()}`;

setDefaultTimeout(30000);

async function makeApp() {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "api-key");
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent account API", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-account-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Agent Account Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Agent Account Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    await getDb()
      .insert(agentWallets)
      .values([
        {
          agentId: AGENT_ID,
          chainFamily: "evm",
          address: "0x1234567890123456789012345678901234567890",
          purpose: "primary",
        },
        {
          agentId: AGENT_ID,
          chainFamily: "solana",
          address: "7cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
          purpose: "primary",
        },
        {
          agentId: AGENT_ID,
          chainFamily: "bitcoin",
          address: "tb1q9x5p7m6d3l0q8s2e4r6t8y0u2i4o6p8a0s2d4f",
          purpose: "primary",
          venue: "bitcoin:testnet:p2wpkh:0:0:0",
          metadata: {
            bitcoin: {
              network: "testnet",
              addressType: "p2wpkh",
              path: "m/84'/1'/0'/0/0",
              publicKey: "0x" + "03".repeat(33),
              privateKey: "0x" + "bb".repeat(32),
              seedPhrase:
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
              account: 0,
              change: 0,
              index: 0,
              caip2: "bip122:000000000933ea01ad0ee984209779ba",
            },
          },
        },
      ]);
    await getDb()
      .insert(transactions)
      .values({
        id: `account-spend-${Date.now()}`,
        agentId: AGENT_ID,
        status: "confirmed",
        toAddress: "0x0000000000000000000000000000000000000001",
        value: "42",
        chainId: 8453,
        policyResults: [],
      });
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("returns an aggregated account without requiring live chain balance", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/account`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        id: string;
        agentId: string;
        tenantId: string;
        walletAddresses: { evm?: string; solana?: string; bitcoin?: string };
        wallets: Array<{
          chainFamily: string;
          address: string;
          purpose: string | null;
          metadata?: Record<string, unknown>;
        }>;
        balances: {
          evm: null | {
            native: string;
            chainId: number;
            walletAddress: string;
          };
          unavailableReason?: string;
        };
        portfolio: {
          chainId: number | null;
          walletAddress: string;
          native: null | {
            token: string;
            balance: string;
            usdPrice: number | null;
            usdValue: number | null;
            usdPriceText: string | null;
            usdValueText: string | null;
          };
          tokens: Array<{
            token: string;
            balance: string;
            usdPrice: number | null;
            usdValue: number | null;
            usdPriceText: string | null;
            usdValueText: string | null;
          }>;
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
    expect(body.data.id).toBe(AGENT_ID);
    expect(body.data.tenantId).toBe(TENANT_ID);
    expect(body.data.walletAddresses).toEqual({
      evm: "0x1234567890123456789012345678901234567890",
      solana: "7cV5Y7R3UKPqJb1x4yQzq8oZsVbGZ3h5m3NkQW2kUZmx",
      bitcoin: "tb1q9x5p7m6d3l0q8s2e4r6t8y0u2i4o6p8a0s2d4f",
    });
    expect(body.data.wallets.map((wallet) => wallet.chainFamily).sort()).toEqual([
      "bitcoin",
      "evm",
      "solana",
    ]);
    const serialized = JSON.stringify(body.data);
    expect(serialized).not.toContain("privateKey");
    expect(serialized).not.toContain("seedPhrase");
    expect(serialized).not.toContain(
      "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    if (body.data.balances.evm) {
      expect(body.data.balances.evm.walletAddress).toBe(
        "0x1234567890123456789012345678901234567890",
      );
      expect(typeof body.data.balances.evm.native).toBe("string");
    } else {
      expect(typeof body.data.balances.unavailableReason).toBe("string");
    }
    expect(body.data.portfolio.walletAddress).toBe("0x1234567890123456789012345678901234567890");
    expect(Array.isArray(body.data.portfolio.tokens)).toBe(true);
    if (body.data.portfolio.native) {
      expect(body.data.portfolio.native.token).toBe("native");
      expect(typeof body.data.portfolio.native.balance).toBe("string");
    } else {
      expect(typeof body.data.portfolio.unavailableReason).toBe("string");
    }
    expect(body.data.spend).toEqual({
      todayWei: "42",
      weekWei: "42",
      monthWei: "42",
    });
    expect(body.data.capabilities).toContain("sign_transaction");
    expect(body.data.capabilities).toContain("solana_transaction");
    expect(body.data.sponsorship).toEqual({
      enabled: false,
      provider: null,
      circuitBreakerEnabled: false,
    });
  });

  it("rejects invalid account portfolio query parameters before provider calls", async () => {
    const invalidChain = await app.request(`/agents/${AGENT_ID}/account?chainId=1abc`);
    expect(invalidChain.status).toBe(400);
    const invalidChainBody = (await invalidChain.json()) as { error?: string };
    expect(invalidChainBody.error).toContain("chainId");

    const invalidToken = await app.request(`/agents/${AGENT_ID}/account?tokens=0x1234`);
    expect(invalidToken.status).toBe(400);
    const invalidTokenBody = (await invalidToken.json()) as { error?: string };
    expect(invalidTokenBody.error).toContain("tokens");
  });

  it("returns token portfolio assets with best-effort USD values", async () => {
    const context = await import("../services/context");
    const originalGetBalance = context.vault.getBalance.bind(context.vault);
    const originalGetTokenBalances = context.vault.getTokenBalances.bind(context.vault);
    const originalNativePrice = context.priceOracle.getNativeUsdPrice.bind(context.priceOracle);
    const originalTokenPrice = context.priceOracle.getTokenUsdPrice.bind(context.priceOracle);
    const originalWeiToUsd = context.priceOracle.weiToUsd.bind(context.priceOracle);
    context.vault.getBalance = async () => ({
      native: 2_000000000000000000n,
      nativeFormatted: "2",
      chainId: 8453,
      symbol: "ETH",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    context.vault.getTokenBalances = async () => [
      {
        token: "0x1111111111111111111111111111111111111111",
        symbol: "USDC",
        balance: "1500000",
        formatted: "1.5",
        decimals: 6,
      },
    ];
    context.priceOracle.getNativeUsdPrice = async () => 3000;
    context.priceOracle.getTokenUsdPrice = async () => 1;
    context.priceOracle.weiToUsd = async (value, _chainId, token) =>
      token ? Number(value) / 1_000_000 : 6000;

    try {
      const response = await app.request(
        `/agents/${AGENT_ID}/account?chainId=8453&tokens=0x1111111111111111111111111111111111111111`,
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        data: {
          portfolio: {
            native: {
              usdPrice: number | null;
              usdValue: number | null;
              usdPriceText: string | null;
              usdValueText: string | null;
            } | null;
            tokens: Array<{
              symbol: string;
              usdPrice: number | null;
              usdValue: number | null;
              usdPriceText: string | null;
              usdValueText: string | null;
            }>;
            totalUsd: number | null;
            totalUsdText: string | null;
          };
        };
      };
      expect(body.data.portfolio.native?.usdPrice).toBe(3000);
      expect(body.data.portfolio.native?.usdValue).toBe(6000);
      expect(body.data.portfolio.native?.usdPriceText).toBe("3000");
      expect(body.data.portfolio.native?.usdValueText).toBe("6000");
      expect(body.data.portfolio.tokens).toEqual([
        expect.objectContaining({
          symbol: "USDC",
          usdPrice: 1,
          usdValue: 1.5,
          usdPriceText: "1",
          usdValueText: "1.5",
        }),
      ]);
      expect(body.data.portfolio.totalUsd).toBe(6001.5);
      expect(body.data.portfolio.totalUsdText).toBe("6001.5");
    } finally {
      context.vault.getBalance = originalGetBalance;
      context.vault.getTokenBalances = originalGetTokenBalances;
      context.priceOracle.getNativeUsdPrice = originalNativePrice;
      context.priceOracle.getTokenUsdPrice = originalTokenPrice;
      context.priceOracle.weiToUsd = originalWeiToUsd;
    }
  });
});
