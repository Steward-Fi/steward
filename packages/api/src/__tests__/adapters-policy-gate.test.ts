/**
 * Asserts the fund-moving adapter routes run the SAME policy/spend gate the
 * trade route uses BEFORE returning any signable artifact, and that non-fund
 * read endpoints + the custodial signer behave fail-closed.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenantAppClients, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { initRedis } from "../middleware/redis";
import type { AppVariables } from "../services/context";

let adapterRoutesModule: Awaited<typeof import("../routes/adapters")>;

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
  // Audit writes require an HMAC key; set a sufficiently-strong one for tests.
  process.env.STEWARD_AUDIT_HMAC_KEY ??=
    "adapters-policy-gate-test-audit-hmac-key-0123456789abcdef";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  // The fund-moving spend gate (enforceFundMovingPolicy → checkAgentSpendLimit)
  // fails CLOSED when Redis is *configured* (REDIS_URL set in this env) but the
  // process never connected. Without an explicit connect, redisAvailable stays
  // false and every "within caps" build would be wrongly denied with a 400
  // "daily-spend-cap ... fail-closed" reason. The merged environment runs a real
  // Redis, so connect to it here; fresh per-test agent ids start at spent=0, so
  // the daily-cap evaluator passes and only the per-op cap distinguishes
  // allow/deny — exactly what these assertions exercise.
  await initRedis();
  adapterRoutesModule = await import("../routes/adapters");
}, 120_000);

afterAll(async () => {
  await closeDb();
});

const AGENT_WALLET = "0x1111111111111111111111111111111111111111";
const USER_1 = "00000000-0000-4000-8000-000000000001";
const USER_EXCHANGE = "00000000-0000-4000-8000-000000000002";
const FOREIGN_USER = "00000000-0000-4000-8000-000000000003";
const EXCHANGE_RETURN_URL = "https://app.example.com/exchange/callback";
const USDC = { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 };
const WETH = {
  address: "0x4200000000000000000000000000000000000006",
  symbol: "WETH",
  decimals: 18,
};

async function makeApp(tenantId: string, options?: { userId?: string }) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "Adapter Test Tenant", apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
  await getDb()
    .insert(users)
    .values([
      { id: USER_1, email: "adapter-user-1@example.test" },
      { id: USER_EXCHANGE, email: "adapter-exchange@example.test" },
      { id: FOREIGN_USER, email: "adapter-foreign@example.test" },
    ])
    .onConflictDoNothing();
  await getDb()
    .insert(userTenants)
    .values([
      { tenantId, userId: USER_1, role: "member" },
      { tenantId, userId: USER_EXCHANGE, role: "member" },
    ])
    .onConflictDoNothing();
  await getDb()
    .insert(tenantAppClients)
    .values({
      id: "adapter-test-client",
      tenantId,
      name: "Adapter Test Client",
      enabled: true,
      allowedRedirectUrls: [EXCHANGE_RETURN_URL],
    })
    .onConflictDoNothing();
  // The fund-moving adapter routes resolve + ownership-check the named agent
  // (resolveAgentId → ensureAgentForTenant), so the agent must exist under this
  // tenant or the route fails closed with 404. Seed it like the real flow would.
  // agents.id is a global PK, so the id is tenant-scoped to stay unique across
  // the per-test tenants this helper is called with.
  const agentId = `agent-${tenantId}`;
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId,
      name: "Adapter Test Agent",
      walletAddress: AGENT_WALLET,
    })
    .onConflictDoNothing();
  const { adapterRoutes, fiatRoutes } = adapterRoutesModule;
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("tenantRole", "owner");
    c.set("authType", "api-key");
    if (options?.userId) c.set("userId", options.userId);
    await next();
  });
  app.route("/adapters", adapterRoutes);
  app.route("/v1/users", fiatRoutes);
  return { app, agentId };
}

describe("adapter fund-moving policy gate", () => {
  it("DENIES a swap build when the estimated notional exceeds the per-op cap", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "100";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "1000";
    const { app, agentId } = await makeApp(`tenant-adapter-deny-${Date.now()}`);

    // Get a real quote first.
    const quoteRes = await app.request("/adapters/swap/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        fromToken: USDC,
        toToken: WETH,
        amount: "1000000",
        chainId: 8453,
      }),
    });
    expect(quoteRes.status).toBe(200);
    const { data } = (await quoteRes.json()) as { data: { quote: unknown } };

    // Build with an estimate ABOVE the per-op cap -> must be policy-rejected.
    const buildRes = await app.request("/adapters/swap/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        agentAddress: AGENT_WALLET,
        quote: data.quote,
        estimatedUsd: 5000,
      }),
    });
    expect(buildRes.status).toBe(400);
    const body = (await buildRes.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    // The denial must NOT include any signable artifact.
    expect((body as Record<string, unknown>).unsignedIntent).toBeUndefined();
  });

  it("ALLOWS a swap build within caps and returns an UNSIGNED intent", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "100000";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "1000000";
    const { app, agentId } = await makeApp(`tenant-adapter-allow-${Date.now()}`);

    const quoteRes = await app.request("/adapters/swap/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        fromToken: USDC,
        toToken: WETH,
        amount: "1000000",
        chainId: 8453,
      }),
    });
    const { data } = (await quoteRes.json()) as { data: { quote: unknown } };

    const buildRes = await app.request("/adapters/swap/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        agentAddress: AGENT_WALLET,
        quote: data.quote,
        estimatedUsd: 250,
      }),
    });
    expect(buildRes.status).toBe(200);
    const body = (await buildRes.json()) as {
      ok: boolean;
      data: { unsignedIntent: { signed: boolean; category: string } };
    };
    expect(body.ok).toBe(true);
    expect(body.data.unsignedIntent.signed).toBe(false);
    expect(body.data.unsignedIntent.category).toBe("swap");
  });

  it("DENIES an earn deposit above cap (gate applies to all fund-moving ops)", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "10";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "100";
    const { app, agentId } = await makeApp(`tenant-adapter-earn-${Date.now()}`);

    const res = await app.request("/adapters/earn/deposit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        vault: "0x4626000000000000000000000000000000000001",
        assets: "1050",
        owner: AGENT_WALLET,
        estimatedUsd: 5000,
      }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string };
    expect(body.code).toBe("policy-violation");
  });

  it("ALLOWS a bridge build within caps and returns an UNSIGNED intent", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "100000";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "1000000";
    const { app, agentId } = await makeApp(`tenant-adapter-bridge-${Date.now()}`);

    const quoteRes = await app.request("/adapters/bridge/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        fromChainId: 8453,
        toChainId: 42161,
        fromToken: USDC,
        toToken: WETH,
        amount: "1000000",
        recipient: AGENT_WALLET,
      }),
    });
    expect(quoteRes.status).toBe(200);
    const { data } = (await quoteRes.json()) as { data: { quote: unknown } };

    const buildRes = await app.request("/adapters/bridge/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        owner: AGENT_WALLET,
        quote: data.quote,
        estimatedUsd: 250,
      }),
    });
    expect(buildRes.status).toBe(200);
    const body = (await buildRes.json()) as {
      ok: boolean;
      data: {
        unsignedIntent: { signed: boolean; category: string; metadata: { toChainId: number } };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.unsignedIntent.signed).toBe(false);
    expect(body.data.unsignedIntent.category).toBe("bridge");
    expect(body.data.unsignedIntent.metadata.toChainId).toBe(42161);
  });

  it("DENIES a bridge build above cap before returning a signable artifact", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "10";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "100";
    const { app, agentId } = await makeApp(`tenant-adapter-bridge-deny-${Date.now()}`);

    const quoteRes = await app.request("/adapters/bridge/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        fromChainId: 8453,
        toChainId: 42161,
        fromToken: USDC,
        toToken: WETH,
        amount: "1000000",
        recipient: AGENT_WALLET,
      }),
    });
    const { data } = (await quoteRes.json()) as { data: { quote: unknown } };

    const buildRes = await app.request("/adapters/bridge/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        owner: AGENT_WALLET,
        quote: data.quote,
        estimatedUsd: 5000,
      }),
    });
    expect(buildRes.status).toBe(400);
    const body = (await buildRes.json()) as Record<string, unknown>;
    expect(body.code).toBe("policy-violation");
    expect(body.unsignedIntent).toBeUndefined();
  });

  it("creates Spark BTC/Lightning mock DTOs and reads wallet balance", async () => {
    const { app } = await makeApp(`tenant-adapter-spark-dtos-${Date.now()}`);

    const walletRes = await app.request("/adapters/spark/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, network: "testnet", label: "primary" }),
    });
    expect(walletRes.status).toBe(201);
    expect(walletRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const walletBody = (await walletRes.json()) as {
      data: { wallet: { id: string; provider: string; sparkAddress: string } };
    };
    expect(walletBody.data.wallet.provider).toBe("mock");
    expect(walletBody.data.wallet.sparkAddress).toMatch(/^spk_testnet_/);

    const balanceRes = await app.request(
      `/adapters/spark/wallets/${walletBody.data.wallet.id}/balance`,
    );
    expect(balanceRes.status).toBe(200);
    const balanceBody = (await balanceRes.json()) as {
      data: { balance: { btcSats: string; lightningSats: string } };
    };
    expect(balanceBody.data.balance.btcSats).toBe("0");
    expect(balanceBody.data.balance.lightningSats).toBe("0");

    const depositRes = await app.request("/adapters/spark/static-btc-deposits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletId: walletBody.data.wallet.id, amountSats: "1000" }),
    });
    expect(depositRes.status).toBe(201);
    const depositBody = (await depositRes.json()) as {
      data: { quote: { depositAddress: string; status: string } };
    };
    expect(depositBody.data.quote.depositAddress).toMatch(/^tb1q/);
    expect(depositBody.data.quote.status).toBe("created");

    const invoiceRes = await app.request("/adapters/spark/lightning/invoices", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        walletId: walletBody.data.wallet.id,
        amountSats: "2500",
        memo: "coffee",
      }),
    });
    expect(invoiceRes.status).toBe(201);
    const invoiceBody = (await invoiceRes.json()) as {
      data: { invoice: { paymentRequest: string; status: string } };
    };
    expect(invoiceBody.data.invoice.paymentRequest).toMatch(/^lntb/);
    expect(invoiceBody.data.invoice.status).toBe("created");
  });

  it("DENIES Spark transfers above cap before returning a signable artifact", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "10";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "100";
    const { app, agentId } = await makeApp(`tenant-adapter-spark-deny-${Date.now()}`);

    const walletRes = await app.request("/adapters/spark/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, network: "testnet" }),
    });
    const walletBody = (await walletRes.json()) as { data: { wallet: { id: string } } };

    const transferRes = await app.request("/adapters/spark/transfers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        walletId: walletBody.data.wallet.id,
        recipient: "spk_testnet_recipient_123456",
        amountSats: "1000",
        estimatedUsd: 5000,
      }),
    });
    expect(transferRes.status).toBe(400);
    const body = (await transferRes.json()) as Record<string, unknown>;
    expect(body.code).toBe("policy-violation");
    expect(body.unsignedIntent).toBeUndefined();
  });

  it("ALLOWS Spark transfer and Lightning pay builds within caps as UNSIGNED intents", async () => {
    process.env.STEWARD_ADAPTER_PER_OP_CAP_USD = "100000";
    process.env.STEWARD_ADAPTER_DAILY_CAP_USD = "1000000";
    const { app, agentId } = await makeApp(`tenant-adapter-spark-allow-${Date.now()}`);

    const walletRes = await app.request("/adapters/spark/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, network: "testnet" }),
    });
    const walletBody = (await walletRes.json()) as { data: { wallet: { id: string } } };

    const transferRes = await app.request("/adapters/spark/transfers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        walletId: walletBody.data.wallet.id,
        recipient: "spk_testnet_recipient_123456",
        amountSats: "1000",
        estimatedUsd: 5,
      }),
    });
    expect(transferRes.status).toBe(200);
    const transferBody = (await transferRes.json()) as {
      data: {
        unsignedIntent: {
          signed: boolean;
          kind: string;
          category: string;
          owner: string;
          metadata: { operation: string };
        };
      };
    };
    expect(transferBody.data.unsignedIntent.signed).toBe(false);
    expect(transferBody.data.unsignedIntent.kind).toBe("abstract-intent");
    expect(transferBody.data.unsignedIntent.category).toBe("spark");
    expect(transferBody.data.unsignedIntent.owner).toBe(agentId);
    expect(transferBody.data.unsignedIntent.metadata.operation).toBe("spark.transfer");

    const payRes = await app.request("/adapters/spark/lightning/pay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        walletId: walletBody.data.wallet.id,
        paymentRequest: "lntb2500n1mockinvoice",
        maxFeeSats: "10",
        estimatedUsd: 5,
      }),
    });
    expect(payRes.status).toBe(200);
    const payBody = (await payRes.json()) as {
      data: { unsignedIntent: { signed: boolean; metadata: { operation: string } } };
    };
    expect(payBody.data.unsignedIntent.signed).toBe(false);
    expect(payBody.data.unsignedIntent.metadata.operation).toBe("spark.lightning.pay");
  });

  it("Spark identity signing fails closed with 501 and NEVER returns a signature", async () => {
    const { app } = await makeApp(`tenant-adapter-spark-sign-${Date.now()}`);
    const walletRes = await app.request("/adapters/spark/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, network: "testnet" }),
    });
    const walletBody = (await walletRes.json()) as { data: { wallet: { id: string } } };

    const signRes = await app.request("/adapters/spark/identity/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ walletId: walletBody.data.wallet.id, payload: "0xdeadbeef" }),
    });
    expect(signRes.status).toBe(501);
    const body = (await signRes.json()) as Record<string, unknown>;
    expect(body.signature).toBeUndefined();
    expect(body.ok).toBe(false);
    expect(String(body.error)).toContain("mock never holds keys");
  });

  it("custodial sign endpoint fails closed with 501 and NEVER returns a signature", async () => {
    const { app } = await makeApp(`tenant-adapter-cust-${Date.now()}`);
    const createRes = await app.request("/adapters/custodial/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, chain: "evm" }),
    });
    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as { data: { wallet: { id: string } } };

    const signRes = await app.request(
      `/adapters/custodial/wallets/${created.data.wallet.id}/sign`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload: "0xdeadbeef", scheme: "evm-personal" }),
      },
    );
    expect(signRes.status).toBe(501);
    const body = (await signRes.json()) as Record<string, unknown>;
    expect(body.signature).toBeUndefined();
    expect(body.ok).toBe(false);
  });

  it("exchange embed creates sessions, lists/revokes links, and refuses mock order placement", async () => {
    const { app } = await makeApp(`tenant-adapter-exchange-${Date.now()}`);
    const createRes = await app.request("/adapters/exchange/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: USER_EXCHANGE,
        provider: "kraken",
        returnUrl: EXCHANGE_RETURN_URL,
        scopes: ["account:read", "trade:read"],
      }),
    });
    expect(createRes.status).toBe(201);
    expect(createRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const created = (await createRes.json()) as {
      data: { session: { id: string; url: string } };
    };
    expect(created.data.session.url).toContain("https://mock.exchange.local/embed/");

    const accountsRes = await app.request(`/adapters/exchange/accounts?userId=${USER_EXCHANGE}`);
    expect(accountsRes.status).toBe(200);
    const accountsBody = (await accountsRes.json()) as {
      data: { accounts: Array<{ id: string; status: string }> };
    };
    expect(accountsBody.data.accounts).toHaveLength(1);
    expect(accountsBody.data.accounts[0].status).toBe("linked");

    const revokeRes = await app.request(
      `/adapters/exchange/accounts/${accountsBody.data.accounts[0].id}`,
      { method: "DELETE" },
    );
    expect(revokeRes.status).toBe(200);
    const revoked = (await revokeRes.json()) as { data: { account: { status: string } } };
    expect(revoked.data.account.status).toBe("revoked");

    const orderRes = await app.request("/adapters/exchange/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ symbol: "ETH/USD", side: "buy", amount: "1" }),
    });
    expect(orderRes.status).toBe(501);
    const orderBody = (await orderRes.json()) as { ok: boolean; error?: string };
    expect(orderBody.ok).toBe(false);
    expect(orderBody.error).toContain("Exchange order placement is not available");
  });

  it("DENIES adapter user resources across user and tenant boundaries", async () => {
    const tenantId = `tenant-adapter-boundary-${Date.now()}`;
    const { app, agentId } = await makeApp(tenantId);

    const foreignCreate = await app.request("/adapters/kyc/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: FOREIGN_USER, level: "basic" }),
    });
    expect(foreignCreate.status).toBe(404);

    const kycRes = await app.request("/adapters/kyc/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, level: "basic" }),
    });
    expect(kycRes.status).toBe(201);
    const kyc = (await kycRes.json()) as { data: { verification: { id: string } } };

    const walletRes = await app.request("/adapters/custodial/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, chain: "evm" }),
    });
    expect(walletRes.status).toBe(201);
    const wallet = (await walletRes.json()) as { data: { wallet: { id: string } } };

    const quoteRes = await app.request("/adapters/bridge/quote", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        fromChainId: 8453,
        toChainId: 42161,
        fromToken: USDC,
        toToken: WETH,
        amount: "1000000",
        recipient: AGENT_WALLET,
      }),
    });
    expect(quoteRes.status).toBe(200);
    const quoteBody = (await quoteRes.json()) as { data: { quote: unknown } };
    const bridgeSessionRes = await app.request("/adapters/bridge/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, quote: quoteBody.data.quote }),
    });
    expect(bridgeSessionRes.status).toBe(201);
    expect(bridgeSessionRes.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    const bridgeSession = (await bridgeSessionRes.json()) as { data: { session: { id: string } } };

    const userApp = (await makeApp(tenantId, { userId: USER_EXCHANGE })).app;
    const foreignKycRead = await userApp.request(
      `/adapters/kyc/verifications/${kyc.data.verification.id}`,
    );
    expect(foreignKycRead.status).toBe(403);

    const foreignWalletRead = await userApp.request(
      `/adapters/custodial/wallets/${wallet.data.wallet.id}`,
    );
    expect(foreignWalletRead.status).toBe(403);

    const foreignBridgeRead = await userApp.request(
      `/adapters/bridge/sessions/${bridgeSession.data.session.id}`,
    );
    expect(foreignBridgeRead.status).toBe(403);
  });

  it("DENIES exchange return URLs outside tenant app-client allowlists", async () => {
    const { app } = await makeApp(`tenant-adapter-return-url-${Date.now()}`);

    const createRes = await app.request("/adapters/exchange/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: USER_EXCHANGE,
        provider: "kraken",
        returnUrl: "https://evil.example.com/exchange/callback",
        scopes: ["account:read"],
      }),
    });
    expect(createRes.status).toBe(400);
    const body = (await createRes.json()) as { error?: string };
    expect(body.error).toContain("returnUrl is not allowed");
  });

  it("KYC document submission audits the HASH and never echoes raw content", async () => {
    const { app } = await makeApp(`tenant-adapter-kyc-${Date.now()}`);
    const startRes = await app.request("/adapters/kyc/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: USER_1, level: "basic" }),
    });
    expect(startRes.status).toBe(201);
    const started = (await startRes.json()) as { data: { verification: { id: string } } };

    const secret = "RAW-SSN-123-45-6789";
    const contentBase64 = Buffer.from(secret, "utf8").toString("base64");
    const docRes = await app.request(
      `/adapters/kyc/verifications/${started.data.verification.id}/documents`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ documentType: "ssn", contentBase64 }),
      },
    );
    expect(docRes.status).toBe(200);
    const raw = await docRes.text();
    expect(raw).not.toContain(secret);
    const body = JSON.parse(raw) as {
      data: { verification: { status: string; documents: { contentHash: string }[] } };
    };
    expect(body.data.verification.status).toBe("verified");
    expect(body.data.verification.documents[0].contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("exposes Privy-shaped fiat aliases without weakening user boundaries or PII handling", async () => {
    const { app } = await makeApp(`tenant-adapter-fiat-alias-${Date.now()}`);

    const foreignAccounts = await app.request(`/v1/users/${FOREIGN_USER}/fiat/accounts`);
    expect(foreignAccounts.status).toBe(404);

    const accounts = await app.request(`/v1/users/${USER_1}/fiat/accounts`);
    expect(accounts.status).toBe(200);
    expect(accounts.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    await expect(accounts.json()).resolves.toMatchObject({ ok: true, data: { accounts: [] } });

    const createAccount = await app.request(`/v1/users/${USER_1}/fiat/accounts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "mock" }),
    });
    expect(createAccount.status).toBe(501);

    const kycLink = await app.request(`/v1/users/${USER_1}/fiat/kyc_link`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ level: "basic" }),
    });
    expect(kycLink.status).toBe(201);
    const kycLinkBody = (await kycLink.json()) as {
      data: { verification: { id: string }; kycLink: string };
    };
    expect(kycLinkBody.data.kycLink).toContain(kycLinkBody.data.verification.id);

    const secret = "PASSPORT-RAW-CONTENT";
    const patchKyc = await app.request(`/v1/users/${USER_1}/fiat/kyc`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        verificationId: kycLinkBody.data.verification.id,
        documentType: "passport",
        contentBase64: Buffer.from(secret, "utf8").toString("base64"),
      }),
    });
    expect(patchKyc.status).toBe(200);
    const patchKycText = await patchKyc.text();
    expect(patchKycText).not.toContain(secret);
    expect(JSON.parse(patchKycText).data.verification.documents[0].contentHash).toMatch(
      /^[0-9a-f]{64}$/,
    );

    const onramp = await app.request(`/v1/users/${USER_1}/fiat/onramp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fiatCurrency: "USD",
        fiatAmount: 100,
        cryptoAsset: "ETH",
        chainId: 8453,
        destinationAddress: AGENT_WALLET,
      }),
    });
    expect(onramp.status).toBe(201);
    const onrampBody = (await onramp.json()) as { data: { session: { id: string } } };
    const onrampRead = await app.request(
      `/v1/users/${USER_1}/fiat/onramp/${onrampBody.data.session.id}`,
    );
    expect(onrampRead.status).toBe(200);

    const offramp = await app.request(`/v1/users/${USER_1}/fiat/offramp`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cryptoAsset: "ETH",
        cryptoAmount: "1000000000000000000",
        chainId: 8453,
        fiatCurrency: "USD",
        payoutMethodId: "pm_mock",
      }),
    });
    expect(offramp.status).toBe(201);
    const offrampBody = (await offramp.json()) as { data: { session: { id: string } } };
    const foreignOfframpRead = await app.request(
      `/v1/users/${USER_EXCHANGE}/fiat/offramp/${offrampBody.data.session.id}`,
    );
    expect(foreignOfframpRead.status).toBe(404);
  });
});
