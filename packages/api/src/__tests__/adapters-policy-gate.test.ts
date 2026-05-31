/**
 * Asserts the fund-moving adapter routes run the SAME policy/spend gate the
 * trade route uses BEFORE returning any signable artifact, and that non-fund
 * read endpoints + the custodial signer behave fail-closed.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenantAppClients, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
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
  const { adapterRoutes } = adapterRoutesModule;
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("tenantRole", "owner");
    c.set("authType", "api-key");
    if (options?.userId) c.set("userId", options.userId);
    await next();
  });
  app.route("/adapters", adapterRoutes);
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
});
