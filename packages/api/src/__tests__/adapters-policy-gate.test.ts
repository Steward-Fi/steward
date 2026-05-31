/**
 * Asserts the fund-moving adapter routes run the SAME policy/spend gate the
 * trade route uses BEFORE returning any signable artifact, and that non-fund
 * read endpoints + the custodial signer behave fail-closed.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

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
});

afterAll(async () => {
  await closeDb();
});

const AGENT_WALLET = "0x1111111111111111111111111111111111111111";
const USDC = { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 };
const WETH = {
  address: "0x4200000000000000000000000000000000000006",
  symbol: "WETH",
  decimals: 18,
};

async function makeApp(tenantId: string) {
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "Adapter Test Tenant", apiKeyHash: `hash-${tenantId}` })
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
  const { adapterRoutes } = await import("../routes/adapters");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("tenantRole", "owner");
    c.set("authType", "api-key");
    c.set("userId", `${tenantId}-owner`);
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

  it("custodial sign endpoint fails closed with 501 and NEVER returns a signature", async () => {
    const { app } = await makeApp(`tenant-adapter-cust-${Date.now()}`);
    const createRes = await app.request("/adapters/custodial/wallets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: "user-1", chain: "evm" }),
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

  it("KYC document submission audits the HASH and never echoes raw content", async () => {
    const { app } = await makeApp(`tenant-adapter-kyc-${Date.now()}`);
    const startRes = await app.request("/adapters/kyc/verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: "user-1", level: "basic" }),
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
