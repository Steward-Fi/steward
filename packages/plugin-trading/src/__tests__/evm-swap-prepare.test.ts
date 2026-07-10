import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import {
  AdapterRegistry,
  type SwapAdapter,
  type SwapQuote,
  type SwapQuoteRequest,
} from "@stwd/adapters";
import { asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { StewardAppContext } from "../context";

// Set these before dynamically loading the API context. Bun may evaluate test
// files concurrently in one module graph, before any beforeAll hook runs.
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_DB_MODE = "pglite";
process.env.STEWARD_MASTER_PASSWORD = "evm-swap-master-password";
process.env.STEWARD_AUDIT_HMAC_KEY = "evm-swap-audit-hmac-key-with-enough-entropy";
process.env.STEWARD_PLATFORM_KEYS = "evm-swap-platform-key";

const TENANT_ID = "evm-swap-tenant";
const OTHER_TENANT_ID = "evm-swap-other-tenant";
const AGENT_ID = "evm-swap-agent";
const OTHER_AGENT_ID = "evm-swap-other-agent";
const SESSION_ID = "evm-swap-session";
const KID = "evm-swap-kid";
const PLATFORM_KEY = "evm-swap-platform-key";
const TARGET = "0x00000000000000000000000000000000000000bb";
const FROM_TOKEN = "0x00000000000000000000000000000000000000cc";
const TO_TOKEN = "0x00000000000000000000000000000000000000dd";
const SELECTOR = "0x12345678";
const CALLDATA = `${SELECTOR}${"0".repeat(63)}1`;

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;
let requireAgentJwt: typeof import("../../../api/src/middleware/agent-jwt")["requireAgentJwt"];
let clearAgentJwksCacheForTests: typeof import("../../../api/src/middleware/agent-jwt")["clearAgentJwksCacheForTests"];
let testCtx: () => StewardAppContext;
let tradingPlugin: typeof import("../index")["tradingPlugin"];
let createEvmSwapRoutes: typeof import("../routes/evm-swap")["createEvmSwapRoutes"];
let auditEvents: typeof import("@stwd/db")["auditEvents"];
let intents: typeof import("@stwd/db")["intents"];
let policies: typeof import("@stwd/db")["policies"];
let tenants: typeof import("@stwd/db")["tenants"];
let tradeSessions: typeof import("@stwd/db")["tradeSessions"];
let transactions: typeof import("@stwd/db")["transactions"];
let vaultSigningFreezes: typeof import("@stwd/db")["vaultSigningFreezes"];
let closeDb: typeof import("@stwd/db")["closeDb"];
let getDb: typeof import("@stwd/db")["getDb"];
let pgliteDb: ReturnType<typeof getDb>;
let agentWalletAddress: string;

class FakeSwapAdapter implements SwapAdapter {
  readonly category = "swap" as const;
  readonly provider = "fake";
  readonly enabled = true;
  quoteCalls = 0;
  buildCalls = 0;
  target = TARGET;
  data = CALLDATA;
  value = "0";
  chainId: number | null = null;
  mutateOwner = false;
  mutateQuoteId = false;
  mutateQuoteFromToken = false;
  mutateQuoteToToken = false;
  mutateQuoteAmount = false;
  expireQuote = false;
  failUnavailable = false;
  observedTaker: string | undefined;

  async getQuote(request: SwapQuoteRequest): Promise<SwapQuote> {
    this.quoteCalls += 1;
    this.observedTaker = request.taker;
    if (this.failUnavailable) {
      const { AdapterUnavailableError } = await import("@stwd/adapters");
      throw new AdapterUnavailableError("swap", "recorded provider failure");
    }
    return {
      provider: this.provider,
      fromToken: this.mutateQuoteFromToken
        ? { ...request.fromToken, address: "0x00000000000000000000000000000000000000ef" }
        : request.fromToken,
      toToken: this.mutateQuoteToToken
        ? { ...request.toToken, address: "0x00000000000000000000000000000000000000ef" }
        : request.toToken,
      chainId: this.chainId ?? request.chainId,
      amountIn: this.mutateQuoteAmount ? "999" : request.amount,
      amountOut: request.amount,
      minAmountOut: request.amount,
      route: [
        { venue: "fake", fromToken: request.fromToken.address, toToken: request.toToken.address },
      ],
      feeAmount: "0",
      slippageBps: request.slippageBps ?? 50,
      expiresAt: this.expireQuote ? Date.now() - 1 : Date.now() + 60_000,
      quoteId: `quote-${request.chainId}-${request.amount}`,
    };
  }

  async buildSwap(quote: SwapQuote, agentAddress: string) {
    this.buildCalls += 1;
    return {
      signed: false,
      kind: "evm-tx" as const,
      chainId: quote.chainId,
      to: this.target,
      value: this.value,
      data: this.data,
      owner: this.mutateOwner ? "0x00000000000000000000000000000000000000ee" : agentAddress,
      category: "swap" as const,
      provider: this.provider,
      metadata: {
        quoteId: this.mutateQuoteId ? "mutated" : quote.quoteId,
        amountIn: quote.amountIn,
        minAmountOut: quote.minAmountOut,
        slippageBps: quote.slippageBps,
      },
    };
  }
}

class FakeEvmRpc {
  pendingNonce = 0;
  gasPrice = "1000000000";
  sendCalls: string[] = [];
  receipt: Record<string, unknown> | null = null;
  transaction: Record<string, unknown> | null = null;
  failSend: Error | null = null;
  onBeforeSend?: () => Promise<void>;

  async getPendingNonce() {
    return this.pendingNonce;
  }

  async getGasPrice() {
    return this.gasPrice;
  }

  async sendRawTransaction(_chainId: number, rawTransaction: string) {
    this.sendCalls.push(rawTransaction);
    await this.onBeforeSend?.();
    if (this.failSend) throw this.failSend;
    const { keccak256 } = await import("viem");
    return keccak256(rawTransaction as `0x${string}`).toLowerCase();
  }

  async getTransactionReceipt() {
    return this.receipt;
  }

  async getTransactionByHash() {
    return this.transaction;
  }
}

function makeRegistry(adapter: FakeSwapAdapter) {
  const registry = new AdapterRegistry({ env: { NODE_ENV: "test" } });
  registry.register("swap", adapter.provider, adapter);
  return registry;
}

async function signToken(agentId = AGENT_ID): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    agent_id: agentId,
    tenant_id: TENANT_ID,
    scopes: ["trade:order"],
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setSubject(`agent:${agentId}`)
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setIssuedAt(now - 10)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

async function seedPolicy(
  overrides: {
    chainId?: number;
    target?: string;
    selector?: string;
    maxNativeValueWei?: string;
    selectorConstraints?: Record<string, { maxNativeValueWei: string }>;
    venueAllowlist?: string[];
  } = {},
) {
  await getDb().delete(policies).where(eq(policies.agentId, AGENT_ID));
  await getDb()
    .insert(policies)
    .values([
      {
        id: `chain-${crypto.randomUUID()}`,
        agentId: AGENT_ID,
        type: "allowed-chains",
        enabled: true,
        config: { chains: [`eip155:${overrides.chainId ?? 8453}`] },
      },
      {
        id: `contract-${crypto.randomUUID()}`,
        agentId: AGENT_ID,
        type: "contract-allowlist",
        enabled: true,
        config: {
          contracts: [
            {
              address: overrides.target ?? TARGET,
              selectors: [overrides.selector ?? SELECTOR],
              constraints: overrides.selectorConstraints ?? {
                [overrides.selector ?? SELECTOR]: {
                  maxNativeValueWei: overrides.maxNativeValueWei ?? "0",
                },
              },
            },
          ],
        },
      },
      ...(overrides.venueAllowlist
        ? [
            {
              id: `venue-${crypto.randomUUID()}`,
              agentId: AGENT_ID,
              type: "venue-allowlist" as const,
              enabled: true,
              config: { allowedVenues: overrides.venueAllowlist },
            },
          ]
        : []),
    ]);
}

function requestBody(agentId = AGENT_ID) {
  return {
    agentId,
    sessionId: SESSION_ID,
    chainId: 8453,
    fromToken: { address: FROM_TOKEN, symbol: "A", decimals: 0 },
    toToken: { address: TO_TOKEN, symbol: "B", decimals: 18 },
    amount: "10",
    slippageBps: 50,
  };
}

async function buildApp(options?: {
  adapter?: FakeSwapAdapter;
  simulator?: { ok: boolean; revertReason?: string };
  evmRpc?: FakeEvmRpc | null;
  tokenUsdPrice?: number | null;
  auditLog?: unknown[];
  auditFailureActions?: string[];
}) {
  const adapter = options?.adapter ?? new FakeSwapAdapter();
  let simulationCalls = 0;
  const baseCtx = testCtx();
  const ctx = {
    ...baseCtx,
    adapterRegistry: makeRegistry(adapter),
    priceOracle: {
      getNativeUsdPrice: async () => options?.tokenUsdPrice ?? 1,
      getTokenUsdPrice: async () => options?.tokenUsdPrice ?? 1,
      weiToUsd: async (value: string) => Number(value) * (options?.tokenUsdPrice ?? 1),
      usdToWei: async (value: number) => String(value),
    },
    evmSimulator: options?.simulator
      ? {
          simulate: async (request: unknown) => {
            simulationCalls += 1;
            if (options.auditLog) options.auditLog.push({ simulation: request });
            return options.simulator?.ok
              ? { ok: true as const, gasEstimate: "0x5208" }
              : { ok: false as const, revertReason: options.simulator?.revertReason ?? "revert" };
          },
        }
      : null,
    evmRpc: options?.evmRpc ?? null,
    writeAuditEvent: async (event: Parameters<typeof baseCtx.writeAuditEvent>[0]) => {
      if (options?.auditFailureActions?.includes(event.action)) {
        throw new Error(`audit failed for ${event.action}`);
      }
      return baseCtx.writeAuditEvent(event);
    },
  };
  const app = new Hono();
  app.use("/v1/trade/evm/swap/*", (c, next) => requireAgentJwt(c as never, next));
  app.route("/v1/trade", createEvmSwapRoutes(ctx));
  return { app, adapter, simulationCalls: () => simulationCalls };
}

async function buildPluginMountedApp(options?: {
  adapter?: FakeSwapAdapter;
  simulator?: { ok: boolean; revertReason?: string };
  evmRpc?: FakeEvmRpc | null;
}) {
  const adapter = options?.adapter ?? new FakeSwapAdapter();
  const ctx = {
    ...testCtx(),
    adapterRegistry: makeRegistry(adapter),
    priceOracle: {
      getNativeUsdPrice: async () => 1,
      getTokenUsdPrice: async () => 1,
      weiToUsd: async (value: string) => Number(value),
      usdToWei: async (value: number) => String(value),
    },
    evmSimulator: options?.simulator
      ? { simulate: async () => ({ ok: true as const, gasEstimate: "0x5208" }) }
      : null,
    evmRpc: options?.evmRpc ?? null,
  };
  const app = new Hono();
  tradingPlugin.register(app as never, ctx);
  return { app, adapter };
}

async function postPrepare(
  app: Hono,
  body = requestBody(),
  key = crypto.randomUUID(),
  agentId = AGENT_ID,
) {
  return app.request("/v1/trade/evm/swap/prepare", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await signToken(agentId)}`,
      "X-Steward-Tenant": TENANT_ID,
      "Content-Type": "application/json",
      "Idempotency-Key": key,
    },
    body: JSON.stringify(body),
  });
}

async function getIntent(app: Hono, id: string, agentId = AGENT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}`, {
    headers: {
      Authorization: `Bearer ${await signToken(agentId)}`,
      "X-Steward-Tenant": TENANT_ID,
    },
  });
}

async function revokeIntent(app: Hono, id: string, agentId = AGENT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}/revoke`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await signToken(agentId)}`,
      "X-Steward-Tenant": TENANT_ID,
    },
  });
}

async function executeIntent(app: Hono, id: string, key = crypto.randomUUID(), agentId = AGENT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}/execute`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await signToken(agentId)}`,
      "X-Steward-Tenant": TENANT_ID,
      "Content-Type": "application/json",
      "Idempotency-Key": key,
    },
    body: JSON.stringify({}),
  });
}

async function reconcileIntent(app: Hono, id: string, agentId = AGENT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}/reconcile`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await signToken(agentId)}`,
      "X-Steward-Tenant": TENANT_ID,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({}),
  });
}

async function dailySpendOf(sessionId = SESSION_ID): Promise<number> {
  const [row] = await getDb()
    .select({ spent: tradeSessions.dailySpendUsd })
    .from(tradeSessions)
    .where(eq(tradeSessions.id, sessionId));
  return Number(row?.spent ?? 0);
}

async function getIntentWithPlatform(app: Hono, id: string, tenantId = TENANT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}`, {
    headers: {
      "X-Steward-Tenant": tenantId,
      "X-Steward-Platform-Key": PLATFORM_KEY,
    },
  });
}

async function revokeIntentWithPlatform(app: Hono, id: string, tenantId = TENANT_ID) {
  return app.request(`/v1/trade/evm/swap/intents/${id}/revoke`, {
    method: "POST",
    headers: {
      "X-Steward-Tenant": tenantId,
      "X-Steward-Platform-Key": PLATFORM_KEY,
    },
  });
}

beforeAll(async () => {
  const { createPGLiteDb, setPGLiteOverride } = await import("@stwd/db/pglite");
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  pgliteDb = db as ReturnType<typeof getDb>;

  ({
    auditEvents,
    closeDb,
    getDb,
    intents,
    policies,
    tenants,
    tradeSessions,
    transactions,
    vaultSigningFreezes,
  } = await import("@stwd/db"));
  ({ testCtx } = await import("./_ctx"));
  ({ tradingPlugin } = await import("../index"));
  ({ createEvmSwapRoutes } = await import("../routes/evm-swap"));

  const keys = await generateKeyPair("RS256", { extractable: true });
  privateKey = keys.privateKey;
  publicJwk = await exportJWK(keys.publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  globalThis.fetch = mock(async () =>
    Response.json({ keys: [publicJwk] }),
  ) as unknown as typeof fetch;

  ({ requireAgentJwt, clearAgentJwksCacheForTests } = await import(
    "../../../api/src/middleware/agent-jwt"
  ));
  const { vault } = await import("../../../api/src/services/context");
  await getDb()
    .insert(tenants)
    .values([
      { id: TENANT_ID, name: "EVM Swap Tenant", apiKeyHash: "hash" },
      { id: OTHER_TENANT_ID, name: "Other EVM Swap Tenant", apiKeyHash: "other-hash" },
    ])
    .onConflictDoNothing();
  await vault.createAgent(TENANT_ID, AGENT_ID, "EVM Swap Agent");
  await vault.createAgent(TENANT_ID, OTHER_AGENT_ID, "Other EVM Swap Agent");
  agentWalletAddress = (await vault.getWallet({ agentId: AGENT_ID, chainId: 8453 })).address;
});

afterAll(async () => {
  mock.restore();
  await closeDb();
});

beforeEach(async () => {
  clearAgentJwksCacheForTests();
  await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
  await getDb().delete(intents).where(eq(intents.tenantId, TENANT_ID));
  await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  await getDb().delete(vaultSigningFreezes).where(eq(vaultSigningFreezes.tenantId, TENANT_ID));
  await getDb().delete(tradeSessions).where(eq(tradeSessions.tenantId, TENANT_ID));
  await getDb()
    .insert(tradeSessions)
    .values({
      id: SESSION_ID,
      agentId: AGENT_ID,
      tenantId: TENANT_ID,
      venue: "evm",
      walletId: agentWalletAddress,
      status: "active",
      dailySpendUsd: "0",
      dailyCapUsd: "100",
      perOrderCapUsd: "100",
      leverageCap: "1",
      allowedAssets: ["eip155:8453"],
      expiresAt: new Date(Date.now() + 60_000),
    });
  await seedPolicy();
});

describe("governed EVM swap prepare", () => {
  it("uses the in-memory PGLite override installed before API context imports", () => {
    expect(getDb()).toBe(pgliteDb);
    expect(process.env.STEWARD_DB_MODE).toBe("pglite");
    expect(process.env.STEWARD_PGLITE_MEMORY).toBe("true");
  });

  it("prepares an unsigned intent, replays idempotently, and sanitizes audit", async () => {
    const { app, adapter, simulationCalls } = await buildApp({ simulator: { ok: true } });
    const key = crypto.randomUUID();
    const res = await postPrepare(app, requestBody(), key);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: { intentId: string; intentHash: string; unsignedIntent: { data: string } };
    };
    expect(body.data.intentId).toMatch(/^evm_/);
    expect(body.data.intentHash).toMatch(/^sha256:/);
    expect(body.data.unsignedIntent.data).toBe(CALLDATA);
    expect(adapter.observedTaker).toMatch(/^0x[a-f0-9]{40}$/i);
    expect(adapter.buildCalls).toBe(1);
    expect(simulationCalls()).toBe(1);

    const stored = await getDb().select().from(intents).where(eq(intents.id, body.data.intentId));
    expect(stored).toHaveLength(1);
    expect(stored[0]?.status).toBe("prepared");
    expect(stored[0]?.idempotencyKey).toBe(key);
    expect(stored[0]?.semanticRequestHash).toMatch(/^sha256:/);

    const replay = await postPrepare(app, requestBody(), key);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await replay.json()).toEqual(body);
    expect(adapter.buildCalls).toBe(1);
    expect(simulationCalls()).toBe(1);

    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, TENANT_ID))
      .orderBy(asc(auditEvents.seq));
    expect(rows.map((row) => row.action)).toEqual([
      "trade.evm.swap.prepare.requested",
      "trade.evm.swap.prepare.prepared",
    ]);
    expect(JSON.stringify(rows.map((row) => row.metadata))).not.toContain(CALLDATA.slice(10));
  });

  it("persists replay and status across handler recreation", async () => {
    const key = crypto.randomUUID();
    const first = await buildApp({ simulator: { ok: true } });
    const created = await postPrepare(first.app, requestBody(), key);
    expect(created.status).toBe(200);
    const createdBody = (await created.json()) as { data: { intentId: string } };

    const second = await buildApp({ simulator: { ok: true } });
    const replay = await postPrepare(second.app, requestBody(), key);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect((await replay.json()) as unknown).toEqual(createdBody);
    expect(second.adapter.buildCalls).toBe(0);

    const status = await getIntent(second.app, createdBody.data.intentId);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({
      ok: true,
      data: { intentId: createdBody.data.intentId, status: "prepared" },
    });
  });

  it("mounts through the trading plugin on unversioned and v1 prefixes", async () => {
    const { app, adapter } = await buildPluginMountedApp({ simulator: { ok: true } });
    const unversioned = await app.request("/trade/evm/swap/prepare", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await signToken()}`,
        "X-Steward-Tenant": TENANT_ID,
        "Content-Type": "application/json",
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify(requestBody()),
    });
    expect(unversioned.status).toBe(200);

    const versioned = await postPrepare(app, requestBody(), crypto.randomUUID());
    expect(versioned.status).toBe(200);
    expect(adapter.buildCalls).toBe(2);
  });

  it("handles concurrent same-key requests and rejects conflicting semantics", async () => {
    const { app, adapter, simulationCalls } = await buildApp({ simulator: { ok: true } });
    const key = crypto.randomUUID();
    const [a, b] = await Promise.all([
      postPrepare(app, requestBody(), key),
      postPrepare(app, requestBody(), key),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(adapter.buildCalls).toBe(1);
    expect(simulationCalls()).toBe(1);

    const conflict = await postPrepare(app, { ...requestBody(), amount: "1001" }, key);
    expect(conflict.status).toBe(409);
  });

  it("durably replays non-5xx rejections across handler recreation and conflicts on semantic drift", async () => {
    const key = crypto.randomUUID();
    const rejectedAdapter = Object.assign(new FakeSwapAdapter(), {
      target: "0x00000000000000000000000000000000000000ff",
    });
    const first = await buildApp({ adapter: rejectedAdapter, simulator: { ok: true } });
    const rejected = await postPrepare(first.app, requestBody(), key);
    expect(rejected.status).toBe(400);
    const rejectedBody = await rejected.json();
    expect(rejectedAdapter.buildCalls).toBe(1);

    const second = await buildApp({ simulator: { ok: true } });
    const replayed = await postPrepare(second.app, requestBody(), key);
    expect(replayed.status).toBe(400);
    expect(replayed.headers.get("Idempotency-Replayed")).toBe("true");
    expect(await replayed.json()).toEqual(rejectedBody);
    expect(second.adapter.quoteCalls).toBe(0);
    expect(second.adapter.buildCalls).toBe(0);

    const stored = await getDb().select().from(intents).where(eq(intents.idempotencyKey, key));
    expect(stored).toHaveLength(1);
    expect(stored[0]?.status).toBe("rejected");
    expect(JSON.stringify(stored[0]?.payload)).not.toContain(CALLDATA.slice(10));

    const conflict = await postPrepare(second.app, { ...requestBody(), amount: "1001" }, key);
    expect(conflict.status).toBe(409);
    expect(second.adapter.quoteCalls).toBe(0);
  });

  it("keeps 5xx prepare failures retryable", async () => {
    const key = crypto.randomUUID();
    const unavailableAdapter = Object.assign(new FakeSwapAdapter(), { failUnavailable: true });
    const unavailable = await buildApp({
      adapter: unavailableAdapter,
      simulator: { ok: true },
    });
    const first = await postPrepare(unavailable.app, requestBody(), key);
    expect(first.status).toBe(503);
    expect(unavailableAdapter.quoteCalls).toBe(1);

    const healthy = await buildApp({ simulator: { ok: true } });
    const retry = await postPrepare(healthy.app, requestBody(), key);
    expect(retry.status).toBe(200);
    expect(retry.headers.get("Idempotency-Replayed")).toBe(null);
    expect(healthy.adapter.quoteCalls).toBe(1);
  });

  it("revokes and expires prepared intents before execution", async () => {
    const { app } = await buildApp({ simulator: { ok: true } });
    const created = await postPrepare(app);
    const body = (await created.json()) as { data: { intentId: string } };
    const revoked = await revokeIntent(app, body.data.intentId);
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({
      data: { intentId: body.data.intentId, status: "revoked" },
    });

    await getDb()
      .update(intents)
      .set({ status: "prepared", expiresAt: new Date(Date.now() - 1000) })
      .where(eq(intents.id, body.data.intentId));
    const expired = await getIntent(app, body.data.intentId);
    expect(expired.status).toBe(200);
    expect(await expired.json()).toMatchObject({
      data: { intentId: body.data.intentId, status: "expired" },
    });
  });

  it("allows platform recovery status and revoke while denying cross-agent and cross-tenant access", async () => {
    const { app } = await buildPluginMountedApp({ simulator: { ok: true } });
    const created = await postPrepare(app);
    expect(created.status).toBe(200);
    const body = (await created.json()) as { data: { intentId: string } };

    const otherAgentStatus = await getIntent(app, body.data.intentId, OTHER_AGENT_ID);
    expect(otherAgentStatus.status).toBe(404);

    const wrongTenantStatus = await getIntentWithPlatform(app, body.data.intentId, OTHER_TENANT_ID);
    expect(wrongTenantStatus.status).toBe(404);

    const platformStatus = await getIntentWithPlatform(app, body.data.intentId);
    expect(platformStatus.status).toBe(200);
    expect(await platformStatus.json()).toMatchObject({
      ok: true,
      data: { intentId: body.data.intentId, status: "prepared" },
    });

    const platformRevoke = await revokeIntentWithPlatform(app, body.data.intentId);
    expect(platformRevoke.status).toBe(200);
    expect(await platformRevoke.json()).toMatchObject({
      ok: true,
      data: { intentId: body.data.intentId, status: "revoked" },
    });
  });

  it("denies revoked session and wallet drift before persistence", async () => {
    await getDb()
      .update(tradeSessions)
      .set({ status: "revoked", revokedAt: new Date(), revokedBy: "test" })
      .where(eq(tradeSessions.id, SESSION_ID));
    const revokedSession = await buildApp({ simulator: { ok: true } });
    expect((await postPrepare(revokedSession.app)).status).toBe(403);
    expect(revokedSession.adapter.buildCalls).toBe(0);

    await getDb()
      .update(tradeSessions)
      .set({
        status: "active",
        revokedAt: null,
        revokedBy: null,
        walletId: "0x00000000000000000000000000000000000000aa",
      })
      .where(eq(tradeSessions.id, SESSION_ID));
    const walletDrift = await buildApp({ simulator: { ok: true } });
    expect((await postPrepare(walletDrift.app)).status).toBe(409);
    expect(walletDrift.adapter.buildCalls).toBe(0);
  });

  it("denies cross-agent and caller-supplied transaction fields", async () => {
    const { app } = await buildApp({ simulator: { ok: true } });
    const cross = await postPrepare(app, requestBody(OTHER_AGENT_ID));
    expect(cross.status).toBe(403);

    const smuggled = await postPrepare(app, { ...requestBody(), target: TARGET } as never);
    expect(smuggled.status).toBe(400);
  });

  it("denies chain, target, selector, and native value outside EVM policy", async () => {
    const cases: Array<[string, Partial<FakeSwapAdapter>, Parameters<typeof seedPolicy>[0]]> = [
      ["chain", {}, { chainId: 1 }],
      ["target", { target: "0x00000000000000000000000000000000000000ff" }, {}],
      ["selector", { data: `0x87654321${"0".repeat(64)}` }, {}],
      ["value", { value: "2" }, { maxNativeValueWei: "1" }],
    ];
    for (const [, adapterPatch, policyPatch] of cases) {
      await seedPolicy(policyPatch);
      const adapter = Object.assign(new FakeSwapAdapter(), adapterPatch);
      const { app } = await buildApp({ adapter, simulator: { ok: true } });
      const res = await postPrepare(app);
      expect(res.status).toBe(400);
      expect((await res.json()) as { code: string }).toMatchObject({ code: "policy-violation" });
    }
  });

  it("passes authoritative intent provider as venue into policy evaluation", async () => {
    await seedPolicy({ venueAllowlist: ["fake"] });
    const { app } = await buildApp({ simulator: { ok: true } });
    const res = await postPrepare(app);
    expect(res.status).toBe(200);
  });

  it("denies provider venues outside the policy allowlist", async () => {
    await seedPolicy({ venueAllowlist: ["other-venue"] });
    const { app } = await buildApp({ simulator: { ok: true } });
    const res = await postPrepare(app);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      code: "policy-violation",
      reason: "venue-not-allowlisted: fake",
    });
  });

  it("accepts mixed-case selector constraint keys in strict EVM policy", async () => {
    await seedPolicy({ selector: "0xAbCdEf12", maxNativeValueWei: "1" });
    const adapter = Object.assign(new FakeSwapAdapter(), {
      data: `0xabcdef12${"0".repeat(64)}`,
      value: "1",
    });
    const { app } = await buildApp({ adapter, simulator: { ok: true } });
    const res = await postPrepare(app);
    expect(res.status).toBe(200);
  });

  it("prefers an exact lowercase selector constraint over an earlier folded duplicate in strict EVM policy", async () => {
    await seedPolicy({
      selector: "0xabcdef12",
      selectorConstraints: {
        "0xAbCdEf12": { maxNativeValueWei: "10" },
        "0xabcdef12": { maxNativeValueWei: "1" },
      },
    });
    const adapter = Object.assign(new FakeSwapAdapter(), {
      data: `0xabcdef12${"0".repeat(64)}`,
      value: "2",
    });
    const { app } = await buildApp({ adapter, simulator: { ok: true } });
    const res = await postPrepare(app);
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      code: "policy-violation",
      reason: "EVM policy must allowlist target, selector, and max native value",
    });
  });

  it("denies intent owner and quote binding mutation", async () => {
    for (const adapterPatch of [{ mutateOwner: true }, { mutateQuoteId: true }]) {
      const adapter = Object.assign(new FakeSwapAdapter(), adapterPatch);
      const { app } = await buildApp({ adapter, simulator: { ok: true } });
      const res = await postPrepare(app);
      expect([400, 403]).toContain(res.status);
    }
  });

  it("denies provider-returned quote mutation and unavailable failures before simulation", async () => {
    const cases: Array<[Partial<FakeSwapAdapter>, number]> = [
      [{ chainId: 1 }, 400],
      [{ mutateQuoteFromToken: true }, 400],
      [{ mutateQuoteToToken: true }, 400],
      [{ mutateQuoteAmount: true }, 400],
      [{ expireQuote: true }, 400],
      [{ failUnavailable: true }, 503],
    ];
    for (const [adapterPatch, status] of cases) {
      const adapter = Object.assign(new FakeSwapAdapter(), adapterPatch);
      const { app, simulationCalls } = await buildApp({ adapter, simulator: { ok: true } });
      const res = await postPrepare(app);
      expect(res.status).toBe(status);
      expect(simulationCalls()).toBe(0);
    }
  });

  it("fails closed when simulation reverts or is unavailable", async () => {
    const unavailable = await buildApp();
    expect((await postPrepare(unavailable.app)).status).toBe(503);

    const reverting = await buildApp({
      simulator: { ok: false, revertReason: "execution reverted" },
    });
    const res = await postPrepare(reverting.app);
    expect(res.status).toBe(503);
    expect(reverting.adapter.buildCalls).toBe(1);
  });

  it("does not call vault signing", async () => {
    const ctx = testCtx();
    const signSpy = mock(ctx.vault.signTransaction);
    ctx.vault.signTransaction = signSpy as never;
    const adapter = new FakeSwapAdapter();
    const app = new Hono();
    app.use("/v1/trade/evm/swap/prepare", (c, next) => requireAgentJwt(c as never, next));
    app.route(
      "/v1/trade",
      createEvmSwapRoutes({
        ...ctx,
        adapterRegistry: makeRegistry(adapter),
        evmSimulator: { simulate: async () => ({ ok: true, gasEstimate: "0x5208" }) },
      }),
    );
    const res = await postPrepare(app);
    expect(res.status).toBe(200);
    expect(signSpy).not.toHaveBeenCalled();
  });

  it("executes a prepared swap once, persists tx identity before send, and never exposes raw tx", async () => {
    const rpc = new FakeEvmRpc();
    let persistedBeforeSend: string | null = null;
    rpc.onBeforeSend = async () => {
      const [row] = await getDb().select().from(intents).where(eq(intents.id, intentId));
      const execution = (row?.executionResult ?? {}) as Record<string, unknown>;
      persistedBeforeSend =
        typeof execution.transactionHash === "string" ? execution.transactionHash : null;
    };
    const { app } = await buildApp({ simulator: { ok: true }, evmRpc: rpc });
    const prepared = await postPrepare(app);
    const preparedBody = (await prepared.json()) as { data: { intentId: string } };
    const intentId = preparedBody.data.intentId;

    const key = crypto.randomUUID();
    const executed = await executeIntent(app, intentId, key);
    expect(executed.status).toBe(200);
    const body = (await executed.json()) as {
      data: { status: string; executionStatus: string; transactionHash: string };
    };
    expect(body.data.status).toBe("submitted");
    expect(body.data.executionStatus).toBe("submitted");
    expect(body.data.transactionHash).toMatch(/^0x[a-f0-9]{64}$/);
    expect(persistedBeforeSend).toBe(body.data.transactionHash);
    expect(rpc.sendCalls).toHaveLength(1);
    expect(JSON.stringify(body)).not.toContain(rpc.sendCalls[0] ?? "raw-missing");
    expect(JSON.stringify(await getDb().select().from(intents))).not.toContain(
      rpc.sendCalls[0] ?? "raw-missing",
    );
    expect(JSON.stringify(await getDb().select().from(transactions))).not.toContain(
      rpc.sendCalls[0] ?? "raw-missing",
    );
    expect(await dailySpendOf()).toBeGreaterThan(0);

    const replay = await executeIntent(app, intentId, key);
    expect(replay.status).toBe(200);
    expect((await replay.json()) as unknown).toEqual(body);
    expect(rpc.sendCalls).toHaveLength(1);

    const conflict = await executeIntent(app, intentId, crypto.randomUUID());
    expect(conflict.status).toBe(409);
    expect(rpc.sendCalls).toHaveLength(1);
  });

  it("preserves submitted identity when the post-submit audit write fails", async () => {
    const rpc = new FakeEvmRpc();
    const { app } = await buildApp({
      simulator: { ok: true },
      evmRpc: rpc,
      auditFailureActions: ["trade.evm.swap.execute.submitted"],
    });
    const prepared = await postPrepare(app);
    const { data } = (await prepared.json()) as { data: { intentId: string } };

    const executed = await executeIntent(app, data.intentId);
    expect(executed.status).toBe(200);
    expect(await executed.json()).toMatchObject({
      data: { status: "submitted", executionStatus: "submitted", retry: "not-retryable" },
    });
    expect(await dailySpendOf()).toBeGreaterThan(0);

    const [intentRow] = await getDb().select().from(intents).where(eq(intents.id, data.intentId));
    const [txRow] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, data.intentId));
    expect(intentRow?.status).toBe("submitted");
    expect(txRow?.status).toBe("broadcast");
    expect(txRow?.txHash).toMatch(/^0x[a-f0-9]{64}$/);
  });

  it("rejects execute for non-owning agents and pre-sign fences without reserving spend", async () => {
    const rpc = new FakeEvmRpc();
    const { app } = await buildApp({ simulator: { ok: true }, evmRpc: rpc });
    const prepared = await postPrepare(app);
    const { data } = (await prepared.json()) as { data: { intentId: string } };

    expect(
      (await executeIntent(app, data.intentId, crypto.randomUUID(), OTHER_AGENT_ID)).status,
    ).toBe(404);

    await getDb()
      .update(tradeSessions)
      .set({ status: "revoked", revokedAt: new Date(), revokedBy: "test" })
      .where(eq(tradeSessions.id, SESSION_ID));
    const revoked = await executeIntent(app, data.intentId);
    expect(revoked.status).toBe(403);
    expect(await dailySpendOf()).toBe(0);
    expect(rpc.sendCalls).toHaveLength(0);
  });

  it("releases spend and drops nonce on pre-submit signing freeze rejection", async () => {
    const rpc = new FakeEvmRpc();
    const { app } = await buildApp({ simulator: { ok: true }, evmRpc: rpc });
    const prepared = await postPrepare(app);
    const { data } = (await prepared.json()) as { data: { intentId: string } };
    await getDb().insert(vaultSigningFreezes).values({
      tenantId: TENANT_ID,
      scopeType: "agent",
      agentId: AGENT_ID,
      reason: "test freeze",
      createdByType: "system",
    });

    const rejected = await executeIntent(app, data.intentId);
    expect(rejected.status).toBe(409);
    expect(await rejected.json()).toMatchObject({
      data: { executionStatus: "not_attempted" },
    });
    expect(rpc.sendCalls).toHaveLength(0);
    expect(await dailySpendOf()).toBe(0);
    const [row] = await getDb().select().from(intents).where(eq(intents.id, data.intentId));
    expect(row?.status).toBe("rejected");
  });

  it("classifies send timeout as unknown, retains spend, and never resubmits on replay", async () => {
    const rpc = Object.assign(new FakeEvmRpc(), { failSend: new Error("network timeout") });
    const { app } = await buildApp({ simulator: { ok: true }, evmRpc: rpc });
    const prepared = await postPrepare(app);
    const { data } = (await prepared.json()) as { data: { intentId: string } };
    const key = crypto.randomUUID();

    const unknown = await executeIntent(app, data.intentId, key);
    expect(unknown.status).toBe(200);
    expect(await unknown.json()).toMatchObject({
      data: { status: "unknown", executionStatus: "unknown", retry: "reconcile-only" },
    });
    expect(await dailySpendOf()).toBeGreaterThan(0);
    expect(rpc.sendCalls).toHaveLength(1);

    const replay = await executeIntent(app, data.intentId, key);
    expect(replay.status).toBe(200);
    expect(rpc.sendCalls).toHaveLength(1);

    const blindRetry = await executeIntent(app, data.intentId, crypto.randomUUID());
    expect(blindRetry.status).toBe(409);
    expect(rpc.sendCalls).toHaveLength(1);
  });

  it("marks definite RPC-rejected sends failed in the transaction ledger", async () => {
    const rpc = Object.assign(new FakeEvmRpc(), {
      failSend: new Error("insufficient funds for gas * price + value"),
    });
    const { app } = await buildApp({ simulator: { ok: true }, evmRpc: rpc });
    const prepared = await postPrepare(app);
    const { data } = (await prepared.json()) as { data: { intentId: string } };

    const rejected = await executeIntent(app, data.intentId);
    expect(rejected.status).toBe(409);
    expect(await rejected.json()).toMatchObject({
      data: { executionStatus: "rejected" },
    });
    expect(await dailySpendOf()).toBe(0);
    const [intentRow] = await getDb().select().from(intents).where(eq(intents.id, data.intentId));
    const [txRow] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, data.intentId));
    expect(intentRow?.status).toBe("rejected");
    expect(txRow?.status).toBe("failed");
  });

  it("reconciles confirmed, reverted, and not-found ambiguity from persisted tx hash only", async () => {
    const confirmedRpc = Object.assign(new FakeEvmRpc(), { failSend: new Error("timeout") });
    const confirmedApp = await buildApp({ simulator: { ok: true }, evmRpc: confirmedRpc });
    const confirmedPrepared = await postPrepare(confirmedApp.app);
    const confirmedId = ((await confirmedPrepared.json()) as { data: { intentId: string } }).data
      .intentId;
    await executeIntent(confirmedApp.app, confirmedId);
    const [confirmedRow] = await getDb().select().from(intents).where(eq(intents.id, confirmedId));
    const confirmedHash = ((confirmedRow?.executionResult ?? {}) as Record<string, unknown>)
      .transactionHash as string;
    confirmedRpc.failSend = null;
    confirmedRpc.receipt = { status: "0x1", transactionHash: confirmedHash, blockNumber: "0x1" };
    expect((await reconcileIntent(confirmedApp.app, confirmedId)).status).toBe(200);
    expect(await getIntent(confirmedApp.app, confirmedId).then((r) => r.json())).toMatchObject({
      data: { status: "submitted" },
    });

    await getDb().delete(intents).where(eq(intents.tenantId, TENANT_ID));
    await getDb()
      .update(tradeSessions)
      .set({ dailySpendUsd: "0", status: "active" })
      .where(eq(tradeSessions.id, SESSION_ID));

    const revertedRpc = Object.assign(new FakeEvmRpc(), { failSend: new Error("timeout") });
    const revertedApp = await buildApp({ simulator: { ok: true }, evmRpc: revertedRpc });
    const revertedPrepared = await postPrepare(revertedApp.app);
    const revertedId = ((await revertedPrepared.json()) as { data: { intentId: string } }).data
      .intentId;
    await executeIntent(revertedApp.app, revertedId);
    const [revertedRow] = await getDb().select().from(intents).where(eq(intents.id, revertedId));
    const revertedHash = ((revertedRow?.executionResult ?? {}) as Record<string, unknown>)
      .transactionHash as string;
    expect(await dailySpendOf()).toBeGreaterThan(0);
    revertedRpc.failSend = null;
    revertedRpc.receipt = { status: "0x0", transactionHash: revertedHash, blockNumber: "0x2" };
    await reconcileIntent(revertedApp.app, revertedId);
    expect(await getIntent(revertedApp.app, revertedId).then((r) => r.json())).toMatchObject({
      data: { status: "rejected" },
    });
    expect(await dailySpendOf()).toBe(0);
    await getDb()
      .update(tradeSessions)
      .set({ dailySpendUsd: "10" })
      .where(eq(tradeSessions.id, SESSION_ID));
    await reconcileIntent(revertedApp.app, revertedId);
    expect(await dailySpendOf()).toBe(10);

    await getDb().delete(intents).where(eq(intents.tenantId, TENANT_ID));
    await getDb()
      .update(tradeSessions)
      .set({ dailySpendUsd: "0", status: "active" })
      .where(eq(tradeSessions.id, SESSION_ID));

    const missingRpc = Object.assign(new FakeEvmRpc(), { failSend: new Error("timeout") });
    const missingApp = await buildApp({ simulator: { ok: true }, evmRpc: missingRpc });
    const missingPrepared = await postPrepare(missingApp.app);
    const missingId = ((await missingPrepared.json()) as { data: { intentId: string } }).data
      .intentId;
    await executeIntent(missingApp.app, missingId);
    missingRpc.failSend = null;
    missingRpc.receipt = null;
    missingRpc.transaction = null;
    await reconcileIntent(missingApp.app, missingId);
    expect(await getIntent(missingApp.app, missingId).then((r) => r.json())).toMatchObject({
      data: { status: "unknown" },
    });
    expect(await dailySpendOf()).toBeGreaterThan(0);
  });
});
