import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";
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
process.env.ELIZA_CLOUD_JWKS_URL = "https://jwks.example.test/.well-known/jwks.json";

setDefaultTimeout(30000);

const TENANT_ID = "evm-swap-tenant";
const AGENT_ID = "evm-swap-agent";
const OTHER_AGENT_ID = "evm-swap-other-agent";
const KID = "evm-swap-kid";
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
let policies: typeof import("@stwd/db")["policies"];
let tenants: typeof import("@stwd/db")["tenants"];
let closeDb: typeof import("@stwd/db")["closeDb"];
let getDb: typeof import("@stwd/db")["getDb"];
let pgliteDb: ReturnType<typeof getDb>;

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

  async getQuote(request: SwapQuoteRequest): Promise<SwapQuote> {
    this.quoteCalls += 1;
    return {
      provider: this.provider,
      fromToken: request.fromToken,
      toToken: request.toToken,
      chainId: this.chainId ?? request.chainId,
      amountIn: request.amount,
      amountOut: request.amount,
      minAmountOut: request.amount,
      route: [
        { venue: "fake", fromToken: request.fromToken.address, toToken: request.toToken.address },
      ],
      feeAmount: "0",
      slippageBps: request.slippageBps ?? 50,
      expiresAt: Date.now() + 60_000,
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
    chainId: 8453,
    fromToken: { address: FROM_TOKEN, symbol: "A", decimals: 18 },
    toToken: { address: TO_TOKEN, symbol: "B", decimals: 18 },
    amount: "1000",
    slippageBps: 50,
  };
}

async function buildApp(options?: {
  adapter?: FakeSwapAdapter;
  simulator?: { ok: boolean; revertReason?: string };
  auditLog?: unknown[];
}) {
  const adapter = options?.adapter ?? new FakeSwapAdapter();
  let simulationCalls = 0;
  const ctx = {
    ...testCtx(),
    adapterRegistry: makeRegistry(adapter),
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
  };
  const app = new Hono();
  app.use("/v1/trade/evm/swap/prepare", (c, next) => requireAgentJwt(c as never, next));
  app.route("/v1/trade", createEvmSwapRoutes(ctx));
  return { app, adapter, simulationCalls: () => simulationCalls };
}

async function buildPluginMountedApp(options?: {
  adapter?: FakeSwapAdapter;
  simulator?: { ok: boolean; revertReason?: string };
}) {
  const adapter = options?.adapter ?? new FakeSwapAdapter();
  const ctx = {
    ...testCtx(),
    adapterRegistry: makeRegistry(adapter),
    evmSimulator: options?.simulator
      ? { simulate: async () => ({ ok: true as const, gasEstimate: "0x5208" }) }
      : null,
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

beforeAll(async () => {
  const { createPGLiteDb, setPGLiteOverride } = await import("@stwd/db/pglite");
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  pgliteDb = db as ReturnType<typeof getDb>;

  ({ auditEvents, closeDb, getDb, policies, tenants } = await import("@stwd/db"));
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
    .values({ id: TENANT_ID, name: "EVM Swap Tenant", apiKeyHash: "hash" })
    .onConflictDoNothing();
  await vault.createAgent(TENANT_ID, AGENT_ID, "EVM Swap Agent");
  await vault.createAgent(TENANT_ID, OTHER_AGENT_ID, "Other EVM Swap Agent");
});

afterAll(async () => {
  mock.restore();
  await closeDb();
});

beforeEach(async () => {
  clearAgentJwksCacheForTests();
  await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
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
      data: { intentHash: string; unsignedIntent: { data: string } };
    };
    expect(body.data.intentHash).toMatch(/^sha256:/);
    expect(body.data.unsignedIntent.data).toBe(CALLDATA);
    expect(adapter.buildCalls).toBe(1);
    expect(simulationCalls()).toBe(1);

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

  it("coalesces concurrent same-key requests and rejects conflicting bodies", async () => {
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

  it("denies cross-agent and caller-supplied transaction fields", async () => {
    const { app } = await buildApp({ simulator: { ok: true } });
    const cross = await postPrepare(app, requestBody(OTHER_AGENT_ID));
    expect(cross.status).toBe(403);

    const smuggled = await postPrepare(app, { ...requestBody(), target: TARGET } as never);
    expect(smuggled.status).toBe(400);
  });

  it("SEC-185: rejects slippageBps at or above the 5000 bps doctrine", async () => {
    const { app } = await buildApp({ simulator: { ok: true } });
    for (const slippageBps of [5_000, 10_000]) {
      const res = await postPrepare(app, { ...requestBody(), slippageBps });
      expect(res.status).toBe(400);
    }
    // The doctrine boundary is exclusive; the highest sane value still passes.
    const ok = await postPrepare(app, { ...requestBody(), slippageBps: 4_999 });
    expect(ok.status).toBe(200);
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
});
