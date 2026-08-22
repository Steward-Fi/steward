/**
 * operator-recovery.test.ts: Operator close-all + withdraw endpoint tests.
 *
 * Covers:
 *   - auth: no key → 401, wrong platform key → 403, valid platform key → proceeds
 *   - withdraw with destination NOT in approved-addresses → policy-violation
 *   - happy-path close-all + withdraw with a MOCKED adapter (no network),
 *     asserting closeAllPositions / signWithdraw are invoked.
 *
 * The HyperliquidAdapter is mocked via `mock.module` so no real signing or
 * network I/O occurs. The vault never signs because the adapter is replaced.
 */

import { afterAll, beforeAll, describe, expect, it, mock, setDefaultTimeout } from "bun:test";
import {
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  getDb,
  policies as policiesTable,
  tenants,
  writeAuditEvent,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { verifyAuditChain } from "../../../api/src/services/audit";

const PLATFORM_KEY = "stw_platform_test_operator_key";
setDefaultTimeout(30_000);

// ── Mock the Hyperliquid adapter (no signing / no network) ─────────────────────
const closeAllCalls: number[] = [];
const signWithdrawCalls: Array<{ amount: string | number; destination: string }> = [];
const submitWithdrawCalls: unknown[] = [];
const updateLeverageCalls: Array<{ coin: string; leverage: number; isCross?: boolean }> = [];
const addIsolatedMarginCalls: Array<{ coin: string; amountUsdc: string | number }> = [];
const approveBuilderFeeCalls: Array<{ builder: string; maxFeeRate: string }> = [];
const usdSendCalls: Array<{ destination: string; amount: string }> = [];
const signSendAssetCalls: Array<{
  destination: string;
  sourceDex: string;
  destinationDex: string;
  token?: string;
  amount: string | number;
}> = [];
const submitSendAssetCalls: unknown[] = [];
let signSendAssetError: Error | undefined;
let submitSendAssetError: Error | undefined;
let closeAllPause: Promise<void> | null = null;

mock.module("@stwd/policy-engine", () => ({
  aggregationLookupFromMap: () => undefined,
  aggregationQueriesForPolicies: () => [],
  aggregationQueryKey: () => "unused",
  assetAllowlistEvaluator: () => ({ passed: true }),
  evaluateTradeOrder: () => ({ approved: true, results: [] }),
  tradeLeverageCapEvaluator: () => ({ passed: true }),
  tradeVenueAllowlistEvaluator: () => ({ passed: true }),
}));

class MockHyperliquidAdapter {
  constructor(
    public vault: unknown,
    public agentId: string,
    public walletAddress: string,
  ) {}

  async closeAllPositions() {
    closeAllCalls.push(Date.now());
    await closeAllPause;
    return [
      { coin: "BTC", result: { status: "filled", orderId: "1001" } },
      { coin: "ETH", result: { status: "filled", orderId: "1002" } },
    ];
  }

  async signWithdraw(params: { amount: string | number; destination: string }) {
    signWithdrawCalls.push(params);
    return {
      action: { type: "withdraw3", destination: params.destination },
      nonce: 1,
      signature: { r: "0x1", s: "0x2", v: 27 },
    };
  }

  async submitWithdraw(signed: unknown) {
    submitWithdrawCalls.push(signed);
    return { status: "ok", response: { type: "default" } };
  }

  async updateLeverage(params: { coin: string; leverage: number; isCross?: boolean }) {
    updateLeverageCalls.push(params);
    return { status: "ok", raw: { response: { type: "default" } } };
  }

  async addIsolatedMargin(params: { coin: string; amountUsdc: string | number }) {
    addIsolatedMarginCalls.push(params);
    return { status: "ok", raw: { response: { type: "default" } } };
  }

  async approveBuilderFee(params: { builder: string; maxFeeRate: string }) {
    approveBuilderFeeCalls.push(params);
    return { status: "ok", raw: { response: { type: "default" } } };
  }

  async signUsdSend(params: { destination: string; amount: string }) {
    return params;
  }

  async submitUsdSend(params: { destination: string; amount: string }) {
    usdSendCalls.push(params);
    return { status: "ok", raw: { response: { type: "default" } } };
  }

  async signSendAsset(params: {
    destination: string;
    sourceDex: string;
    destinationDex: string;
    token?: string;
    amount: string | number;
  }) {
    signSendAssetCalls.push(params);
    if (signSendAssetError) throw signSendAssetError;
    return {
      action: {
        type: "sendAsset",
        destination: params.destination,
        sourceDex: params.sourceDex,
        destinationDex: params.destinationDex,
        amount: params.amount,
      },
      nonce: 1,
      signature: { r: "0x1", s: "0x2", v: 27 },
    };
  }

  async submitSendAsset(signed: unknown) {
    submitSendAssetCalls.push(signed);
    if (submitSendAssetError) throw submitSendAssetError;
    return { status: "ok", response: { type: "default" } };
  }
}

mock.module("@stwd/venue-hyperliquid", () => ({
  HyperliquidAdapter: MockHyperliquidAdapter,
  hyperliquidAssetSchema: z.union([
    z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"]),
    z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/),
  ]),
  isBuilderPerpSymbol: (coin: string) => /^[a-z0-9]+:[A-Z0-9]+$/.test(coin),
  getMarketableLimitPx: async () => "1",
  validateBuilderFeeEnv: () => undefined,
}));

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "test-audit-hmac-key-operator-recovery";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

async function seedAgent(opts: {
  tenantId: string;
  agentId: string;
  approvedAddresses?: string[];
}) {
  // api_key_hash and owner_address are unique per tenant,
  // so derive them from the tenant id rather than reusing fixed values.
  await getDb()
    .insert(tenants)
    .values({
      id: opts.tenantId,
      name: "Operator Recovery Tenant",
      apiKeyHash: `test-hash-${opts.tenantId}`,
      ownerAddress: `0x${opts.tenantId
        .replace(/[^a-fA-F0-9]/g, "")
        .padEnd(40, "0")
        .slice(0, 40)}`,
    });
  await getDb().insert(agents).values({
    id: opts.agentId,
    tenantId: opts.tenantId,
    name: "Recovery Agent",
    walletAddress: "0x00000000000000000000000000000000000000aa",
  });
  await getDb().insert(agentWallets).values({
    agentId: opts.agentId,
    chainFamily: "evm",
    address: "0x00000000000000000000000000000000000000bb",
    venue: "hyperliquid",
    purpose: "perp",
  });
  if (opts.approvedAddresses) {
    await getDb()
      .insert(policiesTable)
      .values({
        id: `pol_${opts.agentId}`,
        agentId: opts.agentId,
        type: "approved-addresses",
        enabled: true,
        config: { mode: "whitelist", addresses: opts.approvedAddresses },
      });
  }
}

/**
 * Build a Hono app that wires the operator gate exactly like app.ts:
 * platform key OR tenant-admin (here we only exercise the platform-key arm
 * plus the unauthenticated/wrong-key rejections, which is what production
 * operator recovery uses).
 */
async function buildApp() {
  const { isValidPlatformKey } = await import("@stwd/auth");
  const { createOperatorRecoveryRoutes } = await import("../routes/operator-recovery");
  const { testCtx } = await import("./_ctx");
  const app = new Hono();
  app.use("/v1/trade/*", async (c, next) => {
    const key = c.req.header("X-Steward-Platform-Key");
    if (!key) {
      return c.json({ ok: false, error: "X-Steward-Platform-Key header is required" }, 401);
    }
    if (!isValidPlatformKey(key)) {
      return c.json({ ok: false, error: "Invalid platform key" }, 403);
    }
    const tenantId = c.req.header("X-Steward-Tenant") || "default";
    c.set("tenantId", tenantId);
    c.set("authType", "platform");
    return next();
  });
  app.route("/v1/trade", createOperatorRecoveryRoutes(testCtx()));
  return app;
}

async function buildTransferApp(failAuditAction?: string) {
  const { tradingPlugin } = await import("../index");
  const baseWriteAuditEvent = writeAuditEvent;
  const app = new Hono();
  const ctx = {
    db: getDb(),
    vault: {
      getWallet: async () => ({
        address: "0x00000000000000000000000000000000000000bb",
      }),
    },
    ensureAgentForTenant: async (tenantId: string, agentId: string) => ({
      id: agentId,
      tenantId,
    }),
    getPolicySet: async () => [],
    isValidAnyAddress: () => true,
    policyEngine: { evaluate: async () => ({ approved: true, results: [] }) },
    priceOracle: {
      getNativeUsdPrice: async () => 1,
      weiToUsd: async () => 0,
      usdToWei: async () => "0",
    },
    safeJsonParse: async (c: { req: { json: () => Promise<unknown> } }) => c.req.json(),
    writeAuditEvent: async (event) => {
      if (event.action === failAuditAction) throw new Error("forced completion audit failure");
      await baseWriteAuditEvent(event);
    },
    verifyAuditChain,
    getRedisClient: () => null,
    requireAgentJwt: async (_c: unknown, next: () => Promise<void>) => next(),
    tenantAuth: async (_c: unknown, next: () => Promise<void>) => next(),
    operatorAuth: async (
      c: {
        req: { header: (name: string) => string | undefined };
        set: (key: string, value: unknown) => void;
        json: (body: unknown, status: number) => Response;
      },
      next: () => Promise<void>,
    ) => {
      c.set("tenantId", c.req.header("X-Steward-Tenant") || "default");
      if (c.req.header("X-Steward-Platform-Key") === PLATFORM_KEY) {
        c.set("authType", "platform");
        return next();
      }
      if (c.req.header("X-Steward-Key")) c.set("authType", "api-key");
      else if (c.req.header("Authorization") === "Bearer owner-session") {
        c.set("authType", "session-jwt");
        c.set("userId", "owner-user");
      } else if (c.req.header("Authorization") === "Bearer agent-session") {
        c.set("authType", "agent-token");
        c.set("agentScope", "agent-scope");
      } else {
        return c.json({ ok: false, error: "Operator credentials required" }, 401);
      }
      return next();
    },
  } as never;
  tradingPlugin.register(app as never, ctx);
  return app;
}

function resetSendAssetMock(): void {
  signSendAssetCalls.length = 0;
  submitSendAssetCalls.length = 0;
  signSendAssetError = undefined;
  submitSendAssetError = undefined;
}

function transferRequest(
  app: Hono,
  tenantId: string,
  agentId: string,
  options: {
    idempotencyKey: string;
    sourceDex?: string;
    destinationDex?: string;
    token?: string;
    credential?: "platform" | "api-key" | "session-jwt" | "agent-token";
  },
) {
  const credentialHeaders =
    options.credential === "api-key"
      ? { "X-Steward-Key": "tenant-admin-key" }
      : options.credential === "session-jwt"
        ? { Authorization: "Bearer owner-session" }
        : options.credential === "agent-token"
          ? { Authorization: "Bearer agent-session" }
          : { "X-Steward-Platform-Key": PLATFORM_KEY };
  return app.request("/v1/trade/hyperliquid/transfer", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Tenant": tenantId,
      "Idempotency-Key": options.idempotencyKey,
      ...credentialHeaders,
    },
    body: JSON.stringify({
      agentId,
      sourceDex: options.sourceDex ?? "xyz",
      destinationDex: options.destinationDex ?? "",
      amountUsdc: "12.5",
      token: options.token,
    }),
  });
}

async function transferAudits(tenantId: string, agentId: string) {
  return getDb()
    .select({
      action: auditEvents.action,
      actorType: auditEvents.actorType,
      actorId: auditEvents.actorId,
      resourceType: auditEvents.resourceType,
      resourceId: auditEvents.resourceId,
      metadata: auditEvents.metadata,
    })
    .from(auditEvents)
    .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.resourceId, agentId)))
    .orderBy(asc(auditEvents.seq));
}

async function transferAuditActions(tenantId: string, agentId: string): Promise<string[]> {
  const rows = await transferAudits(tenantId, agentId);
  return rows.map(({ action }) => action).filter((action) => action.includes("recovery.transfer"));
}

describe("operator recovery auth", () => {
  it("rejects close-all with no auth (401)", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/close-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agentId: "agent-x" }),
    });
    expect(res.status).toBe(401);
  });

  it("rejects close-all with a wrong platform key (403)", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/close-all", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": "stw_platform_wrong_key",
      },
      body: JSON.stringify({ agentId: "agent-x" }),
    });
    expect(res.status).toBe(403);
  });
});

describe("mounted HIP-3 collateral transfer", () => {
  it.each([
    "api-key",
    "session-jwt",
    "agent-token",
  ] as const)("rejects %s authority before adapter calls", async (authType) => {
    resetSendAssetMock();
    const app = await buildTransferApp();
    const response = await transferRequest(app, "tenant-denied", "agent-denied", {
      idempotencyKey: `denied-${authType}`,
      credential: authType,
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      ok: false,
      error: "Platform key required for collateral transfer",
    });
    expect(signSendAssetCalls).toHaveLength(0);
    expect(submitSendAssetCalls).toHaveLength(0);
  });

  it.each([
    ["builder exit", "xyz", "", undefined],
    ["core allocation", "", "xyz", "USDC"],
  ] as const)("binds exact adapter inputs for %s", async (_name, sourceDex, destinationDex, token) => {
    resetSendAssetMock();
    const tenantId = `tenant-transfer-${Date.now()}-${sourceDex || "core"}`;
    const agentId = `agent-transfer-${Date.now()}-${sourceDex || "core"}`;
    await seedAgent({ tenantId, agentId });
    const app = await buildTransferApp();

    const response = await transferRequest(app, tenantId, agentId, {
      idempotencyKey: `transfer-${sourceDex || "core"}-${destinationDex || "core"}`,
      sourceDex,
      destinationDex,
      token,
    });

    expect(response.status).toBe(200);
    expect(signSendAssetCalls).toEqual([
      {
        destination: "0x00000000000000000000000000000000000000bb",
        sourceDex,
        destinationDex,
        token,
        amount: "12.5",
      },
    ]);
    expect(submitSendAssetCalls).toEqual([
      {
        action: {
          type: "sendAsset",
          destination: "0x00000000000000000000000000000000000000bb",
          sourceDex,
          destinationDex,
          amount: "12.5",
        },
        nonce: 1,
        signature: { r: "0x1", s: "0x2", v: 27 },
      },
    ]);
    const replayApp = await buildTransferApp();
    const replay = await transferRequest(replayApp, tenantId, agentId, {
      idempotencyKey: `transfer-${sourceDex || "core"}-${destinationDex || "core"}`,
      sourceDex,
      destinationDex,
      token,
    });
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitSendAssetCalls).toHaveLength(1);
    expect(await transferAuditActions(tenantId, agentId)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.submitted",
    ]);
    const audits = await transferAudits(tenantId, agentId);
    expect(audits).toEqual([
      expect.objectContaining({
        action: "trade.recovery.transfer.requested",
        actorType: "platform",
        actorId: "platform-operator",
        resourceType: "trade",
        resourceId: agentId,
        metadata: expect.objectContaining({
          idempotencyKey: `transfer-${sourceDex || "core"}-${destinationDex || "core"}`,
          requestFingerprint: expect.stringMatching(/^[0-9a-f]{64}$/),
          amountBaseUnits: "12500000",
          outcome: "submission_pending",
        }),
      }),
      expect.objectContaining({
        action: "trade.recovery.transfer.submitted",
        actorType: "platform",
        actorId: "platform-operator",
        resourceType: "trade",
        resourceId: agentId,
        metadata: expect.objectContaining({
          amountBaseUnits: "12500000",
          response: expect.objectContaining({ sourceDex, destinationDex, amountUsdc: "12.5" }),
          action: expect.objectContaining({ type: "sendAsset" }),
        }),
      }),
    ]);
  });

  it("releases a local signing failure for a safe retry and records failed audit state", async () => {
    resetSendAssetMock();
    const tenantId = `tenant-transfer-sign-${Date.now()}`;
    const agentId = `agent-transfer-sign-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    signSendAssetError = new Error("signing secret marker");
    const app = await buildTransferApp();
    const request = () =>
      transferRequest(app, tenantId, agentId, { idempotencyKey: "transfer-sign-failure" });

    expect((await request()).status).toBe(502);
    expect((await request()).status).toBe(502);
    expect(signSendAssetCalls).toHaveLength(2);
    expect(submitSendAssetCalls).toHaveLength(0);
    expect(await transferAuditActions(tenantId, agentId)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.failed",
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.failed",
    ]);
    expect(JSON.stringify(await transferAudits(tenantId, agentId))).not.toContain(
      "signing secret marker",
    );
  });

  it("releases a definite venue rejection but replays ambiguous transport loss", async () => {
    resetSendAssetMock();
    const rejectedTenant = `tenant-transfer-rejected-${Date.now()}`;
    const rejectedAgent = `agent-transfer-rejected-${Date.now()}`;
    await seedAgent({ tenantId: rejectedTenant, agentId: rejectedAgent });
    const rejected = new Error("venue rejected");
    rejected.name = "HyperliquidExchangeRejectedError";
    submitSendAssetError = rejected;
    const rejectedApp = await buildTransferApp();
    const rejectedRequest = () =>
      transferRequest(rejectedApp, rejectedTenant, rejectedAgent, {
        idempotencyKey: "definite-rejection",
      });

    expect(await (await rejectedRequest()).json()).toEqual({
      ok: false,
      error: "Hyperliquid rejected collateral transfer",
    });
    expect((await rejectedRequest()).status).toBe(502);
    expect(submitSendAssetCalls).toHaveLength(2);
    const rejectedAudits = await transferAudits(rejectedTenant, rejectedAgent);
    expect(rejectedAudits.at(-1)?.metadata).toEqual(
      expect.objectContaining({
        definiteRejection: true,
        ambiguousOutcome: false,
        phase: "submit",
      }),
    );
    expect(JSON.stringify(rejectedAudits)).not.toContain("venue rejected");

    resetSendAssetMock();
    const ambiguousTenant = `tenant-transfer-ambiguous-${Date.now()}`;
    const ambiguousAgent = `agent-transfer-ambiguous-${Date.now()}`;
    await seedAgent({ tenantId: ambiguousTenant, agentId: ambiguousAgent });
    submitSendAssetError = new Error("transport lost after write");
    const ambiguousApp = await buildTransferApp();
    const ambiguousRequest = () =>
      transferRequest(ambiguousApp, ambiguousTenant, ambiguousAgent, {
        idempotencyKey: "ambiguous-loss",
      });

    const first = await ambiguousRequest();
    const durableReplayApp = await buildTransferApp();
    const retry = await transferRequest(durableReplayApp, ambiguousTenant, ambiguousAgent, {
      idempotencyKey: "ambiguous-loss",
    });
    expect(first.status).toBe(502);
    expect(await first.json()).toEqual({
      ok: false,
      error: "Failed to submit collateral transfer",
    });
    expect(retry.status).toBe(502);
    expect(await retry.json()).toEqual({
      ok: false,
      error: "Failed to submit collateral transfer",
    });
    expect(signSendAssetCalls).toHaveLength(1);
    expect(submitSendAssetCalls).toHaveLength(1);
    expect(await transferAuditActions(ambiguousTenant, ambiguousAgent)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.failed",
    ]);
    const ambiguousAudits = await transferAudits(ambiguousTenant, ambiguousAgent);
    expect(ambiguousAudits.at(-1)?.metadata).toEqual(
      expect.objectContaining({
        definiteRejection: false,
        ambiguousOutcome: true,
        phase: "submit",
      }),
    );
    expect(JSON.stringify(ambiguousAudits)).not.toContain("transport lost after write");
  });

  it("replays terminal success when the completion audit fails after venue submission", async () => {
    resetSendAssetMock();
    const tenantId = `tenant-transfer-audit-${Date.now()}`;
    const agentId = `agent-transfer-audit-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    const app = await buildTransferApp("trade.recovery.transfer.submitted");
    const request = () =>
      transferRequest(app, tenantId, agentId, { idempotencyKey: "completion-audit-failure" });

    const first = await request();
    const retry = await request();
    expect(first.status).toBe(200);
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual(await first.json());
    expect(signSendAssetCalls).toHaveLength(1);
    expect(submitSendAssetCalls).toHaveLength(1);
    expect(await transferAuditActions(tenantId, agentId)).toEqual([
      "trade.recovery.transfer.requested",
    ]);
    const coldReplayApp = await buildTransferApp("trade.recovery.transfer.submitted");
    const coldReplay = await transferRequest(coldReplayApp, tenantId, agentId, {
      idempotencyKey: "completion-audit-failure",
    });
    expect(coldReplay.status).toBe(409);
    expect(coldReplay.headers.get("Retry-After")).toBe("60");
    expect(await coldReplay.json()).toEqual({
      ok: false,
      error: "Collateral transfer outcome requires reconciliation",
    });
    expect(submitSendAssetCalls).toHaveLength(1);
  });

  it("fails closed instead of replaying tampered durable audit evidence", async () => {
    resetSendAssetMock();
    const tenantId = `tenant-transfer-tamper-${Date.now()}`;
    const agentId = `agent-transfer-tamper-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    const idempotencyKey = "tampered-replay";
    const first = await transferRequest(await buildTransferApp(), tenantId, agentId, {
      idempotencyKey,
    });
    expect(first.status).toBe(200);

    const durableAudits = await transferAudits(tenantId, agentId);
    const submitted = durableAudits.at(-1);
    expect(submitted?.action).toBe("trade.recovery.transfer.submitted");
    await getDb()
      .update(auditEvents)
      .set({
        metadata: {
          ...submitted?.metadata,
          response: { forged: true },
        },
      })
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          eq(auditEvents.action, "trade.recovery.transfer.submitted"),
        ),
      );

    const replay = await transferRequest(await buildTransferApp(), tenantId, agentId, {
      idempotencyKey,
    });
    expect(replay.status).toBe(503);
    expect(await replay.json()).toEqual({
      ok: false,
      error: "Collateral transfer replay evidence is unavailable",
    });
    expect(submitSendAssetCalls).toHaveLength(1);
  });
});

describe("operator recovery leverage", () => {
  it("rejects leverage updates without a valid platform key", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/leverage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agentId: "agent-x", coin: "xyz:SPCX", leverage: 10 }),
    });
    expect(res.status).toBe(401);
  });

  it("clamps builder-perp leverage to 3x isolated and returns the adapter result", async () => {
    const tenantId = `tenant-lev-ok-${Date.now()}`;
    const agentId = `agent-lev-ok-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    updateLeverageCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/leverage", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({ agentId, coin: "xyz:SPCX", leverage: 10, isCross: true }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { leverage: number; isCross: boolean };
    };
    expect(body.ok).toBe(true);
    expect(body.data.leverage).toBe(3);
    expect(body.data.isCross).toBe(false);
    expect(updateLeverageCalls).toEqual([{ coin: "xyz:SPCX", leverage: 3, isCross: false }]);
  });
});

describe("operator recovery usd-send", () => {
  it("rejects usd-send without a valid platform key", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/usd-send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId: "agent-x",
        destination: "0xabcdef0123456789abcdef0123456789abcdef01",
        amount: "100",
      }),
    });
    expect(res.status).toBe(401);
  });

  it("submits usdSend through the platform-gated adapter path", async () => {
    const tenantId = `tenant-usdsend-ok-${Date.now()}`;
    const agentId = `agent-usdsend-ok-${Date.now()}`;
    // SEC-004: usd-send is a withdrawal rail and now runs the same policy gate
    // as /withdraw — the destination must be on the agent's approved list.
    const destination = "0xABCDEF0123456789abcdef0123456789ABCDEF01";
    await seedAgent({ tenantId, agentId, approvedAddresses: [destination] });
    usdSendCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/usd-send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": "usd-send-once",
      },
      body: JSON.stringify({
        agentId,
        destination: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
        amount: "100",
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { destination: string; amount: string; result: { status: string } };
    };
    expect(body.ok).toBe(true);
    expect(body.data.destination).toBe("0xabcdef0123456789abcdef0123456789abcdef01");
    expect(body.data.amount).toBe("100");
    expect(body.data.result.status).toBe("ok");
    expect(usdSendCalls).toEqual([
      { destination: "0xabcdef0123456789abcdef0123456789abcdef01", amount: "100" },
    ]);
  });
});

describe("operator recovery approve-builder", () => {
  it("rejects approve-builder without a valid platform key", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/approve-builder", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId: "agent-x",
        builder: "0xabcdef0123456789abcdef0123456789abcdef01",
        maxFeeRate: "0.1%",
      }),
    });
    expect(res.status).toBe(401);
  });

  it("approves a builder fee through the platform-gated adapter path", async () => {
    const tenantId = `tenant-builder-ok-${Date.now()}`;
    const agentId = `agent-builder-ok-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    approveBuilderFeeCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/approve-builder", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": "builder-approve-once",
      },
      body: JSON.stringify({
        agentId,
        builder: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
        maxFeeRate: "0.1%",
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { builder: string; maxFeeRate: string; result: { status: string } };
    };
    expect(body.ok).toBe(true);
    expect(body.data.builder).toBe("0xabcdef0123456789abcdef0123456789abcdef01");
    expect(body.data.maxFeeRate).toBe("0.1%");
    expect(body.data.result.status).toBe("ok");
    expect(approveBuilderFeeCalls).toEqual([
      { builder: "0xabcdef0123456789abcdef0123456789abcdef01", maxFeeRate: "0.1%" },
    ]);
  });

  it("rejects an excessive builder fee before calling the adapter", async () => {
    const tenantId = `tenant-builder-cap-${Date.now()}`;
    const agentId = `agent-builder-cap-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    approveBuilderFeeCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/approve-builder", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
      },
      body: JSON.stringify({
        agentId,
        builder: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
        maxFeeRate: "100%",
      }),
    });

    expect(res.status).toBe(400);
    expect(approveBuilderFeeCalls).toHaveLength(0);
  });
});

describe("operator recovery add-margin", () => {
  it("requires idempotency keys for every operator fund movement", async () => {
    const tenantId = `tenant-required-idempotency-${Date.now()}`;
    const app = await buildApp();
    const cases = [
      {
        path: "/v1/trade/hyperliquid/deposit",
        body: { agentId: "missing-agent", amount: "5" },
      },
      {
        path: "/v1/trade/hyperliquid/add-margin",
        body: { agentId: "missing-agent", coin: "xyz:SPCX", amountUsdc: "1" },
      },
      {
        path: "/v1/trade/hyperliquid/transfer",
        body: {
          agentId: "missing-agent",
          sourceDex: "xyz",
          destinationDex: "",
          amountUsdc: "1",
        },
      },
    ] as const;

    for (const testCase of cases) {
      const res = await app.request(testCase.path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Steward-Platform-Key": PLATFORM_KEY,
          "X-Steward-Tenant": tenantId,
        },
        body: JSON.stringify(testCase.body),
      });

      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        ok: false,
        error: "Idempotency-Key is required and must be at most 256 characters",
      });
    }
  });

  it("rejects add-margin without a valid platform key", async () => {
    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/add-margin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agentId: "agent-x", coin: "xyz:SPCX", amountUsdc: "25" }),
    });
    expect(res.status).toBe(401);
  });

  it("adds isolated margin through the platform-gated adapter path", async () => {
    const tenantId = `tenant-margin-ok-${Date.now()}`;
    const agentId = `agent-margin-ok-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    addIsolatedMarginCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/add-margin", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `margin-${agentId}`,
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
      },
      body: JSON.stringify({ agentId, coin: "xyz:SPCX", amountUsdc: "25.5" }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { coin: string; amountUsdc: string; amountBaseUnits: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.coin).toBe("xyz:SPCX");
    expect(body.data.amountUsdc).toBe("25.5");
    expect(body.data.amountBaseUnits).toBe("25500000");
    expect(addIsolatedMarginCalls).toEqual([{ coin: "xyz:SPCX", amountUsdc: "25.5" }]);
  });
});

describe("operator recovery close-all", () => {
  it("closes all positions with a valid platform key and audits each close", async () => {
    const tenantId = `tenant-close-${Date.now()}`;
    const agentId = `agent-close-${Date.now()}`;
    await seedAgent({ tenantId, agentId });
    closeAllCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/close-all", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
      },
      body: JSON.stringify({ agentId }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { closed: unknown[] } };
    expect(body.ok).toBe(true);
    expect(body.data.closed).toHaveLength(2);
    expect(closeAllCalls.length).toBe(1);
  });

  it("admits only one concurrent request for the same idempotency key", async () => {
    const tenantId = `tenant-close-concurrent-${crypto.randomUUID()}`;
    const agentId = `agent-close-concurrent-${crypto.randomUUID()}`;
    await seedAgent({ tenantId, agentId });
    const app = await buildApp();
    closeAllCalls.length = 0;

    let releaseFirst!: () => void;
    closeAllPause = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const request = () =>
      app.request("/v1/trade/hyperliquid/close-all", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Steward-Platform-Key": PLATFORM_KEY,
          "X-Steward-Tenant": tenantId,
          "Idempotency-Key": "same-concurrent-key",
        },
        body: JSON.stringify({ agentId }),
      });

    const first = request();
    while (closeAllCalls.length === 0) await Bun.sleep(1);
    const second = await request();
    expect(second.status).toBe(409);
    expect(second.headers.get("Retry-After")).toBe("1");
    expect(await second.json()).toEqual({
      ok: false,
      error: "Request with this idempotency key is in progress",
    });
    expect(closeAllCalls).toHaveLength(1);

    releaseFirst();
    expect((await first).status).toBe(200);
    closeAllPause = null;
  });
});

describe("operator recovery withdraw", () => {
  it("rejects a withdraw to a destination NOT in approved-addresses", async () => {
    const tenantId = `tenant-wd-bad-${Date.now()}`;
    const agentId = `agent-wd-bad-${Date.now()}`;
    const approved = "0x1111111111111111111111111111111111111111";
    const badDest = "0x2222222222222222222222222222222222222222";
    await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
    signWithdrawCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/withdraw", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({ agentId, amount: "100", destination: badDest }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: string; reason: string };
    expect(body.code).toBe("policy-violation");
    // Signing must never happen on a policy rejection.
    expect(signWithdrawCalls.length).toBe(0);
  });

  it("signs + submits a withdraw to an approved destination", async () => {
    const tenantId = `tenant-wd-ok-${Date.now()}`;
    const agentId = `agent-wd-ok-${Date.now()}`;
    const approved = "0x3333333333333333333333333333333333333333";
    await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;

    const app = await buildApp();
    const res = await app.request("/v1/trade/hyperliquid/withdraw", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify({ agentId, amount: "100", destination: approved }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { destination: string } };
    expect(body.ok).toBe(true);
    expect(body.data.destination).toBe(approved);
    expect(signWithdrawCalls.length).toBe(1);
    expect(signWithdrawCalls[0]).toMatchObject({ amount: "100", destination: approved });
    expect(submitWithdrawCalls.length).toBe(1);
  });

  it("returns cached success for a no-amount withdraw retry before reading a changed live balance", async () => {
    const tenantId = `tenant-wd-idem-${Date.now()}`;
    const agentId = `agent-wd-idem-${Date.now()}`;
    const approved = "0x4444444444444444444444444444444444444444";
    await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;

    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ withdrawable: fetchCalls === 1 ? "42" : "0" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }) as typeof fetch;

    try {
      const app = await buildApp();
      const headers = {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
        "X-Steward-Tenant": tenantId,
        "Idempotency-Key": `idem-${Date.now()}`,
      };
      const body = JSON.stringify({ agentId, destination: approved });

      const first = await app.request("/v1/trade/hyperliquid/withdraw", {
        method: "POST",
        headers,
        body,
      });
      expect(first.status).toBe(200);
      const firstJson = (await first.json()) as { ok: boolean; data: { amount: string } };
      expect(firstJson.ok).toBe(true);
      expect(firstJson.data.amount).toBe("42");

      const retry = await app.request("/v1/trade/hyperliquid/withdraw", {
        method: "POST",
        headers,
        body,
      });
      expect(retry.status).toBe(200);
      const retryJson = (await retry.json()) as { ok: boolean; data: { amount: string } };
      expect(retryJson).toEqual(firstJson);
      expect(fetchCalls).toBe(1);
      expect(signWithdrawCalls.length).toBe(1);
      expect(submitWithdrawCalls.length).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
