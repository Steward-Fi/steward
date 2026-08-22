import { afterAll, describe, expect, mock, test } from "bun:test";
import {
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  writeAuditEvent,
} from "@stwd/db";
import { and, asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";

const PLATFORM_KEY = "stw_platform_real_pg_transfer";
const HAS_REAL_PG =
  Boolean(process.env.DATABASE_URL) && process.env.STEWARD_PGLITE_MEMORY !== "true";
const submitCalls: unknown[] = [];
let submitError: Error | undefined;

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
  async signSendAsset(params: Record<string, unknown>) {
    return { action: { type: "sendAsset", ...params }, nonce: 1, signature: { value: "signed" } };
  }

  async submitSendAsset(signed: unknown) {
    submitCalls.push(signed);
    if (submitError) throw submitError;
    return { status: "ok", response: { type: "default" } };
  }
}

mock.module("@stwd/venue-hyperliquid", () => ({
  HyperliquidAdapter: MockHyperliquidAdapter,
  getMarketableLimitPx: async () => "1",
  hyperliquidAssetSchema: z.union([
    z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"]),
    z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/),
  ]),
  isBuilderPerpSymbol: (coin: string) => /^[a-z0-9]+:[A-Z0-9]+$/.test(coin),
  validateBuilderFeeEnv: () => undefined,
}));

process.env.STEWARD_AUDIT_HMAC_KEY ??= "operator-transfer-real-pg-audit-hmac-key-0123456789abcdef";

async function seed() {
  const suffix = `${Date.now()}-${crypto.randomUUID().slice(0, 8)}`;
  const tenantId = `transfer-pg-tenant-${suffix}`;
  const agentId = `transfer-pg-agent-${suffix}`;
  await getDb()
    .insert(tenants)
    .values({
      id: tenantId,
      name: "Transfer real PG",
      apiKeyHash: `hash-${suffix}`,
    });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "Transfer Agent",
    walletAddress: "0x00000000000000000000000000000000000000aa",
  });
  await getDb().insert(agentWallets).values({
    agentId,
    chainFamily: "evm",
    address: "0x00000000000000000000000000000000000000bb",
    venue: "hyperliquid",
    purpose: "perp",
  });
  return { tenantId, agentId };
}

async function buildApp(failAuditAction?: string) {
  const { tradingPlugin } = await import("../index");
  const app = new Hono();
  const ctx = {
    db: getDb(),
    vault: {
      getWallet: async () => ({ address: "0x00000000000000000000000000000000000000bb" }),
    },
    ensureAgentForTenant: async (tenantId: string, agentId: string) => ({ id: agentId, tenantId }),
    getPolicySet: async () => [],
    isValidAnyAddress: () => true,
    policyEngine: { evaluate: async () => ({ approved: true, results: [] }) },
    priceOracle: {
      getNativeUsdPrice: async () => 1,
      weiToUsd: async () => 0,
      usdToWei: async () => "0",
    },
    safeJsonParse: async (c: { req: { json: () => Promise<unknown> } }) => c.req.json(),
    writeAuditEvent: async (event: Parameters<typeof writeAuditEvent>[0]) => {
      if (event.action === failAuditAction) throw new Error("forced terminal audit failure");
      await writeAuditEvent(event);
    },
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
      if (c.req.header("X-Steward-Platform-Key") !== PLATFORM_KEY) {
        return c.json({ ok: false, error: "Invalid platform key" }, 403);
      }
      c.set("authType", "platform");
      return next();
    },
  } as never;
  tradingPlugin.register(app as never, ctx);
  return app;
}

function transfer(app: Hono, tenantId: string, agentId: string, idempotencyKey: string) {
  return app.request("/v1/trade/hyperliquid/transfer", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Tenant": tenantId,
      "X-Steward-Platform-Key": PLATFORM_KEY,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      agentId,
      sourceDex: "xyz",
      destinationDex: "",
      amountUsdc: "7.5",
    }),
  });
}

async function actions(tenantId: string, agentId: string) {
  return getDb()
    .select({ action: auditEvents.action, metadata: auditEvents.metadata })
    .from(auditEvents)
    .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.resourceId, agentId)))
    .orderBy(asc(auditEvents.seq));
}

afterAll(async () => {
  if (HAS_REAL_PG) await closeDb();
});

describe.skipIf(!HAS_REAL_PG)("collateral transfer durable replay on real PostgreSQL", () => {
  test("cold workers replay terminal success and ambiguous failure from chained audit evidence", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const success = await seed();
    const first = await transfer(await buildApp(), success.tenantId, success.agentId, "pg-success");
    const replay = await transfer(
      await buildApp(),
      success.tenantId,
      success.agentId,
      "pg-success",
    );
    expect(first.status).toBe(200);
    expect(replay.status).toBe(200);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitCalls).toHaveLength(1);
    expect((await actions(success.tenantId, success.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
      "trade.recovery.transfer.submitted",
    ]);

    submitCalls.length = 0;
    submitError = new Error("transport status unknown secret marker");
    const ambiguous = await seed();
    const failed = await transfer(
      await buildApp(),
      ambiguous.tenantId,
      ambiguous.agentId,
      "pg-ambiguous",
    );
    const failedReplay = await transfer(
      await buildApp(),
      ambiguous.tenantId,
      ambiguous.agentId,
      "pg-ambiguous",
    );
    expect(failed.status).toBe(502);
    expect(failedReplay.status).toBe(502);
    expect(failedReplay.headers.get("Idempotency-Replayed")).toBe("true");
    expect(submitCalls).toHaveLength(1);
    const ambiguousAudits = await actions(ambiguous.tenantId, ambiguous.agentId);
    expect(ambiguousAudits.at(-1)?.metadata).toEqual(
      expect.objectContaining({ ambiguousOutcome: true, phase: "submit" }),
    );
    expect(JSON.stringify(ambiguousAudits)).not.toContain("secret marker");
  });

  test("a terminal audit outage leaves durable pending evidence that prevents a cold resubmit", async () => {
    submitCalls.length = 0;
    submitError = undefined;
    const seeded = await seed();
    const first = await transfer(
      await buildApp("trade.recovery.transfer.submitted"),
      seeded.tenantId,
      seeded.agentId,
      "pg-audit-outage",
    );
    expect(first.status).toBe(200);
    const coldRetry = await transfer(
      await buildApp("trade.recovery.transfer.submitted"),
      seeded.tenantId,
      seeded.agentId,
      "pg-audit-outage",
    );
    expect(coldRetry.status).toBe(409);
    expect(coldRetry.headers.get("Retry-After")).toBe("60");
    expect(submitCalls).toHaveLength(1);
    expect((await actions(seeded.tenantId, seeded.agentId)).map(({ action }) => action)).toEqual([
      "trade.recovery.transfer.requested",
    ]);
  });
});
