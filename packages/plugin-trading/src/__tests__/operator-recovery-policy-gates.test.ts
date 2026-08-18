/**
 * operator-recovery-policy-gates.test.ts — regression coverage for the operator
 * TRANSFER rail guardrails:
 *
 *   SEC-004 — /usd-send previously moved arbitrary USDC to any address with no
 *     policy gate, no per-call cap, and no rate limit. It now runs the same
 *     policy evaluation as /withdraw (approved-addresses + spend/rate caps),
 *     enforces the per-call 2000 USDC ceiling, and is rate limited.
 *   SEC-042 — /withdraw's policy evaluation was largely inert: recent-tx counts
 *     and spend counters were hardcoded to 0 (rate-limit + daily/weekly rules
 *     could never fire), and `value` was passed as 6-decimal USDC base units
 *     while the spending-limit evaluator prices `value` as native wei (so even
 *     per-tx USD caps never tripped). The gate now denominates `value` in wei
 *     via the price oracle and feeds real chain-scoped counters.
 *   SEC-043 — operator routes stored idempotency records only on success, so a
 *     retry of a possibly-landed submit re-executed. Ambiguous-outcome 502s are
 *     now stored and replayed.
 *
 * The HyperliquidAdapter is mocked (no signing / no network). The price oracle
 * is a deterministic stub injected via the plugin context.
 */

import { afterAll, beforeAll, describe, expect, it, mock, setDefaultTimeout } from "bun:test";
import {
  agents,
  agentWallets,
  closeDb,
  getDb,
  operatorTransferReservations,
  policies as policiesTable,
  tenants,
  transactions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { PriceOracle } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import type { StewardAppContext } from "../context";

const PLATFORM_KEY = "stw_platform_test_operator_gates_key";
const ARBITRUM_CHAIN_ID = 42161;
// Deterministic stub ETH price for the spending-limit denomination tests.
const STUB_ETH_USD = 4000;
setDefaultTimeout(30_000);

// ── Mock the Hyperliquid adapter (no signing / no network) ────────────────────
const signWithdrawCalls: Array<{ amount: string | number; destination: string }> = [];
const submitWithdrawCalls: unknown[] = [];
const usdSendCalls: Array<{ destination: string; amount: string }> = [];
let failNextSubmitWithdraw = false;
let rejectNextSubmitWithdraw = false;
let failNextSignUsdSend = false;

class MockHyperliquidExchangeRejectedError extends Error {
  readonly name = "HyperliquidExchangeRejectedError";
}

class MockHyperliquidAdapter {
  constructor(
    public vault: unknown,
    public agentId: string,
    public walletAddress: string,
  ) {}

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
    if (failNextSubmitWithdraw) {
      failNextSubmitWithdraw = false;
      throw new Error("simulated submit failure (may have landed)");
    }
    if (rejectNextSubmitWithdraw) {
      rejectNextSubmitWithdraw = false;
      throw new MockHyperliquidExchangeRejectedError("definite venue rejection");
    }
    return { status: "ok", response: { type: "default" } };
  }

  async signUsdSend(params: { destination: string; amount: string }) {
    if (failNextSignUsdSend) {
      failNextSignUsdSend = false;
      throw new Error("definite local signing failure");
    }
    return params;
  }

  async submitUsdSend(params: { destination: string; amount: string }) {
    usdSendCalls.push(params);
    return { status: "ok", raw: { response: { type: "default" } } };
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
}));

const stubPriceOracle: PriceOracle = {
  async getNativeUsdPrice() {
    return STUB_ETH_USD;
  },
  async getTokenUsdPrice() {
    return STUB_ETH_USD;
  },
  async weiToUsd(weiValue: string) {
    return (Number(BigInt(weiValue)) / 1e18) * STUB_ETH_USD;
  },
  async usdToWei(usdValue: number) {
    return BigInt(Math.floor((usdValue / STUB_ETH_USD) * 1e18)).toString();
  },
};

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "test-audit-hmac-key-operator-gates";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

let seedSeq = 0;
async function seedAgent(opts: {
  policies?: Array<{ type: string; config: Record<string, unknown> }>;
}): Promise<{ tenantId: string; agentId: string }> {
  seedSeq += 1;
  const tenantId = `tenant-gates-${Date.now()}-${seedSeq}`;
  const agentId = `agent-gates-${Date.now()}-${seedSeq}`;
  await getDb()
    .insert(tenants)
    .values({
      id: tenantId,
      name: "Operator Gates Tenant",
      apiKeyHash: `test-hash-${tenantId}`,
      ownerAddress: `0x${tenantId
        .replace(/[^a-fA-F0-9]/g, "")
        .padEnd(40, "0")
        .slice(0, 40)}`,
    });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "Gates Agent",
    walletAddress: "0x00000000000000000000000000000000000000aa",
  });
  await getDb().insert(agentWallets).values({
    agentId,
    chainFamily: "evm",
    address: "0x00000000000000000000000000000000000000bb",
    venue: "hyperliquid",
    purpose: "perp",
  });
  for (const [i, policy] of (opts.policies ?? []).entries()) {
    await getDb()
      .insert(policiesTable)
      .values({
        id: `pol_${agentId}_${i}`,
        agentId,
        type: policy.type,
        enabled: true,
        config: policy.config,
      });
  }
  return { tenantId, agentId };
}

async function buildApp(ctxOverrides: Partial<StewardAppContext> = {}) {
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
    c.set("tenantId", c.req.header("X-Steward-Tenant") || "default");
    c.set("authType", "platform");
    return next();
  });
  app.route("/v1/trade", createOperatorRecoveryRoutes({ ...testCtx(), ...ctxOverrides }));
  return app;
}

function postTransfer(
  app: Hono,
  rail: "withdraw" | "usd-send",
  tenantId: string,
  body: Record<string, unknown>,
  idempotencyKey?: string,
) {
  return app.request(`/v1/trade/hyperliquid/${rail}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
      "X-Steward-Tenant": tenantId,
      "Idempotency-Key": idempotencyKey ?? crypto.randomUUID(),
    },
    body: JSON.stringify(body),
  });
}

const DEST_A = "0x1111111111111111111111111111111111111111";
const DEST_B = "0x2222222222222222222222222222222222222222";

describe("SEC-004: usd-send policy gate + caps", () => {
  it("rejects a usd-send to a destination NOT in approved-addresses (no adapter call)", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    usdSendCalls.length = 0;
    const app = await buildApp();

    const res = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_B,
      amount: "100",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string };
    expect(body.code).toBe("policy-violation");
    expect(usdSendCalls).toHaveLength(0);
  });

  it("rejects a usd-send for an agent with NO policies (default-deny)", async () => {
    const { tenantId, agentId } = await seedAgent({});
    usdSendCalls.length = 0;
    const app = await buildApp();

    const res = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "100",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string };
    expect(body.code).toBe("policy-violation");
    expect(usdSendCalls).toHaveLength(0);
  });

  it("rejects a usd-send above the per-call 2000 USDC ceiling before any signing", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    usdSendCalls.length = 0;
    const app = await buildApp();

    const res = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "2000.000001",
    });
    expect(res.status).toBe(400);
    expect(usdSendCalls).toHaveLength(0);
  });

  it("rate-limits repeated usd-send calls (11th call in a minute -> 429)", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    usdSendCalls.length = 0;
    const app = await buildApp();

    let lastStatus = 0;
    for (let i = 0; i < 10; i++) {
      const res = await postTransfer(app, "usd-send", tenantId, {
        agentId,
        destination: DEST_A,
        amount: "1",
      });
      lastStatus = res.status;
    }
    expect(lastStatus).toBe(200);
    const res = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "1",
    });
    expect(res.status).toBe(429);
    expect(usdSendCalls).toHaveLength(10);
  });
});

describe("SEC-042: withdraw policy evaluation is real", () => {
  it("enforces a per-tx USD spending limit against the REAL notional (not USDC-as-wei)", async () => {
    // maxPerTxUsd 50 with a 100 USDC withdraw. Pre-fix the evaluator priced the
    // 6-decimal USDC base units (100000000) as wei (~$0.0000004) and approved;
    // the fixed gate converts to wei first, so the engine sees ~$100 and denies.
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerTxUsd: 50 } },
      ],
    });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;
    const app = await buildApp({ priceOracle: stubPriceOracle });

    const res = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "100",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toContain("per-tx USD limit");
    expect(signWithdrawCalls).toHaveLength(0);
    expect(submitWithdrawCalls).toHaveLength(0);
  });

  it("allows a withdraw UNDER the per-tx USD limit (denomination is not over-broad)", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerTxUsd: 500 } },
      ],
    });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;
    const app = await buildApp({ priceOracle: stubPriceOracle });

    const res = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "100",
    });
    expect(res.status).toBe(200);
    expect(signWithdrawCalls).toHaveLength(1);
    expect(submitWithdrawCalls).toHaveLength(1);
  });

  it("enforces a rate-limit policy using the agent's REAL recent tx count", async () => {
    // maxTxPerHour 1 with one confirmed tx in the trailing hour. Pre-fix the
    // route hardcoded recentTxCount1h: 0 and the rule could never fire.
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "rate-limit", config: { maxTxPerHour: 1, maxTxPerDay: 100 } },
      ],
    });
    await getDb()
      .insert(transactions)
      .values({
        id: `tx_${agentId}`,
        agentId,
        status: "confirmed",
        toAddress: DEST_A,
        value: "1000000",
        chainId: ARBITRUM_CHAIN_ID,
        signedAt: new Date(),
      });
    signWithdrawCalls.length = 0;
    const app = await buildApp();

    const res = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "100",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toContain("Hourly tx limit");
    expect(signWithdrawCalls).toHaveLength(0);
  });
});

describe("SEC-043: operator idempotency stores ambiguous outcomes", () => {
  it("releases durable spend before freeing the idempotency claim", async () => {
    const source = await Bun.file(
      new URL("../routes/operator-recovery.ts", import.meta.url),
    ).text();
    const helperStart = source.indexOf("async function releaseOperatorTransfer");
    const helperEnd = source.indexOf("function operatorActor", helperStart);
    const helper = source.slice(helperStart, helperEnd);
    expect(helperStart).toBeGreaterThan(-1);
    expect(helperEnd).toBeGreaterThan(helperStart);
    expect(helper.indexOf("finishOperatorReservation")).toBeLessThan(
      helper.indexOf("idempotency.release"),
    );
    expect(helper).toContain("if (released)");

    const finishStart = source.indexOf("async function finishOperatorReservation");
    const finish = source.slice(finishStart, helperStart);
    expect(finish).toContain('eq(operatorTransferReservations.status, "pending")');
  });

  it("releases a usd-send reservation after a definite local signing failure", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerDayUsd: 100 } },
      ],
    });
    const app = await buildApp({ priceOracle: stubPriceOracle });
    failNextSignUsdSend = true;
    const key = crypto.randomUUID();
    const failed = await postTransfer(
      app,
      "usd-send",
      tenantId,
      { agentId, destination: DEST_A, amount: "60" },
      key,
    );
    expect(failed.status).toBe(502);

    const retry = await postTransfer(
      app,
      "usd-send",
      tenantId,
      { agentId, destination: DEST_A, amount: "60" },
      key,
    );
    expect(retry.status).toBe(200);
    const rows = await getDb()
      .select({ status: operatorTransferReservations.status })
      .from(operatorTransferReservations)
      .where(eq(operatorTransferReservations.tenantId, tenantId));
    expect(rows.map((row) => row.status).sort()).toEqual(["final", "released"]);
  });

  it("releases a withdraw reservation after a definite venue rejection", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerDayUsd: 100 } },
      ],
    });
    const app = await buildApp({ priceOracle: stubPriceOracle });
    rejectNextSubmitWithdraw = true;
    const key = crypto.randomUUID();
    const failed = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "60" },
      key,
    );
    expect(failed.status).toBe(502);
    const retry = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "60" },
      key,
    );
    expect(retry.status).toBe(200);
  });

  it("enforces the durable combined 10/minute ceiling from reservation rows", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    await getDb()
      .insert(operatorTransferReservations)
      .values(
        Array.from({ length: 10 }, (_, index) => ({
          tenantId,
          agentId,
          rail: index % 2 === 0 ? "withdraw" : "usd-send",
          idempotencyKey: `durable-rate-${index}`,
          destination: DEST_A,
          amountBaseUnits: "1",
          status: "final",
        })),
      );
    const app = await buildApp();
    const blocked = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "1",
    });
    expect(blocked.status).toBe(400);
    expect(((await blocked.json()) as { reason: string }).reason).toContain("rate limit");
  });

  it("replays the stored 502 for a possibly-landed withdraw instead of re-submitting", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;
    failNextSubmitWithdraw = true;
    const app = await buildApp();
    const key = `wd-ambiguous-${Date.now()}`;

    const first = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(first.status).toBe(502);
    expect(submitWithdrawCalls).toHaveLength(1);

    // Same key + same body: the recorded ambiguous outcome is replayed — the
    // venue is NOT touched again (no second sign, no second submit).
    const retry = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(retry.status).toBe(502);
    expect(signWithdrawCalls).toHaveLength(1);
    expect(submitWithdrawCalls).toHaveLength(1);
  });

  it("counts an ambiguous reservation and replays it exactly once", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerDayUsd: 150 } },
      ],
    });
    const app = await buildApp({ priceOracle: stubPriceOracle });
    submitWithdrawCalls.length = 0;
    failNextSubmitWithdraw = true;
    const key = crypto.randomUUID();
    const first = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(first.status).toBe(502);
    const replay = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(replay.status).toBe(502);
    expect(submitWithdrawCalls).toHaveLength(1);

    const blocked = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "100",
    });
    expect(blocked.status).toBe(400);
    const rows = await getDb()
      .select({ status: operatorTransferReservations.status })
      .from(operatorTransferReservations)
      .where(
        and(
          eq(operatorTransferReservations.tenantId, tenantId),
          eq(operatorTransferReservations.agentId, agentId),
        ),
      );
    expect(rows).toEqual([{ status: "pending" }]);
  });

  it("serializes parallel policy checks and finalizes the single admitted transfer", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerDayUsd: 100 } },
      ],
    });
    const app = await buildApp({ priceOracle: stubPriceOracle });
    submitWithdrawCalls.length = 0;
    const responses = await Promise.all([
      postTransfer(app, "withdraw", tenantId, {
        agentId,
        destination: DEST_A,
        amount: "60",
      }),
      postTransfer(app, "withdraw", tenantId, {
        agentId,
        destination: DEST_A,
        amount: "60",
      }),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 400]);
    expect(submitWithdrawCalls).toHaveLength(1);
    const rows = await getDb()
      .select({ status: operatorTransferReservations.status })
      .from(operatorTransferReservations)
      .where(eq(operatorTransferReservations.tenantId, tenantId));
    expect(rows).toEqual([{ status: "final" }]);
  });
});
