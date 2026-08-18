/**
 * Behavioral coverage for operator transfer policy gates, durable
 * idempotency, and reservation lifecycle. The venue adapter and price oracle
 * are deterministic test fixtures; no signing or network access occurs.
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

describe("usd-send policy gate and caps", () => {
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

  it("fails closed (429) when the process-local rate-limit map is saturated with live windows", async () => {
    // The fallback map caps at 1_000 keys. Under a distinct-agent flood the
    // limiter must deny new keys instead of growing unbounded or resetting
    // live budgets. Agent existence is checked first, so seed the distinct
    // principals that exercise the fallback instead of relying on unknown
    // request identities to mutate limiter state.
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    usdSendCalls.length = 0;
    const app = await buildApp();

    await getDb()
      .insert(agents)
      .values(
        Array.from({ length: 1_000 }, (_, i) => ({
          id: i === 999 ? "flood-agent-overflow" : `flood-agent-${i}`,
          tenantId,
          name: `Flood Agent ${i}`,
          walletAddress: "0x1111111111111111111111111111111111111111",
        })),
      );

    // One real call so the agent has a LIVE window recorded.
    const first = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "1",
    });
    expect(first.status).toBe(200);

    // Fill the remaining 999 slots with distinct keys.
    for (let i = 0; i < 999; i++) {
      await postTransfer(app, "usd-send", tenantId, {
        agentId: `flood-agent-${i}`,
        destination: DEST_A,
        amount: "1",
      });
    }

    // The real agent's live window survived the flood: its next call is
    // counted, not reset or dropped.
    const second = await postTransfer(app, "usd-send", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "1",
    });
    expect(second.status).toBe(200);

    // A NEW key beyond the cap is denied (fail closed), not tracked.
    const overflow = await postTransfer(app, "usd-send", tenantId, {
      agentId: "flood-agent-overflow",
      destination: DEST_A,
      amount: "1",
    });
    expect(overflow.status).toBe(429);
    expect(usdSendCalls).toHaveLength(2);
  });
});

describe("withdraw policy evaluation", () => {
  it("enforces a per-tx USD spending limit against the REAL notional (not USDC-as-wei)", async () => {
    // The gate converts the USDC amount into the denomination expected by the
    // policy engine, so a 100 USDC transfer exceeds a $50 per-transaction cap.
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

  it("keeps prior operator USDC out of a conjunctive native-wei cap", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        {
          type: "spending-limit",
          config: { maxPerDay: "20000000000000000", maxPerDayUsd: 200 },
        },
      ],
    });
    const app = await buildApp({ priceOracle: stubPriceOracle });

    const first = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "60",
    });
    const second = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "60",
    });

    // Each request is 0.015 ETH at the pinned quote and fits the 0.02 ETH raw
    // cap. Their $120 cumulative operator spend is enforced only by the $200
    // USD cap; adding prior USDC-as-quoted-wei would corrupt the raw counter.
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
  });

  it("enforces a rate-limit policy using the agent's REAL recent tx count", async () => {
    // One confirmed transaction in the trailing hour exhausts this policy.
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

  it("keeps an outcome-unknown core transfer in operator rate counters", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "rate-limit", config: { maxTxPerHour: 1, maxTxPerDay: 100 } },
      ],
    });
    await getDb()
      .insert(transactions)
      .values({
        id: `tx_unknown_rate_${agentId}`,
        agentId,
        status: "outcome_unknown",
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
      amount: "1",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { reason?: string }).reason).toContain("Hourly tx limit");
    expect(signWithdrawCalls).toHaveLength(0);
  });

  it("keeps an outcome-unknown core transfer in operator USD spend", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
        { type: "spending-limit", config: { maxPerDayUsd: 100 } },
      ],
    });
    await getDb()
      .insert(transactions)
      .values({
        id: `tx_unknown_spend_${agentId}`,
        agentId,
        status: "outcome_unknown",
        toAddress: DEST_A,
        // $95 at the pinned $4,000/ETH quote.
        value: "23750000000000000",
        chainId: ARBITRUM_CHAIN_ID,
        signedAt: new Date(),
      });
    signWithdrawCalls.length = 0;
    const app = await buildApp({ priceOracle: stubPriceOracle });

    const res = await postTransfer(app, "withdraw", tenantId, {
      agentId,
      destination: DEST_A,
      amount: "10",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { reason?: string }).reason).toContain(
      "daily USD spending limit",
    );
    expect(signWithdrawCalls).toHaveLength(0);
  });
});

describe("durable operator transfer idempotency", () => {
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
          requestDigest: (index + 100).toString(16).padStart(64, "0"),
          destination: DEST_A,
          amountBaseUnits: "1",
          status: "pending",
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
    let app = await buildApp();
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

    // Recreate the application to prove replay is independent of process-local
    // state and survives cache expiry or a worker restart.
    app = await buildApp();
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

  it("rejects reuse of an active key with a different request after restart", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A, DEST_B] } },
      ],
    });
    submitWithdrawCalls.length = 0;
    failNextSubmitWithdraw = true;
    let app = await buildApp();
    const key = `wd-conflict-${Date.now()}`;

    const first = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(first.status).toBe(502);

    app = await buildApp();
    const conflict = await postTransfer(
      app,
      "withdraw",
      tenantId,
      { agentId, destination: DEST_B, amount: "100" },
      key,
    );
    expect(conflict.status).toBe(409);
    expect(submitWithdrawCalls).toHaveLength(1);
  });

  it("replays a terminal success after restart without signing or submitting", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;
    let app = await buildApp();
    const key = `wd-success-${Date.now()}`;
    const request = { agentId, destination: DEST_A, amount: "100" };

    const first = await postTransfer(app, "withdraw", tenantId, request, key);
    expect(first.status).toBe(200);
    const firstBody = await first.json();

    app = await buildApp();
    const replay = await postTransfer(app, "withdraw", tenantId, request, key);
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(firstBody);
    expect(signWithdrawCalls).toHaveLength(1);
    expect(submitWithdrawCalls).toHaveLength(1);
  });

  it("replays the reconciliation response for a reservation created before durable responses", async () => {
    const { tenantId, agentId } = await seedAgent({
      policies: [
        { type: "approved-addresses", config: { mode: "whitelist", addresses: [DEST_A] } },
      ],
    });
    const key = `legacy-transfer-${Date.now()}`;
    await getDb()
      .insert(operatorTransferReservations)
      .values({
        tenantId,
        agentId,
        rail: "withdraw",
        idempotencyKey: key,
        requestDigest: "0".repeat(64),
        destination: DEST_A,
        amountBaseUnits: "100000000",
        status: "pending",
        responseStatus: 502,
        responseBody: {
          ok: false,
          error: "Operator transfer outcome requires reconciliation",
        },
      });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;

    const response = await postTransfer(
      await buildApp(),
      "withdraw",
      tenantId,
      { agentId, destination: DEST_A, amount: "100" },
      key,
    );
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      ok: false,
      error: "Operator transfer outcome requires reconciliation",
    });
    expect(signWithdrawCalls).toHaveLength(0);
    expect(submitWithdrawCalls).toHaveLength(0);
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
