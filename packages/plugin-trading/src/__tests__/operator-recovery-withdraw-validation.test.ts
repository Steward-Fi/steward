/**
 * operator-recovery-withdraw-validation.test.ts: Regression tests for issue #109.
 *
 * Without the fix, POST /v1/trade/:venue/withdraw (operator fund-recovery):
 *   - accepts an unvalidated explicit `amount` (negative / NaN / non-finite /
 *     over-precision / whole-reserve), signing it verbatim, and
 *   - evaluates the policy set with a hardcoded `value: "0"`, so the
 *     spending-limit / spend-cap evaluator never sees the real withdraw amount.
 *
 * These tests assert the now-symmetric-with-/deposit validation AND that the
 * real notional is fed into the policy gate. They FAIL on the unfixed route and
 * pass with the fix. Harness mirrors operator-recovery.test.ts (PGLite +
 * mock.module HyperliquidAdapter, no signing / no network).
 */

import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import { agents, agentWallets, closeDb, getDb, policies as policiesTable, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { z } from "zod";

const PLATFORM_KEY = "stw_platform_test_operator_key";

// ── Mock the Hyperliquid adapter (no signing / no network) ─────────────────────
const signWithdrawCalls: Array<{ amount: string | number; destination: string }> = [];
const submitWithdrawCalls: unknown[] = [];

class MockHyperliquidAdapter {
  constructor(
    public vault: unknown,
    public agentId: string,
    public walletAddress: string,
  ) {}

  async closeAllPositions() {
    return [] as Array<{ coin: string; result: { status: string; orderId?: string } }>;
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
}

mock.module("@stwd/venue-hyperliquid", () => ({
  HyperliquidAdapter: MockHyperliquidAdapter,
  hyperliquidAssetSchema: z.union([
    z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"]),
    z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/),
  ]),
  isBuilderPerpSymbol: (coin: string) => /^[a-z0-9]+:[A-Z0-9]+$/.test(coin),
}));

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "test-audit-hmac-key-operator-withdraw-validation";
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
  // spending-limit config in canonical wei format, e.g. { maxPerTx: "50000000" }.
  // The withdraw amount is fed to the policy engine as USDC 6-decimal base units,
  // so 100 USDC == 100000000 base units.
  spendingLimit?: Record<string, unknown>;
}) {
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
  if (opts.spendingLimit) {
    await getDb()
      .insert(policiesTable)
      .values({
        id: `pol_spend_${opts.agentId}`,
        agentId: opts.agentId,
        type: "spending-limit",
        enabled: true,
        config: opts.spendingLimit,
      });
  }
}

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

async function postWithdraw(
  app: Awaited<ReturnType<typeof buildApp>>,
  tenantId: string,
  body: Record<string, unknown>,
) {
  return app.request("/v1/trade/hyperliquid/withdraw", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
      "X-Steward-Tenant": tenantId,
    },
    body: JSON.stringify(body),
  });
}

describe("operator recovery withdraw amount validation (issue #109)", () => {
  const approved = "0x4444444444444444444444444444444444444444";

  // Each bad amount must be rejected 400 and signWithdraw must NEVER be called.
  const badAmounts: Array<{ label: string; amount: unknown }> = [
    { label: "negative", amount: "-100" },
    { label: "zero", amount: "0" },
    { label: "NaN", amount: "NaN" },
    { label: "non-finite-1e308", amount: 1e308 },
    { label: "over-precision-7dp", amount: "1.0000001" },
  ];

  for (const { label, amount } of badAmounts) {
    it(`rejects an explicit ${label} amount (400) without signing`, async () => {
      const tenantId = `tenant-wd-bad-${label}-${Date.now()}`;
      const agentId = `agent-wd-bad-${label}-${Date.now()}`;
      await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
      signWithdrawCalls.length = 0;

      const app = await buildApp();
      const res = await postWithdraw(app, tenantId, { agentId, amount, destination: approved });

      expect(res.status).toBe(400);
      expect(signWithdrawCalls.length).toBe(0);
    });
  }

  it("rejects an amount above the per-withdraw maximum (400) without signing", async () => {
    const tenantId = `tenant-wd-max-${Date.now()}`;
    const agentId = `agent-wd-max-${Date.now()}`;
    await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
    signWithdrawCalls.length = 0;

    const app = await buildApp();
    // HL_MAX_WITHDRAW_USDC is 2000; 5000 must be rejected.
    const res = await postWithdraw(app, tenantId, {
      agentId,
      amount: "5000",
      destination: approved,
    });

    expect(res.status).toBe(400);
    const bodyJson = (await res.json()) as { error?: string };
    expect(bodyJson.error ?? "").toContain("maximum");
    expect(signWithdrawCalls.length).toBe(0);
  });

  it("accepts a valid 6-decimal USDC amount without floating-point rejection", async () => {
    const tenantId = `tenant-wd-six-dec-${Date.now()}`;
    const agentId = `agent-wd-six-dec-${Date.now()}`;
    await seedAgent({ tenantId, agentId, approvedAddresses: [approved] });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;

    const app = await buildApp();
    const res = await postWithdraw(app, tenantId, {
      agentId,
      amount: "1.000001",
      destination: approved,
    });

    expect(res.status).toBe(200);
    expect(signWithdrawCalls.length).toBe(1);
    expect(signWithdrawCalls[0]).toMatchObject({ amount: "1.000001", destination: approved });
  });
});

describe("operator recovery withdraw spend-cap enforcement (issue #109)", () => {
  const approved = "0x5555555555555555555555555555555555555555";

  it("rejects an in-bounds amount that exceeds the spend-cap, even to an approved destination", async () => {
    const tenantId = `tenant-wd-cap-${Date.now()}`;
    const agentId = `agent-wd-cap-${Date.now()}`;
    // maxPerTx = 50 USDC in base units; a 100 USDC withdraw (100000000 base
    // units) exceeds it. Before the fix the policy saw value:"0" and PASSED.
    await seedAgent({
      tenantId,
      agentId,
      approvedAddresses: [approved],
      spendingLimit: { maxPerTx: "50000000" },
    });
    signWithdrawCalls.length = 0;

    const app = await buildApp();
    const res = await postWithdraw(app, tenantId, {
      agentId,
      amount: "100",
      destination: approved,
    });

    expect(res.status).toBe(400);
    const bodyJson = (await res.json()) as { code?: string };
    expect(bodyJson.code).toBe("policy-violation");
    expect(signWithdrawCalls.length).toBe(0);
  });

  it("signs a withdraw whose amount is within the spend-cap", async () => {
    const tenantId = `tenant-wd-cap-ok-${Date.now()}`;
    const agentId = `agent-wd-cap-ok-${Date.now()}`;
    // maxPerTx = 200 USDC base units; a 100 USDC withdraw is within the cap.
    await seedAgent({
      tenantId,
      agentId,
      approvedAddresses: [approved],
      spendingLimit: { maxPerTx: "200000000" },
    });
    signWithdrawCalls.length = 0;
    submitWithdrawCalls.length = 0;

    const app = await buildApp();
    const res = await postWithdraw(app, tenantId, {
      agentId,
      amount: "100",
      destination: approved,
    });

    expect(res.status).toBe(200);
    expect(signWithdrawCalls.length).toBe(1);
    // The human-readable amount (not base units) is what gets signed.
    expect(signWithdrawCalls[0]).toMatchObject({ amount: "100", destination: approved });
    expect(submitWithdrawCalls.length).toBe(1);
  });
});
