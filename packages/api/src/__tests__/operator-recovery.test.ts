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

import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import { agents, agentWallets, closeDb, getDb, policies as policiesTable, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";

const PLATFORM_KEY = "stw_platform_test_operator_key";

// ── Mock the Hyperliquid adapter (no signing / no network) ─────────────────────
const closeAllCalls: number[] = [];
const signWithdrawCalls: Array<{ amount: string | number; destination: string }> = [];
const submitWithdrawCalls: unknown[] = [];

class MockHyperliquidAdapter {
  constructor(
    public vault: unknown,
    public agentId: string,
    public walletAddress: string,
  ) {}

  async closeAllPositions() {
    closeAllCalls.push(Date.now());
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
}

mock.module("@stwd/venue-hyperliquid", () => ({
  HyperliquidAdapter: MockHyperliquidAdapter,
}));

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
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
  // api_key_hash and owner_address are unique per tenant (PR #79 constraints),
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
  const { operatorRecoveryRoutes } = await import("../routes/operator-recovery");
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
  app.route("/v1/trade", operatorRecoveryRoutes);
  return app;
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
