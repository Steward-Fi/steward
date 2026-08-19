/**
 * Behavioral coverage for POST /v1/trade/polymarket/order.
 *
 * The harness uses PGLite, TradeSessionManager, the public route, vault
 * provisioning, credential derivation, and the execution adapter. Focused
 * fault cases retain narrow wallet/adapter spies; the deterministic end-to-end
 * case uses the real vault signer and SDK while intercepting only network I/O.
 */
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  setDefaultTimeout,
  spyOn,
} from "bun:test";
import { ClobClient } from "@polymarket/clob-client";
import {
  agentPolicies,
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { TradeSessionManager } from "@stwd/trade-sessions";
import { Vault } from "@stwd/vault";
import { PolymarketExecutionAdapter } from "@stwd/venue-polymarket";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const TOKEN_ID = "71321045679252212594626385532706912750332728571942532289631379312455583992563";
const COND_ID = `0x${"a".repeat(64)}`;
const OTHER_COND_ID = `0x${"b".repeat(64)}`;
const FUNDER = "0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c";
const WALLET = "0x1111111111111111111111111111111111111111";

let submitSpy: ReturnType<typeof spyOn> | undefined;
let getWalletSpy: ReturnType<typeof spyOn> | undefined;
let buildSpy: ReturnType<typeof spyOn> | undefined;
let fenceSpy: ReturnType<typeof spyOn> | undefined;
let createTradeRoutesForTest: typeof import("../routes/trade").createTradeRoutes;

// Inject a polymarket venue wallet WITH funder metadata so the creds resolver
// gets past the wallet step. Whether the L2 credentials resolve is toggled
// separately per test by mutating the metadata.
function stubWallet(withFunder: boolean) {
  getWalletSpy = spyOn(Vault.prototype, "getWallet").mockImplementation((async (args: {
    venue?: string;
  }) => {
    if (args.venue !== "polymarket") throw new Error("no wallet");
    return {
      agentId: "x",
      chainFamily: "evm" as const,
      venue: "polymarket",
      purpose: null,
      address: WALLET,
      metadata: withFunder ? { funderAddress: FUNDER } : {},
    };
  }) as never);
}

async function seedSession(opts: {
  allowedAssets?: string[];
  perOrderCapUsd?: string;
  dailyCapUsd?: string;
  status?: "active" | "revoked";
  walletId?: string;
}): Promise<{ tenantId: string; agentId: string; sessionId: string }> {
  const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const tenantId = `pm-tenant-${suffix}`;
  const agentId = `pm-agent-${suffix}`;
  const sessionId = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tenants)
    .values({ id: tenantId, name: "PM Tenant", apiKeyHash: `hash-${tenantId}` });
  await getDb().insert(agents).values({
    id: agentId,
    tenantId,
    name: "PM Agent",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
  await getDb()
    .insert(tradeSessions)
    .values({
      id: sessionId,
      tenantId,
      agentId,
      venue: "polymarket",
      walletId: opts.walletId ?? WALLET,
      status: opts.status ?? "active",
      dailySpendUsd: "0",
      dailyCapUsd: opts.dailyCapUsd ?? "100",
      perOrderCapUsd: opts.perOrderCapUsd ?? "50",
      leverageCap: "1",
      allowedAssets: opts.allowedAssets ?? [`pm:${TOKEN_ID}`],
      expiresAt: new Date(Date.now() + 60_000),
      ...(opts.status === "revoked" ? { revokedAt: new Date() } : {}),
    });
  return { tenantId, agentId, sessionId };
}

function makeApp(tenantId: string, agentId: string, routes: Hono) {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent-token");
    await next();
  });
  app.route("/v1/trade", routes);
  return app;
}

function postOrder(
  app: Hono,
  sessionId: string,
  idempotencyKey: string,
  body: Record<string, unknown> = {},
) {
  return app.request("/v1/trade/polymarket/order", {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": idempotencyKey },
    body: JSON.stringify({
      sessionId,
      tokenId: TOKEN_ID,
      side: "buy",
      amount: 10,
      price: 0.5,
      ...body,
    }),
  });
}

async function dailySpendOf(sessionId: string): Promise<number> {
  const [row] = await getDb()
    .select({ spent: tradeSessions.dailySpendUsd })
    .from(tradeSessions)
    .where(eq(tradeSessions.id, sessionId));
  return Number(row.spent);
}

async function auditCount(tenantId: string, action: string): Promise<number> {
  const rows = await getDb()
    .select({ seq: auditEvents.seq })
    .from(auditEvents)
    .where(and(eq(auditEvents.action, action), eq(auditEvents.tenantId, tenantId)));
  return rows.length;
}

async function auditMetadata(tenantId: string, action: string): Promise<Record<string, unknown>> {
  const [row] = await getDb()
    .select({ metadata: auditEvents.metadata })
    .from(auditEvents)
    .where(and(eq(auditEvents.action, action), eq(auditEvents.tenantId, tenantId)))
    .limit(1);
  return row?.metadata ?? {};
}

// Module-level DB + fence setup shared by both describe blocks. The api suite
// runs all test files in one process; a per-describe closeDb() would tear down
// PGLite before the second describe's beforeAll re-imports routes.
let sharedTradeRoutes: Hono;
let sharedTestContext: StewardAppContext;
beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "pm-order-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "pm-order-test-audit-hmac-key-0123456789abcdef0";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  // Faithful pass-through for the fence's DB-transaction wrapper. The real
  // wrapper opens getDb().transaction() + an advisory lock and re-selects the
  // active session; under single-connection PGLite the callback's own base-
  // connection queries (reserveSpend + audit writes) deadlock against the outer
  // transaction (production runs them on a pooled connection). The advisory-lock
  // atomicity is a @stwd/trade-sessions concern; the spend/audit invariants the
  // route owns run for real inside the callback. Returns null when the session
  // is not active so the route's revoke-race 409 path is exercised.
  fenceSpy = spyOn(TradeSessionManager.prototype, "withActiveSubmissionFence").mockImplementation(
    (async (input: { tenantId: string; id: string }, cb: () => Promise<unknown>) => {
      const active = await new TradeSessionManager().getActive(input.tenantId, input.id);
      if (!active) return null;
      return cb();
    }) as never,
  );
  const { createTradeRoutes } = await import("../routes/trade");
  createTradeRoutesForTest = createTradeRoutes;
  const { testCtx } = await import("./_ctx");
  sharedTestContext = testCtx();
  sharedTradeRoutes = createTradeRoutes(sharedTestContext);
});

afterAll(async () => {
  fenceSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
});

describe("POST /v1/trade/polymarket/order", () => {
  let tradeRoutes: Hono;

  beforeAll(() => {
    tradeRoutes = sharedTradeRoutes;
  });

  afterEach(() => {
    submitSpy?.mockRestore();
    getWalletSpy?.mockRestore();
    buildSpy?.mockRestore();
    submitSpy = undefined;
    getWalletSpy = undefined;
    buildSpy = undefined;
  });

  it("rejects an order whose market is not allowlisted (400 policy-violation, no spend)", async () => {
    // session allowlist is only pm:<OTHER>, so pm:<TOKEN_ID> is not allowed.
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: ["pm:99999999"],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toBe("market-not-allowed");

    expect(await dailySpendOf(sessionId)).toBe(0);
    expect(await auditCount(tenantId, "trade.order.policy-rejected")).toBe(1);
    expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
  });

  it("rejects an order over the per-order cap (400 policy-violation)", async () => {
    // perOrderCap 5, BUY amount 10 USD -> notional 10 > 5.
    const { tenantId, agentId, sessionId } = await seedSession({
      perOrderCapUsd: "5",
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(400);
    const body = (await res.json()) as { code?: string; reason?: string };
    expect(body.code).toBe("policy-violation");
    expect(body.reason).toBe("per-order-cap-exceeded");
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("does not let a caller conditionId turn an unrelated policy denial into a metadata dependency", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:${TOKEN_ID}`],
      perOrderCapUsd: "5",
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const key = crypto.randomUUID();
    const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("policy denials must not perform market metadata IO"),
    );

    try {
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const res = await postOrder(app, sessionId, key, {
          amount: 10,
          conditionId: COND_ID,
        });
        expect(res.status).toBe(400);
        expect(await res.json()).toEqual({
          code: "policy-violation",
          reason: "per-order-cap-exceeded",
        });
      }
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects a caller conditionId that disagrees with authoritative token metadata", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:cond:${COND_ID}`],
    });
    stubWallet(true);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          condition_id: OTHER_COND_ID,
          primary_token_id: TOKEN_ID,
          secondary_token_id: "8".repeat(72),
        }),
        { status: 200 },
      ),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        conditionId: COND_ID,
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { code?: string; reason?: string };
      expect(body).toEqual({ code: "policy-violation", reason: "condition-id-mismatch" });
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects a caller conditionId mismatch even when the token itself is directly allowlisted", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:${TOKEN_ID}`],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          condition_id: OTHER_COND_ID,
          primary_token_id: TOKEN_ID,
          secondary_token_id: "8".repeat(72),
        }),
        { status: 200 },
      ),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        conditionId: COND_ID,
      });
      expect(res.status).toBe(400);
      expect((await res.json()) as { code?: string; reason?: string }).toEqual({
        code: "policy-violation",
        reason: "condition-id-mismatch",
      });
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("authorizes a market-wide grant only after resolving the token's condition", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:cond:0x${"A".repeat(64)}`],
    });
    stubWallet(true);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          condition_id: COND_ID,
          primary_token_id: TOKEN_ID,
          secondary_token_id: "8".repeat(72),
        }),
        { status: 200 },
      ),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(409);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "credentials are not provisioned",
      );
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("rejects authoritative token metadata for a different, non-allowlisted condition", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:cond:${COND_ID}`],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          condition_id: OTHER_COND_ID,
          primary_token_id: TOKEN_ID,
          secondary_token_id: "8".repeat(72),
        }),
        { status: 200 },
      ),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({
        code: "policy-violation",
        reason: "market-not-allowed",
      });
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditMetadata(tenantId, "trade.order.policy-rejected")).toMatchObject({
        conditionId: OTHER_COND_ID,
        reason: "market-not-allowed",
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps metadata outages retryable without authorizing an unverified market grant", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:cond:${COND_ID}`],
    });
    stubWallet(true);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const key = crypto.randomUUID();
    const fetchSpy = spyOn(globalThis, "fetch")
      .mockRejectedValueOnce(new Error("TOKEN_METADATA_SECRET_CANARY"))
      .mockResolvedValue(
        new Response(
          JSON.stringify({
            condition_id: COND_ID,
            primary_token_id: TOKEN_ID,
            secondary_token_id: "8".repeat(72),
          }),
          { status: 200 },
        ),
      );

    try {
      const first = await postOrder(app, sessionId, key);
      expect(first.status).toBe(502);
      expect(await first.json()).toEqual({
        ok: false,
        error: "Unable to verify Polymarket market binding",
      });

      const retry = await postOrder(app, sessionId, key);
      expect(retry.status).toBe(409);
      expect(((await retry.json()) as { error?: string }).error).toContain(
        "credentials are not provisioned",
      );
      expect(fetchSpy).toHaveBeenCalledTimes(2);
      expect(await dailySpendOf(sessionId)).toBe(0);
      const metadata = await auditMetadata(tenantId, "trade.order.policy-rejected");
      expect(metadata).toMatchObject({
        reason: "market-metadata-unavailable",
        errorClass: "Error",
        errorCode: null,
      });
      expect(JSON.stringify(metadata)).not.toContain("TOKEN_METADATA_SECRET_CANARY");
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("releases metadata and mismatch claims when the audit sink fails", async () => {
    const failingRoutes = createTradeRoutesForTest({
      ...sharedTestContext,
      writeAuditEvent: async () => {
        throw new Error("audit unavailable");
      },
    });
    failingRoutes.onError(() => new Response("audit unavailable", { status: 500 }));

    const originalError = console.error;
    const logs: string[] = [];
    console.error = (...args: unknown[]) => logs.push(args.map(String).join(" "));
    try {
      for (const scenario of ["metadata", "mismatch"] as const) {
        const { tenantId, agentId, sessionId } = await seedSession({
          allowedAssets: [`pm:cond:${COND_ID}`],
        });
        const app = makeApp(tenantId, agentId, failingRoutes);
        const key = crypto.randomUUID();
        const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
          scenario === "metadata"
            ? async () => {
                throw new Error("metadata unavailable");
              }
            : async () =>
                new Response(
                  JSON.stringify({
                    condition_id: OTHER_COND_ID,
                    primary_token_id: TOKEN_ID,
                    secondary_token_id: "8".repeat(72),
                  }),
                  { status: 200 },
                ),
        );

        try {
          const extra = scenario === "mismatch" ? { conditionId: COND_ID } : {};
          const expectedStatus = scenario === "metadata" ? 502 : 500;
          expect((await postOrder(app, sessionId, key, extra)).status).toBe(expectedStatus);
          expect((await postOrder(app, sessionId, key, extra)).status).toBe(expectedStatus);
          expect(fetchSpy).toHaveBeenCalledTimes(2);
          expect(await dailySpendOf(sessionId)).toBe(0);
        } finally {
          fetchSpy.mockRestore();
        }
      }
      expect(logs.join("\n")).not.toContain("audit unavailable");
      expect(logs.join("\n")).not.toContain("metadata unavailable");
    } finally {
      console.error = originalError;
    }
  });

  it("SEC-041: SELL notional is floored at the CLOB best bid (low-limit cap bypass fails)", async () => {
    // perOrderCap 50. A FOK sell of 100 shares at limit 0.01 would fill at the
    // best bid (0.90): real notional ~$90 must be capped, not the caller-stated
    // $1. The route must not size on the caller's price and pass the gate.
    const { tenantId, agentId, sessionId } = await seedSession({
      perOrderCapUsd: "50",
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      (async () =>
        new Response(JSON.stringify({ [TOKEN_ID]: { SELL: "0.90" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as typeof fetch,
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        side: "sell",
        amount: 100,
        price: 0.01,
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { code?: string; reason?: string };
      expect(body.code).toBe("policy-violation");
      expect(body.reason).toBe("per-order-cap-exceeded");
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("SEC-041: SELL caps use the $1/share upper bound despite a lower bid", async () => {
    // A mutable best-bid snapshot cannot bound the eventual fill. 100 shares
    // can return up to $100, so a $50 cap must reject even when bid/limit are .40/.50.
    const { tenantId, agentId, sessionId } = await seedSession({
      perOrderCapUsd: "50",
    });
    stubWallet(true);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      (async () =>
        new Response(JSON.stringify({ [TOKEN_ID]: { SELL: "0.40" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as typeof fetch,
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        side: "sell",
        amount: 100,
        price: 0.5,
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { reason?: string }).reason).toBe("per-order-cap-exceeded");
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("SEC-041: SELL fails closed when the best bid cannot be resolved", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(new Error("clob down"));

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        side: "sell",
        amount: 10,
        price: 0.5,
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { code?: string; reason?: string };
      expect(body.code).toBe("policy-violation");
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("honors an exact pm:<tokenId> allowlist entry (passes the policy gate)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: [`pm:${TOKEN_ID}`],
    });
    stubWallet(true); // funder present, L2 creds unprovisioned -> 409 past the gate
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(
      new Error("exact token grants must not require market metadata"),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(409);
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("returns 409 on idempotency-key reuse with a different body; replays the same envelope", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({
      allowedAssets: ["pm:99999999"],
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const key = crypto.randomUUID();

    // First call: market-not-allowed -> 400, stored under the key.
    const first = await postOrder(app, sessionId, key);
    expect(first.status).toBe(400);

    // Same key, DIFFERENT body (different price) -> conflict 409.
    const conflict = await postOrder(app, sessionId, key, { price: 0.6 });
    expect(conflict.status).toBe(409);
    expect(((await conflict.json()) as { error?: string }).error).toContain(
      "Idempotency key reused",
    );

    // Same key, SAME body -> replay of the stored 400.
    const replay = await postOrder(app, sessionId, key);
    expect(replay.status).toBe(400);
    expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
  });

  it("returns 403 when the session is not active (revoked)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({ status: "revoked" });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error?: string }).error).toContain(
      "Active Polymarket session required",
    );
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("fails closed with 409 when polymarket creds are not provisioned (no spend reserved)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    stubWallet(true); // wallet + funder present, but L2 creds unprovisioned
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error?: string }).error).toContain(
      "credentials are not provisioned",
    );
    // Creds are resolved BEFORE spend reservation, so the daily cap is untouched.
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("fails closed with 409 when the polymarket venue wallet is missing", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    // getWallet throws -> wallet-not-found.
    getWalletSpy = spyOn(Vault.prototype, "getWallet").mockImplementation((async () => {
      throw new Error("no wallet");
    }) as never);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const res = await postOrder(app, sessionId, crypto.randomUUID());
    expect(res.status).toBe(409);
    expect(((await res.json()) as { error?: string }).error).toContain("venue wallet not found");
    expect(await dailySpendOf(sessionId)).toBe(0);
  });

  it("SEC-111: STEWARD_PM_TEST_CREDS is hard-disabled in production", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    stubWallet(true); // wallet + funder present, but no provisioned L2 creds
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const prevNodeEnv = process.env.NODE_ENV;
    const prevMemoryAck = process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    const prevCustodyAck = process.env.STEWARD_ACK_LOCAL_CUSTODY;
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = "true";
    process.env.STEWARD_ACK_LOCAL_CUSTODY = "true";
    process.env.STEWARD_PM_TEST_CREDS = "1";
    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      // The test-creds seam is ignored in production, so creds resolution falls
      // through to real L2 derivation, which fails closed in this harness.
      expect(res.status).toBe(409);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "credentials are not provisioned",
      );
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
      if (prevMemoryAck === undefined) delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
      else process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = prevMemoryAck;
      if (prevCustodyAck === undefined) delete process.env.STEWARD_ACK_LOCAL_CUSTODY;
      else process.env.STEWARD_ACK_LOCAL_CUSTODY = prevCustodyAck;
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("SEC-111: a plain-http POLYMARKET_CLOB_API_URL is refused in production", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    stubWallet(true);
    // Mock the adapter edge so the ONLY thing that can fail the order is creds
    // resolution: the HTTP override and test credentials must not bypass it.
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-http-guard",
      status: "matched",
      success: true,
      makingAmount: "10",
      takingAmount: "20",
      actualAmount: 20,
      actualPrice: 0.5,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);
    const app = makeApp(tenantId, agentId, tradeRoutes);

    const prevNodeEnv = process.env.NODE_ENV;
    const prevMemoryAck = process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    const prevCustodyAck = process.env.STEWARD_ACK_LOCAL_CUSTODY;
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = "true";
    process.env.STEWARD_ACK_LOCAL_CUSTODY = "true";
    process.env.POLYMARKET_CLOB_API_URL = "http://clob.e2e.invalid";
    process.env.STEWARD_PM_TEST_CREDS = "1";
    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(409);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "credentials are not provisioned",
      );
      expect(submitSpy).not.toHaveBeenCalled();
      expect(await dailySpendOf(sessionId)).toBe(0);
    } finally {
      if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = prevNodeEnv;
      if (prevMemoryAck === undefined) delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
      else process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = prevMemoryAck;
      if (prevCustodyAck === undefined) delete process.env.STEWARD_ACK_LOCAL_CUSTODY;
      else process.env.STEWARD_ACK_LOCAL_CUSTODY = prevCustodyAck;
      delete process.env.POLYMARKET_CLOB_API_URL;
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("rejects credential-bearing or non-canonical CLOB endpoint overrides", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    stubWallet(true);
    const app = makeApp(tenantId, agentId, tradeRoutes);
    const previous = process.env.POLYMARKET_CLOB_API_URL;
    process.env.STEWARD_PM_TEST_CREDS = "1";

    try {
      for (const value of [
        "https://user:secret@clob.e2e.invalid/base",
        "https://clob.e2e.invalid/base?token=secret",
        "https://clob.e2e.invalid/base#secret",
        "https://clob.e2e.invalid/line\nbreak",
        `https://clob.e2e.invalid/${"a".repeat(2_048)}`,
      ]) {
        process.env.POLYMARKET_CLOB_API_URL = value;
        const res = await postOrder(app, sessionId, crypto.randomUUID());
        expect(res.status).toBe(409);
        const responseText = await res.text();
        expect(responseText).not.toContain("secret");
        expect(await dailySpendOf(sessionId)).toBe(0);
      }
    } finally {
      if (previous === undefined) delete process.env.POLYMARKET_CLOB_API_URL;
      else process.env.POLYMARKET_CLOB_API_URL = previous;
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("happy path: filled order -> 200, spend reserved, submitted + authorized audits (mocked adapter)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    // Provision funder metadata on the venue wallet + flip the route's test-only
    // L2 credential seam so resolvePolymarketCreds resolves (production uses the real
    // secret-vault read here). The adapter network edge is stubbed so no real
    // clob-client / signing runs.
    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-ok-1",
      status: "matched",
      success: true,
      makingAmount: "10",
      takingAmount: "20",
      actualAmount: 20,
      actualPrice: 0.5,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { orderId: string; filledQty: number; avgPrice: number; status: string };
      };
      expect(body.ok).toBe(true);
      expect(body.data.orderId).toBe("pm-ok-1");
      expect(body.data.filledQty).toBe(20);
      expect(body.data.avgPrice).toBeCloseTo(0.5, 10);
      expect(submitSpy).toHaveBeenCalledTimes(1);
      // BUY notional = amount (10 USD) is reserved against the daily cap.
      expect(await dailySpendOf(sessionId)).toBe(10);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.submit.authorized")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.canceled")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("deterministic E2E: real vault wallet -> L2 derive -> policy/session -> SDK sign/post -> audit/idempotency", async () => {
    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tenantId = `pm-e2e-tenant-${suffix}`;
    const agentId = `pm-e2e-agent-${suffix}`;
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: "PM E2E Tenant", apiKeyHash: `hash-${tenantId}` });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "PM E2E Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb()
      .insert(agentPolicies)
      .values({
        agentId,
        tenantId,
        dailyCapUsd: "100",
        perOrderCapUsd: "25",
        leverageCap: "1",
        allowedAssets: [`pm:${TOKEN_ID}`],
        allowedVenues: ["polymarket"],
        updatedBy: "e2e-human-policy",
      });

    // This is real provisioning into the encrypted venue-scoped vault. No
    // getWallet/signing spy and no raw private key leaves the vault.
    const wallet = await sharedTestContext.vault.createWallet({
      agentId,
      tenantId,
      venue: "polymarket",
      chainType: "evm",
    });
    // Promote the provisioned delegate to the preferred sigType-2 topology:
    // Safe holds funds (maker), venue-scoped EOA signs. Metadata is public and
    // identity-bound; no secret material is introduced.
    await getDb()
      .update(agentWallets)
      .set({ metadata: { funderAddress: FUNDER } })
      .where(and(eq(agentWallets.agentId, agentId), eq(agentWallets.venue, "polymarket")));

    const requests: Array<{ method: string; path: string; body?: unknown }> = [];
    type ClobHttpOptions = { headers?: Record<string, string>; data?: unknown };
    type ClobHttpPrototype = {
      get(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
      post(endpoint: string, options?: ClobHttpOptions): Promise<unknown>;
    };
    const clobPrototype = ClobClient.prototype as unknown as ClobHttpPrototype;
    const getSpy = spyOn(clobPrototype, "get").mockImplementation((async (endpoint: string) => {
      const path = new URL(endpoint).pathname;
      requests.push({ method: "GET", path });
      if (path === "/tick-size") return { minimum_tick_size: 0.01 };
      if (path === "/fee-rate") return { base_fee: 0 };
      throw new Error(`unexpected deterministic CLOB GET ${path}`);
    }) as never);
    const postSpy = spyOn(clobPrototype, "post").mockImplementation((async (
      endpoint: string,
      options?: ClobHttpOptions,
    ) => {
      const path = new URL(endpoint).pathname;
      requests.push({ method: "POST", path, body: options?.data });
      const headers = new Headers(options?.headers);
      if (path === "/auth/api-key") {
        expect(headers.get("poly_address")?.toLowerCase()).toBe(wallet.address.toLowerCase());
        expect(headers.get("poly_signature")).toMatch(/^0x[0-9a-f]+$/i);
        return {
          apiKey: "deterministic-e2e-key",
          secret: "ZGV0ZXJtaW5pc3RpYy1zZWNyZXQ=",
          passphrase: "deterministic-e2e-passphrase",
        };
      }
      if (path === "/order") {
        expect(headers.get("poly_api_key")).toBe("deterministic-e2e-key");
        const payload = options?.data as {
          owner?: string;
          order?: { maker?: string; signer?: string; signature?: string; tokenId?: string };
        };
        expect(payload.owner).toBe("deterministic-e2e-key");
        expect(payload.order?.maker?.toLowerCase()).toBe(FUNDER.toLowerCase());
        expect(payload.order?.signer?.toLowerCase()).toBe(wallet.address.toLowerCase());
        expect(payload.order?.tokenId).toBe(TOKEN_ID);
        expect(payload.order?.signature).toMatch(/^0x[0-9a-f]+$/i);
        return {
          orderID: "pm-e2e-order-1",
          status: "matched",
          success: true,
          makingAmount: "10",
          takingAmount: "20",
        };
      }
      throw new Error(`unexpected deterministic CLOB POST ${path}`);
    }) as never);

    process.env.POLYMARKET_CLOB_API_URL = "https://clob.e2e.invalid";
    try {
      const app = makeApp(tenantId, agentId, tradeRoutes);
      const sessionRes = await app.request("/v1/trade/sessions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agentId,
          venue: "polymarket",
          dailyCap: 40,
          perOrderCap: 20,
          allowedAssets: [`pm:${TOKEN_ID}`],
        }),
      });
      expect(sessionRes.status).toBe(201);
      const sessionBody = (await sessionRes.json()) as { data: { sessionId: string } };
      const idempotencyKey = `pm-e2e-${crypto.randomUUID()}`;
      const orderBody = {
        sessionId: sessionBody.data.sessionId,
        tokenId: TOKEN_ID,
        side: "buy",
        amount: 10,
        price: 0.5,
        tickSize: "0.01",
        negRisk: true,
      };
      const first = await app.request("/v1/trade/polymarket/order", {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(orderBody),
      });
      expect(first.status).toBe(200);
      expect((await first.json()) as unknown).toMatchObject({
        ok: true,
        data: { orderId: "pm-e2e-order-1", filledQty: 20, avgPrice: 0.5, notionalUsd: 10 },
      });

      // Same governed request is replayed without a second CLOB POST or spend.
      const replay = await app.request("/v1/trade/polymarket/order", {
        method: "POST",
        headers: { "content-type": "application/json", "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(orderBody),
      });
      expect(replay.status).toBe(200);
      expect(replay.headers.get("Idempotency-Replayed")).toBe("true");
      expect(requests.filter((r) => r.path === "/auth/api-key")).toHaveLength(1);
      expect(requests.filter((r) => r.path === "/order")).toHaveLength(1);
      expect(await dailySpendOf(sessionBody.data.sessionId)).toBe(10);
      expect(await auditCount(tenantId, "trade.order.submit.authorized")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(1);
    } finally {
      delete process.env.POLYMARKET_CLOB_API_URL;
      getSpy.mockRestore();
      postSpy.mockRestore();
    }
  });

  it("no funder metadata -> EOA funder path still executes (sigType 0, funder=wallet)", async () => {
    // v1 EOA custody: when no funder Safe is recorded, the delegate EOA is its
    // own funder. The order should still flow end-to-end (sigType selection is
    // internal; we assert the path reaches submit + fills).
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(false); // NO funder metadata -> EOA path
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-eoa-1",
      status: "matched",
      success: true,
      makingAmount: "10",
      takingAmount: "20",
      actualAmount: 20,
      actualPrice: 0.5,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(200);
      expect(submitSpy).toHaveBeenCalledTimes(1);
      expect(await dailySpendOf(sessionId)).toBe(10);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("wallet-binding mismatch (rotated wallet) -> 409 fail-closed, no spend, no submit", async () => {
    // Session bound to a DIFFERENT wallet than the one the vault now resolves
    // (simulates a rotation/reprovision after the session was created).
    const { tenantId, agentId, sessionId } = await seedSession({
      walletId: "0x2222222222222222222222222222222222222222",
    });
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true); // getWallet returns WALLET (0x111...), != session.walletId
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue(
      {} as never,
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(409);
      expect(submitSpy).not.toHaveBeenCalled();
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("venue rejection -> 400, releases reserved spend, writes canceled audit (no submitted)", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-rej-1",
      success: false,
      errorMsg: "order rejected by book",
      actualAmount: 0,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(400);
      const body = (await res.json()) as { ok: boolean; error?: string };
      expect(body.ok).toBe(false);
      expect(body.error).toBe("order rejected by book");
      // Reserved spend was released back to 0 on rejection.
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.canceled")).toBe(1);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("live-book unavailable -> refuses to guess options, releases spend, never posts", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    const fetchSpy = spyOn(globalThis, "fetch").mockRejectedValue(new Error("book down"));
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    try {
      // No caller-supplied tickSize/negRisk. The real adapter must resolve the
      // live book and fail closed when it is unavailable, never guess defaults.
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error?: string }).error).toContain("could not be built");
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(submitSpy).toHaveBeenCalledTimes(0);
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      fetchSpy.mockRestore();
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("sub-0.01 SELL -> real adapter rejects pre-sign and releases spend", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    // SEC-041: sells now resolve the CLOB best bid for notional sizing first.
    const fetchSpy = spyOn(globalThis, "fetch").mockImplementation(
      (async () =>
        new Response(JSON.stringify({ [TOKEN_ID]: { SELL: "0.5" } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        })) as typeof fetch,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID(), {
        side: "sell",
        amount: 0.005,
        price: 0.5,
        tickSize: "0.01",
        negRisk: true,
      });
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error?: string }).error).toContain("could not be built");
      expect(submitSpy).toHaveBeenCalledTimes(0);
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      fetchSpy.mockRestore();
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("submit-status-unknown (adapter throws post-submit) -> 502, KEEPS spend reserved", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    // The build succeeded; the POST faults -> the order may have landed. Spend
    // stays reserved (mirrors HL's 502 path).
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockRejectedValue(
      new Error("socket hang up"),
    );

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      expect(res.status).toBe(502);
      expect(((await res.json()) as { error?: string }).error).toContain(
        "Trade submission status unknown",
      );
      // The order may have landed -> spend is NOT released.
      expect(await dailySpendOf(sessionId)).toBe(10);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });

  it("revoke race: session revoked before the submit fence -> 409, never submits", async () => {
    const { tenantId, agentId, sessionId } = await seedSession({});
    const app = makeApp(tenantId, agentId, tradeRoutes);

    process.env.STEWARD_PM_TEST_CREDS = "1";
    stubWallet(true);
    buildSpy = spyOn(PolymarketExecutionAdapter.prototype, "buildSignedOrder").mockResolvedValue(
      {} as never,
    );
    submitSpy = spyOn(PolymarketExecutionAdapter.prototype, "submitSignedOrder").mockResolvedValue({
      venue: "polymarket" as const,
      orderId: "pm-should-not-run",
      success: true,
      actualAmount: 20,
    } as Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>);

    // Simulate the revoke landing in the fence window: revoke the session right
    // after the policy gate but before the fence runs its active recheck. The
    // fence stub re-reads getActive() and returns null -> route fails closed.
    await getDb()
      .update(tradeSessions)
      .set({ status: "revoked", revokedAt: new Date() })
      .where(eq(tradeSessions.id, sessionId));

    try {
      const res = await postOrder(app, sessionId, crypto.randomUUID());
      // The pre-fence checkActiveOrder also sees it revoked -> 403; either way
      // the order is NOT submitted and no spend is consumed.
      expect([403, 409]).toContain(res.status);
      expect(submitSpy).toHaveBeenCalledTimes(0);
      expect(await dailySpendOf(sessionId)).toBe(0);
      expect(await auditCount(tenantId, "trade.order.submitted")).toBe(0);
    } finally {
      delete process.env.STEWARD_PM_TEST_CREDS;
    }
  });
});

describe("POST /v1/trade/sessions (polymarket)", () => {
  let tradeRoutes: Hono;

  beforeAll(() => {
    tradeRoutes = sharedTradeRoutes;
  });

  afterEach(() => {
    getWalletSpy?.mockRestore();
    getWalletSpy = undefined;
  });

  async function seedAgent(): Promise<{ tenantId: string; agentId: string }> {
    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const tenantId = `pm-sess-tenant-${suffix}`;
    const agentId = `pm-sess-agent-${suffix}`;
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: "PM Sess Tenant", apiKeyHash: `hash-${tenantId}` });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "PM Sess Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    return { tenantId, agentId };
  }

  function makeHumanApp(tenantId: string, routes: Hono) {
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "api-key"); // tenant-level api-key can manage sessions
      await next();
    });
    app.route("/v1/trade", routes);
    return app;
  }

  it("creates a polymarket session with a pm: allowlist through the public route", async () => {
    const { tenantId, agentId } = await seedAgent();
    stubWallet(true);
    const app = makeHumanApp(tenantId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "polymarket",
        dailyCap: 100,
        perOrderCap: 50,
        allowedAssets: [`pm:${TOKEN_ID}`, `pm:cond:${COND_ID}`],
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { ok: boolean; data: { sessionId: string } };
    expect(body.ok).toBe(true);
    expect(body.data.sessionId).toMatch(/^ses_/);

    // The persisted session is bound to the polymarket wallet + pm: allowlist.
    const [row] = await getDb()
      .select()
      .from(tradeSessions)
      .where(eq(tradeSessions.id, body.data.sessionId));
    expect(row.venue).toBe("polymarket");
    expect(row.walletId).toBe(WALLET);
    expect(row.allowedAssets).toContain(`pm:${TOKEN_ID}`);
    expect(row.allowedAssets).toContain(`pm:cond:${COND_ID}`);
  });

  it("rejects a polymarket session with no allowlist (400)", async () => {
    const { tenantId, agentId } = await seedAgent();
    stubWallet(true);
    const app = makeHumanApp(tenantId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId, venue: "polymarket", dailyCap: 100, perOrderCap: 50 }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error?: string }).error).toContain("require an explicit");
  });

  it("rejects a hyperliquid session that allowlists a pm: market (400)", async () => {
    const { tenantId, agentId } = await seedAgent();
    const app = makeHumanApp(tenantId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "hyperliquid",
        dailyCap: 100,
        perOrderCap: 50,
        allowedAssets: [`pm:${TOKEN_ID}`],
      }),
    });
    expect(res.status).toBe(400);
  });

  // ---- Agent-self path: the human-controlled agent_policies allowlist is the
  // ceiling for prediction markets too (security: no self-grant of arbitrary
  // pm: markets just because `polymarket` is an allowed venue). ----

  function makeAgentApp(tenantId: string, agentId: string, routes: Hono) {
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("agentScope", agentId);
      c.set("authType", "agent-token");
      await next();
    });
    app.route("/v1/trade", routes);
    return app;
  }

  async function seedPolicy(
    tenantId: string,
    agentId: string,
    allowedAssets: string[],
  ): Promise<void> {
    await getDb()
      .insert(agentPolicies)
      .values({
        agentId,
        tenantId,
        dailyCapUsd: "1000",
        perOrderCapUsd: "500",
        leverageCap: "1",
        allowedAssets,
        allowedVenues: ["hyperliquid", "polymarket"],
        updatedBy: "test",
      });
  }

  it("agent-self: rejects a pm: market NOT in the agent policy allowlist (400)", async () => {
    const { tenantId, agentId } = await seedAgent();
    // Policy allows polymarket venue but ONLY a different market.
    await seedPolicy(tenantId, agentId, ["pm:99999999"]);
    stubWallet(true);
    const app = makeAgentApp(tenantId, agentId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "polymarket",
        dailyCap: 100,
        perOrderCap: 50,
        allowedAssets: [`pm:${TOKEN_ID}`],
      }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { message?: string }).message).toContain(
      "not allowed by agent policy",
    );
  });

  it("agent-self: allows a pm: market that IS in the agent policy allowlist (201)", async () => {
    const { tenantId, agentId } = await seedAgent();
    await seedPolicy(tenantId, agentId, [`pm:${TOKEN_ID}`]);
    stubWallet(true);
    const app = makeAgentApp(tenantId, agentId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "polymarket",
        dailyCap: 100,
        perOrderCap: 50,
        allowedAssets: [`pm:${TOKEN_ID}`],
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { ok: boolean; data: { sessionId: string } };
    const [row] = await getDb()
      .select()
      .from(tradeSessions)
      .where(eq(tradeSessions.id, body.data.sessionId));
    expect(row.allowedAssets).toEqual([`pm:${TOKEN_ID}`]);
  });

  it("agent-self: rejects a polymarket session when the agent has no policy (403)", async () => {
    const { tenantId, agentId } = await seedAgent();
    stubWallet(true);
    const app = makeAgentApp(tenantId, agentId, tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "polymarket",
        dailyCap: 100,
        perOrderCap: 50,
        allowedAssets: [`pm:${TOKEN_ID}`],
      }),
    });
    expect(res.status).toBe(403);
  });
});
