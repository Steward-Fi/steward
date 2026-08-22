import { afterAll, beforeAll, describe, expect, setDefaultTimeout, spyOn, test } from "bun:test";
import { fileURLToPath } from "node:url";
import {
  agents,
  createPostgresClient,
  eq,
  getDb,
  runPluginMigrations,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { TradeSessionManager } from "@stwd/trade-sessions";
import { HyperliquidAdapter } from "@stwd/venue-hyperliquid";
import { Hono } from "hono";
import type { AppVariables } from "@stwd/shared";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `route-fence-tenant-${suffix}`;
const agentId = `route-fence-agent-${suffix}`;
const blocker = databaseUrl ? createPostgresClient(databaseUrl) : null;
const inspector = databaseUrl ? createPostgresClient(databaseUrl) : null;
let routes: Hono;
let initialFenceSpy: ReturnType<typeof spyOn> | undefined;

setDefaultTimeout(120_000);

function lockKey(sessionId: string): string {
  return `trade_session_fence_${tenantId}:${sessionId}`;
}

async function waitForBlockedLock(key: string, expected: number): Promise<void> {
  if (!inspector) throw new Error("real PostgreSQL inspector is unavailable");
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const rows = await inspector<{ count: number }[]>`
      WITH target AS (SELECT hashtextextended(${key}, 0)::bigint AS key)
      SELECT count(DISTINCT locks.pid)::int AS count
      FROM pg_locks locks CROSS JOIN target
      WHERE locks.locktype = 'advisory' AND locks.granted = false
        AND locks.database = (SELECT oid FROM pg_database WHERE datname = current_database())
        AND locks.classid::bigint = ((target.key >> 32) & 4294967295)
        AND locks.objid::bigint = (target.key & 4294967295) AND locks.objsubid = 1
    `;
    if ((rows[0]?.count ?? 0) >= expected) return;
    await Bun.sleep(10);
  }
  throw new Error(`timed out waiting for ${expected} blocked route-fence connection(s)`);
}

async function holdFence(key: string): Promise<{ release: () => void; done: Promise<void> }> {
  if (!blocker) throw new Error("real PostgreSQL blocker is unavailable");
  let release!: () => void;
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  let ready!: () => void;
  const acquired = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const done = blocker.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))`;
    ready();
    await released;
  });
  await acquired;
  return { release, done };
}

async function seedSession(): Promise<string> {
  const id = `ses_${crypto.randomUUID()}`;
  await getDb()
    .insert(tradeSessions)
    .values({
      id,
      tenantId,
      agentId,
      venue: "hyperliquid",
      walletId: "0x0000000000000000000000000000000000000001",
      status: "active",
      dailySpendUsd: "0",
      dailyCapUsd: "100",
      perOrderCapUsd: "50",
      leverageCap: "5",
      allowedAssets: ["BTC"],
      expiresAt: new Date(Date.now() + 120_000),
    });
  return id;
}

function mountedApp(): Hono<{ Variables: AppVariables }> {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", agentId);
    c.set("authType", "agent");
    await next();
  });
  app.route("/v1/trade", routes);
  return app;
}

function postOrder(app: Hono, sessionId: string, key: string) {
  return app.request("/v1/trade/hyperliquid/order", {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify({
      sessionId,
      asset: "BTC",
      side: "buy",
      size: 1,
      limitPx: 10,
      leverage: 1,
    }),
  });
}

realPostgres("assembled trade route final revocation fence", () => {
  beforeAll(async () => {
    process.env.STEWARD_MASTER_PASSWORD ??= "route-fence-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "route-fence-audit-hmac-key-0123456789abcdef";
    await runPluginMigrations({
      id: "trading",
      migrationsFolder: fileURLToPath(new URL("../../drizzle", import.meta.url)),
    });
    await getDb()
      .insert(tenants)
      .values({ id: tenantId, name: "Route Fence Tenant", apiKeyHash: `hash-${tenantId}` });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Route Fence Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    initialFenceSpy = spyOn(
      TradeSessionManager.prototype,
      "withActiveSubmissionFence",
    ).mockImplementation((async (_input, callback) => callback(undefined)) as never);
    const [{ createTradeRoutes }, { testCtx }] = await Promise.all([
      import("../routes/trade"),
      import("./_ctx"),
    ]);
    routes = createTradeRoutes(testCtx());
  });

  afterAll(async () => {
    initialFenceSpy?.mockRestore();
    await getDb().delete(tradeSessions).where(eq(tradeSessions.tenantId, tenantId));
    await getDb().delete(agents).where(eq(agents.tenantId, tenantId));
    await getDb().delete(tenants).where(eq(tenants.id, tenantId));
    await blocker?.end();
    await inspector?.end();
  });

  test("submit-first route holds revocation through the bounded venue call", async () => {
    const sessionId = await seedSession();
    let releaseSubmit!: () => void;
    const submitBarrier = new Promise<void>((resolve) => {
      releaseSubmit = resolve;
    });
    let entered!: () => void;
    const venueEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const sign = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue({} as never);
    const submit = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockImplementation(
      async () => {
        entered();
        await submitBarrier;
        return { orderId: "route-submit-first", status: "filled", filledQty: 1, avgPrice: 10 };
      },
    );
    const response = postOrder(mountedApp(), sessionId, crypto.randomUUID());
    await venueEntered;
    const revocation = new TradeSessionManager().revokeSession({
      tenantId,
      id: sessionId,
      revokedBy: "route-race-test",
    });
    await waitForBlockedLock(lockKey(sessionId), 1);
    releaseSubmit();
    expect((await response).status).toBe(200);
    expect((await revocation)?.status).toBe("revoked");
    expect(submit).toHaveBeenCalledTimes(1);
    sign.mockRestore();
    submit.mockRestore();
  });

  test("revoke-first route never invokes the venue", async () => {
    const sessionId = await seedSession();
    const held = await holdFence(lockKey(sessionId));
    const revocation = new TradeSessionManager().revokeSession({
      tenantId,
      id: sessionId,
      revokedBy: "route-race-test",
    });
    await waitForBlockedLock(lockKey(sessionId), 1);
    const sign = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue({} as never);
    const submit = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockResolvedValue({
      orderId: "must-not-submit",
      status: "filled",
    } as never);
    const response = postOrder(mountedApp(), sessionId, crypto.randomUUID());
    await waitForBlockedLock(lockKey(sessionId), 2);
    held.release();
    await held.done;
    expect((await revocation)?.status).toBe("revoked");
    expect((await response).status).toBe(409);
    expect(submit).toHaveBeenCalledTimes(0);
    sign.mockRestore();
    submit.mockRestore();
  });

  test("route timeout abort releases the fence for queued revocation", async () => {
    const sessionId = await seedSession();
    let abortSubmit!: () => void;
    const submitAborted = new Promise<void>((_resolve, reject) => {
      abortSubmit = () => reject(new DOMException("venue timeout", "AbortError"));
    });
    let entered!: () => void;
    const venueEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const sign = spyOn(HyperliquidAdapter.prototype, "signOrder").mockResolvedValue({} as never);
    const submit = spyOn(HyperliquidAdapter.prototype, "submitOrder").mockImplementation(
      async () => {
        entered();
        await submitAborted;
        throw new Error("unreachable");
      },
    );
    const response = postOrder(mountedApp(), sessionId, crypto.randomUUID());
    await venueEntered;
    const revocation = new TradeSessionManager().revokeSession({
      tenantId,
      id: sessionId,
      revokedBy: "route-timeout-test",
    });
    await waitForBlockedLock(lockKey(sessionId), 1);
    abortSubmit();

    expect((await response).status).toBe(502);
    expect((await revocation)?.status).toBe("revoked");
    expect(submit).toHaveBeenCalledTimes(1);
    sign.mockRestore();
    submit.mockRestore();
  });
});
