import { afterAll, beforeAll, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agentPolicies,
  agents,
  agentWallets,
  and,
  auditChainHeads,
  auditEvents,
  closeDb,
  createDb,
  eq,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt =
  databaseUrl && !process.env.STEWARD_PGLITE_MEMORY && process.env.STEWARD_DB_MODE !== "pglite"
    ? it
    : it.skip;

const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
const auditKey = "trade-session-atomic-postgres-test-key-0123456789abcdef";

beforeAll(() => {
  process.env.STEWARD_AUDIT_HMAC_KEY = auditKey;
  __resetAuditHmacKeyCacheForTests();
});

afterAll(async () => {
  await closeDb().catch(() => undefined);
  if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
  else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
  __resetAuditHmacKeyCacheForTests();
});

async function mountSessionRoute(tenantId: string, configure?: (ctx: StewardAppContext) => void) {
  const { createTradeRoutes } = await import("../routes/trade");
  const { testCtx } = await import("./_ctx");
  const ctx = testCtx();
  configure?.(ctx);
  const app = new Hono();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("agentScope", null);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/v1/trade", createTradeRoutes(ctx));
  app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  return { app, ctx };
}

async function seedAgent(admin: ReturnType<typeof createDb>, tenantId: string, agentId: string) {
  await admin.db.insert(tenants).values({
    id: tenantId,
    name: tenantId,
    apiKeyHash: `hash-${tenantId}`,
  });
  await admin.db.insert(agents).values({
    id: agentId,
    tenantId,
    name: agentId,
    walletAddress: "0x0000000000000000000000000000000000000753",
  });
  await admin.db.insert(agentWallets).values({
    agentId,
    chainFamily: "evm",
    venue: "hyperliquid",
    address: "0x0000000000000000000000000000000000000753",
  });
  await admin.db.insert(agentPolicies).values({
    agentId,
    tenantId,
    dailyCapUsd: "250",
    perOrderCapUsd: "50",
    leverageCap: "3",
    allowedAssets: ["BTC", "ETH"],
    allowedVenues: ["hyperliquid"],
    updatedBy: "test:issue-753",
    updatedReason: "initial policy",
  });
}

async function cleanup(admin: ReturnType<typeof createDb>, tenantId: string, agentId: string) {
  await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  await admin.db.delete(tradeSessions).where(eq(tradeSessions.tenantId, tenantId));
  await admin.db.delete(agentPolicies).where(eq(agentPolicies.tenantId, tenantId));
  await admin.db.delete(agentWallets).where(eq(agentWallets.agentId, agentId));
  await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
  await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
}

function sessionRequest(app: Hono, agentId: string) {
  return app.request("/v1/trade/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agentId,
      venue: "hyperliquid",
      dailyCap: 200,
      perOrderCap: 40,
      leverageCap: 2,
      allowedAssets: ["BTC"],
    }),
  });
}

realPostgresIt(
  "rolls back the durable session when the mounted required completion audit fails",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant-session-audit-pg-${suffix}`;
    const agentId = `agent-session-audit-pg-${suffix}`;
    const triggerFunction = `fail_trade_session_audit_${suffix}`;
    const triggerName = `fail_trade_session_audit_${suffix}`;
    const admin = createDb(databaseUrl!);
    try {
      await seedAgent(admin, tenantId, agentId);
      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}' and new.action = 'trade.session.created' then
            raise exception 'forced required completion audit failure';
          end if;
          return new;
        end
        $$
      `);
      await admin.client.unsafe(`
        create trigger "${triggerName}"
        before insert on audit_events
        for each row execute function "${triggerFunction}"()
      `);
      const { app } = await mountSessionRoute(tenantId);

      const response = await sessionRequest(app, agentId);
      expect(response.status).toBe(500);
      expect(await response.json()).toMatchObject({
        ok: false,
        error: expect.stringContaining("INSERT INTO audit_events"),
      });
      expect(
        await admin.db
          .select({ id: tradeSessions.id })
          .from(tradeSessions)
          .where(and(eq(tradeSessions.tenantId, tenantId), eq(tradeSessions.agentId, agentId))),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "trade.session.created"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await cleanup(admin, tenantId, agentId);
      await admin.client.end();
    }
  },
  120_000,
);

realPostgresIt(
  "rejects a mounted create when a second connection changes policy after preflight",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant-session-policy-race-${suffix}`;
    const agentId = `agent-session-policy-race-${suffix}`;
    const admin = createDb(databaseUrl!);
    const writer = createDb(databaseUrl!);
    try {
      await seedAgent(admin, tenantId, agentId);
      let releaseTransaction!: () => void;
      const transactionReleased = new Promise<void>((resolve) => {
        releaseTransaction = resolve;
      });
      let reachedTransaction!: () => void;
      const transactionReached = new Promise<void>((resolve) => {
        reachedTransaction = resolve;
      });
      const { app } = await mountSessionRoute(tenantId, (ctx) => {
        const realAuditedTransaction = ctx.withTenantAuditedTransaction;
        ctx.withTenantAuditedTransaction = async (targetTenantId, fn) => {
          reachedTransaction();
          await transactionReleased;
          return realAuditedTransaction(targetTenantId, fn);
        };
      });

      const request = sessionRequest(app, agentId);
      await Promise.race([
        transactionReached,
        Bun.sleep(10_000).then(() => {
          throw new Error("mounted create did not reach the audited transaction boundary");
        }),
      ]);
      await writer.db
        .update(agentPolicies)
        .set({
          dailyCapUsd: "100",
          perOrderCapUsd: "25",
          leverageCap: "1",
          updatedBy: "test:concurrent-policy-writer",
          updatedReason: "policy tightened during session create",
          updatedAt: new Date(),
        })
        .where(and(eq(agentPolicies.tenantId, tenantId), eq(agentPolicies.agentId, agentId)));
      releaseTransaction();

      const response = await request;
      expect(response.status).toBe(500);
      expect(await response.json()).toMatchObject({
        ok: false,
        error: "Agent trade policy changed during session creation",
      });
      expect(
        await admin.db
          .select({ id: tradeSessions.id })
          .from(tradeSessions)
          .where(and(eq(tradeSessions.tenantId, tenantId), eq(tradeSessions.agentId, agentId))),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "trade.session.created"),
            ),
          ),
      ).toHaveLength(0);
      const [winningPolicy] = await admin.db
        .select({
          dailyCapUsd: agentPolicies.dailyCapUsd,
          perOrderCapUsd: agentPolicies.perOrderCapUsd,
          leverageCap: agentPolicies.leverageCap,
          updatedBy: agentPolicies.updatedBy,
        })
        .from(agentPolicies)
        .where(and(eq(agentPolicies.tenantId, tenantId), eq(agentPolicies.agentId, agentId)));
      expect(winningPolicy).toMatchObject({
        dailyCapUsd: "100",
        perOrderCapUsd: "25",
        leverageCap: "1",
        updatedBy: "test:concurrent-policy-writer",
      });
    } finally {
      await cleanup(admin, tenantId, agentId);
      await writer.client.end();
      await admin.client.end();
    }
  },
  120_000,
);

realPostgresIt(
  "rejects a mounted create when a second connection rotates the venue wallet after preflight",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant-session-wallet-race-${suffix}`;
    const agentId = `agent-session-wallet-race-${suffix}`;
    const admin = createDb(databaseUrl!);
    const writer = createDb(databaseUrl!);
    try {
      await seedAgent(admin, tenantId, agentId);
      let releaseTransaction!: () => void;
      const transactionReleased = new Promise<void>((resolve) => {
        releaseTransaction = resolve;
      });
      let reachedTransaction!: () => void;
      const transactionReached = new Promise<void>((resolve) => {
        reachedTransaction = resolve;
      });
      const { app } = await mountSessionRoute(tenantId, (ctx) => {
        const realAuditedTransaction = ctx.withTenantAuditedTransaction;
        ctx.withTenantAuditedTransaction = async (targetTenantId, fn) => {
          reachedTransaction();
          await transactionReleased;
          return realAuditedTransaction(targetTenantId, fn);
        };
      });

      const request = sessionRequest(app, agentId);
      await Promise.race([
        transactionReached,
        Bun.sleep(10_000).then(() => {
          throw new Error("mounted create did not reach the audited transaction boundary");
        }),
      ]);
      await writer.db
        .update(agentWallets)
        .set({ address: "0x0000000000000000000000000000000000000754" })
        .where(
          and(
            eq(agentWallets.agentId, agentId),
            eq(agentWallets.venue, "hyperliquid"),
            eq(agentWallets.chainFamily, "evm"),
          ),
        );
      releaseTransaction();

      const response = await request;
      expect(response.status).toBe(500);
      expect(await response.json()).toMatchObject({
        ok: false,
        error: "Agent venue wallet changed during session creation",
      });
      expect(
        await admin.db
          .select({ id: tradeSessions.id })
          .from(tradeSessions)
          .where(and(eq(tradeSessions.tenantId, tenantId), eq(tradeSessions.agentId, agentId))),
      ).toHaveLength(0);
      const [winningWallet] = await admin.db
        .select({ address: agentWallets.address })
        .from(agentWallets)
        .where(
          and(
            eq(agentWallets.agentId, agentId),
            eq(agentWallets.venue, "hyperliquid"),
            eq(agentWallets.chainFamily, "evm"),
          ),
        );
      expect(winningWallet?.address).toBe("0x0000000000000000000000000000000000000754");
    } finally {
      await cleanup(admin, tenantId, agentId);
      await writer.client.end();
      await admin.client.end();
    }
  },
  120_000,
);

realPostgresIt(
  "preserves both winners under two concurrent mounted session creates",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant-session-create-race-${suffix}`;
    const agentId = `agent-session-create-race-${suffix}`;
    const admin = createDb(databaseUrl!);
    try {
      await seedAgent(admin, tenantId, agentId);
      const { app } = await mountSessionRoute(tenantId);
      const [first, second] = await Promise.all([
        sessionRequest(app, agentId),
        sessionRequest(app, agentId),
      ]);
      expect([first.status, second.status]).toEqual([201, 201]);
      const firstBody = (await first.json()) as { data: { sessionId: string } };
      const secondBody = (await second.json()) as { data: { sessionId: string } };
      expect(firstBody.data.sessionId).not.toBe(secondBody.data.sessionId);
      expect(
        await admin.db
          .select({ id: tradeSessions.id })
          .from(tradeSessions)
          .where(and(eq(tradeSessions.tenantId, tenantId), eq(tradeSessions.agentId, agentId))),
      ).toHaveLength(2);
      expect(
        await admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "trade.session.created"),
            ),
          ),
      ).toHaveLength(2);
    } finally {
      await cleanup(admin, tenantId, agentId);
      await admin.client.end();
    }
  },
  120_000,
);
