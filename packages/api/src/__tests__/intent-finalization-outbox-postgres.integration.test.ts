import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  intents,
  tenants,
  users,
  userTenants,
  webhookConfigs,
  webhookDeliveries,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `intent-outbox-${suffix}`;
const agentId = `intent-outbox-agent-${suffix}`;
const intentId = `intent-outbox-intent-${suffix}`;
const userId = crypto.randomUUID();
const triggerName = `fail_intent_outer_commit_${suffix}`;

realPostgres("intent finalization durable outbox (mounted Postgres)", () => {
  let admin: ReturnType<typeof createDb>;
  let app: Hono<{ Variables: AppVariables }>;
  let runMounted: () => Promise<Response>;
  let previousMasterPassword: string | undefined;
  let previousAuditKey: string | undefined;

  beforeAll(async () => {
    previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_MASTER_PASSWORD = `intent-outbox-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `intent-outbox-audit-${suffix}`;
    __resetAuditHmacKeyCacheForTests();
    admin = createDb(databaseUrl!);
    await admin.db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: suffix });
    await admin.db.insert(users).values({ id: userId, email: `${suffix}@example.test` });
    await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });
    await admin.db.insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000710",
    });
    await admin.db.insert(webhookConfigs).values({
      tenantId,
      url: "https://example.com/intent-outbox",
      secret: "intent-outbox-secret",
      events: ["wallet_action.transfer.succeeded", "intent.executed"],
      maxRetries: 2,
      retryBackoffMs: 1_000,
    });
    await admin.db.insert(intents).values({
      id: intentId,
      tenantId,
      agentId,
      intentType: "wallet_action",
      status: "executing",
      createdByType: "user",
      createdById: userId,
      authorizedBy: userId,
      executedBy: userId,
      payload: { action: "transfer" },
      executionResult: {
        handler: "wallet_action.transfer",
        actionId: intentId,
        status: "signed",
        signedTx: "[redacted]",
      },
    });

    const [{ intentRoutes }, { withAuthenticatedTenantDatabase }] = await Promise.all([
      import("../routes/intents"),
      import("../services/context"),
    ]);
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", userId);
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", `intent-outbox-${suffix}`);
      await next();
    });
    app.route("/intents", intentRoutes);
    runMounted = () =>
      withAuthenticatedTenantDatabase(
        tenantId,
        "session-jwt",
        userId,
        () =>
          app.request(`/intents/${intentId}/execute`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: "{}",
          }),
        userId,
      );
  }, 120_000);

  afterAll(async () => {
    await admin.client.unsafe(`drop trigger if exists "${triggerName}" on intents`);
    await admin.client.unsafe(`drop function if exists "${triggerName}"()`);
    await admin.db.delete(webhookDeliveries).where(eq(webhookDeliveries.tenantId, tenantId));
    await admin.db.delete(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(intents).where(eq(intents.tenantId, tenantId));
    await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
    await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.db.delete(users).where(eq(users.id, userId));
    await admin.client.end();
    if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  });

  it("rolls back queued effects with the outer transaction, then recovers exactly once", async () => {
    await admin.client.unsafe(`
      create function "${triggerName}"() returns trigger language plpgsql as $$
      begin
        if new.id = '${intentId}' and new.status = 'executed' then
          raise exception 'forced outer intent commit failure';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create constraint trigger "${triggerName}"
      after update on intents deferrable initially deferred
      for each row execute function "${triggerName}"()
    `);

    await expect(runMounted()).rejects.toThrow("forced outer intent commit failure");
    const [rolledBack] = await admin.db.select().from(intents).where(eq(intents.id, intentId));
    expect(rolledBack).toMatchObject({ status: "executing" });
    expect(
      await admin.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.tenantId, tenantId)),
    ).toHaveLength(0);
    expect(
      await admin.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "intent.executed"))),
    ).toHaveLength(0);

    await admin.client.unsafe(`drop trigger "${triggerName}" on intents`);
    await admin.client.unsafe(`drop function "${triggerName}"()`);
    const recovered = await runMounted();
    expect(recovered.status).toBe(200);
    const deliveries = await admin.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.tenantId, tenantId));
    expect(deliveries).toHaveLength(2);
    expect(deliveries.map(({ status }) => status)).toEqual(["pending", "pending"]);

    const replay = await runMounted();
    expect(replay.status).toBe(409);
    expect(
      await admin.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.tenantId, tenantId)),
    ).toHaveLength(2);
  }, 120_000);
});
