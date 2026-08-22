import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  intents,
  policies,
  tenants,
  transactions,
  users,
  userTenants,
  webhookConfigs,
  webhookDeliveries,
} from "@stwd/db";
import { PersistentQueue } from "@stwd/webhooks";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `intent-recovery-${suffix}`;
const agentId = `intent-recovery-agent-${suffix}`;
const intentId = `intent-recovery-intent-${suffix}`;
const userId = crypto.randomUUID();
const requestId = `intent-recovery-request-${suffix}`;
const triggerName = `fail_intent_outer_commit_${suffix}`;
const rlsTriggerName = `require_intent_tenant_context_${suffix}`;
const deliveryAckTriggerName = `fail_delivery_ack_${suffix}`;
const txHash = `0x${"71".repeat(32)}`;

realPostgres("intent execution recovery (mounted production tenantAuth)", () => {
  let admin: ReturnType<typeof createDb>;
  let app: Hono<{ Variables: AppVariables }>;
  let token: string;
  let releaseSend: (() => void) | undefined;
  let sendReached: Promise<void>;
  let sendCount = 0;
  let originalFetch: typeof globalThis.fetch;
  const previousEnv = new Map<string, string | undefined>();
  const envKeys = [
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
  ] as const;

  const runMounted = () =>
    app.request(`/intents/${intentId}/execute`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Request-Id": requestId,
      },
      body: "{}",
    });

  beforeAll(async () => {
    for (const key of envKeys) previousEnv.set(key, process.env[key]);
    process.env.STEWARD_MASTER_PASSWORD = `intent-recovery-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `intent-recovery-audit-${suffix}`;
    process.env.STEWARD_JWT_SECRET = `intent-recovery-jwt-${suffix}-${"x".repeat(32)}`;
    __resetAuditHmacKeyCacheForTests();
    admin = createDb(databaseUrl!);

    await admin.db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: suffix });
    await admin.db.insert(users).values({ id: userId, email: `${suffix}@example.test` });
    await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });

    const [{ intentRoutes }, context, { createSessionToken }] = await Promise.all([
      import("../routes/intents"),
      import("../services/context"),
      import("../routes/auth"),
    ]);
    await context.vault.createAgent(tenantId, agentId, agentId);
    await admin.db.insert(policies).values({
      id: `intent-recovery-policy-${suffix}`,
      agentId,
      type: "approved-addresses",
      enabled: true,
      config: {
        mode: "whitelist",
        addresses: ["0x0000000000000000000000000000000000000710"],
      },
    });
    await admin.db.insert(webhookConfigs).values({
      tenantId,
      url: "https://example.com/intent-recovery",
      secret: "intent-recovery-secret",
      events: ["wallet_action.transfer.succeeded", "intent.executed"],
      maxRetries: 2,
      retryBackoffMs: 1_000,
    });
    await admin.db.insert(intents).values({
      id: intentId,
      tenantId,
      agentId,
      intentType: "wallet_action",
      status: "pending",
      createdByType: "api",
      createdById: `test:${suffix}`,
      payload: {
        action: "transfer",
        transfer: {
          to: "0x0000000000000000000000000000000000000710",
          value: "1",
          chainId: 84532,
          gasLimit: "21000",
          broadcast: true,
        },
      },
    });

    token = await createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", correlationId);
    app.use("*", (c, next) => context.tenantAuth(c, next));
    app.route("/intents", intentRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));

    const authorized = await app.request(`/intents/${intentId}/authorize`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Request-Id": `intent-authorize-${suffix}`,
      },
      body: "{}",
    });
    expect(authorized.status).toBe(200);

    await admin.client.unsafe(`
      create function "${rlsTriggerName}"() returns trigger language plpgsql as $$
      begin
        if new.id = '${intentId}' and new.status = 'executing' and old.status = 'authorized' then
          if nullif(current_setting('steward.tenant_id', true), '') is distinct from '${tenantId}' then
            raise exception 'intent reservation escaped tenant RLS context';
          end if;
          if nullif(current_setting('steward.user_id', true), '') is distinct from '${userId}' then
            raise exception 'intent reservation escaped authenticated user context';
          end if;
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${rlsTriggerName}"
      before update on intents
      for each row execute function "${rlsTriggerName}"()
    `);
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

    originalFetch = globalThis.fetch;
    sendReached = new Promise<void>((resolve) => {
      globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
        const rpc = JSON.parse(String(init?.body ?? "{}")) as { id?: number; method?: string };
        let result: unknown = null;
        if (rpc.method === "eth_chainId") result = "0x14a34";
        else if (rpc.method === "eth_getTransactionCount") result = "0x0";
        else if (rpc.method === "eth_estimateGas") result = "0x5208";
        else if (rpc.method === "eth_gasPrice") result = "0x3b9aca00";
        else if (rpc.method === "eth_maxPriorityFeePerGas") result = "0x3b9aca00";
        else if (rpc.method === "eth_getBlockByNumber") {
          result = {
            baseFeePerGas: "0x3b9aca00",
            difficulty: "0x0",
            extraData: "0x",
            gasLimit: "0x1c9c380",
            gasUsed: "0x0",
            hash: `0x${"11".repeat(32)}`,
            logsBloom: `0x${"00".repeat(256)}`,
            miner: `0x${"00".repeat(20)}`,
            mixHash: `0x${"22".repeat(32)}`,
            nonce: "0x0000000000000000",
            number: "0x1",
            parentHash: `0x${"33".repeat(32)}`,
            receiptsRoot: `0x${"44".repeat(32)}`,
            sha3Uncles: `0x${"55".repeat(32)}`,
            size: "0x1",
            stateRoot: `0x${"66".repeat(32)}`,
            timestamp: "0x1",
            totalDifficulty: "0x0",
            transactions: [],
            transactionsRoot: `0x${"77".repeat(32)}`,
            uncles: [],
          };
        } else if (rpc.method === "eth_sendRawTransaction") {
          sendCount++;
          resolve();
          await new Promise<void>((release) => {
            releaseSend = release;
          });
          result = txHash;
        }
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 1, result }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }) as typeof fetch;
    });
  }, 120_000);

  afterAll(async () => {
    releaseSend?.();
    if (originalFetch) globalThis.fetch = originalFetch;
    await admin.client.unsafe(`drop trigger if exists "${triggerName}" on intents`);
    await admin.client.unsafe(`drop function if exists "${triggerName}"()`);
    await admin.client.unsafe(`drop trigger if exists "${rlsTriggerName}" on intents`);
    await admin.client.unsafe(`drop function if exists "${rlsTriggerName}"()`);
    await admin.client.unsafe(
      `drop trigger if exists "${deliveryAckTriggerName}" on webhook_deliveries`,
    );
    await admin.client.unsafe(`drop function if exists "${deliveryAckTriggerName}"()`);
    await admin.db.delete(webhookDeliveries).where(eq(webhookDeliveries.tenantId, tenantId));
    await admin.db.delete(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(transactions).where(eq(transactions.agentId, agentId));
    await admin.db.delete(intents).where(eq(intents.tenantId, tenantId));
    await admin.db.delete(policies).where(eq(policies.agentId, agentId));
    await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
    await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.db.delete(users).where(eq(users.id, userId));
    await admin.client.end();
    for (const key of envKeys) {
      const value = previousEnv.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    __resetAuditHmacKeyCacheForTests();
  });

  it("commits the RLS-bound reservation before send and never repeats an accepted send after outer rollback", async () => {
    const firstRequest = runMounted();
    await sendReached;

    const [visibleReservation] = await admin.db
      .select()
      .from(intents)
      .where(eq(intents.id, intentId));
    expect(visibleReservation.status).toBe("executing");
    expect(visibleReservation.executionResult).toMatchObject({
      recoveryVersion: 1,
      state: "reserved",
      intentVersion: expect.any(String),
      intentDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      executionDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      authorizationBaseline: {
        kind: "policy-set",
        hash: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
      reservedBy: userId,
      reservedActorType: "user",
      requestId,
    });
    expect(sendCount).toBe(1);

    const concurrentRetry = await runMounted();
    expect(concurrentRetry.status).toBe(202);
    const concurrentBody = (await concurrentRetry.json()) as {
      data: { executionState: string; recoveryRequired: boolean };
    };
    expect(concurrentBody.data).toMatchObject({
      executionState: "reserved",
      recoveryRequired: true,
    });
    expect(sendCount).toBe(1);

    releaseSend?.();
    const failedOuter = await firstRequest;
    expect(failedOuter.status).toBe(500);

    const [recoverable] = await admin.db.select().from(intents).where(eq(intents.id, intentId));
    expect(recoverable).toMatchObject({
      status: "executing",
      executionResult: {
        recoveryVersion: 1,
        state: "completed",
        result: { handler: "wallet_action.transfer", txHash },
        resultDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      },
    });
    expect(sendCount).toBe(1);
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
    const recoveredBody = (await recovered.json()) as {
      data: { executionResult: { txHash: string } };
    };
    expect(recoveredBody.data.executionResult.txHash).toBe(txHash);
    expect(sendCount).toBe(1);
    const reservedDeliveries = await admin.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.tenantId, tenantId));
    expect(reservedDeliveries).toHaveLength(2);
    const walletDelivery = reservedDeliveries.find(
      ({ eventType }) => eventType === "wallet_action.transfer.succeeded",
    );
    const intentDelivery = reservedDeliveries.find(
      ({ eventType }) => eventType === "intent.executed",
    );
    expect(walletDelivery?.predecessorDeliveryId).toBeNull();
    expect(intentDelivery?.predecessorDeliveryId).toBe(walletDelivery?.id);

    const replay = await runMounted();
    expect(replay.status).toBe(409);
    expect(sendCount).toBe(1);
    expect(
      await admin.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.tenantId, tenantId)),
    ).toHaveLength(2);

    const dispatchAttempts: Array<{ type: string; deliveryId: string }> = [];
    const receiverEffects = new Set<string>();
    const dispatcher = {
      async dispatch(event: { type: string; deliveryId?: string }) {
        const deliveryId = String(event.deliveryId);
        dispatchAttempts.push({ type: event.type, deliveryId });
        // This models the receiver contract: the stable delivery id, rather
        // than transport acknowledgement, is the exact-effect dedupe key.
        receiverEffects.add(deliveryId);
        return { success: true, attempts: 1, deliveredAt: new Date() };
      },
    };
    const queueA = new PersistentQueue(dispatcher as never, { batchSize: 1 });
    const queueB = new PersistentQueue(dispatcher as never, { batchSize: 1 });

    await admin.client.unsafe(`
      create function "${deliveryAckTriggerName}"() returns trigger language plpgsql as $$
      begin
        if new.status = 'delivered' and old.event_type = 'wallet_action.transfer.succeeded' then
          raise exception 'lost delivery database acknowledgement';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${deliveryAckTriggerName}"
      before update on webhook_deliveries
      for each row execute function "${deliveryAckTriggerName}"()
    `);
    await expect(queueA.processQueue()).rejects.toThrow();
    expect(dispatchAttempts.map(({ type }) => type)).toEqual(["wallet_action.transfer.succeeded"]);
    expect(receiverEffects.size).toBe(1);

    await admin.client.unsafe(`drop trigger "${deliveryAckTriggerName}" on webhook_deliveries`);
    await admin.client.unsafe(`drop function "${deliveryAckTriggerName}"()`);
    await admin.db
      .update(webhookDeliveries)
      .set({ nextRetryAt: new Date() })
      .where(eq(webhookDeliveries.id, walletDelivery!.id));

    const walletRetryClaims = await Promise.all([queueA.processQueue(), queueB.processQueue()]);
    expect(walletRetryClaims.flat()).toHaveLength(1);
    expect(dispatchAttempts.map(({ type }) => type)).toEqual([
      "wallet_action.transfer.succeeded",
      "wallet_action.transfer.succeeded",
    ]);
    expect(dispatchAttempts[0]?.deliveryId).toBe(dispatchAttempts[1]?.deliveryId);
    expect(receiverEffects.size).toBe(1);

    const intentClaims = await Promise.all([queueA.processQueue(), queueB.processQueue()]);
    expect(intentClaims.flat()).toHaveLength(1);
    expect(dispatchAttempts.map(({ type }) => type)).toEqual([
      "wallet_action.transfer.succeeded",
      "wallet_action.transfer.succeeded",
      "intent.executed",
    ]);
    expect(receiverEffects.size).toBe(2);
  }, 120_000);
});
