import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  agents,
  approvalQueue,
  auditEvents,
  closeDb,
  getDb,
  policies,
  sponsoredGasEvents,
  tenantConfigs,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const RUN = crypto.randomUUID().slice(0, 8);
const TENANT_ID = `sponsorship-route-${RUN}`;
const REQUESTER_ID = "00000000-0000-4000-8000-000000007351";
const APPROVER_ID = "00000000-0000-4000-8000-000000007352";
const AUTO_AGENT = `sponsor-auto-${RUN}`;
const MANUAL_AGENT = `sponsor-manual-${RUN}`;
const AUDIT_AGENT = `sponsor-audit-${RUN}`;
const RECIPIENT = "0x1234567890123456789012345678901234567890";
const TOKEN = "0x4200000000000000000000000000000000000006";

const originalRedisUrl = process.env.REDIS_URL;
const originalRedisRequired = process.env.REDIS_REQUIRED;
const originalAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
const originalMasterPassword = process.env.STEWARD_MASTER_PASSWORD;

async function makeApp(userId: string) {
  const { vaultRoutes } = await import("../routes/vault");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", userId);
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/vault", vaultRoutes);
  app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  return app;
}

async function seedTransferAgent(agentId: string, manual: boolean) {
  await getDb()
    .insert(agents)
    .values({
      id: agentId,
      tenantId: TENANT_ID,
      name: agentId,
      walletAddress:
        `0x${agentId === AUTO_AGENT ? "1" : agentId === MANUAL_AGENT ? "2" : "3"}`.padEnd(42, "0"),
    });
  await getDb()
    .insert(policies)
    .values([
      {
        id: `${agentId}-addresses`,
        agentId,
        type: "approved-addresses",
        enabled: true,
        config: { addresses: [RECIPIENT, TOKEN], mode: "whitelist" },
      },
      {
        id: `${agentId}-selector`,
        agentId,
        type: "contract-allowlist",
        enabled: true,
        config: {
          contracts: [
            {
              address: TOKEN,
              selectors: ["0xa9059cbb"],
              constraints: {
                "0xa9059cbb": { recipientAllowlist: [RECIPIENT], maxAmount: "1000000" },
              },
            },
          ],
        },
      },
      ...(manual
        ? [
            {
              id: `${agentId}-manual`,
              agentId,
              type: "auto-approve-threshold",
              enabled: true,
              config: {},
            },
          ]
        : []),
    ]);
}

function transfer(
  app: Awaited<ReturnType<typeof makeApp>>,
  agentId: string,
  key: string,
  extra = {},
) {
  return app.request(`/vault/${agentId}/actions/transfer`, {
    method: "POST",
    headers: { "content-type": "application/json", "Idempotency-Key": key },
    body: JSON.stringify({
      to: RECIPIENT,
      token: TOKEN,
      value: "10",
      chainId: 8453,
      broadcast: true,
      sponsor: true,
      referenceId: key,
      ...extra,
    }),
  });
}

describe("gas sponsorship mounted accounting", () => {
  let requesterApp: Awaited<ReturnType<typeof makeApp>>;
  let approverApp: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    delete process.env.REDIS_URL;
    delete process.env.REDIS_REQUIRED;
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "sponsorship-route-test-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "sponsorship-route-test-audit-key-0123456789abcdef0123456789";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: TENANT_ID,
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        gasSponsorshipConfig: {
          enabled: true,
          provider: "mock",
          mode: "erc4337",
          allowClientSponsorship: true,
          allowedChainIds: [8453],
          maxPerTxUsd: 0.5,
          maxPerWalletDayUsd: 0.5,
          maxTenantDayUsd: 0.5,
        },
      });
    await getDb()
      .insert(users)
      .values([
        { id: REQUESTER_ID, email: `sponsor-requester-${RUN}@example.test` },
        { id: APPROVER_ID, email: `sponsor-approver-${RUN}@example.test` },
      ]);
    await getDb()
      .insert(userTenants)
      .values([
        { userId: REQUESTER_ID, tenantId: TENANT_ID, role: "owner" },
        { userId: APPROVER_ID, tenantId: TENANT_ID, role: "owner" },
      ]);
    await seedTransferAgent(AUTO_AGENT, false);
    await seedTransferAgent(MANUAL_AGENT, true);
    await seedTransferAgent(AUDIT_AGENT, false);
    requesterApp = await makeApp(REQUESTER_ID);
    approverApp = await makeApp(APPROVER_ID);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
    if (originalRedisRequired === undefined) delete process.env.REDIS_REQUIRED;
    else process.env.REDIS_REQUIRED = originalRedisRequired;
    if (originalAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = originalAuditKey;
    if (originalMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = originalMasterPassword;
  });

  it("rejects signed-only sponsorship, including replay, before reservation or signing", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      throw new Error("signed-only sponsorship reached signing");
    };
    try {
      for (let replay = 0; replay < 2; replay += 1) {
        const response = await requesterApp.request(`/vault/${AUTO_AGENT}/actions/transfer`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            to: RECIPIENT,
            token: TOKEN,
            value: "10",
            chainId: 8453,
            broadcast: false,
            sponsor: true,
            referenceId: "signed-only-replay",
          }),
        });
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({
          ok: false,
          error: expect.stringContaining("signed-only actions"),
        });
      }
      expect(signCalls).toBe(0);
      expect(await getDb().select().from(sponsoredGasEvents)).toHaveLength(0);
      expect(await getDb().select().from(transactions)).toHaveLength(0);
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });

  it("does not sign and records a zero-value failure when the required audit fails", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      return "0xunexpected";
    };
    await getDb().execute(
      sql.raw(`
      create function fail_sponsor_authorized_${RUN}() returns trigger language plpgsql as $$
      begin
        if new.action = 'wallet_action.transfer.authorized' then
          raise exception 'forced sponsorship authorization audit failure';
        end if;
        return new;
      end $$
    `),
    );
    await getDb().execute(
      sql.raw(`
      create trigger fail_sponsor_authorized_${RUN}
      before insert on audit_events for each row
      execute function fail_sponsor_authorized_${RUN}()
    `),
    );
    try {
      const response = await transfer(requesterApp, AUDIT_AGENT, "audit-failure");
      expect([500, 502]).toContain(response.status);
      const body = (await response.json()) as { data: { actionId: string } };
      expect(signCalls).toBe(0);
      const [event] = await getDb()
        .select()
        .from(sponsoredGasEvents)
        .where(eq(sponsoredGasEvents.txId, body.data.actionId));
      expect(event).toMatchObject({
        status: "failed",
        reservedUsd: "0.000000",
        actualUsd: "0.000000",
      });
      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.actionId));
      expect(tx.status).toBe("failed");
      expect(
        await getDb()
          .select()
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, TENANT_ID),
              eq(auditEvents.action, "wallet_action.transfer.authorized"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      await getDb().execute(sql.raw(`drop trigger fail_sponsor_authorized_${RUN} on audit_events`));
      await getDb().execute(sql.raw(`drop function fail_sponsor_authorized_${RUN}()`));
      context.vault.signTransaction = originalSign;
    }
  });

  it("turns a reservation into a zero-value failure when signing fails", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      throw new Error("fault-injected signer failure");
    };
    try {
      const response = await transfer(requesterApp, AUTO_AGENT, "signer-failure");
      expect(response.status, await response.clone().text()).toBe(500);
      const body = (await response.json()) as { data: { actionId: string } };
      expect(signCalls).toBe(1);
      const [event] = await getDb()
        .select()
        .from(sponsoredGasEvents)
        .where(eq(sponsoredGasEvents.txId, body.data.actionId));
      expect(event).toMatchObject({
        status: "failed",
        reservedUsd: "0.000000",
        actualUsd: "0.000000",
      });
      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.actionId));
      expect(tx.status).toBe("failed");
      const actions = (
        await getDb()
          .select({ action: auditEvents.action })
          .from(auditEvents)
          .where(eq(auditEvents.resourceId, body.data.actionId))
      ).map((row) => row.action);
      expect(actions).toEqual([
        "wallet_action.transfer.authorized",
        "wallet_action.transfer.failed",
      ]);
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });

  it("queues, approves, and broadcasts with one reservation row and one finalization", async () => {
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      return "0xmanual-sponsored-broadcast";
    };
    try {
      const queued = await transfer(requesterApp, MANUAL_AGENT, "manual-sponsored");
      expect(queued.status, await queued.clone().text()).toBe(202);
      const queuedBody = (await queued.json()) as { data: { id: string; status: string } };
      expect(queuedBody.data.status).toBe("pending_approval");
      expect(signCalls).toBe(0);

      let rows = await getDb()
        .select()
        .from(sponsoredGasEvents)
        .where(eq(sponsoredGasEvents.txId, queuedBody.data.id));
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ status: "reserved", reservedUsd: "0.500000" });

      const approved = await approverApp.request(
        `/vault/${MANUAL_AGENT}/approve/${queuedBody.data.id}`,
        { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      );
      expect(approved.status, await approved.clone().text()).toBe(200);
      expect(signCalls).toBe(1);
      rows = await getDb()
        .select()
        .from(sponsoredGasEvents)
        .where(eq(sponsoredGasEvents.txId, queuedBody.data.id));
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        status: "submitted",
        reservedUsd: "0.500000",
        txHash: "0xmanual-sponsored-broadcast",
      });
      const [tx] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, queuedBody.data.id));
      expect(tx).toMatchObject({ status: "broadcast", txHash: "0xmanual-sponsored-broadcast" });
      const [approval] = await getDb()
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, queuedBody.data.id));
      expect(approval.status).toBe("approved");
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });

  it("admits one bounded winner when concurrent mounted requests race the remaining cap", async () => {
    await getDb()
      .update(tenantConfigs)
      .set({
        gasSponsorshipConfig: {
          enabled: true,
          provider: "mock",
          mode: "erc4337",
          allowClientSponsorship: true,
          allowedChainIds: [8453],
          maxPerTxUsd: 0.5,
          maxPerWalletDayUsd: 1,
          maxTenantDayUsd: 1,
        },
      })
      .where(eq(tenantConfigs.tenantId, TENANT_ID));
    const context = await import("../services/context");
    const originalSign = context.vault.signTransaction.bind(context.vault);
    let signCalls = 0;
    context.vault.signTransaction = async () => {
      signCalls += 1;
      return `0xcap-race-${signCalls}`;
    };
    try {
      const responses = await Promise.all([
        transfer(requesterApp, AUTO_AGENT, "cap-race-a"),
        transfer(requesterApp, AUTO_AGENT, "cap-race-b"),
      ]);
      expect(responses.map((response) => response.status).sort()).toEqual([200, 403]);
      expect(signCalls).toBe(1);
      const submitted = (
        await getDb()
          .select()
          .from(sponsoredGasEvents)
          .where(eq(sponsoredGasEvents.agentId, AUTO_AGENT))
      ).filter((row) => row.status === "submitted");
      expect(submitted).toHaveLength(1);
      expect(submitted[0]?.reservedUsd).toBe("0.500000");
    } finally {
      context.vault.signTransaction = originalSign;
    }
  });
});
