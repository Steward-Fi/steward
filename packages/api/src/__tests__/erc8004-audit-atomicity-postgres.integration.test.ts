import { expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agentRegistrations,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;
const registryAddress = "0x0000000000000000000000000000000000008004";

realPostgresIt(
  "rolls back a mounted ERC-8004 registration when its required audit fails",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `erc8004-atomic-${suffix}`;
    const agentId = `erc8004-agent-${suffix}`;
    const requestId = `failed-${suffix}`;
    const triggerFunction = `fail_erc8004_audit_${suffix}`;
    const triggerName = `fail_erc8004_audit_${suffix}`;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    process.env.STEWARD_AUDIT_HMAC_KEY = `erc8004-audit-key-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `erc8004-master-password-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `hash-${tenantId}`,
      });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "0x00000000000000000000000000000000000000aa",
      });
      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}'
             and new.request_id = '${requestId}'
             and new.action = 'erc8004.register' then
            raise exception 'forced ERC-8004 completion audit failure';
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

      const { erc8004Routes } = await import("../routes/erc8004");
      const app = mountedApp(tenantId, erc8004Routes);
      const response = await app.request(`/agents/${agentId}/register-onchain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": requestId,
        },
        body: JSON.stringify({ capabilities: ["must-rollback"] }),
      });

      expect(response.status).toBe(500);
      const registrations = await admin.db
        .select()
        .from(agentRegistrations)
        .where(
          and(
            eq(agentRegistrations.tenantId, tenantId),
            eq(agentRegistrations.agentId, agentId),
            eq(agentRegistrations.chainId, 8453),
          ),
        );
      expect(registrations).toHaveLength(0);

      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId));
      expect(events).toEqual([{ action: "erc8004.register.authorized", requestId }]);
    } finally {
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await cleanup(admin, tenantId);
      await admin.client.end();
      restoreAuditKey(previousAuditKey);
      restoreEnvironment("STEWARD_MASTER_PASSWORD", previousMasterPassword);
    }
  },
  120_000,
);

realPostgresIt(
  "keeps the concurrent ERC-8004 winner and exact audit after a mounted update audit fails",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `erc8004-race-${suffix}`;
    const agentId = `erc8004-agent-${suffix}`;
    const failedRequestId = `failed-${suffix}`;
    const successRequestId = `success-${suffix}`;
    const winnerUrl = `https://winner-${suffix}.example.test/api`;
    const triggerFunction = `fail_erc8004_audit_${suffix}`;
    const triggerName = `fail_erc8004_audit_${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    process.env.STEWARD_AUDIT_HMAC_KEY = `erc8004-audit-key-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `erc8004-master-password-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    let gateLocked = false;
    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `hash-${tenantId}`,
      });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "0x00000000000000000000000000000000000000aa",
      });
      await admin.db.insert(agentRegistrations).values({
        tenantId,
        agentId,
        chainId: 8453,
        registryAddress,
        agentCardJson: { name: agentId, apiUrl: "https://initial.example.test/api" },
        status: "pending",
      });
      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}'
             and new.request_id = '${failedRequestId}'
             and new.action = 'erc8004.register' then
            perform pg_advisory_xact_lock(${gateKey});
            raise exception 'forced ERC-8004 completion audit failure';
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
      await locker`select pg_advisory_lock(${gateKey})`;
      gateLocked = true;

      const { erc8004Routes } = await import("../routes/erc8004");
      const app = mountedApp(tenantId, erc8004Routes);
      const failedRequest = app.request(`/agents/${agentId}/register-onchain`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": failedRequestId,
        },
        body: JSON.stringify({ capabilities: ["must-rollback"] }),
      });

      await waitForAdvisoryWaiters(
        admin,
        1,
        "mounted ERC-8004 route did not reach the blocked audit trigger",
      );
      const writer = Bun.spawn(
        [
          process.execPath,
          new URL("./fixtures/erc8004-concurrent-writer.ts", import.meta.url).pathname,
        ],
        {
          cwd: new URL("../../../..", import.meta.url).pathname,
          env: {
            ...process.env,
            DATABASE_URL: databaseUrl!,
            STEWARD_AUDIT_HMAC_KEY: process.env.STEWARD_AUDIT_HMAC_KEY!,
            TEST_TENANT_ID: tenantId,
            TEST_AGENT_ID: agentId,
            TEST_REQUEST_ID: successRequestId,
            TEST_API_URL: winnerUrl,
          },
          stderr: "pipe",
        },
      );
      await waitForAdvisoryWaiters(
        admin,
        2,
        "concurrent ERC-8004 writer did not reach the database serialization lock",
      );

      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;
      const [failedResponse, writerExit] = await Promise.all([failedRequest, writer.exited]);
      if (writerExit !== 0) {
        throw new Error(
          `concurrent ERC-8004 writer failed: ${await new Response(writer.stderr).text()}`,
        );
      }
      expect(failedResponse.status).toBe(500);

      const [stored] = await admin.db
        .select({ agentCardJson: agentRegistrations.agentCardJson })
        .from(agentRegistrations)
        .where(
          and(
            eq(agentRegistrations.tenantId, tenantId),
            eq(agentRegistrations.agentId, agentId),
            eq(agentRegistrations.chainId, 8453),
          ),
        );
      expect(stored?.agentCardJson).toMatchObject({
        apiUrl: winnerUrl,
        capabilities: ["concurrent-winner"],
      });

      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId));
      expect(events.filter((event) => event.requestId === failedRequestId)).toEqual([
        { action: "erc8004.register.authorized", requestId: failedRequestId },
      ]);
      expect(events.filter((event) => event.requestId === successRequestId)).toEqual([
        { action: "erc8004.register", requestId: successRequestId },
      ]);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await cleanup(admin, tenantId);
      await admin.client.end();
      restoreAuditKey(previousAuditKey);
      restoreEnvironment("STEWARD_MASTER_PASSWORD", previousMasterPassword);
    }
  },
  120_000,
);

function mountedApp(tenantId: string, routes: typeof import("../routes/erc8004").erc8004Routes) {
  const app = new Hono();
  app.use("*", correlationId);
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("userId", "erc8004-test-owner");
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/agents", routes);
  return app;
}

async function waitForAdvisoryWaiters(
  admin: ReturnType<typeof createDb>,
  minimum: number,
  failureMessage: string,
) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const [waiting] = await admin.client<{ count: string }[]>`
      select count(*)::text as count
      from pg_stat_activity
      where wait_event = 'advisory'
    `;
    if (Number(waiting?.count ?? "0") >= minimum) return;
    if (attempt === 199) throw new Error(failureMessage);
    await Bun.sleep(10);
  }
}

async function cleanup(admin: ReturnType<typeof createDb>, tenantId: string) {
  await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
}

function restoreAuditKey(previousAuditKey: string | undefined) {
  restoreEnvironment("STEWARD_AUDIT_HMAC_KEY", previousAuditKey);
  __resetAuditHmacKeyCacheForTests();
}

function restoreEnvironment(name: string, previousValue: string | undefined) {
  if (previousValue === undefined) delete process.env[name];
  else process.env[name] = previousValue;
}
