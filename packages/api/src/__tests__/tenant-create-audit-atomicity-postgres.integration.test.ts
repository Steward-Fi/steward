import { expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
} from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && process.env.STEWARD_PGLITE_MEMORY !== "true" ? it : it.skip;
const fixturePath = new URL("./fixtures/tenant-create-dependent-writer.ts", import.meta.url)
  .pathname;

realPostgresIt(
  "keeps tenant and dependent first use invisible until the required audit commits",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const platformKey = `tenant-create-platform-${suffix}`;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const previousPlatformKeys = process.env.STEWARD_PLATFORM_KEYS;
    const previousPlatformScopes = process.env.STEWARD_PLATFORM_KEY_SCOPES;
    process.env.STEWARD_AUDIT_HMAC_KEY = `tenant-create-audit-${suffix}`;
    process.env.STEWARD_PLATFORM_KEYS = platformKey;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [platformKey]: ["platform:write", "platform:tenant:create"],
    });
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    const createdTenantIds: string[] = [];
    const createdAgentIds: string[] = [];
    let gateLocked = false;

    const { platformRoutes } = await import("../routes/platform");
    const app = new Hono();
    app.route("/platform", platformRoutes);
    app.onError((_error, c) => c.json({ ok: false, error: "tenant creation failed" }, 500));

    async function waitForAuditBarrier(): Promise<void> {
      for (let attempt = 0; attempt < 200; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count
          from pg_stat_activity
          where wait_event = 'advisory' and query ilike '%audit_events%'
        `;
        if (waiting?.count !== "0") return;
        if (attempt === 199) throw new Error("tenant route did not reach completion-audit barrier");
        await Bun.sleep(10);
      }
    }

    async function waitForDependentBarrier(applicationName: string): Promise<void> {
      for (let attempt = 0; attempt < 200; attempt++) {
        const [waiting] = await admin.client<{ blockers: number[] }[]>`
          select pg_blocking_pids(pid) as blockers
          from pg_stat_activity
          where application_name = ${applicationName} and wait_event_type = 'Lock'
        `;
        if (waiting && waiting.blockers.length > 0) return;
        if (attempt === 199)
          throw new Error("dependent first use did not block on tenant creation");
        await Bun.sleep(10);
      }
    }

    async function runCase(failCompletionAudit: boolean): Promise<void> {
      const mode = failCompletionAudit ? "failure" : "success";
      const tenantId = `tenant-create-pg-${mode}-${suffix}`;
      const agentId = `tenant-create-agent-${mode}-${suffix}`;
      const requestId = `tenant-create-${mode}-${suffix}`;
      const applicationName = `tenant-create-dependent-${mode}-${suffix}`;
      const triggerFunction = `gate_tenant_create_${mode}_${suffix}`;
      const triggerName = `gate_tenant_create_${mode}_${suffix}`;
      const gateKey = Number.parseInt(
        `${failCompletionAudit ? "2" : "1"}${suffix.slice(0, 11)}`,
        16,
      );
      createdTenantIds.push(tenantId);
      createdAgentIds.push(agentId);

      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}' and new.action = 'tenant.create' then
            perform pg_advisory_xact_lock(${gateKey});
            ${failCompletionAudit ? "raise exception 'forced tenant completion audit failure';" : "return new;"}
          end if;
          return new;
        end
        $$;
        create trigger "${triggerName}"
          before insert on audit_events
          for each row execute function "${triggerFunction}"();
      `);
      await locker`select pg_advisory_lock(${gateKey})`;
      gateLocked = true;

      try {
        const createRequest = app.request("/platform/tenants", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Platform-Key": platformKey,
            "X-Request-Id": requestId,
          },
          body: JSON.stringify({ id: tenantId, name: tenantId }),
        });
        await waitForAuditBarrier();

        expect(await admin.db.select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(
          0,
        );
        expect(
          await admin.db.select().from(auditEvents).where(eq(auditEvents.tenantId, tenantId)),
        ).toHaveLength(0);
        expect(
          await admin.db
            .select()
            .from(auditChainHeads)
            .where(eq(auditChainHeads.tenantId, tenantId)),
        ).toHaveLength(0);

        const childUrl = new URL(databaseUrl!);
        childUrl.searchParams.set("application_name", applicationName);
        const dependent = Bun.spawn([process.execPath, fixturePath], {
          cwd: new URL("../../../..", import.meta.url).pathname,
          env: {
            ...process.env,
            DATABASE_URL: childUrl.toString(),
            TEST_TENANT_ID: tenantId,
            TEST_AGENT_ID: agentId,
          },
          stdout: "pipe",
          stderr: "pipe",
        });
        await waitForDependentBarrier(applicationName);
        expect(await admin.db.select().from(agents).where(eq(agents.id, agentId))).toHaveLength(0);

        await locker`select pg_advisory_unlock(${gateKey})`;
        gateLocked = false;
        const [response, dependentExit, dependentOutput, dependentError] = await Promise.all([
          createRequest,
          dependent.exited,
          new Response(dependent.stdout).text(),
          new Response(dependent.stderr).text(),
        ]);
        if (dependentExit !== 0) {
          throw new Error(`dependent writer exited ${dependentExit}: ${dependentError}`);
        }
        const dependentResult = JSON.parse(dependentOutput) as { ok: boolean; code?: string };

        if (failCompletionAudit) {
          expect(response.status).toBe(500);
          expect(dependentResult).toEqual({ ok: false, code: "23503" });
          expect(
            await admin.db.select().from(tenants).where(eq(tenants.id, tenantId)),
          ).toHaveLength(0);
          expect(await admin.db.select().from(agents).where(eq(agents.id, agentId))).toHaveLength(
            0,
          );
          expect(
            await admin.db.select().from(auditEvents).where(eq(auditEvents.tenantId, tenantId)),
          ).toHaveLength(0);
          expect(
            await admin.db
              .select()
              .from(auditChainHeads)
              .where(eq(auditChainHeads.tenantId, tenantId)),
          ).toHaveLength(0);
        } else {
          expect(response.status).toBe(201);
          expect(dependentResult).toEqual({ ok: true });
          expect(
            await admin.db.select().from(tenants).where(eq(tenants.id, tenantId)),
          ).toHaveLength(1);
          expect(await admin.db.select().from(agents).where(eq(agents.id, agentId))).toHaveLength(
            1,
          );
          expect(
            (
              await admin.db.select().from(auditEvents).where(eq(auditEvents.tenantId, tenantId))
            ).map(({ action }) => action),
          ).toEqual([
            "tenant.create.authorized",
            "tenant.api_key.create.authorized",
            "tenant.create",
            "tenant.api_key.create",
          ]);
        }
      } finally {
        if (gateLocked) {
          await locker`select pg_advisory_unlock(${gateKey})`;
          gateLocked = false;
        }
        await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
        await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      }
    }

    try {
      await runCase(false);
      await runCase(true);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock_all()`;
      locker.release();
      for (const agentId of createdAgentIds) {
        await admin.db.delete(agents).where(eq(agents.id, agentId));
      }
      for (const tenantId of createdTenantIds) {
        await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
        await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
        await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      }
      await admin.client.end();
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      if (previousPlatformKeys === undefined) delete process.env.STEWARD_PLATFORM_KEYS;
      else process.env.STEWARD_PLATFORM_KEYS = previousPlatformKeys;
      if (previousPlatformScopes === undefined) delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
      else process.env.STEWARD_PLATFORM_KEY_SCOPES = previousPlatformScopes;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
