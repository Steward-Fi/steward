import { expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  policies,
  policyTemplates,
  tenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && process.env.STEWARD_PGLITE_MEMORY !== "true" ? it : it.skip;

for (const mode of ["create", "update", "delete", "assign"] as const) {
  realPostgresIt(
    `preserves the concurrent ${mode} winner when mounted completion audit fails`,
    async () => {
      const suffix = crypto.randomUUID().replaceAll("-", "");
      const tenantId = `policy-atomic-${suffix}`;
      const templateId = crypto.randomUUID();
      const agentId = `policy-agent-${suffix}`;
      const failRequestId = `fail-${suffix}`;
      const successRequestId = `success-${suffix}`;
      const writerApplicationName = `policy-template-writer-${suffix}`;
      const triggerFunction = `fail_policy_audit_${suffix}`;
      const triggerName = `fail_policy_audit_${suffix}`;
      const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
      const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
      process.env.STEWARD_AUDIT_HMAC_KEY = `policy-template-audit-key-${suffix}`;
      __resetAuditHmacKeyCacheForTests();

      const admin = createDb(databaseUrl!);
      const locker = await admin.client.reserve();
      let gateLocked = false;
      try {
        await admin.db.insert(tenants).values({
          id: tenantId,
          name: tenantId,
          apiKeyHash: `hash-${suffix}`,
        });
        await admin.db.insert(agents).values({
          id: agentId,
          tenantId,
          name: "Policy atomicity agent",
          walletAddress: `0x${suffix.padEnd(40, "0").slice(0, 40)}`,
        });
        if (mode !== "create") {
          await admin.db.insert(policyTemplates).values({
            id: templateId,
            tenantId,
            name: "initial-template",
            rules: [{ type: "spending-limit", enabled: true, config: { maxPerTx: "123" } }],
          });
        }
        await admin.db.insert(policies).values({
          id: `initial-${suffix}`,
          agentId,
          type: "approved-addresses",
          enabled: true,
          config: { addresses: ["0x0000000000000000000000000000000000000001"] },
        });

        await admin.client.unsafe(`
          create function "${triggerFunction}"() returns trigger language plpgsql as $$
          begin
            if new.request_id = '${failRequestId}' and new.action = 'policy.template.${mode}' then
              perform pg_advisory_xact_lock(${gateKey});
              raise exception 'forced policy template completion audit failure';
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

        const { policiesStandaloneRoutes } = await import("../routes/policies-standalone");
        const app = new Hono<{ Variables: AppVariables }>();
        app.use("*", correlationId);
        app.use("*", async (c, next) => {
          c.set("tenantId", tenantId);
          c.set("authType", "session-jwt");
          c.set("tenantRole", "admin");
          c.set("sessionMfaVerifiedAt", Date.now());
          c.set("userId", "11111111-1111-4111-8111-111111111111");
          await next();
        });
        app.route("/policies", policiesStandaloneRoutes);
        app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));

        const path =
          mode === "create"
            ? "/policies"
            : mode === "assign"
              ? `/policies/${templateId}/assign`
              : `/policies/${templateId}`;
        const failedRequest = app.request(path, {
          method: mode === "update" ? "PUT" : mode === "delete" ? "DELETE" : "POST",
          headers: { "Content-Type": "application/json", "X-Request-Id": failRequestId },
          body:
            mode === "create"
              ? JSON.stringify({ name: "failed-create", rules: [] })
              : mode === "update"
                ? JSON.stringify({ name: "failed-update" })
                : mode === "assign"
                  ? JSON.stringify({ agentIds: [agentId] })
                  : undefined,
        });
        let earlyResponse: Response | undefined;
        void failedRequest.then((response) => {
          earlyResponse = response;
        });

        for (let attempt = 0; attempt < 100; attempt++) {
          const [waiting] = await admin.client<{ count: string }[]>`
            select count(*)::text as count from pg_stat_activity
            where wait_event = 'advisory' and query ilike '%INSERT INTO audit_events%'
          `;
          if (waiting?.count !== "0") break;
          if (attempt === 99) {
            throw new Error(
              earlyResponse
                ? `mounted route returned early (${earlyResponse.status}): ${await earlyResponse.clone().text()}`
                : "mounted route did not reach audit trigger",
            );
          }
          await Bun.sleep(10);
        }

        const writerUrl = new URL(databaseUrl!);
        writerUrl.searchParams.set("application_name", writerApplicationName);
        const writer = Bun.spawn(
          [
            process.execPath,
            new URL("./fixtures/policy-template-concurrent-writer.ts", import.meta.url).pathname,
          ],
          {
            cwd: new URL("../../../..", import.meta.url).pathname,
            env: {
              ...process.env,
              DATABASE_URL: writerUrl.toString(),
              TEST_TENANT_ID: tenantId,
              TEST_TEMPLATE_ID: templateId,
              TEST_AGENT_ID: agentId,
              TEST_REQUEST_ID: successRequestId,
              TEST_WRITER_MODE: mode,
            },
            stderr: "pipe",
          },
        );
        for (let attempt = 0; attempt < 100; attempt++) {
          const [waiting] = await admin.client<{ count: string }[]>`
            select count(*)::text as count
            from pg_stat_activity
            where application_name = ${writerApplicationName}
              and wait_event = 'advisory'
              and cardinality(pg_blocking_pids(pid)) > 0
          `;
          if (waiting?.count !== "0") break;
          if (attempt === 99) throw new Error("concurrent writer did not reach tenant audit lock");
          await Bun.sleep(10);
        }

        const [interimTemplate] = await admin.db
          .select({ name: policyTemplates.name })
          .from(policyTemplates)
          .where(and(eq(policyTemplates.id, templateId), eq(policyTemplates.tenantId, tenantId)));
        if (mode === "create") {
          const visibleCreates = await admin.db
            .select({ name: policyTemplates.name })
            .from(policyTemplates)
            .where(eq(policyTemplates.tenantId, tenantId));
          expect(visibleCreates).toEqual([]);
        } else {
          expect(interimTemplate?.name).toBe("initial-template");
        }
        if (mode === "assign") {
          const visiblePolicies = await admin.db
            .select({ type: policies.type })
            .from(policies)
            .where(eq(policies.agentId, agentId));
          expect(visiblePolicies).toEqual([{ type: "approved-addresses" }]);
        }
        expect(
          await admin.db
            .select({ action: auditEvents.action })
            .from(auditEvents)
            .where(
              and(
                eq(auditEvents.tenantId, tenantId),
                eq(auditEvents.requestId, failRequestId),
                eq(auditEvents.action, `policy.template.${mode}`),
              ),
            ),
        ).toEqual([]);

        await locker`select pg_advisory_unlock(${gateKey})`;
        gateLocked = false;
        const [failedResponse, writerExit] = await Promise.all([failedRequest, writer.exited]);
        if (writerExit !== 0) {
          throw new Error(`concurrent writer failed: ${await new Response(writer.stderr).text()}`);
        }
        expect(failedResponse.status).toBeGreaterThanOrEqual(400);

        const [storedTemplate] = await admin.db
          .select({ name: policyTemplates.name })
          .from(policyTemplates)
          .where(and(eq(policyTemplates.id, templateId), eq(policyTemplates.tenantId, tenantId)));
        if (mode === "create" || mode === "update") {
          expect(storedTemplate?.name).toBe("concurrent-winner");
        }
        if (mode === "create") {
          const templates = await admin.db
            .select({ name: policyTemplates.name })
            .from(policyTemplates)
            .where(eq(policyTemplates.tenantId, tenantId));
          expect(templates).toEqual([{ name: "concurrent-winner" }]);
        }
        if (mode === "delete") expect(storedTemplate).toBeUndefined();
        if (mode === "assign") {
          const storedPolicies = await admin.db
            .select({ type: policies.type, config: policies.config })
            .from(policies)
            .where(eq(policies.agentId, agentId));
          expect(storedPolicies).toEqual([{ type: "spending-limit", config: { maxPerTx: "777" } }]);
        }

        const events = await admin.db
          .select({ action: auditEvents.action, requestId: auditEvents.requestId })
          .from(auditEvents)
          .where(eq(auditEvents.tenantId, tenantId));
        expect(events).toContainEqual({
          action: `policy.template.concurrent_${mode}`,
          requestId: successRequestId,
        });
        expect(events).not.toContainEqual({
          action: `policy.template.${mode}`,
          requestId: failRequestId,
        });
      } finally {
        if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
        locker.release();
        await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
        await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
        await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
        await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
        await admin.db.delete(policies).where(eq(policies.agentId, agentId));
        await admin.db.delete(policyTemplates).where(eq(policyTemplates.tenantId, tenantId));
        await admin.db.delete(agents).where(eq(agents.id, agentId));
        await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
        await admin.client.end();
        if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
        else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
        __resetAuditHmacKeyCacheForTests();
      }
    },
    120_000,
  );
}
