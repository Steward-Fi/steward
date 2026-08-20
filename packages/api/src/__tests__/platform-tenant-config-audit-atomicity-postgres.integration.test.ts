import { expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tenantConfigs,
  tenants,
} from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

for (const writerMode of ["same", "unrelated"] as const) {
  realPostgresIt(
    `keeps a concurrent ${writerMode}-column platform config write when mounted-route audit fails`,
    async () => {
      const suffix = crypto.randomUUID().replaceAll("-", "");
      const tenantId = `platform-config-atomic-${suffix}`;
      const platformKey = `platform-config-key-${suffix}`;
      const failRequestId = `fail-${suffix}`;
      const successRequestId = `success-${suffix}`;
      const triggerFunction = `fail_platform_config_audit_${suffix}`;
      const triggerName = `fail_platform_config_audit_${suffix}`;
      const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
      const previousPlatformKeys = process.env.STEWARD_PLATFORM_KEYS;
      const previousPlatformScopes = process.env.STEWARD_PLATFORM_KEY_SCOPES;
      const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
      process.env.STEWARD_PLATFORM_KEYS = platformKey;
      process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
        [platformKey]: ["platform:read", "platform:write", "platform:tenant-join-mode:write"],
      });
      process.env.STEWARD_AUDIT_HMAC_KEY = `platform-config-audit-key-${suffix}`;
      __resetAuditHmacKeyCacheForTests();

      const admin = createDb(databaseUrl!);
      const locker = await admin.client.reserve();
      let gateLocked = false;
      try {
        const keyPair = generateApiKey();
        await admin.db.insert(tenants).values({
          id: tenantId,
          name: tenantId,
          apiKeyHash: keyPair.hash,
        });
        await admin.db.insert(tenantConfigs).values({
          tenantId,
          joinMode: "invite",
          allowedOrigins: ["https://initial.example"],
        });

        await admin.client.unsafe(`
          create function "${triggerFunction}"() returns trigger language plpgsql as $$
          begin
            if new.request_id = '${failRequestId}' and new.action = 'tenant.join_mode.update' then
              perform pg_advisory_xact_lock(${gateKey});
              raise exception 'forced platform config completion audit failure';
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

        const { platformRoutes } = await import("../routes/platform");
        const app = new Hono();
        app.use("*", correlationId);
        app.route("/platform", platformRoutes);
        app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
        const failedRequest = app.request(`/platform/tenants/${tenantId}/join-mode`, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            "X-Request-Id": failRequestId,
            "X-Steward-Platform-Key": platformKey,
          },
          body: JSON.stringify({ joinMode: "closed" }),
        });
        let earlyResponse: Response | undefined;
        void failedRequest.then((response) => {
          earlyResponse = response;
        });

        for (let attempt = 0; attempt < 100; attempt++) {
          const [waiting] = await admin.client<{ count: string }[]>`
            select count(*)::text as count
            from pg_stat_activity
            where wait_event = 'advisory' and query ilike '%INSERT INTO audit_events%'
          `;
          if (waiting?.count !== "0") break;
          if (attempt === 99) {
            throw new Error(
              earlyResponse
                ? `mounted platform route returned early (${earlyResponse.status}): ${await earlyResponse.clone().text()}`
                : "mounted platform route did not reach audit trigger",
            );
          }
          await Bun.sleep(10);
        }

        const writer = Bun.spawn(
          [
            process.execPath,
            new URL("./fixtures/platform-tenant-config-concurrent-writer.ts", import.meta.url)
              .pathname,
          ],
          {
            cwd: new URL("../../../..", import.meta.url).pathname,
            env: {
              ...process.env,
              DATABASE_URL: databaseUrl!,
              TEST_TENANT_ID: tenantId,
              TEST_REQUEST_ID: successRequestId,
              TEST_WRITER_MODE: writerMode,
            },
            stderr: "pipe",
          },
        );
        for (let attempt = 0; attempt < 100; attempt++) {
          const [waiting] = await admin.client<{ count: string }[]>`
            select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'
          `;
          if (Number(waiting?.count ?? "0") >= 2) break;
          if (attempt === 99) throw new Error("concurrent writer did not reach tenant audit lock");
          await Bun.sleep(10);
        }

        await locker`select pg_advisory_unlock(${gateKey})`;
        gateLocked = false;
        const [failedResponse, writerExit] = await Promise.all([failedRequest, writer.exited]);
        if (writerExit !== 0) {
          throw new Error(`concurrent writer failed: ${await new Response(writer.stderr).text()}`);
        }
        expect(failedResponse.status).toBe(500);

        const [stored] = await admin.db
          .select({
            joinMode: tenantConfigs.joinMode,
            allowedOrigins: tenantConfigs.allowedOrigins,
          })
          .from(tenantConfigs)
          .where(eq(tenantConfigs.tenantId, tenantId));
        expect(stored?.joinMode).toBe(writerMode === "same" ? "open" : "invite");
        expect(stored?.allowedOrigins).toEqual(
          writerMode === "unrelated" ? ["https://concurrent.example"] : ["https://initial.example"],
        );

        const events = await admin.db
          .select({ action: auditEvents.action, requestId: auditEvents.requestId })
          .from(auditEvents)
          .where(eq(auditEvents.tenantId, tenantId));
        expect(events).toContainEqual({
          action: `tenant.platform_config.concurrent_${writerMode}`,
          requestId: successRequestId,
        });
        expect(events).not.toContainEqual({
          action: "tenant.join_mode.update",
          requestId: failRequestId,
        });
      } finally {
        if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
        locker.release();
        await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
        await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
        await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
        await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
        await admin.db.delete(tenantConfigs).where(eq(tenantConfigs.tenantId, tenantId));
        await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
        await admin.client.end();
        if (previousPlatformKeys === undefined) delete process.env.STEWARD_PLATFORM_KEYS;
        else process.env.STEWARD_PLATFORM_KEYS = previousPlatformKeys;
        if (previousPlatformScopes === undefined) delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
        else process.env.STEWARD_PLATFORM_KEY_SCOPES = previousPlatformScopes;
        if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
        else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
        __resetAuditHmacKeyCacheForTests();
      }
    },
    120_000,
  );
}
