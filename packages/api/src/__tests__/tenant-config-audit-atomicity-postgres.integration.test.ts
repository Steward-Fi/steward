import { expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditEvents,
  createDb,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "keeps a concurrent tenant-config write and audit when a mounted route audit fails",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant-config-atomic-${suffix}`;
    const userId = crypto.randomUUID();
    const failRequestId = `fail-${suffix}`;
    const successRequestId = `success-${suffix}`;
    const triggerFunction = `fail_tenant_config_audit_${suffix}`;
    const triggerName = `fail_tenant_config_audit_${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_JWT_SECRET = `tenant-config-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `tenant-config-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `tenant-config-audit-key-${suffix}`;
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
      await admin.db.insert(users).values({ id: userId, email: `${suffix}@example.test` });
      await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });
      await admin.db.insert(tenantConfigs).values({
        tenantId,
        allowedRedirectUrls: ["https://initial.example/callback"],
      });

      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.request_id = '${failRequestId}' and new.action = 'tenant.redirect_url.add' then
            perform pg_advisory_xact_lock(${gateKey});
            raise exception 'forced tenant config completion audit failure';
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

      const { createSessionToken } = await import("../routes/auth");
      const { tenantConfigRoutes } = await import("../routes/tenant-config");
      const token = await createSessionToken(
        "0x0000000000000000000000000000000000000000",
        tenantId,
        { userId, tenantId, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
      );
      const app = new Hono();
      app.route("/tenants", tenantConfigRoutes);
      app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));

      const failedRequest = app.request(`/tenants/${tenantId}/redirect-urls`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "X-Request-Id": failRequestId,
        },
        body: JSON.stringify({ url: "https://failed.example/callback" }),
      });

      for (let attempt = 0; attempt < 100; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count
          from pg_stat_activity
          where wait_event = 'advisory' and query ilike '%INSERT INTO audit_events%'
        `;
        if (waiting?.count !== "0") break;
        if (attempt === 99)
          throw new Error("mounted route did not reach the blocked audit trigger");
        await Bun.sleep(10);
      }

      const writer = Bun.spawn(
        [
          process.execPath,
          new URL("./fixtures/tenant-config-concurrent-writer.ts", import.meta.url).pathname,
        ],
        {
          cwd: new URL("../../../..", import.meta.url).pathname,
          env: {
            ...process.env,
            DATABASE_URL: databaseUrl!,
            STEWARD_AUDIT_HMAC_KEY: process.env.STEWARD_AUDIT_HMAC_KEY!,
            TEST_TENANT_ID: tenantId,
            TEST_REQUEST_ID: successRequestId,
            TEST_REDIRECT_URL: "https://successful.example/callback",
          },
          stderr: "pipe",
        },
      );
      for (let attempt = 0; attempt < 100; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'
        `;
        if (Number(waiting?.count ?? "0") >= 2) break;
        if (attempt === 99)
          throw new Error("concurrent writer did not reach the tenant audit lock");
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
        .select({ allowedRedirectUrls: tenantConfigs.allowedRedirectUrls })
        .from(tenantConfigs)
        .where(eq(tenantConfigs.tenantId, tenantId));
      expect(stored?.allowedRedirectUrls).toEqual(["https://successful.example/callback"]);

      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId));
      expect(events).toContainEqual({
        action: "tenant.redirect_url.concurrent_success",
        requestId: successRequestId,
      });
      expect(events).not.toContainEqual({
        action: "tenant.redirect_url.add",
        requestId: failRequestId,
      });
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.client.end();
      if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
