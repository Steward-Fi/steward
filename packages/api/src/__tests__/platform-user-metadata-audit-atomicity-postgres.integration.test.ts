import { expect, it, mock } from "bun:test";
import { __resetAuditHmacKeyCacheForTests, auditEvents, createDb, users } from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const dispatchWebhookMock = mock(() => undefined);
mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "restricted platform writers preserve the concurrent winner and fence webhooks on rollback",
  async () => {
    dispatchWebhookMock.mockClear();
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const platformKey = `platform-metadata-key-${suffix}`;
    const failedRequestId = `failed-${suffix}`;
    const successRequestId = `success-${suffix}`;
    const triggerFunction = `fail_platform_metadata_audit_${suffix}`;
    const triggerName = `fail_platform_metadata_audit_${suffix}`;
    const platformRole = `steward_platform_722_${suffix.slice(0, 16)}`;
    const platformPassword = `platform-metadata-password-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const oldKeys = process.env.STEWARD_PLATFORM_KEYS;
    const oldScopes = process.env.STEWARD_PLATFORM_KEY_SCOPES;
    const oldAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    const oldPlatformDatabaseUrl = process.env.STEWARD_PLATFORM_DATABASE_URL;
    const oldPlatformDatabaseRole = process.env.STEWARD_PLATFORM_DATABASE_ROLE;
    process.env.STEWARD_PLATFORM_KEYS = platformKey;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [platformKey]: ["platform:read", "platform:write", "platform:user:write"],
    });
    process.env.STEWARD_AUDIT_HMAC_KEY = `platform-metadata-audit-key-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    let gateLocked = false;
    let roleCreated = false;
    let userId: string | undefined;
    try {
      const [database] = await admin.client<{ name: string }[]>`SELECT current_database() AS name`;
      if (!database) throw new Error("failed to resolve integration database name");
      await admin.client.unsafe(
        `CREATE ROLE ${quoteIdentifier(platformRole)} LOGIN PASSWORD '${platformPassword}' ` +
          "NOSUPERUSER NOBYPASSRLS NOINHERIT",
      );
      roleCreated = true;
      await admin.client.unsafe(
        `GRANT CONNECT ON DATABASE ${quoteIdentifier(database.name)} TO ${quoteIdentifier(platformRole)}`,
      );
      await admin.client.unsafe(`GRANT USAGE ON SCHEMA public TO ${quoteIdentifier(platformRole)}`);
      await admin.client.unsafe(
        `GRANT SELECT, UPDATE ON TABLE public.users TO ${quoteIdentifier(platformRole)}`,
      );
      await admin.client.unsafe(
        `GRANT SELECT, INSERT, UPDATE ON TABLE public.audit_events, public.audit_chain_heads TO ${quoteIdentifier(platformRole)}`,
      );
      const platformUrl = new URL(databaseUrl!);
      platformUrl.username = platformRole;
      platformUrl.password = platformPassword;
      process.env.STEWARD_PLATFORM_DATABASE_URL = platformUrl.toString();
      process.env.STEWARD_PLATFORM_DATABASE_ROLE = platformRole;

      const [created] = await admin.db
        .insert(users)
        .values({
          email: `platform-metadata-${suffix}@example.test`,
          customMetadata: { owner: "initial" },
        })
        .returning({ id: users.id });
      if (!created) throw new Error("failed to seed platform metadata user");
      userId = created.id;
      await admin.client.unsafe(`create function "${triggerFunction}"() returns trigger language plpgsql as $$
      begin
        if new.request_id = '${failedRequestId}' and new.action = 'user.metadata.update' then
          perform pg_advisory_xact_lock(${gateKey});
          raise exception 'forced platform metadata completion audit failure';
        end if;
        return new;
      end $$`);
      await admin.client.unsafe(`create trigger "${triggerName}" before insert on audit_events
      for each row execute function "${triggerFunction}"()`);
      await locker`select pg_advisory_lock(${gateKey})`;
      gateLocked = true;

      const { platformRoutes } = await import("../routes/platform");
      const app = new Hono();
      app.use("*", correlationId);
      app.route("/platform", platformRoutes);
      app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
      const failedRequest = app.request(`/platform/users/${userId}/metadata`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "X-Request-Id": failedRequestId,
          "X-Steward-Platform-Key": platformKey,
        },
        body: JSON.stringify({ customMetadata: { owner: "must-rollback" } }),
      });
      await waitForWaiters(admin, 1, "mounted platform route did not reach blocked audit");
      expect(dispatchWebhookMock).not.toHaveBeenCalled();

      const writer = Bun.spawn(
        [
          process.execPath,
          new URL("./fixtures/platform-user-metadata-concurrent-writer.ts", import.meta.url)
            .pathname,
        ],
        {
          cwd: new URL("../../../..", import.meta.url).pathname,
          env: {
            ...process.env,
            DATABASE_URL: process.env.STEWARD_PLATFORM_DATABASE_URL,
            TEST_USER_ID: userId,
            TEST_REQUEST_ID: successRequestId,
            TEST_EXPECTED_DATABASE_ROLE: platformRole,
          },
          stderr: "pipe",
        },
      );
      await waitForWaiters(admin, 2, "concurrent metadata writer did not reach serialization lock");
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;

      const [failedResponse, writerExit] = await Promise.all([failedRequest, writer.exited]);
      if (writerExit !== 0) throw new Error(await new Response(writer.stderr).text());
      expect(failedResponse.status).toBe(500);
      expect(dispatchWebhookMock).not.toHaveBeenCalled();
      const [stored] = await admin.db
        .select({ metadata: users.customMetadata })
        .from(users)
        .where(eq(users.id, userId));
      expect(stored?.metadata).toEqual({ owner: "concurrent-winner" });
      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.resourceId, userId),
            inArray(auditEvents.requestId, [failedRequestId, successRequestId]),
          ),
        );
      expect(events.filter((event) => event.requestId === failedRequestId)).toEqual([
        { action: "user.metadata.update.authorized", requestId: failedRequestId },
      ]);
      expect(events.filter((event) => event.requestId === successRequestId)).toEqual([
        { action: "user.metadata.update", requestId: successRequestId },
      ]);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      if (userId) await admin.db.delete(users).where(eq(users.id, userId));
      if (roleCreated) {
        await admin.client.unsafe(`DROP OWNED BY ${quoteIdentifier(platformRole)}`);
        await admin.client.unsafe(`DROP ROLE ${quoteIdentifier(platformRole)}`);
      }
      await admin.client.end();
      restore("STEWARD_PLATFORM_KEYS", oldKeys);
      restore("STEWARD_PLATFORM_KEY_SCOPES", oldScopes);
      restore("STEWARD_AUDIT_HMAC_KEY", oldAuditKey);
      restore("STEWARD_PLATFORM_DATABASE_URL", oldPlatformDatabaseUrl);
      restore("STEWARD_PLATFORM_DATABASE_ROLE", oldPlatformDatabaseRole);
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);

async function waitForWaiters(
  admin: ReturnType<typeof createDb>,
  minimum: number,
  message: string,
) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const [row] = await admin.client<{ count: string }[]>`
      select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'`;
    if (Number(row?.count ?? "0") >= minimum) return;
    if (attempt === 199) throw new Error(message);
    await Bun.sleep(10);
  }
}

function restore(name: string, value: string | undefined) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}
