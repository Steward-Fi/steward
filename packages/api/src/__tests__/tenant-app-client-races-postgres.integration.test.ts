import { expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  auditChainHeads,
  auditEvents,
  createDb,
  tenantAppClientSecrets,
  tenantAppClients,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "serializes duplicate create, secret rotation, and an ordered delete/replace race",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `app-client-race-${suffix}`;
    const userId = crypto.randomUUID();
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const triggerFunction = `gate_app_client_delete_${suffix}`;
    const triggerName = `gate_app_client_delete_${suffix}`;
    const previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_JWT_SECRET = `app-client-race-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `app-client-race-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `app-client-race-audit-${suffix}`;

    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    let gateLocked = false;
    try {
      const keyPair = generateApiKey();
      await admin.db
        .insert(tenants)
        .values({ id: tenantId, name: tenantId, apiKeyHash: keyPair.hash });
      await admin.db.insert(users).values({
        id: userId,
        email: `${suffix}@example.test`,
        emailVerified: true,
      });
      await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });

      const { createSessionToken } = await import("../routes/auth");
      const token = await createSessionToken(
        "0x0000000000000000000000000000000000000000",
        tenantId,
        { userId, tenantId, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
      );
      const spawnRequest = (path: string, method: string, body?: unknown) =>
        Bun.spawn(
          [
            process.execPath,
            new URL("./fixtures/tenant-app-client-request.ts", import.meta.url).pathname,
          ],
          {
            cwd: new URL("../../../..", import.meta.url).pathname,
            env: {
              ...process.env,
              DATABASE_URL: databaseUrl!,
              TEST_TENANT_ID: tenantId,
              TEST_SESSION_TOKEN: token,
              TEST_METHOD: method,
              TEST_PATH: path,
              ...(body === undefined ? {} : { TEST_BODY: JSON.stringify(body) }),
            },
            stdout: "pipe",
            stderr: "pipe",
          },
        );
      const finishRequest = async (process: ReturnType<typeof spawnRequest>) => {
        const exit = await process.exited;
        if (exit !== 0) {
          throw new Error(
            `app-client request failed: ${await new Response(process.stderr).text()}`,
          );
        }
        return JSON.parse(await new Response(process.stdout).text()) as {
          status: number;
          body: string;
        };
      };
      const client = {
        id: "race-client",
        name: "Race Client",
        environment: "production",
        enabled: true,
        isDefault: true,
        allowedOrigins: ["https://race.example.test"],
        allowedRedirectUrls: ["https://race.example.test/callback"],
        allowedBundleIds: ["com.example.race"],
        allowedPackageNames: ["com.example.race"],
      };

      const createProcesses = [
        spawnRequest("/app-clients", "POST", { client }),
        spawnRequest("/app-clients", "POST", { client }),
      ];
      const createResponses = await Promise.all(createProcesses.map(finishRequest));
      expect(createResponses.map((response) => response.status).sort()).toEqual([201, 409]);
      expect(
        await admin.db
          .select()
          .from(tenantAppClients)
          .where(eq(tenantAppClients.tenantId, tenantId)),
      ).toHaveLength(1);

      const rotateProcesses = [
        spawnRequest("/app-clients/race-client/secrets", "POST", {}),
        spawnRequest("/app-clients/race-client/secrets", "POST", {}),
      ];
      const rotateResponses = await Promise.all(rotateProcesses.map(finishRequest));
      expect(rotateResponses.map((response) => response.status)).toEqual([201, 201]);
      const rotated = await admin.db
        .select({ status: tenantAppClientSecrets.status })
        .from(tenantAppClientSecrets)
        .where(eq(tenantAppClientSecrets.tenantId, tenantId));
      expect(rotated.map((row) => row.status).sort()).toEqual(["active", "retiring"]);

      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}' and new.action = 'tenant.app_client.delete' then
            perform pg_advisory_xact_lock(${gateKey});
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

      const deleting = spawnRequest("/app-clients/race-client", "DELETE");
      for (let attempt = 0; attempt < 100; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count
          from pg_stat_activity
          where wait_event = 'advisory' and query ilike '%INSERT INTO audit_events%'
        `;
        if (Number(waiting?.count ?? "0") > 0) break;
        if (attempt === 99) throw new Error("delete did not reach the completion-audit gate");
        await Bun.sleep(10);
      }

      const replacing = spawnRequest("/app-clients", "PUT", {
        clients: [{ ...client, name: "Recreated After Delete" }],
      });
      for (let attempt = 0; attempt < 100; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'
        `;
        if (Number(waiting?.count ?? "0") >= 2) break;
        if (attempt === 99) throw new Error("replace did not queue behind delete");
        await Bun.sleep(10);
      }

      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;
      const [deleted, replaced] = await Promise.all([
        finishRequest(deleting),
        finishRequest(replacing),
      ]);
      expect([deleted.status, replaced.status]).toEqual([200, 200]);
      const [finalClient] = await admin.db
        .select()
        .from(tenantAppClients)
        .where(
          and(eq(tenantAppClients.tenantId, tenantId), eq(tenantAppClients.id, "race-client")),
        );
      expect(finalClient?.name).toBe("Recreated After Delete");
      expect(
        await admin.db
          .select()
          .from(tenantAppClientSecrets)
          .where(eq(tenantAppClientSecrets.tenantId, tenantId)),
      ).toHaveLength(0);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.db.delete(users).where(eq(users.id, userId));
      await admin.client.end();
      if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
      else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    }
  },
  120_000,
);
