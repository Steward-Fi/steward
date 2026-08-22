import { randomUUID } from "node:crypto";
import { createDb, getDb } from "@stwd/db";
import { sql } from "drizzle-orm";
import { buildPluginContext } from "../../plugin";
import { runInternalJobForTenant } from "../../services/tenant-job";
import { withWorkerRequestDatabase } from "../../worker";

const databaseUrl = process.env.DATABASE_URL ?? "";
const tenantId = process.env.STEWARD_RLS_TEST_TENANT ?? "";
const createdBy = process.env.STEWARD_RLS_TEST_USER_ID ?? "";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: unknown[] })?.rows ?? [])) as T[];
}

assert(databaseUrl.length > 0, "DATABASE_URL is required");
assert(tenantId.length > 0, "STEWARD_RLS_TEST_TENANT is required");
assert(/^[0-9a-f-]{36}$/i.test(createdBy), "STEWARD_RLS_TEST_USER_ID is required");

const handle = createDb(databaseUrl);
let closed = false;
const agentId = `worker-lease-${randomUUID()}`;
const workspaceId = randomUUID();
const leaseId = randomUUID();

await withWorkerRequestDatabase(
  {
    DATABASE_URL: databaseUrl,
    DATABASE_DRIVER: "neon-websocket",
    NODE_ENV: "production",
  },
  () =>
    runInternalJobForTenant(tenantId, "worker-credential-deadline-proof", async () => {
      const requestDb = getDb();
      await requestDb.execute(sql`
        INSERT INTO agents (id, tenant_id, name, wallet_address)
        VALUES (${agentId}, ${tenantId}, 'Worker credential lease',
          '0x1234567890123456789012345678901234567890')
      `);
      await requestDb.execute(sql`
        INSERT INTO workspaces (id, tenant_id, key, name, environment, created_by)
        VALUES (${workspaceId}::uuid, ${tenantId}, ${`worker-${workspaceId}`},
          'Worker credential lease', 'production', ${createdBy}::uuid)
      `);
      await requestDb.execute(sql`
        INSERT INTO upstream_credential_leases (
          id, tenant_id, workspace_id, agent_id, grant_id, capability_id,
          issuer, resource, resource_hash, authority_digest,
          idempotency_key_hash, status, expires_at
        ) VALUES (
          ${leaseId}::uuid, ${tenantId}, ${workspaceId}::uuid, ${agentId},
          ${randomUUID()}::uuid, ${randomUUID()}::uuid, 'github-app', '{}'::jsonb,
          ${"a".repeat(64)}, ${"b".repeat(64)}, ${"c".repeat(64)},
          'active', now() - interval '1 minute'
        )
      `);

      const context = buildPluginContext();
      await context.withCredentialLeaseDatabaseDeadline(
        Date.now() + 8_000,
        async (deadlineDb, auditedTransaction) => {
          assert(deadlineDb === requestDb, "deadline phase replaced the Worker request database");
          const [settings] = rowsOf<{
            role_name: string;
            tenant_id: string;
            transaction_id: string | null;
            statement_timeout_ms: string;
            lock_timeout_ms: string;
          }>(
            await deadlineDb.execute(sql`
              SELECT current_user AS role_name,
                current_setting('steward.tenant_id', true) AS tenant_id,
                txid_current_if_assigned()::text AS transaction_id,
                extract(epoch FROM current_setting('statement_timeout')::interval) * 1000
                  AS statement_timeout_ms,
                extract(epoch FROM current_setting('lock_timeout')::interval) * 1000
                  AS lock_timeout_ms
            `),
          );
          assert(settings?.tenant_id === tenantId, "deadline phase lost the tenant GUC");
          assert(settings?.transaction_id !== null, "deadline phase lost the active transaction");
          assert(
            settings?.role_name === new URL(databaseUrl).username,
            "deadline phase changed role",
          );
          assert(
            Number(settings?.statement_timeout_ms) > 0 &&
              Number(settings?.statement_timeout_ms) <= 8_000,
            "statement deadline was not installed",
          );
          assert(
            Number(settings?.lock_timeout_ms) > 0 && Number(settings?.lock_timeout_ms) <= 8_000,
            "lock deadline was not installed",
          );

          await auditedTransaction(tenantId, async (txRaw, appendRequiredAudit) => {
            const tx = txRaw as typeof deadlineDb;
            await tx.execute(sql`
              UPDATE upstream_credential_leases
              SET status = 'expired', updated_at = now()
              WHERE tenant_id = ${tenantId} AND id = ${leaseId}::uuid AND status = 'active'
            `);
            await tx.execute(sql`
              INSERT INTO upstream_credential_lease_events (
                lease_id, tenant_id, action, decision, metadata
              ) VALUES (${leaseId}::uuid, ${tenantId}, 'lease.expire', 'allow',
                '{"workerDeadlineProof":true}'::jsonb)
            `);
            await appendRequiredAudit({
              tenantId,
              actorType: "system",
              action: "upstream_credential_lease.expired",
              resourceType: "upstream_credential_lease",
              resourceId: leaseId,
              metadata: { workerDeadlineProof: true },
            });
          });
        },
      );

      const [lease] = rowsOf<{ status: string }>(
        await requestDb.execute(sql`
          SELECT status FROM upstream_credential_leases
          WHERE tenant_id = ${tenantId} AND id = ${leaseId}::uuid
        `),
      );
      assert(lease?.status === "expired", "credential lease transition was not durable");
    }),
  {
    createHandle: () => ({
      driver: "neon-websocket",
      db: handle.db as never,
      close: async () => {
        await handle.client.end({ timeout: 5 });
        closed = true;
      },
    }),
  },
);

assert(closed, "Worker request-owned database was not closed");
console.log(JSON.stringify({ ok: true, tenantId, leaseId, closed }));
process.exit(0);
