import { revocationStore } from "@stwd/auth";
import { getDb, withTenantAuditedTransactionOnDb } from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { runInternalJobForEachTenant } from "./tenant-job";

const DEFAULT_INTERVAL_MS = 30_000;
const BATCH_SIZE = 25;

type RevocationJob = {
  id: number | string;
  resource_id: string;
  metadata: {
    revocationJobId?: unknown;
    agentIds?: unknown;
    userIds?: unknown;
  };
};

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: unknown[] })?.rows ?? [])) as T[];
}

function stringArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) return null;
  return [...new Set(value as string[])];
}

/** Drain durable tenant-delete revocation jobs visible in the current tenant
 * context. The source audit event is committed atomically with deletion and is
 * retained after the tenant row disappears. Completion is another chained
 * event, so a crash at any point leaves the idempotent job discoverable. */
export async function runTenantDeletionRevocationSweepForTenant(
  tenantId: string,
): Promise<{ completed: number; pending: number }> {
  const db = getDb();
  const jobs = rowsOf<RevocationJob>(
    await db.execute(sql`
      SELECT source.id, source.resource_id, source.metadata
      FROM audit_events source
      WHERE source.tenant_id = ${tenantId}
        AND source.action = 'tenant.delete'
        AND source.metadata ? 'revocationJobId'
        AND NOT EXISTS (
          SELECT 1 FROM audit_events completion
          WHERE completion.tenant_id = source.tenant_id
            AND completion.action = 'tenant.delete.token_revocation_completed'
            AND completion.metadata->>'revocationJobId' = source.metadata->>'revocationJobId'
        )
      ORDER BY source.id
      LIMIT ${BATCH_SIZE}
    `),
  );

  let completed = 0;
  for (const job of jobs) {
    const jobId =
      typeof job.metadata.revocationJobId === "string" ? job.metadata.revocationJobId : "";
    const agentIds = stringArray(job.metadata.agentIds);
    const userIds = stringArray(job.metadata.userIds);
    if (!jobId || !agentIds || !userIds) {
      // Malformed signed evidence is never treated as completed. Operators can
      // inspect and repair the retained audit job without losing its targets.
      continue;
    }

    const results = await Promise.allSettled([
      ...agentIds.map((agentId) => revocationStore.revokeAgentTokens(agentId)),
      ...userIds.map((userId) => revocationStore.revokeUserTokens(userId)),
    ]);
    if (results.some((result) => result.status === "rejected")) continue;

    const didComplete = await withTenantAuditedTransactionOnDb(
      db,
      tenantId,
      async (txRaw, appendRequiredAudit) => {
        const tx = txRaw as typeof db;
        const completion = rowsOf<{ present: boolean }>(
          await tx.execute(sql`
            SELECT EXISTS (
              SELECT 1 FROM audit_events
              WHERE tenant_id = ${tenantId}
                AND action = 'tenant.delete.token_revocation_completed'
                AND metadata->>'revocationJobId' = ${jobId}
            ) AS present
          `),
        )[0];
        if (completion?.present) return false;
        await appendRequiredAudit({
          tenantId,
          actorType: "system",
          action: "tenant.delete.token_revocation_completed",
          resourceType: "tenant",
          resourceId: job.resource_id,
          metadata: {
            revocationJobId: jobId,
            sourceAuditEventId: String(job.id),
            targetTenantId: job.resource_id,
            agentTokenRevocationTargets: agentIds.length,
            userTokenRevocationTargets: userIds.length,
            failures: 0,
          },
        });
        return true;
      },
    );
    if (didComplete) completed += 1;
  }
  return { completed, pending: jobs.length - completed };
}

export async function runTenantDeletionRevocationSweep() {
  return runInternalJobForEachTenant("tenant-deletion-token-revocation", (tenantId) =>
    runTenantDeletionRevocationSweepForTenant(tenantId),
  );
}

export function startTenantDeletionRevocationScheduler(options?: {
  intervalMs?: number;
  sweep?: typeof runTenantDeletionRevocationSweep;
}): () => void {
  const sweep = options?.sweep ?? runTenantDeletionRevocationSweep;
  let active: Promise<unknown> | null = null;
  const tick = () => {
    if (active) return;
    active = sweep()
      .catch((error) =>
        console.error(
          "[tenant-deletion-revocation] sweep failed",
          redactedThrownDiagnostics(error),
        ),
      )
      .finally(() => {
        active = null;
      });
  };
  tick();
  const timer = setInterval(tick, options?.intervalMs ?? DEFAULT_INTERVAL_MS);
  return () => clearInterval(timer);
}
