import {
  getDatabaseDriver,
  getDb,
  tenantContextForInternalJob,
  withTenantRlsTransaction,
  withTenantTransactionDatabase,
} from "@stwd/db";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { sql } from "drizzle-orm";

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: unknown[] })?.rows ?? [])) as T[];
}

/** Enumerate tenants through the fixed-shape SECURITY DEFINER bootstrap API. */
export async function internalJobTenantIds(): Promise<string[]> {
  const result = await getDb().execute(
    sql`SELECT tenant_id FROM steward_bootstrap.tenant_ids_for_internal_job()`,
  );
  return rowsOf<{ tenant_id: string }>(result).map((row) => row.tenant_id);
}

/**
 * Execute one autonomous unit under a transaction-local tenant capability.
 * Jobs are deliberately sequential: a single scheduler tick cannot exhaust a
 * small production pool by opening one transaction per tenant concurrently.
 */
export async function runInternalJobForEachTenant<T>(
  job: string,
  callback: (tenantId: string) => Promise<T>,
): Promise<Array<{ tenantId: string; value: T }>> {
  const tenantIds = await internalJobTenantIds();
  const results: Array<{ tenantId: string; value: T }> = [];
  for (const tenantId of tenantIds) {
    const value = await runInternalJobForTenant(tenantId, job, () => callback(tenantId));
    results.push({ tenantId, value });
  }
  return results;
}

/** Execute one fixed, server-selected tenant job in its own transaction. */
export async function runInternalJobForTenant<T>(
  tenantId: string,
  job: string,
  callback: () => Promise<T>,
): Promise<T> {
  const context = tenantContextForInternalJob({ tenantId, job });
  return withTenantRlsTransaction(
    getDb() as never,
    runtimeEnvironmentValue("STEWARD_DB_MODE") === "pglite" ||
      runtimeEnvironmentValue("STEWARD_PGLITE_MEMORY") === "true"
      ? "pglite"
      : getDatabaseDriver(),
    context,
    async (tx) => withTenantTransactionDatabase(tx as never, { tenantId }, callback),
  );
}
