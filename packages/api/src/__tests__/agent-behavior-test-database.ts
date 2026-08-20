import {
  auditEvents,
  closeDb,
  getDb,
  tenants,
  upstreamCredentialLeaseEvents,
  upstreamCredentialLeases,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";

/**
 * Agent mutation behavior must exercise the production PostgreSQL transaction
 * and trigger semantics whenever the integration job provides DATABASE_URL.
 * Local runs without PostgreSQL retain the hermetic in-memory PGLite fixture.
 */
export const USING_REAL_POSTGRES = Boolean(process.env.DATABASE_URL);

export async function setupAgentBehaviorTestDatabase(): Promise<
  | {
      db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
      client: Awaited<ReturnType<typeof createPGLiteDb>>["client"];
    }
  | undefined
> {
  if (USING_REAL_POSTGRES) {
    delete process.env.STEWARD_PGLITE_MEMORY;
    return undefined;
  }

  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  return { db, client };
}

export async function cleanupAgentBehaviorTestDatabase(tenantId: string): Promise<void> {
  if (!USING_REAL_POSTGRES) {
    await closeDb();
    return;
  }

  const db = getDb();
  // Lease evidence intentionally has no tenant cascade: production retains it
  // after agent deletion. Test teardown must remove it explicitly before the
  // workspace graph or later real-PG files observe this fixture tenant.
  await db
    .delete(upstreamCredentialLeaseEvents)
    .where(eq(upstreamCredentialLeaseEvents.tenantId, tenantId));
  await db.delete(upstreamCredentialLeases).where(eq(upstreamCredentialLeases.tenantId, tenantId));

  // Capability plugin tables are optional and likewise do not reference the
  // core tenant. Delete the tenant's plugin graph when the migration is loaded.
  const capabilityTable = await db.execute(
    sql`SELECT to_regclass('public.capabilities')::text AS relation`,
  );
  const capabilityRows = Array.isArray(capabilityTable)
    ? capabilityTable
    : ((capabilityTable as { rows?: Array<{ relation: string | null }> }).rows ?? []);
  if ((capabilityRows[0] as { relation?: string | null } | undefined)?.relation) {
    await db.execute(sql`DELETE FROM public.capabilities WHERE tenant_id = ${tenantId}`);
  }

  // Audit rows and their deliberately FK-free high-water mark are not removed
  // by tenant cascades. Remove them explicitly, then let the tenant FK graph
  // clean every agent, wallet, key, signer, quorum, policy, and transaction row.
  await db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await db.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${tenantId}`);
  await db.delete(tenants).where(eq(tenants.id, tenantId));
}
