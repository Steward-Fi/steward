import { auditEvents, closeDb, getDb, tenants } from "@stwd/db";
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
  // Capability plugin tables are optional and likewise do not reference the
  // core tenant. Delete the tenant's plugin graph when the migration is loaded.
  const capabilityTables = await db.execute(
    sql`SELECT
      to_regclass('public.capabilities')::text AS capabilities,
      to_regclass('public.capability_rate_limit_buckets')::text AS buckets,
      to_regclass('public.capability_invocations')::text AS invocations`,
  );
  const capabilityRows = Array.isArray(capabilityTables)
    ? capabilityTables
    : ((
        capabilityTables as {
          rows?: Array<{
            buckets: string | null;
            capabilities: string | null;
            invocations: string | null;
          }>;
        }
      ).rows ?? []);
  const pluginTables = capabilityRows[0] as
    | { buckets?: string | null; capabilities?: string | null; invocations?: string | null }
    | undefined;
  if (pluginTables?.invocations) {
    await db.execute(sql`DELETE FROM public.capability_invocations WHERE tenant_id = ${tenantId}`);
  }
  if (pluginTables?.buckets) {
    await db.execute(
      sql`DELETE FROM public.capability_rate_limit_buckets WHERE tenant_id = ${tenantId}`,
    );
  }
  if (pluginTables?.capabilities) {
    await db.execute(sql`DELETE FROM public.capabilities WHERE tenant_id = ${tenantId}`);
  }

  // Audit rows and their deliberately FK-free high-water mark are not removed
  // by tenant cascades. Remove them explicitly, then let the tenant FK graph
  // clean every agent, wallet, key, signer, quorum, policy, and transaction row.
  await db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await db.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${tenantId}`);
  await db.delete(tenants).where(eq(tenants.id, tenantId));
}
