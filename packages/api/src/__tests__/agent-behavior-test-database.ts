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
  await db.transaction(async (tx) => {
    const capabilityTables = await tx.execute<{
      capabilities: string | null;
      grants: string | null;
      invocations: string | null;
    }>(sql`SELECT
      to_regclass('public.capabilities')::text AS capabilities,
      to_regclass('public.capability_grants')::text AS grants,
      to_regclass('public.capability_invocations')::text AS invocations`);
    const capabilityRows = Array.isArray(capabilityTables)
      ? capabilityTables
      : (capabilityTables.rows ?? []);
    const pluginTables = capabilityRows[0];
    if (pluginTables?.invocations) {
      await tx.execute(
        sql`DELETE FROM public.capability_invocations WHERE tenant_id = ${tenantId}`,
      );
    }
    if (pluginTables?.grants) {
      await tx.execute(sql`DELETE FROM public.capability_grants WHERE tenant_id = ${tenantId}`);
    }
    if (pluginTables?.capabilities) {
      await tx.execute(sql`DELETE FROM public.capabilities WHERE tenant_id = ${tenantId}`);
    }

    // Lease evidence is append-only in production. Remove only this unique
    // fixture tenant while bypassing its immutability triggers transactionally.
    await tx.execute(sql`SET LOCAL session_replication_role = replica`);
    await tx.execute(
      sql`DELETE FROM upstream_credential_lease_events WHERE tenant_id = ${tenantId}`,
    );
    await tx.execute(sql`DELETE FROM upstream_credential_leases WHERE tenant_id = ${tenantId}`);
    await tx.execute(sql`SET LOCAL session_replication_role = origin`);

    // Production agent deletion rejects unresolved execution. Clear only this
    // fixture's blockers before the tenant cascade reaches its agent rows.
    await tx.execute(sql`DELETE FROM provider_action_bindings WHERE tenant_id = ${tenantId}`);
    await tx.execute(sql`
      DELETE FROM transactions
      WHERE agent_id IN (SELECT id FROM agents WHERE tenant_id = ${tenantId})
    `);
    await tx.execute(sql`DELETE FROM pending_proxy_requests WHERE tenant_id = ${tenantId}`);
    await tx.execute(sql`
      UPDATE secret_routes SET enabled = false
      WHERE tenant_id = ${tenantId} AND enabled
    `);

    await tx.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await tx.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${tenantId}`);
    await tx.delete(tenants).where(eq(tenants.id, tenantId));
  });
  await closeDb();
}
