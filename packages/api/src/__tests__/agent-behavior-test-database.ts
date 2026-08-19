import { auditEvents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";

/**
 * Agent mutation behavior must exercise the production PostgreSQL transaction
 * and trigger semantics whenever the integration job provides DATABASE_URL.
 * Local runs without PostgreSQL retain the hermetic in-memory PGLite fixture.
 */
export const USING_REAL_POSTGRES = Boolean(process.env.DATABASE_URL);

export async function setupAgentBehaviorTestDatabase(): Promise<void> {
  if (USING_REAL_POSTGRES) {
    delete process.env.STEWARD_PGLITE_MEMORY;
    return;
  }

  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
}

export async function cleanupAgentBehaviorTestDatabase(tenantId: string): Promise<void> {
  if (!USING_REAL_POSTGRES) {
    await closeDb();
    return;
  }

  const db = getDb();
  // Audit rows and their deliberately FK-free high-water mark are not removed
  // by tenant cascades. Remove them explicitly, then let the tenant FK graph
  // clean every agent, wallet, key, signer, quorum, policy, and transaction row.
  await db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
  await db.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${tenantId}`);
  await db.delete(tenants).where(eq(tenants.id, tenantId));
}
