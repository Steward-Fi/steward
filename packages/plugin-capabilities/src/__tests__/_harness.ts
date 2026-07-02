/**
 * _harness.ts - shared test setup for the capability plugin.
 *
 * builds a hermetic PGLite database carrying BOTH the core schema (createPGLiteDb
 * runs the core migrations: tenants, agents, secrets, secret_routes, ...) and
 * THIS package's own plugin migrations (capabilities, capability_grants), applied
 * via the per-plugin migration runner + the pglite migrator. that mirrors how the
 * host applies plugin migrations in production, into a per-plugin namespaced
 * bookkeeping table isolated from the core journal.
 */

import { fileURLToPath } from "node:url";
import { agents, runPluginMigrations, secretRoutes, secrets, tenants } from "@stwd/db";
import { createPGLiteDb } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { migrate as pgliteMigrate } from "drizzle-orm/pglite/migrator";

const MIGRATIONS_FOLDER = fileURLToPath(new URL("../../drizzle", import.meta.url));

// note (any is intentional): pglite db/client handles are driver-typed.
export type TestDb = any;

export interface Harness {
  db: TestDb;
  // note (any is intentional): pglite client is driver-typed.
  client: any;
  close(): Promise<void>;
}

/** stand up a fresh in-memory pglite with core + capability plugin schema. */
export async function makeHarness(): Promise<Harness> {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  // apply THIS plugin's migrations into its own namespaced ledger (driver-neutral
  // runner, pglite migrator injected, no advisory lock - pglite has none).
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder: MIGRATIONS_FOLDER },
    { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
  );
  return {
    db,
    client,
    async close() {
      await client.close().catch(() => {});
    },
  };
}

export async function ensureTenant(db: TestDb, tenantId: string): Promise<void> {
  await db
    .insert(tenants)
    .values({ id: tenantId, name: tenantId, apiKeyHash: `hash-${tenantId}` })
    .onConflictDoNothing();
}

export async function ensureAgent(db: TestDb, tenantId: string, agentId: string): Promise<void> {
  await db
    .insert(agents)
    .values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000001",
    })
    .onConflictDoNothing();
}

/** insert a bare secret row (the plugin only references its id, never decrypts). */
export async function ensureSecret(db: TestDb, tenantId: string, name: string): Promise<string> {
  const [row] = await db
    .insert(secrets)
    .values({
      tenantId,
      name,
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
    })
    .returning();
  return row.id as string;
}

/** count the ENABLED secret_routes for a tenant (the orphan-route invariant). */
export async function enabledRouteCount(db: TestDb, tenantId: string): Promise<number> {
  const rows = await db
    .select()
    .from(secretRoutes)
    .where(and(eq(secretRoutes.tenantId, tenantId), eq(secretRoutes.enabled, true)));
  return rows.length;
}

/** count ALL secret_routes for a tenant (enabled or not). */
export async function totalRouteCount(db: TestDb, tenantId: string): Promise<number> {
  const rows = await db.select().from(secretRoutes).where(eq(secretRoutes.tenantId, tenantId));
  return rows.length;
}

/** fetch a single secret_route row by id (or null). */
export async function getRoute(db: TestDb, id: string) {
  const [row] = await db.select().from(secretRoutes).where(eq(secretRoutes.id, id));
  return row ?? null;
}
