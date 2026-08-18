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
import { and, eq, sql as rawSql } from "drizzle-orm";
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

/**
 * Seed a `governed_v2` secret route for the plugin governed-gate tests.
 * (spec §5.2, P03/P04). Builds the minimal provider-authority chain the governed
 * CHECK requires: a user (workspace.created_by), a workspace, a provider account,
 * a legacy secret_route, a provider_operation pointing at that route, then flips
 * the route to governed_v2 with provider_operation_id set (the circular route<->
 * operation FK is why we insert the route legacy-first, then wire + flip). Uses
 * raw SQL so the fixture never depends on the API service layer.
 *
 * Returns the governed route id. The route matches host/pathPattern/method so
 * `capabilityMapsToGovernedRoute` in invoke.ts detects it and denies the plugin.
 */
export async function ensureGovernedRoute(
  db: TestDb,
  tenantId: string,
  agentId: string,
  secretId: string,
  opts: {
    hostPattern: string;
    pathPattern: string;
    method: string;
    injectAs?: string;
    injectKey?: string;
    existingRouteId?: string;
  },
): Promise<string> {
  const q = async (query: ReturnType<typeof rawSql>): Promise<Array<Record<string, unknown>>> => {
    const res = (await (db as { execute: (s: unknown) => Promise<unknown> }).execute(query)) as
      | { rows?: Array<Record<string, unknown>> }
      | Array<Record<string, unknown>>;
    return Array.isArray(res) ? res : (res.rows ?? []);
  };

  const injectAs = opts.injectAs ?? "header";
  const injectKey = opts.injectKey ?? "authorization";
  const userRows = await q(
    rawSql`INSERT INTO users (email) VALUES (${`gov-${tenantId}@test.local`}) RETURNING id`,
  );
  const userId = userRows[0].id as string;
  const wsRows = await q(
    rawSql`INSERT INTO workspaces (tenant_id, key, name, environment, created_by)
           VALUES (${tenantId}, ${`ws-${agentId}`}, 'ws', 'production', ${userId}) RETURNING id`,
  );
  const workspaceId = wsRows[0].id as string;
  const accRows = await q(
    rawSql`INSERT INTO provider_accounts (tenant_id, workspace_id, adapter_key, external_ref, display_name)
           VALUES (${tenantId}, ${workspaceId}, 'github', ${`ref-${agentId}`}, 'gh') RETURNING id`,
  );
  const accountId = accRows[0].id as string;
  // Legacy route first (governed CHECK forbids provider_operation_id on legacy).
  let routeId = opts.existingRouteId;
  if (!routeId) {
    const routeRows = await q(
      rawSql`INSERT INTO secret_routes
               (tenant_id, agent_id, secret_id, host_pattern, path_pattern, method, inject_as, inject_key, authority_mode)
             VALUES (${tenantId}, ${agentId}, ${secretId}, ${opts.hostPattern}, ${opts.pathPattern},
                     ${opts.method}, ${injectAs}, ${injectKey}, 'legacy') RETURNING id`,
    );
    routeId = routeRows[0].id as string;
  }
  const opRows = await q(
    rawSql`INSERT INTO provider_operations
             (tenant_id, workspace_id, provider_account_id, operation_key, risk_class, secret_route_id)
           VALUES (${tenantId}, ${workspaceId}, ${accountId}, ${`op-${agentId}`}, 'consequential', ${routeId}) RETURNING id`,
  );
  const operationId = opRows[0].id as string;
  // Flip to governed_v2 (now that the operation exists to name).
  await q(
    rawSql`UPDATE secret_routes SET authority_mode = 'governed_v2', provider_operation_id = ${operationId}
           WHERE id = ${routeId}`,
  );
  return routeId;
}
