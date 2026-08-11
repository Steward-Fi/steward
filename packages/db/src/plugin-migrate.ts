/**
 * plugin-migrate.ts — plugin-owned database migrations with NAMESPACED journals.
 *
 * WHY THIS EXISTS (Phase 2c)
 * --------------------------
 * a steward plugin (e.g. trading) may own tables the lean core does not know
 * about. it declares its schema via a {@link PluginMigrationSource}: its OWN
 * drizzle migrations folder (with its OWN `meta/_journal.json`). the host applies
 * those migrations through this runner.
 *
 * THE ISOLATION GUARANTEE (the whole point)
 * -----------------------------------------
 * a plugin's applied-migrations bookkeeping is recorded in a SEPARATE, per-plugin
 * table derived from the plugin's `id`:
 *
 *     drizzle.__drizzle_migrations_plugin_<sanitized id>
 *
 * NEVER in the core's `drizzle.__drizzle_migrations`. drizzle's migrator is told
 * (via the `migrationsTable` option) to read/write ONLY that namespaced table, so
 * it is structurally IMPOSSIBLE for a plugin migration to be recorded in, read
 * from, or otherwise clobber the core's migration journal. the core's
 * `runMigrations()` (packages/db/src/migrate.ts) is left BYTE-IDENTICAL; this is
 * a wholly separate function with a separate ledger.
 *
 * Two plugins also cannot collide with each other: their ids derive distinct
 * table names (and distinct advisory-lock keys), so each plugin owns exactly one
 * isolated ledger.
 *
 * CONCURRENCY
 * -----------
 * like the core migrator, each plugin run takes a Postgres session advisory lock
 * (a PER-PLUGIN key derived from the id, distinct from the core's
 * "steward_migrations" key) so concurrent API replicas don't race applying the
 * same plugin's migrations on boot. the lock is released in a `finally`.
 *
 * FAIL-CLOSED
 * -----------
 * an id that sanitizes to empty is rejected (a plugin MUST have a usable
 * namespace). any migration error propagates to the caller (the host surfaces it
 * loudly and refuses to half-boot). idempotency is inherited from drizzle's
 * migrator: re-running with the same (already-recorded) migrations applies
 * nothing.
 */

import type { PluginMigrationSource } from "@stwd/shared";
import { migrate } from "drizzle-orm/postgres-js/migrator";

import { createDb } from "./client";

/** the schema the per-plugin bookkeeping table lives in (same as core's). */
const PLUGIN_MIGRATIONS_SCHEMA = "drizzle";

/** prefix for a plugin's per-plugin bookkeeping table; the sanitized id follows. */
const PLUGIN_MIGRATIONS_TABLE_PREFIX = "__drizzle_migrations_plugin_";

/**
 * Sanitize a plugin id into a safe SQL identifier fragment. Lowercases, replaces
 * any character outside `[a-z0-9_]` with `_`, and collapses repeats. This is what
 * gets appended to {@link PLUGIN_MIGRATIONS_TABLE_PREFIX} and used to derive the
 * advisory-lock key, so it must be deterministic + injection-safe.
 *
 * THROWS if the result is empty (an id that carries no usable identifier
 * characters is rejected fail-closed — a plugin MUST have a real namespace, since
 * an empty fragment would leave the table name a bare prefix and risk colliding
 * across ill-formed ids).
 */
export function sanitizePluginMigrationId(id: string): string {
  const sanitized = id
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+|_+$/g, "");
  if (sanitized.length === 0) {
    throw new Error(
      `plugin migration id "${id}" sanitizes to an empty identifier; ` +
        "a plugin migration source must have a non-empty alphanumeric id.",
    );
  }
  return sanitized;
}

/**
 * The per-plugin bookkeeping table name for a plugin id. This is the table
 * drizzle's migrator records applied migrations in for THIS plugin — never the
 * core's `__drizzle_migrations`.
 */
export function pluginMigrationsTable(id: string): string {
  return `${PLUGIN_MIGRATIONS_TABLE_PREFIX}${sanitizePluginMigrationId(id)}`;
}

/**
 * A stable advisory-lock key for a plugin id, distinct from the core migrator's
 * "steward_migrations" key and distinct per plugin, so a plugin's boot-time
 * migration run serializes across replicas without blocking the core migrator or
 * another plugin's run.
 */
export function pluginAdvisoryLockKey(id: string): string {
  return `steward_plugin_migrations_${sanitizePluginMigrationId(id)}`;
}

/**
 * Options for {@link runPluginMigrations}. The defaults create a postgres-js
 * client from `DATABASE_URL` (the same path the core migrator uses) and take the
 * per-plugin advisory lock. Tests inject their own `db`/`client` (e.g. a PGLite
 * harness) and may disable the advisory lock (PGLite has no `pg_advisory_lock`).
 */
export interface RunPluginMigrationsOptions {
  /**
   * a drizzle migrator-compatible db handle. defaults to a fresh postgres-js
   * `createDb().db`. injected by tests to run against a PGLite/other harness.
   */
  // biome-ignore lint/suspicious/noExplicitAny: drizzle's `migrate` is typed per
  // driver (postgres-js/pglite/neon); we accept any drizzle db whose driver's
  // `migrate` shares the MigrationConfig contract. the runner stays driver-neutral.
  db?: any;
  /**
   * the raw SQL tagged-template client used for the advisory lock. defaults to
   * the client paired with the default `db`. only consulted when
   * `useAdvisoryLock` is true.
   */
  // biome-ignore lint/suspicious/noExplicitAny: postgres-js client tagged-template
  // surface; injected harnesses (PGLite) don't take the advisory-lock path.
  client?: any;
  /**
   * take a Postgres session advisory lock around the run (default true). set
   * false for harnesses without `pg_advisory_lock` (PGLite). production/postgres
   * always uses the lock.
   */
  useAdvisoryLock?: boolean;
  /**
   * the drizzle `migrate` implementation to use. defaults to the postgres-js
   * migrator. injected by tests so a PGLite db uses the pglite migrator (both
   * share the `MigrationConfig` shape, so the call site is identical).
   */
  // biome-ignore lint/suspicious/noExplicitAny: per-driver migrator function; all
  // drivers' `migrate` share the (db, MigrationConfig) signature.
  migrateFn?: (
    db: any,
    config: { migrationsFolder: string; migrationsTable?: string; migrationsSchema?: string },
  ) => Promise<void>;
}

/**
 * Apply a plugin's own drizzle migrations into a PER-PLUGIN, NAMESPACED
 * bookkeeping table, totally isolated from the core's `__drizzle_migrations`
 * journal.
 *
 * - reads the plugin's `migrationsFolder` (its own `*.sql` + `meta/_journal.json`).
 * - records applied migrations ONLY in
 *   `drizzle.__drizzle_migrations_plugin_<sanitized id>` (via the migrator's
 *   `migrationsTable`/`migrationsSchema` options) — NEVER the core journal.
 * - serializes concurrent boots on a per-plugin advisory lock.
 * - idempotent (drizzle skips already-recorded migrations).
 *
 * Returns the namespaced table the plugin's ledger was written to, for the host's
 * diagnostics / for a caller to assert isolation in tests.
 */
export async function runPluginMigrations(
  source: PluginMigrationSource,
  options: RunPluginMigrationsOptions = {},
): Promise<{ id: string; migrationsTable: string }> {
  if (!source || typeof source.id !== "string" || source.id.trim().length === 0) {
    throw new Error("runPluginMigrations: source.id is required (non-empty string).");
  }
  if (typeof source.migrationsFolder !== "string" || source.migrationsFolder.trim().length === 0) {
    throw new Error(
      `runPluginMigrations: source.migrationsFolder is required for plugin "${source.id}".`,
    );
  }

  // Derive the isolated ledger table name (also validates the id fail-closed).
  const migrationsTable = pluginMigrationsTable(source.id);
  const lockKey = pluginAdvisoryLockKey(source.id);
  const useAdvisoryLock = options.useAdvisoryLock ?? true;
  const migrateFn = options.migrateFn ?? (migrate as RunPluginMigrationsOptions["migrateFn"]);
  if (!migrateFn) {
    throw new Error("runPluginMigrations: no migrate implementation available.");
  }

  // Build (or reuse the injected) db + client. When we create them, we own them
  // and must close the client at the end.
  let ownsClient = false;
  let db = options.db;
  let client = options.client;
  if (!db) {
    const created = createDb();
    db = created.db;
    client = created.client;
    ownsClient = true;
  }

  try {
    if (useAdvisoryLock) {
      if (!client) {
        throw new Error(
          `runPluginMigrations: advisory lock requested for plugin "${source.id}" ` +
            "but no SQL client was provided. Pass `client` or set useAdvisoryLock:false.",
        );
      }
      await client`SELECT pg_advisory_lock(hashtextextended(${lockKey}, 0))`;
    }

    try {
      // CRITICAL ISOLATION: migrationsTable scopes drizzle's applied-migrations
      // bookkeeping to the per-plugin table. The core's __drizzle_migrations is
      // NEVER touched by this call.
      await migrateFn(db, {
        migrationsFolder: source.migrationsFolder,
        migrationsTable,
        migrationsSchema: PLUGIN_MIGRATIONS_SCHEMA,
      });
    } finally {
      if (useAdvisoryLock && client) {
        await client`SELECT pg_advisory_unlock(hashtextextended(${lockKey}, 0))`;
      }
    }

    return { id: source.id, migrationsTable };
  } finally {
    if (ownsClient && client && typeof client.end === "function") {
      await client.end();
    }
  }
}
