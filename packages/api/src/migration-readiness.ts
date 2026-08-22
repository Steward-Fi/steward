import { getDb, getMigrationExpectation, getPluginMigrationLedgerExpectation } from "@stwd/db";
import { shouldUsePGLite } from "@stwd/db/pglite";
import type { PluginMigrationSource } from "@stwd/shared";
import { sql } from "drizzle-orm";

export type MigrationReadinessCheck = {
  ok: boolean;
  required?: boolean;
  error?: string;
  detail?: unknown;
};

export type EnabledPluginMigrationSource = {
  pluginName: string;
  source: PluginMigrationSource;
};

/**
 * One exact migration-readiness authority shared by Bun `/ready` and Workers
 * cold-start. It validates the checked-in core tip and every enabled plugin's
 * namespaced journal; a core-only database can never serve plugin routes.
 */
export async function readMigrationReadiness(options: {
  db?: ReturnType<typeof getDb>;
  migrationsRan: boolean;
  pluginMigrationSources: EnabledPluginMigrationSource[];
  pglite?: boolean;
}): Promise<{
  database: MigrationReadinessCheck;
  migrations: MigrationReadinessCheck;
  pluginMigrations: MigrationReadinessCheck;
}> {
  const db = options.db ?? getDb();
  const pglite = options.pglite ?? shouldUsePGLite();
  const expectedMigration = getMigrationExpectation();
  const result = pglite
    ? await db.execute(sql`
        SELECT
          EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000 AS database_time_ms,
          EXISTS(
            SELECT 1 FROM __steward_migrations WHERE tag = ${expectedMigration.tag}
          ) AS expected_migration_applied
      `)
    : await db.execute(sql`
        SELECT
          EXTRACT(EPOCH FROM clock_timestamp()) * 1000 AS database_time_ms,
          (SELECT MAX(created_at) FROM drizzle.__drizzle_migrations) AS migration_created_at
      `);
  const rows = Array.isArray(result)
    ? result
    : ((result as unknown as { rows?: unknown[] }).rows ?? []);
  const row = rows[0] as
    | {
        database_time_ms?: string | number;
        migration_created_at?: string | number | null;
        expected_migration_applied?: unknown;
      }
    | undefined;
  const databaseTimeMs = Number(row?.database_time_ms);
  const migrationCreatedAt = Number(row?.migration_created_at);
  const expectedMigrationApplied = row?.expected_migration_applied === true;
  const databaseSkewMs = Math.abs(Date.now() - databaseTimeMs);
  const database: MigrationReadinessCheck = {
    ok: Number.isFinite(databaseTimeMs) && databaseSkewMs <= 30_000,
    detail: { clockSkewMs: Math.round(databaseSkewMs), serverTime: new Date().toISOString() },
  };
  const migrations: MigrationReadinessCheck = {
    ok:
      options.migrationsRan &&
      (pglite ? expectedMigrationApplied : migrationCreatedAt === expectedMigration.createdAt),
    detail: {
      expected: expectedMigration.tag,
      expectedCreatedAt: expectedMigration.createdAt,
      ...(pglite
        ? { expectedMigrationApplied }
        : { actualCreatedAt: Number.isFinite(migrationCreatedAt) ? migrationCreatedAt : null }),
    },
  };

  if (options.pluginMigrationSources.length === 0) {
    return {
      database,
      migrations,
      pluginMigrations: { ok: true, required: false },
    };
  }

  try {
    const pluginDetails: Array<{ plugin: string; ok: boolean; expectedEntries: number }> = [];
    for (const { pluginName, source } of options.pluginMigrationSources) {
      const expectation = getPluginMigrationLedgerExpectation(source);
      const pluginResult = await db.execute(
        sql.raw(
          `SELECT hash, created_at FROM drizzle."${expectation.migrationsTable}" ORDER BY id ASC`,
        ),
      );
      const pluginRows = (
        Array.isArray(pluginResult)
          ? pluginResult
          : ((pluginResult as unknown as { rows?: unknown[] }).rows ?? [])
      ) as Array<{ hash?: unknown; created_at?: unknown }>;
      const ok =
        pluginRows.length === expectation.entries.length &&
        pluginRows.every(
          (pluginRow, index) =>
            pluginRow.hash === expectation.entries[index]?.hash &&
            Number(pluginRow.created_at) === expectation.entries[index]?.createdAt,
        );
      pluginDetails.push({ plugin: pluginName, ok, expectedEntries: expectation.entries.length });
    }
    return {
      database,
      migrations,
      pluginMigrations: {
        ok: pluginDetails.every((plugin) => plugin.ok),
        detail: pluginDetails,
      },
    };
  } catch {
    return {
      database,
      migrations,
      pluginMigrations: {
        ok: false,
        error: "Enabled plugin migration ledger check failed",
      },
    };
  }
}
