import { assertRlsDeploymentSafety, closeDb, getDb } from "@stwd/db";
import { getComposedPluginMigrationSources } from "../packages/api/src/compose";
import { readMigrationReadiness } from "../packages/api/src/migration-readiness";

/**
 * Verify the completed out-of-band release through the exact restricted
 * database credential rendered for the Railway application service.
 */
async function main(): Promise<void> {
  const expectedRole = process.env.STEWARD_APP_DATABASE_ROLE;
  const expectedPlatformRole = process.env.STEWARD_PLATFORM_DATABASE_ROLE;
  const expectedBootstrapRole = process.env.STEWARD_BOOTSTRAP_DATABASE_ROLE;
  const expectedMigrationRole = process.env.STEWARD_MIGRATION_DATABASE_ROLE;
  if (!expectedRole || !expectedPlatformRole || !expectedBootstrapRole || !expectedMigrationRole) {
    throw new Error("all four STEWARD_*_DATABASE_ROLE values are required");
  }

  const pluginMigrationSources = await getComposedPluginMigrationSources();
  const checks = await readMigrationReadiness({
    db: getDb(),
    migrationsRan: true,
    pluginMigrationSources,
    pglite: false,
  });
  if (!checks.database.ok || !checks.migrations.ok || !checks.pluginMigrations.ok) {
    throw new Error("database release readiness did not match this source and plugin set");
  }

  await assertRlsDeploymentSafety(getDb(), {
    expectedRole,
    expectedPlatformRole,
    expectedBootstrapRole,
    expectedMigrationRole,
  });
  console.log(
    `[release] Database, core/plugin journals, and forced RLS are ready for ${pluginMigrationSources.length} enabled plugin(s).`,
  );
}

main()
  .catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : "database release verification failed");
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDb();
  });
