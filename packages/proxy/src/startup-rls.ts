import { assertRlsDeploymentSafety } from "@stwd/db";

type StartupDatabase = { execute(query: unknown): Promise<unknown> };

export async function assertProxyRlsReady(
  db: StartupDatabase,
  environment: NodeJS.ProcessEnv = process.env,
  assertSafety: typeof assertRlsDeploymentSafety = assertRlsDeploymentSafety,
): Promise<void> {
  if (environment.NODE_ENV === "development" || environment.NODE_ENV === "test") return;
  const expectedRole = environment.STEWARD_APP_DATABASE_ROLE?.trim();
  const expectedPlatformRole = environment.STEWARD_PLATFORM_DATABASE_ROLE?.trim();
  const expectedBootstrapRole = environment.STEWARD_BOOTSTRAP_DATABASE_ROLE?.trim();
  const expectedMigrationRole = environment.STEWARD_MIGRATION_DATABASE_ROLE?.trim();
  if (!expectedRole || !expectedPlatformRole || !expectedBootstrapRole || !expectedMigrationRole) {
    throw new Error("PROXY_RLS_DATABASE_ROLES_REQUIRED");
  }
  await assertSafety(db, {
    expectedRole,
    expectedPlatformRole,
    expectedBootstrapRole,
    expectedMigrationRole,
  });
}
