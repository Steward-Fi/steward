import {
  assertPlatformDatabaseAuthority,
  createDb,
  createNeonTransactionDbForRequest,
  getDatabaseDriver,
  getDb,
} from "@stwd/db";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { sql } from "drizzle-orm";

type PlatformDb = ReturnType<typeof getDb>;

export function __platformAuthorityEnvironmentForTests() {
  return {
    databaseMode: runtimeEnvironmentValue("STEWARD_DB_MODE"),
    pgliteMemory: runtimeEnvironmentValue("STEWARD_PGLITE_MEMORY"),
    connectionString: runtimeEnvironmentValue("STEWARD_PLATFORM_DATABASE_URL"),
    expectedRole: runtimeEnvironmentValue("STEWARD_PLATFORM_DATABASE_ROLE"),
    driver: runtimeEnvironmentValue("DATABASE_DRIVER") ?? getDatabaseDriver(),
  };
}

/**
 * Execute a bounded platform-authority unit through a distinct login. The
 * ordinary application connection is intentionally never a fallback in a
 * deployed runtime; tests/PGLite retain the embedded handle because PostgreSQL
 * roles are unavailable there.
 */
export async function withPlatformAuthorityDatabase<T>(
  callback: (db: PlatformDb) => Promise<T>,
): Promise<T> {
  const authority = __platformAuthorityEnvironmentForTests();
  if (authority.databaseMode === "pglite" || authority.pgliteMemory === "true") {
    return callback(getDb());
  }
  const connectionString = authority.connectionString;
  const expectedRole = authority.expectedRole;
  if (!connectionString || !expectedRole) {
    throw new Error("PLATFORM_DATABASE_AUTHORITY_NOT_CONFIGURED");
  }

  if (authority.driver === "neon-websocket") {
    const handle = createNeonTransactionDbForRequest({
      DATABASE_URL: connectionString,
      DATABASE_DRIVER: "neon-websocket",
    });
    try {
      await assertPlatformDatabaseAuthority(handle.db as unknown as PlatformDb, expectedRole);
      return await callback(handle.db as unknown as PlatformDb);
    } finally {
      await handle.close();
    }
  }

  const handle = createDb(connectionString);
  try {
    await assertPlatformDatabaseAuthority(handle.db as unknown as PlatformDb, expectedRole);
    return await callback(handle.db as unknown as PlatformDb);
  } finally {
    await handle.client.end({ timeout: 5 });
  }
}

export async function withPlatformAuthorityTransaction<T>(
  callback: (tx: PlatformDb) => Promise<T>,
): Promise<T> {
  return withPlatformAuthorityDatabase((db) =>
    db.transaction(async (tx) => {
      await tx.execute(sql`SELECT set_config('steward.tenant_id', 'platform', true)`);
      return callback(tx as unknown as PlatformDb);
    }),
  );
}
