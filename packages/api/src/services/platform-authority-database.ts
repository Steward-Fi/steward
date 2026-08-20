import { createDb, createNeonTransactionDbForRequest, getDatabaseDriver, getDb } from "@stwd/db";
import { sql } from "drizzle-orm";

type PlatformDb = ReturnType<typeof getDb>;

function rowsOf<T>(result: unknown): T[] {
  return (Array.isArray(result) ? result : ((result as { rows?: T[] })?.rows ?? [])) as T[];
}

async function assertPlatformRole(db: PlatformDb, expectedRole: string): Promise<void> {
  const [role] = rowsOf<{
    session_user: string;
    current_user: string;
    rolsuper: boolean;
    rolbypassrls: boolean;
  }>(
    await db.execute(sql`
      SELECT session_user::text, current_user::text, role.rolsuper, role.rolbypassrls
      FROM pg_roles role WHERE role.rolname = session_user
    `),
  );
  if (
    !role ||
    role.session_user !== expectedRole ||
    role.current_user !== expectedRole ||
    role.rolsuper ||
    role.rolbypassrls
  ) {
    throw new Error("PLATFORM_DATABASE_ROLE_UNSAFE");
  }
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
  if (process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true") {
    return callback(getDb());
  }
  const connectionString = process.env.STEWARD_PLATFORM_DATABASE_URL;
  const expectedRole = process.env.STEWARD_PLATFORM_DATABASE_ROLE;
  if (!connectionString || !expectedRole) {
    throw new Error("PLATFORM_DATABASE_AUTHORITY_NOT_CONFIGURED");
  }

  if (getDatabaseDriver() === "neon-websocket") {
    const handle = createNeonTransactionDbForRequest({
      DATABASE_URL: connectionString,
      DATABASE_DRIVER: "neon-websocket",
    });
    try {
      await assertPlatformRole(handle.db as unknown as PlatformDb, expectedRole);
      return await callback(handle.db as unknown as PlatformDb);
    } finally {
      await handle.close();
    }
  }

  const handle = createDb(connectionString);
  try {
    await assertPlatformRole(handle.db as unknown as PlatformDb, expectedRole);
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
