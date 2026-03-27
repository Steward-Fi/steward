import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema";
import * as schemaAuth from "./schema-auth";

declare const process: {
  env: Record<string, string | undefined>;
};

export function getDatabaseUrl(): string {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    throw new Error("DATABASE_URL is required");
  }

  return connectionString;
}

export function createPostgresClient(connectionString = getDatabaseUrl()) {
  return postgres(connectionString, {
    max: 10,
    prepare: false,
  });
}

export function createDb(connectionString = getDatabaseUrl()) {
  const client = createPostgresClient(connectionString);
  const db = drizzle(client, { schema: { ...schema, ...schemaAuth } });

  return { client, db };
}

// ─── PGLite support ───────────────────────────────────────────────────────────
// When running in embedded/local mode, the PGLite adapter sets these overrides
// so all existing code that calls getDb()/closeDb() works unchanged.

let pgliteOverride: {
  db: ReturnType<typeof createDb>["db"];
  close: () => Promise<void>;
} | undefined;

/**
 * Set PGLite as the backing database. Called by the embedded entry point
 * BEFORE any route code runs.
 */
export function setPGLiteOverride(
  db: ReturnType<typeof createDb>["db"],
  close: () => Promise<void>,
) {
  pgliteOverride = { db, close };
}

// ─── Global singleton ─────────────────────────────────────────────────────────

let globalDb: ReturnType<typeof createDb> | undefined;

export function getDb() {
  if (pgliteOverride) return pgliteOverride.db;
  globalDb ??= createDb();
  return globalDb.db;
}

export function getSql() {
  if (pgliteOverride) {
    throw new Error("getSql() is not available in PGLite mode — use getDb() instead");
  }
  globalDb ??= createDb();
  return globalDb.client;
}

export async function closeDb() {
  if (pgliteOverride) {
    await pgliteOverride.close();
    pgliteOverride = undefined;
    return;
  }

  if (!globalDb) {
    return;
  }

  await globalDb.client.end();
  globalDb = undefined;
}

export type Database = ReturnType<typeof getDb>;
