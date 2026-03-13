import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema";

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
  const db = drizzle(client, { schema });

  return { client, db };
}

let globalDb: ReturnType<typeof createDb> | undefined;

export function getDb() {
  globalDb ??= createDb();
  return globalDb.db;
}

export function getSql() {
  globalDb ??= createDb();
  return globalDb.client;
}

export async function closeDb() {
  if (!globalDb) {
    return;
  }

  await globalDb.client.end();
  globalDb = undefined;
}

export type Database = ReturnType<typeof getDb>;
