import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";

const rootDatabaseUrl = process.env.DATABASE_URL;
const describeWithPostgres = rootDatabaseUrl ? describe : describe.skip;
const repositoryRoot = new URL("../../../../", import.meta.url).pathname;
const databaseNames = new Set<string>();
let admin: ReturnType<typeof postgres> | undefined;

function databaseUrl(name: string): string {
  const url = new URL(rootDatabaseUrl as string);
  url.pathname = `/${name}`;
  return url.toString();
}

async function createTarget(prefix: string): Promise<{
  name: string;
  url: string;
  client: ReturnType<typeof postgres>;
}> {
  const name = `steward_${prefix}_${process.pid}_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
  await admin!`CREATE DATABASE ${admin!(name)}`;
  databaseNames.add(name);
  const url = databaseUrl(name);
  return { name, url, client: postgres(url, { max: 1 }) };
}

async function runMigrator(url: string): Promise<{
  exitCode: number;
  stdout: string;
  stderr: string;
}> {
  const child = Bun.spawn(["bun", "run", "packages/db/src/migrate.ts"], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      DATABASE_URL: url,
      DATABASE_DRIVER: "postgres-js",
      STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS: "10",
      STEWARD_MIGRATION_LOCK_TIMEOUT_MS: "10000",
      STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS: "120000",
      STEWARD_MIGRATION_OVERALL_TIMEOUT_MS: "180000",
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exitCode, stdout, stderr };
}

async function expectRejectedWithoutMutation(
  target: ReturnType<typeof postgres>,
  result: Awaited<ReturnType<typeof runMigrator>>,
): Promise<void> {
  expect(result.exitCode).not.toBe(0);
  // Entrypoint diagnostics intentionally redact error messages. The durable
  // proof is that the migrator failed and did not create even its schema.
  const [shape] = await target<Array<{ drizzle_schema_exists: boolean; ledger_exists: boolean }>>`
    SELECT
      to_regnamespace('drizzle') IS NOT NULL AS drizzle_schema_exists,
      to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS ledger_exists
  `;
  expect(shape).toEqual({ drizzle_schema_exists: false, ledger_exists: false });
}

describeWithPostgres("migration target inventory (real Postgres)", () => {
  beforeAll(() => {
    const maintenanceUrl = new URL(rootDatabaseUrl as string);
    maintenanceUrl.pathname = "/postgres";
    admin = postgres(maintenanceUrl.toString(), { max: 1 });
  });

  afterAll(async () => {
    try {
      for (const name of databaseNames) {
        await admin!`DROP DATABASE IF EXISTS ${admin!(name)} WITH (FORCE)`;
      }
    } finally {
      await admin?.end({ timeout: 5 });
    }
  });

  test("rejects a foreign table in a custom schema before any mutation", async () => {
    const target = await createTarget("foreign_schema");
    try {
      await target.client`CREATE SCHEMA foreign_application`;
      await target.client`
        CREATE FOREIGN DATA WRAPPER inventory_test_fdw NO HANDLER NO VALIDATOR
      `;
      await target.client`
        CREATE SERVER inventory_test_server FOREIGN DATA WRAPPER inventory_test_fdw
      `;
      await target.client`
        CREATE FOREIGN TABLE foreign_application.customer_records (id integer)
          SERVER inventory_test_server
      `;

      await expectRejectedWithoutMutation(target.client, await runMigrator(target.url));
      const [foreignTable] = await target.client<Array<{ exists: boolean }>>`
        SELECT to_regclass('foreign_application.customer_records') IS NOT NULL AS exists
      `;
      expect(foreignTable?.exists).toBe(true);
    } finally {
      await target.client.end({ timeout: 5 });
    }
  });

  test("rejects a public view-only target before any mutation", async () => {
    const target = await createTarget("public_view");
    try {
      await target.client`CREATE VIEW public.foreign_view AS SELECT 1 AS id`;

      await expectRejectedWithoutMutation(target.client, await runMigrator(target.url));
      const [view] = await target.client<Array<{ exists: boolean }>>`
        SELECT to_regclass('public.foreign_view') IS NOT NULL AS exists
      `;
      expect(view?.exists).toBe(true);
    } finally {
      await target.client.end({ timeout: 5 });
    }
  });

  test("rejects standalone public routines and types before any mutation", async () => {
    const target = await createTarget("public_code");
    try {
      await target.client`CREATE TYPE public.foreign_status AS ENUM ('active')`;
      await target.client`
        CREATE FUNCTION public.foreign_identity(value integer)
        RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT value'
      `;

      await expectRejectedWithoutMutation(target.client, await runMigrator(target.url));
    } finally {
      await target.client.end({ timeout: 5 });
    }
  });

  test("accepts explicit Neon schema and trusted extension metadata", async () => {
    const target = await createTarget("provider_metadata");
    try {
      await target.client`CREATE SCHEMA neon`;
      await target.client`CREATE SCHEMA drizzle`;
      await target.client`CREATE SCHEMA steward_rls`;
      await target.client`CREATE SCHEMA steward_bootstrap`;
      await target.client`CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public`;

      const result = await runMigrator(target.url);
      expect(result.exitCode, result.stderr || result.stdout).toBe(0);
      const [shape] = await target.client<
        Array<{ neon_schema_exists: boolean; extension_exists: boolean; migration_count: number }>
      >`
        SELECT
          to_regnamespace('neon') IS NOT NULL AS neon_schema_exists,
          EXISTS (
            SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
          ) AS extension_exists,
          (
            SELECT count(*)::int FROM drizzle.__drizzle_migrations
          ) AS migration_count
      `;
      expect(shape?.neon_schema_exists).toBe(true);
      expect(shape?.extension_exists).toBe(true);
      expect(shape?.migration_count).toBeGreaterThan(0);

      await target.client`
        CREATE TABLE drizzle.__drizzle_migrations_plugin_capabilities (
          id serial PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `;
      const cleanRetry = await runMigrator(target.url);
      expect(cleanRetry.exitCode, cleanRetry.stderr || cleanRetry.stdout).toBe(0);

      await target.client`CREATE SCHEMA shared_application`;
      await target.client`CREATE TABLE shared_application.foreign_records (id integer)`;
      const sharedResult = await runMigrator(target.url);
      expect(sharedResult.exitCode).not.toBe(0);
      const [afterRejection] = await target.client<Array<{ migration_count: number }>>`
        SELECT count(*)::int AS migration_count FROM drizzle.__drizzle_migrations
      `;
      expect(afterRejection?.migration_count).toBe(shape?.migration_count);
    } finally {
      await target.client.end({ timeout: 5 });
    }
  }, 200_000);

  test("rejects ordinary extra objects even with a complete valid core ledger", async () => {
    const target = await createTarget("valid_ledger_drift");
    try {
      const migrated = await runMigrator(target.url);
      expect(migrated.exitCode, migrated.stderr || migrated.stdout).toBe(0);
      const [before] = await target.client<Array<{ migration_count: number }>>`
        SELECT count(*)::int AS migration_count FROM drizzle.__drizzle_migrations
      `;

      await target.client`CREATE TABLE public.foreign_customer_records (id integer)`;
      await target.client`CREATE SEQUENCE public.foreign_customer_sequence`;
      await target.client`CREATE TYPE public.foreign_customer_status AS ENUM ('active')`;
      await target.client`
        CREATE FUNCTION public.foreign_customer_identity(value integer)
        RETURNS integer LANGUAGE sql IMMUTABLE AS 'SELECT value'
      `;

      const rejected = await runMigrator(target.url);
      expect(rejected.exitCode).not.toBe(0);
      const [after] = await target.client<Array<{ migration_count: number }>>`
        SELECT count(*)::int AS migration_count FROM drizzle.__drizzle_migrations
      `;
      expect(after?.migration_count).toBe(before?.migration_count);
    } finally {
      await target.client.end({ timeout: 5 });
    }
  }, 200_000);

  test("rejects malformed and unknown plugin ledgers on a valid core target", async () => {
    const target = await createTarget("plugin_ledger_drift");
    try {
      const migrated = await runMigrator(target.url);
      expect(migrated.exitCode, migrated.stderr || migrated.stdout).toBe(0);

      await target.client`
        CREATE TABLE drizzle.__drizzle_migrations_plugin_capabilities (
          id serial PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `;
      await target.client`
        INSERT INTO drizzle.__drizzle_migrations_plugin_capabilities(hash, created_at)
        VALUES ('not-a-checked-in-hash', 1782800000000)
      `;
      const malformed = await runMigrator(target.url);
      expect(malformed.exitCode).not.toBe(0);

      await target.client`DROP TABLE drizzle.__drizzle_migrations_plugin_capabilities`;
      await target.client`
        CREATE TABLE drizzle.__drizzle_migrations_plugin_unknown (
          id serial PRIMARY KEY,
          hash text NOT NULL,
          created_at bigint
        )
      `;
      const unknown = await runMigrator(target.url);
      expect(unknown.exitCode).not.toBe(0);
    } finally {
      await target.client.end({ timeout: 5 });
    }
  }, 200_000);

  test("rolls back migrations when non-cooperating DDL lands during the migration", async () => {
    const target = await createTarget("concurrent_ddl");
    try {
      const migration = runMigrator(target.url);
      const deadline = Date.now() + 30_000;
      let migrationTransactionObserved = false;
      while (Date.now() < deadline) {
        const [activity] = await target.client<Array<{ observed: boolean }>>`
          SELECT EXISTS (
            SELECT 1
            FROM pg_stat_activity
            WHERE datname = current_database()
              AND pid <> pg_backend_pid()
              AND xact_start IS NOT NULL
              AND clock_timestamp() - xact_start > interval '250 milliseconds'
          ) AS observed
        `;
        if (activity?.observed) {
          migrationTransactionObserved = true;
          break;
        }
        await Bun.sleep(25);
      }
      expect(migrationTransactionObserved).toBe(true);

      await target.client`CREATE TABLE public.concurrent_foreign_records (id integer)`;
      const result = await migration;
      expect(result.exitCode).not.toBe(0);
      const [shape] = await target.client<
        Array<{ ledger_exists: boolean; foreign_table_exists: boolean }>
      >`
        SELECT
          to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS ledger_exists,
          to_regclass('public.concurrent_foreign_records') IS NOT NULL AS foreign_table_exists
      `;
      expect(shape).toEqual({ ledger_exists: false, foreign_table_exists: true });
    } finally {
      await target.client.end({ timeout: 5 });
    }
  }, 200_000);
});
