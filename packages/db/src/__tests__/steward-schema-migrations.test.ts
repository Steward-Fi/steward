import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import postgres from "postgres";

import {
  getStewardSchemaMigrationExpectation,
  getStewardSchemaMigrationSource,
  renderStewardSchemaMigration,
  runStewardSchemaMigrations,
  STEWARD_SCHEMA_MIGRATIONS_TABLE,
  type StewardSchemaMigrationClient,
  type StewardSchemaMigrationExecutor,
} from "../steward-schema-migrations";

setDefaultTimeout(180_000);

const fixtureTables = `
  CREATE TABLE tenants (
    id varchar(64) PRIMARY KEY,
    name varchar(255) NOT NULL,
    api_key_hash text NOT NULL,
    owner_address varchar(128),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text,
    deactivated_at timestamptz,
    is_guest boolean NOT NULL DEFAULT false,
    guest_expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE user_tenants (
    user_id uuid NOT NULL,
    tenant_id varchar(64) NOT NULL,
    role varchar(32) NOT NULL
  );
  CREATE TABLE agents (
    id varchar(64) PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    name varchar(255) NOT NULL,
    wallet_address varchar(128)
  );
  CREATE TABLE session_signers (
    id uuid PRIMARY KEY,
    jti text,
    tenant_id varchar(64) NOT NULL,
    agent_id varchar(64) NOT NULL,
    policy_ids jsonb,
    expires_at timestamptz,
    revoked_at timestamptz
  );
  CREATE TABLE tenant_app_clients (
    id varchar(64) NOT NULL,
    tenant_id varchar(64) NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    allowed_redirect_urls text[] NOT NULL DEFAULT '{}',
    login_methods jsonb NOT NULL DEFAULT '{}',
    allowed_bundle_ids text[] NOT NULL DEFAULT '{}',
    allowed_package_names text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, id)
  );
  CREATE TABLE tenant_app_client_secrets (
    id uuid PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    client_id varchar(64) NOT NULL,
    secret_hash text NOT NULL,
    status varchar(16) NOT NULL,
    expires_at timestamptz,
    revoked_at timestamptz
  );
  CREATE TABLE tenant_configs (
    tenant_id varchar(64) PRIMARY KEY,
    join_mode varchar(16) NOT NULL DEFAULT 'invite',
    auth_abuse_config jsonb NOT NULL DEFAULT '{}',
    allowed_origins text[] NOT NULL DEFAULT '{}',
    email_config jsonb NOT NULL DEFAULT '{}',
    oidc_providers jsonb NOT NULL DEFAULT '{}',
    test_account jsonb NOT NULL DEFAULT '{}',
    allowed_redirect_urls text[] NOT NULL DEFAULT '{}'
  );
  CREATE TABLE tenant_sso_domains (
    tenant_id varchar(64) NOT NULL,
    domain varchar(255) NOT NULL,
    sso_required boolean NOT NULL DEFAULT false,
    status varchar(16) NOT NULL
  );
  CREATE TABLE refresh_tokens (
    id text PRIMARY KEY,
    user_id uuid NOT NULL,
    tenant_id varchar(64) NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE transactions (id text PRIMARY KEY);

  INSERT INTO tenants (id, name, api_key_hash)
  VALUES ('tenant-fixture', 'Fixture tenant', 'fixture-key');
  INSERT INTO users (id, email)
  VALUES ('00000000-0000-4000-8000-000000000001', 'fixture@example.test');
  INSERT INTO user_tenants (user_id, tenant_id, role)
  VALUES ('00000000-0000-4000-8000-000000000001', 'tenant-fixture', 'owner');
  INSERT INTO tenant_configs (tenant_id, join_mode)
  VALUES ('tenant-fixture', 'invite');
`;

function pgliteAdapter(client: PGlite): StewardSchemaMigrationClient {
  const executor: StewardSchemaMigrationExecutor = {
    async unsafe<T extends Record<string, unknown>>(query: string, parameters?: unknown[]) {
      if (parameters && parameters.length > 0) {
        const result = await client.query<T>(query, parameters);
        return result.rows;
      }
      const results = await client.exec(query);
      return (results.at(-1)?.rows ?? []) as T[];
    },
  };
  return {
    ...executor,
    async begin<T>(callback: (transaction: StewardSchemaMigrationExecutor) => Promise<T>) {
      await client.exec("BEGIN");
      try {
        const result = await callback(executor);
        await client.exec("COMMIT");
        return result;
      } catch (error) {
        await client.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

async function createFixture(executor: StewardSchemaMigrationExecutor, schema: string) {
  if (schema !== "public") {
    await executor.unsafe(`CREATE SCHEMA ${schema}; SET search_path = ${schema}, public`);
  }
  await executor.unsafe(fixtureTables);
}

async function assertInstalled(
  executor: StewardSchemaMigrationExecutor,
  schema: string,
  sharedLedgerExpected = false,
): Promise<void> {
  const expectation = getStewardSchemaMigrationExpectation();
  const markers = await executor.unsafe<{
    migration_order: string | number;
    tag: string;
    hash: string;
    created_at: string | number;
  }>(
    `SELECT migration_order, tag, hash, created_at FROM ${schema}.${STEWARD_SCHEMA_MIGRATIONS_TABLE}`,
  );
  expect(markers).toEqual([
    {
      migration_order: expect.anything(),
      tag: expectation.tag,
      hash: expectation.hash,
      created_at: expect.anything(),
    },
  ]);
  expect(Number(markers[0]?.migration_order)).toBe(1);
  expect(Number(markers[0]?.created_at)).toBe(expectation.createdAt);

  const sharedLedger = await executor.unsafe<{ relation: string | null }>(
    "SELECT to_regclass('drizzle.__drizzle_migrations')::text AS relation",
  );
  expect(sharedLedger).toEqual([
    { relation: sharedLedgerExpected ? "drizzle.__drizzle_migrations" : null },
  ]);

  const definitions = await executor.unsafe<{ definition: string }>(`
    SELECT pg_get_functiondef(proc.oid) AS definition
    FROM pg_proc proc
    JOIN pg_namespace namespace ON namespace.oid = proc.pronamespace
    WHERE namespace.nspname = 'steward_bootstrap'
      AND proc.proname = 'auth_tenant_subject'
  `);
  expect(definitions).toHaveLength(1);
  expect(definitions[0]?.definition).toContain(`FROM "${schema}".tenants`);

  const status = await executor.unsafe<{
    migration_order: string | number;
    tag: string;
    hash: string;
    created_at: string | number;
  }>("SELECT * FROM steward_bootstrap.release_migration_manifest()");
  expect(status.map(({ tag, hash }) => ({ tag, hash }))).toEqual([
    { tag: expectation.tag, hash: expectation.hash },
  ]);

  const tenantSubject = await executor.unsafe<{
    tenant_id: string;
    membership_role: string;
    join_mode: string;
  }>(`
    SELECT * FROM steward_bootstrap.auth_tenant_subject(
      'tenant-fixture',
      '00000000-0000-4000-8000-000000000001'::uuid
    )
  `);
  expect(tenantSubject).toEqual([
    { tenant_id: "tenant-fixture", membership_role: "owner", join_mode: "invite" },
  ]);
}

describe("Steward-owned schema compatibility migration", () => {
  test("renders the immutable #900 bootstrap surface for a configured schema", () => {
    const source = getStewardSchemaMigrationSource();
    const rendered = renderStewardSchemaMigration(source, "steward");

    expect(source).toContain("0111_tenant_rls_policy_install");
    expect(source).toContain("0112_rls_activation_release_gates");
    expect(source).toContain("0113_personal_tenant_account_lifecycle");
    expect(rendered).toContain('FROM "steward".tenants');
    expect(rendered).toContain('existing "steward".users%ROWTYPE');
    expect(rendered).not.toContain("public.");
    expect(source).not.toContain("CREATE POLICY");
    expect(source).not.toContain('CREATE SCHEMA IF NOT EXISTS "steward_rls"');
  });

  for (const schema of ["public", "steward"] as const) {
    test(`installs idempotently in a PGLite ${schema} schema without a shared ledger`, async () => {
      const client = new PGlite("memory://");
      const adapter = pgliteAdapter(client);
      try {
        await createFixture(adapter, schema);
        const first = await runStewardSchemaMigrations({
          client: adapter,
          useAdvisoryLock: false,
        });
        expect(first).toEqual({
          applied: [getStewardSchemaMigrationExpectation().tag],
          schema,
        });
        await assertInstalled(adapter, schema);

        const second = await runStewardSchemaMigrations({
          client: adapter,
          useAdvisoryLock: false,
        });
        expect(second).toEqual({ applied: [], schema });
        await assertInstalled(adapter, schema);
      } finally {
        await client.close();
      }
    });
  }

  test("fails closed when an existing Steward-owned marker hash is not exact", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(
        `UPDATE public.${STEWARD_SCHEMA_MIGRATIONS_TABLE} SET hash = '${"0".repeat(64)}'`,
      );
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("exact expected bootstrap marker");
    } finally {
      await client.close();
    }
  });

  test("accepts only a well-formed forward marker suffix for rollback compatibility", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const expectation = getStewardSchemaMigrationExpectation();
      await adapter.unsafe(
        `INSERT INTO public.${STEWARD_SCHEMA_MIGRATIONS_TABLE} (tag, hash, created_at)
         VALUES ('0001_forward_fixture', '${"1".repeat(64)}', ${expectation.createdAt + 1})`,
      );
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).resolves.toEqual({ applied: [], schema: "public" });

      await adapter.unsafe(
        `UPDATE public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}
         SET created_at = ${expectation.createdAt}
         WHERE tag = '0001_forward_fixture'`,
      );
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("invalid forward suffix");
    } finally {
      await client.close();
    }
  });

  test("rolls back before creating a marker when the configured schema is incomplete", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await adapter.unsafe("CREATE TABLE tenants (id varchar(64) PRIMARY KEY)");
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("missing bootstrap prerequisites");
      const marker = await adapter.unsafe<{ relation: string | null }>(
        `SELECT to_regclass('public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}')::text AS relation`,
      );
      expect(marker).toEqual([{ relation: null }]);
    } finally {
      await client.close();
    }
  });
});

const postgresUrl = process.env.DATABASE_URL;
const postgresDescribe = postgresUrl ? describe : describe.skip;
const postgresDatabases: string[] = [];

postgresDescribe("Steward-owned schema compatibility migration on real Postgres", () => {
  const originalUrl = postgresUrl ?? "postgres://unused.invalid/postgres";
  const maintenanceUrl = new URL(originalUrl);
  maintenanceUrl.pathname = "/postgres";
  maintenanceUrl.searchParams.delete("options");
  const admin = postgres(maintenanceUrl.toString(), { max: 1 });

  afterAll(async () => {
    for (const database of postgresDatabases) {
      await admin.unsafe(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
    }
    await admin.end();
  });

  for (const schema of ["public", "steward"] as const) {
    test(`installs in the configured ${schema} schema and preserves a shared ledger`, async () => {
      const database = `steward_schema_${schema}_${randomUUID().replaceAll("-", "")}`;
      postgresDatabases.push(database);
      await admin.unsafe(`CREATE DATABASE "${database}"`);

      const targetUrl = new URL(originalUrl);
      targetUrl.pathname = `/${database}`;
      targetUrl.searchParams.set("options", `-c search_path=${schema},public`);
      const client = postgres(targetUrl.toString(), { max: 1, prepare: false });
      const adapter = client as unknown as StewardSchemaMigrationClient;
      try {
        await client.unsafe(`
          CREATE SCHEMA drizzle;
          CREATE TABLE drizzle.__drizzle_migrations (
            id serial PRIMARY KEY,
            hash text NOT NULL,
            created_at bigint
          );
          INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
          VALUES ('shared-eliza-sentinel', 1793072800004);
        `);
        await createFixture(adapter, schema);

        await expect(
          runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: true }),
        ).resolves.toEqual({
          applied: [getStewardSchemaMigrationExpectation().tag],
          schema,
        });
        await assertInstalled(adapter, schema, true);

        const sharedRows = await client<
          { hash: string; created_at: string | number }[]
        >`SELECT hash, created_at FROM drizzle.__drizzle_migrations`;
        expect(sharedRows).toEqual([
          { hash: "shared-eliza-sentinel", created_at: "1793072800004" },
        ]);
      } finally {
        await client.end({ timeout: 5 });
      }
    });
  }
});
