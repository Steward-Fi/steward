import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import postgres from "postgres";

import {
  getStewardPasskeyRpProvenanceMigrationSource,
  getStewardSchemaMigrationExpectation,
  getStewardSchemaMigrationExpectations,
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
  CREATE TABLE authenticators (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    credential_id text NOT NULL UNIQUE,
    credential_public_key text NOT NULL,
    counter integer NOT NULL DEFAULT 0,
    credential_device_type varchar(32),
    credential_backed_up boolean DEFAULT false,
    transports text[],
    created_at timestamptz NOT NULL DEFAULT now()
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
  const expectations = getStewardSchemaMigrationExpectations();
  const markers = await executor.unsafe<{
    migration_order: string | number;
    tag: string;
    hash: string;
    created_at: string | number;
  }>(
    `SELECT migration_order, tag, hash, created_at FROM ${schema}.${STEWARD_SCHEMA_MIGRATIONS_TABLE}`,
  );
  expect(
    markers.map((marker) => ({
      migrationOrder: Number(marker.migration_order),
      tag: marker.tag,
      hash: marker.hash,
      createdAt: Number(marker.created_at),
    })),
  ).toEqual(
    expectations.map((expectation, index) => ({
      migrationOrder: index + 1,
      tag: expectation.tag,
      hash: expectation.hash,
      createdAt: expectation.createdAt,
    })),
  );

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
    ...expectations.map(({ tag, hash }) => ({ tag, hash })),
  ]);

  const rpProvenance = await executor.unsafe<{
    data_type: string;
    character_maximum_length: string | number | null;
    is_nullable: string;
    column_default: string | null;
  }>(`
    SELECT data_type, character_maximum_length, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema = '${schema}'
      AND table_name = 'authenticators'
      AND column_name = 'rp_id'
  `);
  expect(rpProvenance).toHaveLength(1);
  expect(rpProvenance[0]).toMatchObject({
    data_type: "character varying",
    is_nullable: "YES",
    column_default: null,
  });
  expect(Number(rpProvenance[0]?.character_maximum_length)).toBe(253);

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
    const rpProvenanceSource = getStewardPasskeyRpProvenanceMigrationSource();
    const renderedRpProvenance = renderStewardSchemaMigration(rpProvenanceSource, "steward");

    expect(source).toContain("0111_tenant_rls_policy_install");
    expect(source).toContain("0112_rls_activation_release_gates");
    expect(source).toContain("0113_personal_tenant_account_lifecycle");
    expect(rpProvenanceSource).toContain(
      'ALTER TABLE "authenticators" ADD COLUMN "rp_id" varchar(253)',
    );
    expect(renderedRpProvenance).toContain(
      'ALTER TABLE "steward"."authenticators" ADD COLUMN "rp_id" varchar(253)',
    );
    expect(renderedRpProvenance).not.toContain('ALTER TABLE "authenticators"');
    expect(rendered).toContain('FROM "steward".tenants');
    expect(rendered).toContain('existing "steward".users%ROWTYPE');
    expect(rendered).not.toContain("public.");
    expect(source).not.toContain("CREATE POLICY");
    expect(source).not.toContain('CREATE SCHEMA IF NOT EXISTS "steward_rls"');

    const expectations = getStewardSchemaMigrationExpectations();
    expect(expectations[0]).toEqual({
      tag: "0000_auth_bootstrap_0111_0113",
      hash: "5d14fb7caea8ce091d16efa1bc64afe08509da2678bbfbd0335b406c263f9344",
      createdAt: 1_787_220_000_001,
      count: 1,
    });
    expect(getStewardSchemaMigrationExpectation()).toMatchObject({
      tag: "0001_passkey_rp_provenance_0114",
      hash: "b14347901c5a2fba9e3b302c0a0754b061423f01733edc46c78aa2d3f9a34d38",
      createdAt: 1_787_529_855_001,
      count: 2,
    });
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
          applied: getStewardSchemaMigrationExpectations().map(({ tag }) => tag),
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

  test("appends 0114 provenance to an existing 0111-0113 marker without rewriting it", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const [bootstrap, rpProvenance] = getStewardSchemaMigrationExpectations();
      if (!bootstrap || !rpProvenance) throw new Error("schema migration fixtures are incomplete");
      await adapter.unsafe(`
        DELETE FROM public.${STEWARD_SCHEMA_MIGRATIONS_TABLE} WHERE migration_order = 2;
        SELECT setval(
          pg_get_serial_sequence('public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}', 'migration_order'),
          1,
          true
        );
        ALTER TABLE public.authenticators DROP COLUMN rp_id;
      `);

      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).resolves.toEqual({ applied: [rpProvenance.tag], schema: "public" });
      const markers = await adapter.unsafe<{
        migration_order: string | number;
        tag: string;
        hash: string;
        created_at: string | number;
      }>(
        `SELECT migration_order, tag, hash, created_at
         FROM public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}
         ORDER BY migration_order`,
      );
      expect(
        markers.map(({ migration_order, tag, hash, created_at }) => ({
          migrationOrder: Number(migration_order),
          tag,
          hash,
          createdAt: Number(created_at),
        })),
      ).toEqual(
        getStewardSchemaMigrationExpectations().map(({ tag, hash, createdAt }, index) => ({
          migrationOrder: index + 1,
          tag,
          hash,
          createdAt,
        })),
      );
      expect(markers[0]).toMatchObject({ tag: bootstrap.tag, hash: bootstrap.hash });
    } finally {
      await client.close();
    }
  });

  test("marks an exact current-schema 0114 column that the core migrator already installed", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await adapter.unsafe('ALTER TABLE public.authenticators ADD COLUMN "rp_id" varchar(253)');
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).resolves.toEqual({
        applied: getStewardSchemaMigrationExpectations().map(({ tag }) => tag),
        schema: "public",
      });
      await assertInstalled(adapter, "public");
    } finally {
      await client.close();
    }
  });

  test("qualifies 0114 to current_schema even when public has a decoy authenticator table", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await adapter.unsafe("CREATE TABLE public.authenticators (id uuid PRIMARY KEY)");
      await createFixture(adapter, "steward");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await assertInstalled(adapter, "steward");
      const publicRpColumn = await adapter.unsafe<{ column_name: string }>(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'authenticators'
          AND column_name = 'rp_id'
      `);
      expect(publicRpColumn).toEqual([]);
    } finally {
      await client.close();
    }
  });

  test("fails closed on an incompatible RP provenance column before recording markers", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await adapter.unsafe(
        "ALTER TABLE public.authenticators ADD COLUMN rp_id text NOT NULL DEFAULT ''",
      );
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("incompatible authenticators.rp_id provenance column");
      const marker = await adapter.unsafe<{ relation: string | null }>(
        `SELECT to_regclass('public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}')::text AS relation`,
      );
      expect(marker).toEqual([{ relation: null }]);
    } finally {
      await client.close();
    }
  });

  test("fails closed when an exact 0114 marker exists without its schema postcondition", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe("ALTER TABLE public.authenticators DROP COLUMN rp_id");
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("RP provenance marker without authenticators.rp_id");
    } finally {
      await client.close();
    }
  });

  test("fails closed when an existing Steward-owned marker hash is not exact", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(
        `UPDATE public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}
         SET hash = '${"0".repeat(64)}'
         WHERE migration_order = 1`,
      );
      await expect(
        runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false }),
      ).rejects.toThrow("exact expected release marker at order 1");
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
        if (schema === "public") {
          await client.unsafe('ALTER TABLE public.authenticators ADD COLUMN "rp_id" varchar(253)');
        }

        await expect(
          runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: true }),
        ).resolves.toEqual({
          applied: getStewardSchemaMigrationExpectations().map(({ tag }) => tag),
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
