import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { PGlite } from "@electric-sql/pglite";
import postgres from "postgres";

import {
  getStewardPasskeyRpProvenanceMigrationSource,
  getStewardSchemaMigrationExpectation,
  getStewardSchemaMigrationExpectations,
  getStewardSchemaMigrationSource,
  type InspectStewardSchemaMigrationsOptions,
  inspectStewardSchemaMigrations as inspectStewardSchemaMigrationsRaw,
  type RunStewardSchemaMigrationsOptions,
  renderStewardSchemaMigration,
  runStewardSchemaMigrations as runStewardSchemaMigrationsRaw,
  STEWARD_SCHEMA_MIGRATIONS_TABLE,
  type StewardSchemaMigrationClient,
  type StewardSchemaMigrationExecutor,
  type StewardSchemaMigrationSchema,
} from "../steward-schema-migrations";

setDefaultTimeout(180_000);

type TestRunOptions = Omit<RunStewardSchemaMigrationsOptions, "expectedSchema"> & {
  expectedSchema?: StewardSchemaMigrationSchema;
};

type TestInspectOptions = Omit<InspectStewardSchemaMigrationsOptions, "expectedSchema"> & {
  expectedSchema?: StewardSchemaMigrationSchema;
};

function runStewardSchemaMigrations(options: TestRunOptions) {
  return runStewardSchemaMigrationsRaw({
    ...options,
    expectedSchema: options.expectedSchema ?? "public",
  });
}

function inspectStewardSchemaMigrations(options: TestInspectOptions) {
  return inspectStewardSchemaMigrationsRaw({
    ...options,
    expectedSchema: options.expectedSchema ?? "public",
  });
}

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

async function getBootstrapFunctionDefinition(
  executor: StewardSchemaMigrationExecutor,
  name: string,
): Promise<string> {
  const rows = await executor.unsafe<{ definition: string }>(
    `
      SELECT pg_get_functiondef(procedure.oid) AS definition
      FROM pg_proc procedure
      JOIN pg_namespace namespace ON namespace.oid = procedure.pronamespace
      WHERE namespace.nspname = 'steward_bootstrap'
        AND procedure.proname = $1::text
      ORDER BY procedure.oid
    `,
    [name],
  );
  if (rows.length !== 1 || !rows[0]?.definition) {
    throw new Error(`expected one bootstrap function definition for ${name}`);
  }
  return rows[0].definition;
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
          expectedSchema: schema,
          useAdvisoryLock: false,
        });
        expect(first).toEqual({
          applied: getStewardSchemaMigrationExpectations().map(({ tag }) => tag),
          schema,
        });
        await assertInstalled(adapter, schema);

        const inspection = await inspectStewardSchemaMigrations({
          client: adapter,
          expectedSchema: schema,
        });
        expect(inspection).toEqual({
          status: "ready",
          schema,
          expectedCount: 2,
          appliedCount: 2,
          forwardCount: 0,
          expectedTip: "0001_passkey_rp_provenance_0114",
          rpProvenance: true,
        });

        const second = await runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: schema,
          useAdvisoryLock: false,
        });
        expect(second).toEqual({ applied: [], schema });
        await assertInstalled(adapter, schema);
      } finally {
        await client.close();
      }
    });
  }

  test("readiness rejects a redefined auth bootstrap function with intact markers", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(`
        CREATE OR REPLACE FUNCTION steward_bootstrap.auth_tenant_config_subject(p_tenant_id text)
        RETURNS TABLE (
          auth_abuse_config jsonb, allowed_origins text[], email_config jsonb,
          oidc_providers jsonb, test_account jsonb, allowed_redirect_urls text[]
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$
          SELECT
            c.auth_abuse_config, c.allowed_origins, c.email_config,
            c.oidc_providers, c.test_account, c.allowed_redirect_urls
          FROM public.tenant_configs c
          WHERE false
        $$
      `);
      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /auth_tenant_config_subject.*source/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects an implicit PUBLIC grant on a recreated definer function", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const definition = await getBootstrapFunctionDefinition(
        adapter,
        "auth_tenant_config_subject",
      );
      await adapter.unsafe("DROP FUNCTION steward_bootstrap.auth_tenant_config_subject(text)");
      await adapter.unsafe(definition);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /auth_tenant_config_subject.*ACL/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects an unexpected bootstrap routine", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(`
        CREATE FUNCTION steward_bootstrap.unreviewed_release_helper()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$ SELECT true $$;
        REVOKE ALL ON FUNCTION steward_bootstrap.unreviewed_release_helper() FROM PUBLIC;
      `);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        "bootstrap function catalog contains unexpected routines",
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects PUBLIC access to the owner-bound bootstrap schema", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe("GRANT USAGE ON SCHEMA steward_bootstrap TO PUBLIC");

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(/ACL/);
    } finally {
      await client.close();
    }
  });

  test("readiness rejects an unreviewed third-party function grant", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(`
        CREATE ROLE steward_unreviewed_reader;
        GRANT EXECUTE ON FUNCTION steward_bootstrap.auth_tenant_config_subject(text)
          TO steward_unreviewed_reader;
      `);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /auth_tenant_config_subject.*ACL/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects PUBLIC execution of the release manifest", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(
        "GRANT EXECUTE ON FUNCTION steward_bootstrap.release_migration_manifest() TO PUBLIC",
      );

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /status function does not match/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects changed bootstrap argument defaults", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const definition = await getBootstrapFunctionDefinition(adapter, "auth_tenant_subject");
      const rebound = definition.replace(
        /DEFAULT\s+NULL(?:::[a-z_][a-z0-9_]*)?/i,
        "DEFAULT '00000000-0000-4000-8000-000000000099'::uuid",
      );
      expect(rebound).not.toBe(definition);
      await adapter.unsafe(rebound);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /auth_tenant_subject.*argument defaults/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects changed bootstrap input signatures and overloads", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const definition = await getBootstrapFunctionDefinition(adapter, "tenant_api_key_subject");
      const rebound = definition.replace("p_tenant_id text", "p_tenant_id character varying");
      expect(rebound).not.toBe(definition);
      await adapter.unsafe("DROP FUNCTION steward_bootstrap.tenant_api_key_subject(text)");
      await adapter.unsafe(rebound);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /tenant_api_key_subject.*arguments/,
      );

      await adapter.unsafe(`
        CREATE FUNCTION steward_bootstrap.tenant_api_key_subject(p_tenant_id integer)
        RETURNS TABLE (tenant_id varchar(64), api_key_hash text)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$ SELECT NULL::varchar(64), NULL::text WHERE false $$
      `);
      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /tenant_api_key_subject.*identity/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects changed bootstrap result signatures", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      const definition = await getBootstrapFunctionDefinition(adapter, "tenant_api_key_subject");
      const rebound = definition.replace("id character varying", "resolved_id character varying");
      expect(rebound).not.toBe(definition);
      await adapter.unsafe("DROP FUNCTION steward_bootstrap.tenant_api_key_subject(text)");
      await adapter.unsafe(rebound);

      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /tenant_api_key_subject.*result/,
      );
    } finally {
      await client.close();
    }
  });

  test("readiness rejects a rebound release manifest with intact marker rows", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "public");
      await runStewardSchemaMigrations({ client: adapter, useAdvisoryLock: false });
      await adapter.unsafe(`
        CREATE OR REPLACE FUNCTION steward_bootstrap.release_migration_manifest()
        RETURNS TABLE (migration_order bigint, tag text, hash text, created_at bigint)
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$
          SELECT marker.migration_order, marker.tag, marker.hash, marker.created_at
          FROM public.${STEWARD_SCHEMA_MIGRATIONS_TABLE} marker
          WHERE false
          ORDER BY marker.migration_order
        $$
      `);
      await expect(inspectStewardSchemaMigrations({ client: adapter })).rejects.toThrow(
        /status function does not match/,
      );
    } finally {
      await client.close();
    }
  });

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
      await runStewardSchemaMigrations({
        client: adapter,
        expectedSchema: "steward",
        useAdvisoryLock: false,
      });
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

  test("fails before mutation when current_schema does not match the pinned target", async () => {
    const client = new PGlite("memory://");
    const adapter = pgliteAdapter(client);
    try {
      await createFixture(adapter, "steward");
      await expect(
        runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: "public",
          useAdvisoryLock: false,
        }),
      ).rejects.toThrow("search_path resolves to steward, expected Steward schema public");
      const marker = await adapter.unsafe<{ relation: string | null }>(
        `SELECT to_regclass('steward.${STEWARD_SCHEMA_MIGRATIONS_TABLE}')::text AS relation`,
      );
      expect(marker).toEqual([{ relation: null }]);
    } finally {
      await client.close();
    }
  });

  test("uses a transaction-scoped advisory lock and fails closed on contention", async () => {
    const queries: string[] = [];
    const executor: StewardSchemaMigrationExecutor = {
      async unsafe<T extends Record<string, unknown>>(query: string) {
        queries.push(query);
        if (query.includes("pg_try_advisory_xact_lock")) {
          return [{ acquired: false }] as T[];
        }
        throw new Error("migration continued after advisory lock contention");
      },
    };
    const client: StewardSchemaMigrationClient = {
      ...executor,
      async begin<T>(callback: (transaction: StewardSchemaMigrationExecutor) => Promise<T>) {
        return callback(executor);
      },
    };

    await expect(
      runStewardSchemaMigrationsRaw({ client, expectedSchema: "public" }),
    ).rejects.toThrow("another Steward schema migration already holds the advisory lock");
    expect(queries).toHaveLength(1);
    expect(queries[0]).toContain("pg_try_advisory_xact_lock");
    expect(queries[0]).not.toContain("pg_advisory_lock(");
  });
});

const postgresUrl = process.env.DATABASE_URL;
const postgresDescribe = postgresUrl ? describe : describe.skip;
const postgresDatabases: string[] = [];
const postgresRoles: string[] = [];

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
    for (const role of postgresRoles) {
      await admin.unsafe(`DROP ROLE IF EXISTS "${role}"`);
    }
    await admin.end();
  });

  test("does not let a search-path function shadow pg_catalog.current_schema", async () => {
    const database = `steward_schema_shadow_${randomUUID().replaceAll("-", "")}`;
    postgresDatabases.push(database);
    await admin.unsafe(`CREATE DATABASE "${database}"`);

    const targetUrl = new URL(originalUrl);
    targetUrl.pathname = `/${database}`;
    targetUrl.searchParams.set("options", "-c search_path=shadow_test,public,pg_catalog");
    const client = postgres(targetUrl.toString(), { max: 1, prepare: false });
    const adapter = client as unknown as StewardSchemaMigrationClient;
    try {
      await client.unsafe(`
        CREATE SCHEMA shadow_test;
        CREATE FUNCTION shadow_test.current_schema()
        RETURNS name
        LANGUAGE sql
        IMMUTABLE
        AS $$ SELECT 'public'::name $$;
      `);
      await createFixture(adapter, "public");

      await expect(
        runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: "public",
          useAdvisoryLock: false,
        }),
      ).rejects.toThrow(
        "DATABASE_URL search_path resolves to shadow_test, expected Steward schema public",
      );
      const rows = await client.unsafe<{ relation_name: string | null }[]>(
        "SELECT pg_catalog.to_regclass('public.__steward_release_migrations')::text AS relation_name",
      );
      expect(rows).toEqual([{ relation_name: null }]);
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects unsafe default function grants and rolls the migration back", async () => {
    const database = `steward_schema_acl_${randomUUID().replaceAll("-", "")}`;
    const unreviewedRole = `steward_default_exec_${randomUUID().replaceAll("-", "")}`;
    postgresDatabases.push(database);
    postgresRoles.push(unreviewedRole);
    await admin.unsafe(`CREATE ROLE "${unreviewedRole}"`);
    await admin.unsafe(`CREATE DATABASE "${database}"`);

    const targetUrl = new URL(originalUrl);
    targetUrl.pathname = `/${database}`;
    targetUrl.searchParams.set("options", "-c search_path=public");
    const client = postgres(targetUrl.toString(), { max: 1, prepare: false });
    const adapter = client as unknown as StewardSchemaMigrationClient;
    try {
      await createFixture(adapter, "public");
      await client.unsafe(
        `ALTER DEFAULT PRIVILEGES GRANT EXECUTE ON FUNCTIONS TO "${unreviewedRole}"`,
      );

      await expect(
        runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: "public",
          useAdvisoryLock: false,
        }),
      ).rejects.toThrow(/Steward bootstrap function .* \(ACL\)/);

      const postcondition = await adapter.unsafe<{
        marker: string | null;
        bootstrap_schema: string | null;
        rp_provenance: boolean;
      }>(`
        SELECT
          pg_catalog.to_regclass('public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}')::text AS marker,
          pg_catalog.to_regnamespace('steward_bootstrap')::text AS bootstrap_schema,
          EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'authenticators'
              AND column_name = 'rp_id'
          ) AS rp_provenance
      `);
      expect(postcondition).toEqual([
        { marker: null, bootstrap_schema: null, rp_provenance: false },
      ]);
    } finally {
      await client.end({ timeout: 5 });
    }
  });

  test("rejects unsafe default marker-table grants and rolls the migration back", async () => {
    const database = `steward_schema_table_acl_${randomUUID().replaceAll("-", "")}`;
    const unreviewedRole = `steward_default_table_${randomUUID().replaceAll("-", "")}`;
    postgresDatabases.push(database);
    postgresRoles.push(unreviewedRole);
    await admin.unsafe(`CREATE ROLE "${unreviewedRole}"`);
    await admin.unsafe(`CREATE DATABASE "${database}"`);

    const targetUrl = new URL(originalUrl);
    targetUrl.pathname = `/${database}`;
    targetUrl.searchParams.set("options", "-c search_path=public");
    const client = postgres(targetUrl.toString(), { max: 1, prepare: false });
    const adapter = client as unknown as StewardSchemaMigrationClient;
    try {
      await createFixture(adapter, "public");
      await client.unsafe(`
        ALTER DEFAULT PRIVILEGES
        GRANT INSERT, UPDATE, DELETE, TRIGGER ON TABLES TO "${unreviewedRole}"
      `);

      await expect(
        runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: "public",
          useAdvisoryLock: false,
        }),
      ).rejects.toThrow("Steward release migration marker in public grants unsafe privileges");

      const postcondition = await adapter.unsafe<{
        marker: string | null;
        bootstrap_schema: string | null;
        rp_provenance: boolean;
      }>(`
        SELECT
          pg_catalog.to_regclass('public.${STEWARD_SCHEMA_MIGRATIONS_TABLE}')::text AS marker,
          pg_catalog.to_regnamespace('steward_bootstrap')::text AS bootstrap_schema,
          EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'authenticators'
              AND column_name = 'rp_id'
          ) AS rp_provenance
      `);
      expect(postcondition).toEqual([
        { marker: null, bootstrap_schema: null, rp_provenance: false },
      ]);
    } finally {
      await client.end({ timeout: 5 });
    }
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
          runStewardSchemaMigrations({
            client: adapter,
            expectedSchema: schema,
            useAdvisoryLock: true,
          }),
        ).resolves.toEqual({
          applied: getStewardSchemaMigrationExpectations().map(({ tag }) => tag),
          schema,
        });
        await assertInstalled(adapter, schema, true);

        await expect(
          inspectStewardSchemaMigrations({ client: adapter, expectedSchema: schema }),
        ).resolves.toEqual({
          status: "ready",
          schema,
          expectedCount: 2,
          appliedCount: 2,
          forwardCount: 0,
          expectedTip: "0001_passkey_rp_provenance_0114",
          rpProvenance: true,
        });

        const splitRuntimeRole = `steward_split_runtime_${randomUUID().replaceAll("-", "")}`;
        postgresRoles.push(splitRuntimeRole);
        await admin.unsafe(`CREATE ROLE "${splitRuntimeRole}"`);
        await client.unsafe(`GRANT USAGE ON SCHEMA "${schema}" TO "${splitRuntimeRole}"`);
        await client.unsafe(`SET ROLE "${splitRuntimeRole}"`);
        try {
          await expect(
            inspectStewardSchemaMigrations({ client: adapter, expectedSchema: schema }),
          ).rejects.toThrow(/owner or an explicit member of the owner role/);
        } finally {
          await client.unsafe("RESET ROLE");
        }

        const sharedRows = await client<
          { hash: string; created_at: string | number }[]
        >`SELECT hash, created_at FROM drizzle.__drizzle_migrations`;
        expect(sharedRows).toEqual([
          { hash: "shared-eliza-sentinel", created_at: "1793072800004" },
        ]);

        await client.unsafe(
          `DELETE FROM "${schema}"."${STEWARD_SCHEMA_MIGRATIONS_TABLE}" WHERE migration_order = 2;
           SELECT setval(
             pg_get_serial_sequence('${schema}.${STEWARD_SCHEMA_MIGRATIONS_TABLE}', 'migration_order'),
             1,
             true
           )`,
        );
        await expect(
          inspectStewardSchemaMigrations({ client: adapter, expectedSchema: schema }),
        ).rejects.toThrow(/behind the required release/);

        await runStewardSchemaMigrations({
          client: adapter,
          expectedSchema: schema,
          useAdvisoryLock: false,
        });
        await client.unsafe(`ALTER TABLE "${schema}".authenticators DROP COLUMN rp_id`);
        await expect(
          inspectStewardSchemaMigrations({ client: adapter, expectedSchema: schema }),
        ).rejects.toThrow(/authenticators\.rp_id/);

        const sharedRowsAfterReadiness = await client<
          { hash: string; created_at: string | number }[]
        >`SELECT hash, created_at FROM drizzle.__drizzle_migrations`;
        expect(sharedRowsAfterReadiness).toEqual([
          { hash: "shared-eliza-sentinel", created_at: "1793072800004" },
        ]);

        const quotedOwner = `steward quoted owner ${randomUUID().replaceAll("-", "").slice(0, 12)}`;
        postgresRoles.push(quotedOwner);
        await admin.unsafe(`CREATE ROLE "${quotedOwner}"`);
        const definition = await getBootstrapFunctionDefinition(
          adapter,
          "auth_tenant_config_subject",
        );
        await client.unsafe("DROP FUNCTION steward_bootstrap.auth_tenant_config_subject(text)");
        await client.unsafe(definition);
        await client.unsafe(
          `ALTER FUNCTION steward_bootstrap.auth_tenant_config_subject(text) OWNER TO "${quotedOwner}"`,
        );
        await client.unsafe(
          "REVOKE ALL ON FUNCTION steward_bootstrap.auth_tenant_config_subject(text) FROM PUBLIC",
        );
        await expect(
          inspectStewardSchemaMigrations({ client: adapter, expectedSchema: schema }),
        ).rejects.toThrow(/auth_tenant_config_subject.*owner/);
      } finally {
        await client.end({ timeout: 5 });
      }
    });
  }
});
