import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { redactedThrownDiagnostics } from "@stwd/shared";

import { createPostgresClient } from "./client";

const CORE_MIGRATIONS_FOLDER = new URL("../drizzle", import.meta.url).pathname;
const ADVISORY_LOCK_KEY = "steward_schema_release_migrations";

export const STEWARD_SCHEMA_MIGRATIONS_TABLE = "__steward_release_migrations";
/**
 * Opt-in identifier for a readiness *component*. This marker proves the
 * schema-aware bootstrap migration only; it is not evidence that core
 * migrations 0084-0110 were applied and must not replace that baseline gate.
 */
export const STEWARD_SCHEMA_MIGRATIONS_MODE = "steward-owned";
export const STEWARD_SCHEMA_MIGRATION_STATUS_FUNCTION =
  "steward_bootstrap.release_migration_manifest";

const BOOTSTRAP_START = 'CREATE SCHEMA IF NOT EXISTS "steward_bootstrap";';
const BOOTSTRAP_END = 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA "steward_bootstrap" FROM PUBLIC;';

const REQUIRED_BOOTSTRAP_RELATIONS = [
  "agents",
  "refresh_tokens",
  "session_signers",
  "tenant_app_client_secrets",
  "tenant_app_clients",
  "tenant_configs",
  "tenant_sso_domains",
  "tenants",
  "transactions",
  "user_tenants",
  "users",
] as const;

type UnsafeResultRow = Record<string, unknown>;

export interface StewardSchemaMigrationExecutor {
  unsafe<T extends UnsafeResultRow = UnsafeResultRow>(
    query: string,
    parameters?: unknown[],
  ): Promise<T[]>;
}

export interface StewardSchemaMigrationClient extends StewardSchemaMigrationExecutor {
  begin<T>(callback: (transaction: StewardSchemaMigrationExecutor) => Promise<T>): Promise<T>;
}

export type StewardSchemaMigrationExpectation = {
  tag: string;
  hash: string;
  createdAt: number;
  count: number;
};

export type RunStewardSchemaMigrationsOptions = {
  client?: StewardSchemaMigrationClient;
  useAdvisoryLock?: boolean;
};

type AppliedMarker = {
  migration_order: string | number;
  tag: string;
  hash: string;
  created_at: string | number;
};

const RELEASE_MIGRATION_TAG = "0000_auth_bootstrap_0111_0113";
const RELEASE_MIGRATION_CREATED_AT = 1_787_220_000_001;

let cachedSource: string | undefined;
let cachedExpectation: StewardSchemaMigrationExpectation | undefined;

function readCoreMigration(tag: string): string {
  return readFileSync(`${CORE_MIGRATIONS_FOLDER}/${tag}.sql`, "utf8");
}

/**
 * Compose the final bootstrap-function definitions from the immutable core
 * migrations that introduced and then hardened them. Policy DDL is
 * deliberately excluded: this compatibility migration is additive and does
 * not activate or rewrite the production RLS surface.
 */
export function getStewardSchemaMigrationSource(): string {
  if (cachedSource) return cachedSource;

  const install = readCoreMigration("0111_tenant_rls_policy_install");
  const start = install.indexOf(BOOTSTRAP_START);
  const end = install.indexOf(BOOTSTRAP_END, start);
  if (start < 0 || end < 0) {
    throw new Error("0111 bootstrap migration boundaries are missing");
  }

  const bootstrap = install.slice(start, end + BOOTSTRAP_END.length);
  const defaultTenantHardening = readCoreMigration("0112_rls_activation_release_gates");
  const personalTenantHardening = readCoreMigration("0113_personal_tenant_account_lifecycle");
  cachedSource = [
    `-- source: 0111_tenant_rls_policy_install (bootstrap functions only)\n${bootstrap}`,
    `-- source: 0112_rls_activation_release_gates\n${defaultTenantHardening}`,
    `-- source: 0113_personal_tenant_account_lifecycle\n${personalTenantHardening}`,
  ].join("\n\n");
  return cachedSource;
}

export function getStewardSchemaMigrationExpectation(): StewardSchemaMigrationExpectation {
  if (cachedExpectation) return cachedExpectation;
  const hash = createHash("sha256").update(getStewardSchemaMigrationSource()).digest("hex");
  cachedExpectation = {
    tag: RELEASE_MIGRATION_TAG,
    hash,
    createdAt: RELEASE_MIGRATION_CREATED_AT,
    count: 1,
  };
  return cachedExpectation;
}

function quoteIdentifier(identifier: string): string {
  if (!identifier || identifier.includes("\0")) {
    throw new Error("database schema name is invalid");
  }
  return `"${identifier.replaceAll('"', '""')}"`;
}

/**
 * Replace only schema-qualified references from the canonical public-schema
 * migration. Unqualified bootstrap schemas remain stable API namespaces.
 */
export function renderStewardSchemaMigration(source: string, schema: string): string {
  const quotedSchema = quoteIdentifier(schema);
  return source
    .replaceAll("public.", `${quotedSchema}.`)
    .replaceAll('"public".', `${quotedSchema}.`);
}

function assertSafeDataSchema(schema: string): void {
  if (["drizzle", "information_schema", "pg_catalog", "steward_bootstrap"].includes(schema)) {
    throw new Error(`refusing reserved Steward data schema: ${schema}`);
  }
}

async function resolveDataSchema(transaction: StewardSchemaMigrationExecutor): Promise<string> {
  const rows = await transaction.unsafe<{ schema_name: string | null }>(
    "SELECT current_schema()::text AS schema_name",
  );
  const schema = rows[0]?.schema_name;
  if (!schema) throw new Error("DATABASE_URL search_path resolves to no writable data schema");
  assertSafeDataSchema(schema);
  return schema;
}

async function assertBootstrapRelations(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<void> {
  const relationLiterals = REQUIRED_BOOTSTRAP_RELATIONS.map((relation) => `'${relation}'`).join(
    ", ",
  );
  const rows = await transaction.unsafe<{ relation_name: string }>(
    `
    SELECT relation_name
    FROM unnest(ARRAY[${relationLiterals}]::text[]) AS required(relation_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class relation
      JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = $1::text
        AND relation.relname = required.relation_name
        AND relation.relkind IN ('r', 'p')
    )
    ORDER BY relation_name
  `,
    [schema],
  );
  if (rows.length > 0) {
    throw new Error(
      `Steward schema ${schema} is missing bootstrap prerequisites: ${rows
        .map((row) => row.relation_name)
        .join(", ")}`,
    );
  }
}

function assertAppliedMarkers(
  rows: AppliedMarker[],
  expectation: StewardSchemaMigrationExpectation,
): boolean {
  if (rows.length === 0) return false;
  const first = rows[0];
  if (
    !first ||
    Number(first.migration_order) !== 1 ||
    first.tag !== expectation.tag ||
    first.hash !== expectation.hash ||
    Number(first.created_at) !== expectation.createdAt
  ) {
    throw new Error(
      "Steward-owned migration ledger does not contain the exact expected bootstrap marker",
    );
  }
  // A newer release may append markers. An older image must remain readable
  // after rollback, so a valid exact prefix plus an unknown forward suffix is
  // accepted without rewriting or deleting it.
  let previousCreatedAt = expectation.createdAt;
  for (let index = 1; index < rows.length; index += 1) {
    const row = rows[index];
    const createdAt = Number(row?.created_at);
    if (
      Number(row?.migration_order) !== index + 1 ||
      !row?.tag ||
      !/^[0-9a-f]{64}$/.test(row.hash) ||
      !Number.isSafeInteger(createdAt) ||
      createdAt <= previousCreatedAt
    ) {
      throw new Error("Steward-owned migration ledger has an invalid forward suffix");
    }
    previousCreatedAt = createdAt;
  }
  return true;
}

async function installStatusFunction(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<void> {
  const quotedSchema = quoteIdentifier(schema);
  const quotedTable = quoteIdentifier(STEWARD_SCHEMA_MIGRATIONS_TABLE);
  await transaction.unsafe(`
    CREATE OR REPLACE FUNCTION "steward_bootstrap"."release_migration_manifest"()
    RETURNS TABLE (migration_order bigint, tag text, hash text, created_at bigint)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS $$
      SELECT marker.migration_order, marker.tag, marker.hash, marker.created_at
      FROM ${quotedSchema}.${quotedTable} marker
      ORDER BY marker.migration_order
    $$;
    GRANT EXECUTE ON FUNCTION "steward_bootstrap"."release_migration_manifest"() TO PUBLIC;
    COMMENT ON FUNCTION "steward_bootstrap"."release_migration_manifest"() IS
      'Read-only Steward-owned release migration manifest for readiness checks.';
  `);
}

async function applyInTransaction(
  transaction: StewardSchemaMigrationExecutor,
): Promise<{ applied: string[]; schema: string }> {
  const schema = await resolveDataSchema(transaction);
  await assertBootstrapRelations(transaction, schema);

  const quotedSchema = quoteIdentifier(schema);
  const quotedTable = quoteIdentifier(STEWARD_SCHEMA_MIGRATIONS_TABLE);
  await transaction.unsafe(`
    CREATE TABLE IF NOT EXISTS ${quotedSchema}.${quotedTable} (
      migration_order bigserial PRIMARY KEY,
      tag text NOT NULL UNIQUE,
      hash text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
      created_at bigint NOT NULL,
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )
  `);

  const rows = await transaction.unsafe<AppliedMarker>(`
    SELECT migration_order, tag, hash, created_at
    FROM ${quotedSchema}.${quotedTable}
    ORDER BY migration_order
  `);
  const expectation = getStewardSchemaMigrationExpectation();
  if (assertAppliedMarkers(rows, expectation)) {
    await installStatusFunction(transaction, schema);
    return { applied: [], schema };
  }

  const rendered = renderStewardSchemaMigration(getStewardSchemaMigrationSource(), schema);
  await transaction.unsafe(rendered);
  await transaction.unsafe(
    `INSERT INTO ${quotedSchema}.${quotedTable} (tag, hash, created_at) VALUES ($1, $2, $3)`,
    [expectation.tag, expectation.hash, expectation.createdAt],
  );
  await installStatusFunction(transaction, schema);
  return { applied: [expectation.tag], schema };
}

/**
 * Install the #900 bootstrap function surface against the first schema in the
 * DATABASE_URL search_path. This explicit operator migration never reads or
 * writes drizzle.__drizzle_migrations; its sole provenance is the
 * schema-local __steward_release_migrations ledger. The marker covers only
 * this additive compatibility layer. A release must separately prove the
 * target schema's exact core-migration baseline before enabling it in
 * production readiness.
 */
export async function runStewardSchemaMigrations(
  options: RunStewardSchemaMigrationsOptions = {},
): Promise<{ applied: string[]; schema: string }> {
  const ownsClient = !options.client;
  const client =
    options.client ?? (createPostgresClient() as unknown as StewardSchemaMigrationClient);
  const useAdvisoryLock = options.useAdvisoryLock ?? true;

  try {
    if (useAdvisoryLock) {
      await client.unsafe("SELECT pg_advisory_lock(hashtextextended($1, 0))", [ADVISORY_LOCK_KEY]);
    }
    try {
      return await client.begin((transaction) => applyInTransaction(transaction));
    } finally {
      if (useAdvisoryLock) {
        await client.unsafe("SELECT pg_advisory_unlock(hashtextextended($1, 0))", [
          ADVISORY_LOCK_KEY,
        ]);
      }
    }
  } finally {
    if (ownsClient) {
      await (client as unknown as { end(options?: { timeout?: number }): Promise<void> }).end({
        timeout: 5,
      });
    }
  }
}

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  runStewardSchemaMigrations()
    .then(({ applied, schema }) => {
      if (applied.length === 0) {
        console.log(`[steward-schema-migrate] ${schema} is already up to date.`);
      } else {
        console.log(
          `[steward-schema-migrate] Applied ${applied.join(", ")} to Steward schema ${schema}.`,
        );
      }
    })
    .catch((error) => {
      console.error("Failed to run Steward schema migrations", redactedThrownDiagnostics(error));
      process.exitCode = 1;
    });
}
