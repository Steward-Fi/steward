import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { redactedThrownDiagnostics } from "@stwd/shared";

import { createPostgresClient } from "./client";

const CORE_MIGRATIONS_FOLDER = new URL("../drizzle", import.meta.url).pathname;
const ADVISORY_LOCK_KEY = "steward_schema_release_migrations";

export const STEWARD_SCHEMA_MIGRATIONS_TABLE = "__steward_release_migrations";
/**
 * Opt-in identifier for a readiness *component*. This marker proves the
 * schema-aware bootstrap and additive RP-provenance migrations only; it is
 * not evidence that the core repair range was applied and must not replace
 * that baseline gate.
 */
export const STEWARD_SCHEMA_MIGRATIONS_MODE = "steward-owned";
export const STEWARD_SCHEMA_MIGRATION_STATUS_FUNCTION =
  "steward_bootstrap.release_migration_manifest";

const BOOTSTRAP_START = 'CREATE SCHEMA IF NOT EXISTS "steward_bootstrap";';
const BOOTSTRAP_END = 'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA "steward_bootstrap" FROM PUBLIC;';

const REQUIRED_BOOTSTRAP_RELATIONS = [
  "agents",
  "authenticators",
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

export type StewardSchemaMigrationSchema = "public" | "steward";

export type StewardSchemaMigrationExpectation = {
  tag: string;
  hash: string;
  createdAt: number;
  count: number;
};

export type RunStewardSchemaMigrationsOptions = {
  expectedSchema: StewardSchemaMigrationSchema;
  client?: StewardSchemaMigrationClient;
  useAdvisoryLock?: boolean;
};

export type InspectStewardSchemaMigrationsOptions = {
  expectedSchema: StewardSchemaMigrationSchema;
  client?: StewardSchemaMigrationClient;
};

export type StewardSchemaMigrationInspection = {
  status: "ready";
  schema: string;
  expectedCount: number;
  appliedCount: number;
  forwardCount: number;
  expectedTip: string;
  rpProvenance: true;
};

type AppliedMarker = {
  migration_order: string | number;
  tag: string;
  hash: string;
  created_at: string | number;
};

const BOOTSTRAP_MIGRATION_TAG = "0000_auth_bootstrap_0111_0113";
const BOOTSTRAP_MIGRATION_CREATED_AT = 1_787_220_000_001;
const PASSKEY_RP_PROVENANCE_MIGRATION_TAG = "0001_passkey_rp_provenance_0114";
const PASSKEY_RP_PROVENANCE_MIGRATION_CREATED_AT = 1_787_529_855_001;

let cachedSource: string | undefined;
let cachedRpProvenanceSource: string | undefined;
let cachedExpectations: StewardSchemaMigrationExpectation[] | undefined;

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

/** Return the immutable core migration that added passkey RP provenance. */
export function getStewardPasskeyRpProvenanceMigrationSource(): string {
  if (cachedRpProvenanceSource) return cachedRpProvenanceSource;
  cachedRpProvenanceSource = readCoreMigration("0114_passkey_rp_provenance");
  return cachedRpProvenanceSource;
}

/** Return every schema-owned marker required by this release, in apply order. */
export function getStewardSchemaMigrationExpectations(): StewardSchemaMigrationExpectation[] {
  if (cachedExpectations) return cachedExpectations.map((entry) => ({ ...entry }));
  const sources = [
    {
      tag: BOOTSTRAP_MIGRATION_TAG,
      createdAt: BOOTSTRAP_MIGRATION_CREATED_AT,
      source: getStewardSchemaMigrationSource(),
    },
    {
      tag: PASSKEY_RP_PROVENANCE_MIGRATION_TAG,
      createdAt: PASSKEY_RP_PROVENANCE_MIGRATION_CREATED_AT,
      source: getStewardPasskeyRpProvenanceMigrationSource(),
    },
  ];
  cachedExpectations = sources.map(({ tag, createdAt, source }, index) => ({
    tag,
    hash: createHash("sha256").update(source).digest("hex"),
    createdAt,
    count: index + 1,
  }));
  return cachedExpectations.map((entry) => ({ ...entry }));
}

/** Return the required schema-owned migration tip for readiness diagnostics. */
export function getStewardSchemaMigrationExpectation(): StewardSchemaMigrationExpectation {
  const expectations = getStewardSchemaMigrationExpectations();
  const tip = expectations.at(-1);
  if (!tip) throw new Error("Steward schema migration manifest is empty");
  return { ...tip, count: expectations.length };
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
    .replaceAll('"public".', `${quotedSchema}.`)
    .replaceAll('ALTER TABLE "authenticators"', `ALTER TABLE ${quotedSchema}."authenticators"`);
}

function assertSafeDataSchema(schema: string): void {
  if (["drizzle", "information_schema", "pg_catalog", "steward_bootstrap"].includes(schema)) {
    throw new Error(`refusing reserved Steward data schema: ${schema}`);
  }
}

async function resolveDataSchema(
  transaction: StewardSchemaMigrationExecutor,
  expectedSchema: StewardSchemaMigrationSchema,
): Promise<StewardSchemaMigrationSchema> {
  const rows = await transaction.unsafe<{
    schema_name: string | null;
    schema_owner: string | null;
    runtime_role: string;
    runtime_owns_schema: boolean;
  }>(`
    SELECT
      namespace.nspname::text AS schema_name,
      pg_catalog.pg_get_userbyid(namespace.nspowner)::text AS schema_owner,
      current_user::text AS runtime_role,
      pg_catalog.pg_has_role(current_user, namespace.nspowner, 'USAGE') AS runtime_owns_schema
    FROM pg_catalog.pg_namespace namespace
    WHERE namespace.nspname = pg_catalog.current_schema()
  `);
  const schema = rows[0]?.schema_name;
  if (!schema) throw new Error("DATABASE_URL search_path resolves to no writable data schema");
  assertSafeDataSchema(schema);
  if (schema !== expectedSchema) {
    throw new Error(
      `DATABASE_URL search_path resolves to ${schema}, expected Steward schema ${expectedSchema}`,
    );
  }
  if (rows[0]?.runtime_owns_schema !== true) {
    throw new Error(
      `Steward schema ${schema} must be inspected and migrated by its owner or an explicit member of the owner role`,
    );
  }
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

function validateAppliedMarkers(
  rows: AppliedMarker[],
  expectations: StewardSchemaMigrationExpectation[],
): number {
  if (rows.length === 0) return 0;
  let previousCreatedAt = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    const createdAt = Number(row?.created_at);
    if (
      Number(row?.migration_order) !== index + 1 ||
      !row?.tag ||
      !/^[a-z0-9_]+$/.test(row.tag) ||
      !/^[0-9a-f]{64}$/.test(row.hash) ||
      !Number.isSafeInteger(createdAt) ||
      createdAt <= previousCreatedAt
    ) {
      throw new Error("Steward-owned migration ledger has an invalid forward suffix");
    }
    const expected = expectations[index];
    if (
      expected &&
      (row.tag !== expected.tag || row.hash !== expected.hash || createdAt !== expected.createdAt)
    ) {
      throw new Error(
        `Steward-owned migration ledger does not contain the exact expected release marker at order ${index + 1}`,
      );
    }
    previousCreatedAt = createdAt;
  }
  return Math.min(rows.length, expectations.length);
}

type RpProvenanceColumn = {
  data_type: string;
  character_maximum_length: string | number | null;
  is_nullable: string;
  column_default: string | null;
};

type BootstrapFunctionCatalogRow = {
  function_name: string;
  identity_arguments: string;
  function_arguments: string;
  result_type: string;
  owner_name: string;
  runtime_role: string;
  language_name: string;
  volatility: string;
  security_definer: boolean;
  configuration: string;
  source: string;
  public_execute: boolean;
  unexpected_execute_grant: boolean;
  bootstrap_schema_owner: string;
  public_schema_usage: boolean;
  unexpected_schema_grant: boolean;
};

type ExpectedBootstrapFunction = {
  identityArguments: string;
  functionArguments: string;
  resultType: string;
  language: "sql" | "plpgsql";
  volatility: "s" | "v";
  source: string;
};

function normalizeFunctionSource(source: string): string {
  return source.replaceAll("\r\n", "\n").trim();
}

function normalizeFunctionDeclaration(source: string): string {
  return source
    .trim()
    .replace(/\s+DEFAULT\s+NULL(?:::[a-z_][a-z0-9_]*(?:\[\])?)?/gi, " DEFAULT NULL")
    .replace(/\bvarchar\(\d+\)/gi, "character varying")
    .replace(/\btimestamptz\b/gi, "timestamp with time zone")
    .replace(/\s+/g, " ")
    .replace(/\s*,\s*/g, ", ")
    .replace(/\bTABLE\s+\(/gi, "TABLE(")
    .replace(/\(\s+/g, "(")
    .replace(/\s+\)/g, ")");
}

function normalizeFunctionIdentityArguments(source: string): string {
  return normalizeFunctionDeclaration(source).replace(/\s+DEFAULT\s+NULL/gi, "");
}

function getExpectedBootstrapFunctions(schema: string): Map<string, ExpectedBootstrapFunction> {
  const rendered = renderStewardSchemaMigration(getStewardSchemaMigrationSource(), schema);
  const functions = new Map<string, ExpectedBootstrapFunction>();
  const pattern =
    /CREATE OR REPLACE FUNCTION\s+"steward_bootstrap"\."([^"]+)"\s*\(([\s\S]*?)\)\s*RETURNS\s+([\s\S]*?)\nLANGUAGE\s+(sql|plpgsql)\s*\n(STABLE|VOLATILE)\s*\nSECURITY DEFINER\s*\nSET search_path = pg_catalog\s*\nAS \$\$([\s\S]*?)\$\$;/g;
  for (const match of rendered.matchAll(pattern)) {
    const [, name, identityArguments, resultType, language, volatility, source] = match;
    if (
      !name ||
      identityArguments === undefined ||
      !resultType ||
      !language ||
      !volatility ||
      source === undefined
    ) {
      throw new Error("Steward bootstrap function source is malformed");
    }
    functions.set(name, {
      identityArguments: normalizeFunctionIdentityArguments(identityArguments),
      functionArguments: normalizeFunctionDeclaration(identityArguments),
      resultType: normalizeFunctionDeclaration(resultType),
      language: language as "sql" | "plpgsql",
      volatility: volatility === "STABLE" ? "s" : "v",
      source: normalizeFunctionSource(source),
    });
  }
  if (functions.size !== 23) {
    throw new Error("Steward bootstrap function manifest is incomplete");
  }
  return functions;
}

function releaseMigrationManifestBody(schema: string): string {
  const quotedSchema = quoteIdentifier(schema);
  const quotedTable = quoteIdentifier(STEWARD_SCHEMA_MIGRATIONS_TABLE);
  return `
      SELECT marker.migration_order, marker.tag, marker.hash, marker.created_at
      FROM ${quotedSchema}.${quotedTable} marker
      ORDER BY marker.migration_order
    `;
}

async function assertBootstrapFunctionCatalog(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<void> {
  const rows = await transaction.unsafe<BootstrapFunctionCatalogRow>(`
    SELECT
      procedure.proname AS function_name,
      pg_catalog.pg_get_function_identity_arguments(procedure.oid) AS identity_arguments,
      pg_catalog.pg_get_function_arguments(procedure.oid) AS function_arguments,
      pg_catalog.pg_get_function_result(procedure.oid) AS result_type,
      pg_catalog.pg_get_userbyid(procedure.proowner)::text AS owner_name,
      current_user::text AS runtime_role,
      language.lanname AS language_name,
      procedure.provolatile::text AS volatility,
      procedure.prosecdef AS security_definer,
      COALESCE(array_to_string(procedure.proconfig, ','), '') AS configuration,
      procedure.prosrc AS source,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
        ) AS function_acl
        WHERE function_acl.grantee = 0
          AND function_acl.privilege_type = 'EXECUTE'
      ) AS public_execute,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
        ) AS function_acl
        WHERE function_acl.grantee NOT IN (0, procedure.proowner)
          AND function_acl.privilege_type = 'EXECUTE'
      ) AS unexpected_execute_grant,
      pg_catalog.pg_get_userbyid(namespace.nspowner)::text AS bootstrap_schema_owner,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) AS schema_acl
        WHERE schema_acl.grantee = 0
          AND schema_acl.privilege_type = 'USAGE'
      ) AS public_schema_usage,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
        ) AS schema_acl
        WHERE schema_acl.grantee NOT IN (0, namespace.nspowner)
      ) AS unexpected_schema_grant
    FROM pg_catalog.pg_proc procedure
    JOIN pg_catalog.pg_namespace namespace ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_language language ON language.oid = procedure.prolang
    WHERE namespace.nspname = 'steward_bootstrap'
    ORDER BY procedure.proname, procedure.oid
  `);
  const expected = getExpectedBootstrapFunctions(schema);
  const allowedNames = new Set([...expected.keys(), "release_migration_manifest"]);
  if (rows.some((row) => !allowedNames.has(row.function_name))) {
    throw new Error("Steward bootstrap function catalog contains unexpected routines");
  }
  for (const [name, functionExpectation] of expected) {
    const matches = rows.filter((row) => row.function_name === name);
    const actual = matches[0];
    const mismatch =
      matches.length !== 1 || !actual
        ? "identity"
        : normalizeFunctionDeclaration(actual.identity_arguments) !==
            functionExpectation.identityArguments
          ? "arguments"
          : normalizeFunctionDeclaration(actual.function_arguments) !==
              functionExpectation.functionArguments
            ? "argument defaults"
            : normalizeFunctionDeclaration(actual.result_type) !== functionExpectation.resultType
              ? "result"
              : actual.language_name !== functionExpectation.language
                ? "language"
                : actual.volatility !== functionExpectation.volatility
                  ? "volatility"
                  : actual.security_definer !== true
                    ? "security"
                    : actual.configuration !== "search_path=pg_catalog"
                      ? "search path"
                      : normalizeFunctionSource(actual.source) !== functionExpectation.source
                        ? "source"
                        : actual.public_execute
                          ? "ACL"
                          : actual.owner_name !== actual.runtime_role ||
                              actual.bootstrap_schema_owner !== actual.runtime_role
                            ? "owner"
                            : actual.unexpected_execute_grant ||
                                actual.public_schema_usage ||
                                actual.unexpected_schema_grant
                              ? "ACL"
                              : undefined;
    if (mismatch) {
      const resultDetail =
        mismatch === "result" && actual
          ? `: ${normalizeFunctionDeclaration(actual.result_type)} != ${functionExpectation.resultType}`
          : "";
      throw new Error(
        `Steward bootstrap function ${name} does not match the release catalog (${mismatch})${resultDetail}`,
      );
    }
  }

  const statusRows = rows.filter((row) => row.function_name === "release_migration_manifest");
  const status = statusRows[0];
  if (
    statusRows.length !== 1 ||
    !status ||
    status.identity_arguments !== "" ||
    normalizeFunctionDeclaration(status.result_type) !==
      "TABLE(migration_order bigint, tag text, hash text, created_at bigint)" ||
    status.language_name !== "sql" ||
    status.volatility !== "s" ||
    status.security_definer !== true ||
    status.configuration !== "search_path=pg_catalog" ||
    status.public_execute !== false ||
    status.owner_name !== status.runtime_role ||
    status.bootstrap_schema_owner !== status.runtime_role ||
    status.unexpected_execute_grant !== false ||
    status.public_schema_usage !== false ||
    status.unexpected_schema_grant !== false ||
    normalizeFunctionSource(status.source) !==
      normalizeFunctionSource(releaseMigrationManifestBody(schema))
  ) {
    throw new Error("Steward release migration status function does not match the release catalog");
  }
}

async function rpProvenanceColumnExists(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<boolean> {
  const rows = await transaction.unsafe<RpProvenanceColumn>(
    `
    SELECT data_type, character_maximum_length, is_nullable, column_default
    FROM information_schema.columns
    WHERE table_schema = $1::text
      AND table_name = 'authenticators'
      AND column_name = 'rp_id'
  `,
    [schema],
  );
  if (rows.length === 0) return false;
  const column = rows[0];
  if (
    rows.length !== 1 ||
    column?.data_type !== "character varying" ||
    Number(column.character_maximum_length) !== 253 ||
    column.is_nullable !== "YES" ||
    column.column_default !== null
  ) {
    throw new Error(
      `Steward schema ${schema} has an incompatible authenticators.rp_id provenance column`,
    );
  }
  return true;
}

async function applyPasskeyRpProvenanceMigration(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<void> {
  if (!(await rpProvenanceColumnExists(transaction, schema))) {
    await transaction.unsafe(
      renderStewardSchemaMigration(getStewardPasskeyRpProvenanceMigrationSource(), schema),
    );
  }
  if (!(await rpProvenanceColumnExists(transaction, schema))) {
    throw new Error(`Steward schema ${schema} did not install authenticators.rp_id provenance`);
  }
}

async function installStatusFunction(
  transaction: StewardSchemaMigrationExecutor,
  schema: string,
): Promise<void> {
  await transaction.unsafe(`
    CREATE OR REPLACE FUNCTION "steward_bootstrap"."release_migration_manifest"()
    RETURNS TABLE (migration_order bigint, tag text, hash text, created_at bigint)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS $$
      ${releaseMigrationManifestBody(schema)}
    $$;
    REVOKE ALL ON SCHEMA "steward_bootstrap" FROM PUBLIC;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA "steward_bootstrap" FROM PUBLIC;
    COMMENT ON FUNCTION "steward_bootstrap"."release_migration_manifest"() IS
      'Owner-bound read-only Steward release migration manifest for readiness checks.';
  `);
}

async function applyInTransaction(
  transaction: StewardSchemaMigrationExecutor,
  expectedSchema: StewardSchemaMigrationSchema,
  useAdvisoryLock: boolean,
): Promise<{ applied: string[]; schema: string }> {
  if (useAdvisoryLock) {
    const lock = await transaction.unsafe<{ acquired: boolean }>(
      "SELECT pg_catalog.pg_try_advisory_xact_lock(pg_catalog.hashtextextended($1, 0)) AS acquired",
      [ADVISORY_LOCK_KEY],
    );
    if (lock[0]?.acquired !== true) {
      throw new Error("another Steward schema migration already holds the advisory lock");
    }
  }
  const schema = await resolveDataSchema(transaction, expectedSchema);
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
  const expectations = getStewardSchemaMigrationExpectations();
  const appliedExpectedCount = validateAppliedMarkers(rows, expectations);
  if (rows.length >= expectations.length) {
    if (!(await rpProvenanceColumnExists(transaction, schema))) {
      throw new Error(
        `Steward schema ${schema} has an RP provenance marker without authenticators.rp_id`,
      );
    }
    await installStatusFunction(transaction, schema);
    return { applied: [], schema };
  }

  const applied: string[] = [];
  for (let index = appliedExpectedCount; index < expectations.length; index += 1) {
    const expectation = expectations[index];
    if (!expectation) throw new Error(`Steward schema migration ${index} is undefined`);
    if (expectation.tag === BOOTSTRAP_MIGRATION_TAG) {
      await transaction.unsafe(
        renderStewardSchemaMigration(getStewardSchemaMigrationSource(), schema),
      );
    } else if (expectation.tag === PASSKEY_RP_PROVENANCE_MIGRATION_TAG) {
      await applyPasskeyRpProvenanceMigration(transaction, schema);
    } else {
      throw new Error(`Steward schema migration ${expectation.tag} has no installer`);
    }
    const inserted = await transaction.unsafe<{ migration_order: string | number }>(
      `INSERT INTO ${quotedSchema}.${quotedTable} (tag, hash, created_at)
       VALUES ($1, $2, $3)
       RETURNING migration_order`,
      [expectation.tag, expectation.hash, expectation.createdAt],
    );
    if (Number(inserted[0]?.migration_order) !== index + 1) {
      throw new Error("Steward-owned migration ledger sequence is not append-only");
    }
    applied.push(expectation.tag);
  }
  await installStatusFunction(transaction, schema);
  return { applied, schema };
}

async function inspectInTransaction(
  transaction: StewardSchemaMigrationExecutor,
  expectedSchema: StewardSchemaMigrationSchema,
): Promise<StewardSchemaMigrationInspection> {
  await transaction.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await transaction.unsafe("SET LOCAL statement_timeout = '2s'");
  await transaction.unsafe("SET LOCAL idle_in_transaction_session_timeout = '2s'");

  const schema = await resolveDataSchema(transaction, expectedSchema);
  await assertBootstrapRelations(transaction, schema);
  await assertBootstrapFunctionCatalog(transaction, schema);
  const rows = await transaction.unsafe<AppliedMarker>(
    `SELECT migration_order, tag, hash, created_at
     FROM steward_bootstrap.release_migration_manifest()
     ORDER BY migration_order`,
  );
  const expectations = getStewardSchemaMigrationExpectations();
  const appliedExpectedCount = validateAppliedMarkers(rows, expectations);
  if (appliedExpectedCount !== expectations.length || rows.length < expectations.length) {
    throw new Error("Steward-owned schema migrations are behind the required release");
  }
  if (!(await rpProvenanceColumnExists(transaction, schema))) {
    throw new Error(
      `Steward schema ${schema} has an RP provenance marker without authenticators.rp_id`,
    );
  }
  const expectedTip = expectations.at(-1);
  if (!expectedTip) throw new Error("Steward schema migration manifest is empty");
  return {
    status: "ready",
    schema,
    expectedCount: expectations.length,
    appliedCount: rows.length,
    forwardCount: rows.length - expectations.length,
    expectedTip: expectedTip.tag,
    rpProvenance: true,
  };
}

/**
 * Verify the schema-owned auth compatibility surface without consulting the
 * shared Drizzle ledger. The SECURITY DEFINER status function is installed for
 * the owner-bound runtime role to read the exact append-only marker chain; the
 * physical RP-provenance column and bootstrap relation prerequisites are
 * checked independently in the same snapshot. Split app/migrator roles are
 * deliberately rejected until their complete grants are a reviewed contract.
 */
export async function inspectStewardSchemaMigrations(
  options: InspectStewardSchemaMigrationsOptions,
): Promise<StewardSchemaMigrationInspection> {
  const ownsClient = !options.client;
  const client =
    options.client ?? (createPostgresClient() as unknown as StewardSchemaMigrationClient);
  try {
    return await client.begin((transaction) =>
      inspectInTransaction(transaction, options.expectedSchema),
    );
  } finally {
    if (ownsClient) {
      await (client as unknown as { end(options?: { timeout?: number }): Promise<void> }).end({
        timeout: 5,
      });
    }
  }
}

/**
 * Install the #900 bootstrap function surface and #914 passkey RP provenance
 * against the explicitly pinned first schema in the DATABASE_URL search_path.
 * This operator migration never reads or writes drizzle.__drizzle_migrations;
 * its sole provenance is the schema-local __steward_release_migrations ledger.
 * The marker covers only this additive compatibility layer. A release must
 * separately prove the target schema's exact core-migration baseline before
 * enabling it in production readiness.
 */
export async function runStewardSchemaMigrations(
  options: RunStewardSchemaMigrationsOptions,
): Promise<{ applied: string[]; schema: string }> {
  const ownsClient = !options.client;
  const client =
    options.client ?? (createPostgresClient() as unknown as StewardSchemaMigrationClient);
  const useAdvisoryLock = options.useAdvisoryLock ?? true;

  try {
    return await client.begin((transaction) =>
      applyInTransaction(transaction, options.expectedSchema, useAdvisoryLock),
    );
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
  const expectedSchema = process.env.STEWARD_CORE_REPAIR_EXPECTED_SCHEMA;
  if (expectedSchema !== "public" && expectedSchema !== "steward") {
    console.error("STEWARD_CORE_REPAIR_EXPECTED_SCHEMA is required (public or steward)");
    process.exitCode = 1;
  } else {
    runStewardSchemaMigrations({ expectedSchema })
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
}
