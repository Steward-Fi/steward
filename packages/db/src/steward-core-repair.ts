import { redactedThrownDiagnostics } from "@stwd/shared";
import { createPostgresClient } from "./client";
import catalogManifestJson from "./steward-core-repair-catalog.json";
import {
  assertStewardCoreRepairSchema,
  type LoadedStewardCoreRepairSource,
  loadStewardCoreRepairSources,
  mapStewardCatalog,
  queryStewardCatalog,
  quoteStewardCoreRepairIdentifier,
  STEWARD_CORE_REPAIR_LEDGER,
  STEWARD_CORE_REPAIR_SOURCE_HEAD,
  STEWARD_CORE_REPAIR_VERSION,
  type StewardCatalogRecord,
  type StewardCoreRepairAction,
  type StewardCoreRepairExecutor,
  type StewardCoreRepairSchema,
  sha256,
  splitStewardMigrationStatements,
  stewardCatalogKey,
} from "./steward-core-repair-sources";

const ADVISORY_LOCK_KEY = "steward_prod_core_0082_0110_repair_v1";

type CatalogKey = {
  kind: string;
  objectName: string;
};

type CatalogEnvelope = {
  keyCount: number;
  keys?: CatalogKey[];
  beforeHash: string;
  afterHash: string;
  deltaHash: string;
};

type CatalogDefinitionChange = CatalogKey & {
  before: string[];
  after: string[];
};

type SchemaCatalogManifest = {
  serverVersionNum: string;
  existing0083: CatalogEnvelope;
  changes0082: CatalogEnvelope;
  changes0084To0110: CatalogEnvelope & { semanticFinalCounts: Record<string, number> };
  changes: CatalogEnvelope;
};

type CoreRepairCatalogManifest = {
  manifestVersion: number;
  repairVersion: string;
  sourceHead: string;
  schemas: Record<StewardCoreRepairSchema, SchemaCatalogManifest>;
};

const catalogManifest = catalogManifestJson as CoreRepairCatalogManifest;

export interface StewardCoreRepairTransactionClient extends StewardCoreRepairExecutor {
  begin<T>(callback: (transaction: StewardCoreRepairExecutor) => Promise<T>): Promise<T>;
}

export interface StewardCoreRepairReservedClient extends StewardCoreRepairExecutor {
  release(): void;
}

export interface StewardCoreRepairClient extends StewardCoreRepairTransactionClient {
  reserve(): Promise<StewardCoreRepairReservedClient>;
  end(options?: { timeout?: number }): Promise<void>;
}

export type StewardCoreRepairPreflight = {
  executionReadyWithoutPolicyEvidence: number;
  externalCustodyNoncesWithoutIdentityDigest: number;
  googleOperationsNeedingRiskUpgrade: number;
  evmNonceNamespaces: number;
  unresolvedEvmNonceNamespaces: number;
};

export type RunStewardCoreRepairOptions = {
  expectedSchema: StewardCoreRepairSchema;
  client?: StewardCoreRepairClient;
  useAdvisoryLock?: boolean;
};

export type StewardCoreRepairResult = {
  status: "applied" | "already_applied";
  schema: StewardCoreRepairSchema;
  bundleHash: string;
  applied: string[];
  verifiedExisting: string[];
  preflight: StewardCoreRepairPreflight | null;
};

export type StewardCoreRepairInspection = {
  status: "eligible" | "already_applied";
  schema: StewardCoreRepairSchema;
  bundleHash: string;
  verifiedExisting: string[];
  preflight: StewardCoreRepairPreflight | null;
};

type LedgerRow = {
  migration_order: string | number;
  tag: string;
  action: StewardCoreRepairAction;
  source_hash: string;
  rendered_hash: string;
  target_schema: string;
  repair_version: string;
  source_head: string;
  bundle_hash: string;
};

type CapturedOutcome<T> = { ok: true; value: T } | { ok: false; error: unknown };

class ReservedTransactionCleanupError extends AggregateError {}

async function captureOutcome<T>(operation: () => Promise<T>): Promise<CapturedOutcome<T>> {
  try {
    return { ok: true, value: await operation() };
  } catch (error) {
    return { ok: false, error };
  }
}

async function runReservedTransaction<T>(
  connection: StewardCoreRepairExecutor,
  operation: (transaction: StewardCoreRepairExecutor) => Promise<T>,
): Promise<T> {
  const begin = await captureOutcome(async () => {
    await connection.unsafe("BEGIN");
  });
  if (!begin.ok) {
    const rollback = await captureOutcome(async () => {
      await connection.unsafe("ROLLBACK");
    });
    if (!rollback.ok) {
      throw new ReservedTransactionCleanupError(
        [begin.error, rollback.error],
        "core-repair transaction start was uncertain and could not be rolled back",
      );
    }
    throw begin.error;
  }
  const result = await captureOutcome(() => operation(connection));
  if (result.ok) {
    const commit = await captureOutcome(async () => {
      await connection.unsafe("COMMIT");
    });
    if (commit.ok) return result.value;

    const rollback = await captureOutcome(async () => {
      await connection.unsafe("ROLLBACK");
    });
    if (!rollback.ok) {
      throw new ReservedTransactionCleanupError(
        [commit.error, rollback.error],
        "core-repair commit failed and its reserved transaction could not be rolled back",
      );
    }
    throw commit.error;
  }

  const rollback = await captureOutcome(async () => {
    await connection.unsafe("ROLLBACK");
  });
  if (!rollback.ok) {
    throw new ReservedTransactionCleanupError(
      [result.error, rollback.error],
      "core repair failed and its reserved transaction could not be rolled back",
    );
  }
  throw result.error;
}

function getSchemaManifest(schema: StewardCoreRepairSchema): SchemaCatalogManifest {
  if (
    catalogManifest.manifestVersion !== 1 ||
    catalogManifest.repairVersion !== STEWARD_CORE_REPAIR_VERSION ||
    catalogManifest.sourceHead !== STEWARD_CORE_REPAIR_SOURCE_HEAD
  ) {
    throw new Error("core-repair catalog manifest metadata does not match the reviewed bundle");
  }
  const manifest = catalogManifest.schemas[schema];
  if (
    !manifest ||
    manifest.changes.keyCount === 0 ||
    manifest.changes.keys?.length !== manifest.changes.keyCount ||
    manifest.existing0083.keyCount === 0 ||
    manifest.existing0083.keys?.length !== manifest.existing0083.keyCount ||
    manifest.changes0082.keyCount === 0 ||
    manifest.changes0084To0110.keyCount === 0
  ) {
    throw new Error(`core-repair catalog manifest for ${schema} is missing or empty`);
  }
  return manifest;
}

async function assertCatalogPostgresMajor(
  transaction: StewardCoreRepairExecutor,
  manifest: SchemaCatalogManifest,
): Promise<void> {
  const rows = await transaction.unsafe<{ server_version_num: string }>("SHOW server_version_num");
  const actual = Number(rows[0]?.server_version_num);
  const generated = Number(manifest.serverVersionNum);
  if (
    !Number.isSafeInteger(actual) ||
    !Number.isSafeInteger(generated) ||
    Math.trunc(actual / 10_000) !== Math.trunc(generated / 10_000)
  ) {
    throw new Error(
      `core-repair catalog manifest was generated for PostgreSQL ${Math.trunc(generated / 10_000)}; ` +
        `resolved server major is ${Math.trunc(actual / 10_000)}; regenerate and review before repair`,
    );
  }
}

function getBundleHash(
  schema: StewardCoreRepairSchema,
  sources: LoadedStewardCoreRepairSource[],
  manifest: SchemaCatalogManifest,
): string {
  return sha256(
    JSON.stringify({
      repairVersion: STEWARD_CORE_REPAIR_VERSION,
      sourceHead: STEWARD_CORE_REPAIR_SOURCE_HEAD,
      schema,
      sources: sources.map(({ order, tag, action, sourceHash, renderedHash }) => ({
        order,
        tag,
        action,
        sourceHash,
        renderedHash,
      })),
      existing0083: manifest.existing0083,
      changes: manifest.changes,
    }),
  );
}

function catalogPhaseHash(
  catalog: Map<string, StewardCatalogRecord[]>,
  keys: CatalogKey[],
): string {
  const phase = keys.map((key) => ({
    ...key,
    definitions: (catalog.get(stewardCatalogKey(key)) ?? []).map((record) => record.definition),
  }));
  return sha256(JSON.stringify(phase));
}

function assertCatalogPhase(
  records: StewardCatalogRecord[],
  envelope: CatalogEnvelope,
  phase: "before" | "after",
  label: string,
): void {
  const keys = envelope.keys;
  if (!keys || keys.length !== envelope.keyCount) {
    throw new Error(`${label} catalog envelope does not contain its reviewed keys`);
  }
  const catalog = mapStewardCatalog(records);
  const actualHash = catalogPhaseHash(catalog, keys);
  const expectedHash = phase === "before" ? envelope.beforeHash : envelope.afterHash;
  if (actualHash !== expectedHash) {
    throw new Error(`${label} exact catalog envelope mismatch; refusing repair`);
  }
}

function diffCatalog(
  before: StewardCatalogRecord[],
  after: StewardCatalogRecord[],
): CatalogDefinitionChange[] {
  const beforeMap = mapStewardCatalog(before);
  const afterMap = mapStewardCatalog(after);
  const keys = [...new Set([...beforeMap.keys(), ...afterMap.keys()])].sort();
  const changes: CatalogDefinitionChange[] = [];
  for (const key of keys) {
    const beforeRecords = beforeMap.get(key) ?? [];
    const afterRecords = afterMap.get(key) ?? [];
    const beforeDefinitions = beforeRecords.map((record) => record.definition);
    const afterDefinitions = afterRecords.map((record) => record.definition);
    if (JSON.stringify(beforeDefinitions) === JSON.stringify(afterDefinitions)) continue;
    const record = afterRecords[0] ?? beforeRecords[0];
    if (!record) throw new Error(`catalog records vanished for key ${key}`);
    changes.push({
      kind: record.kind,
      objectName: record.objectName,
      before: beforeDefinitions,
      after: afterDefinitions,
    });
  }
  return changes;
}

function assertExactCatalogDelta(
  before: StewardCatalogRecord[],
  after: StewardCatalogRecord[],
  expected: CatalogEnvelope,
): void {
  const actual = diffCatalog(before, after);
  const actualHash = sha256(JSON.stringify(actual));
  if (actual.length !== expected.keyCount || actualHash !== expected.deltaHash) {
    const actualKeys = new Set(actual.map((record) => stewardCatalogKey(record)));
    const expectedKeys = new Set((expected.keys ?? []).map((record) => stewardCatalogKey(record)));
    const unexpected = [...actualKeys].filter((key) => !expectedKeys.has(key));
    const missing = [...expectedKeys].filter((key) => !actualKeys.has(key));
    throw new Error(
      `core repair produced an unexpected catalog delta ` +
        `(unexpected=${unexpected.length}, missing=${missing.length}); transaction will roll back`,
    );
  }
}

async function resolveTargetSchema(
  transaction: StewardCoreRepairExecutor,
  expectedSchema: StewardCoreRepairSchema,
): Promise<StewardCoreRepairSchema> {
  const rows = await transaction.unsafe<{ schema_name: string | null }>(
    "SELECT pg_catalog.current_schema()::text AS schema_name",
  );
  const schema = rows[0]?.schema_name;
  if (!schema) throw new Error("DATABASE_URL search_path resolves to no target schema");
  assertStewardCoreRepairSchema(schema);
  if (schema !== expectedSchema) {
    throw new Error(
      `core-repair target schema mismatch: expected ${expectedSchema}, resolved ${schema}`,
    );
  }
  return schema;
}

type RepairSchemaTrustRow = {
  runtime_owns_schema: boolean;
  unexpected_create_grant: boolean;
  unexpected_relation_grant: boolean;
  unexpected_column_grant: boolean;
  unexpected_function_grant: boolean;
  unowned_relation_count: string | number;
  unowned_function_count: string | number;
  unowned_type_count: string | number;
};

/**
 * The repair executes reviewed migration SQL with owner authority. Require a
 * closed target namespace before setting any unqualified lookup path: the
 * effective role must be the exact schema/database owner, no third party may
 * CREATE objects there, and no existing target objects may remain owned by a
 * different role. This prevents pre-positioned function/relation shadowing.
 */
async function assertTrustedRepairSchema(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
): Promise<void> {
  const rows = await transaction.unsafe<RepairSchemaTrustRow>(
    `
      SELECT
        (
          namespace.nspowner = runtime_role.oid
          OR (
            namespace.nspowner = database_owner_role.oid
            AND database.datdba = runtime_role.oid
          )
        ) AS runtime_owns_schema,
        EXISTS (
          SELECT 1
          FROM pg_catalog.aclexplode(
            COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))
          ) AS schema_acl
          WHERE schema_acl.privilege_type = 'CREATE'
            AND schema_acl.grantee NOT IN (
              namespace.nspowner,
              runtime_role.oid
            )
        ) AS unexpected_create_grant,
        EXISTS (
          SELECT 1
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace relation_namespace
            ON relation_namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS relation_acl
          WHERE relation_namespace.nspname = $1
            AND relation_acl.grantee NOT IN (relation.relowner, runtime_role.oid)
        ) AS unexpected_relation_grant,
        EXISTS (
          SELECT 1
          FROM pg_catalog.pg_attribute attribute
          JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
          JOIN pg_catalog.pg_namespace relation_namespace
            ON relation_namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS column_acl
          WHERE relation_namespace.nspname = $1
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
            AND column_acl.grantee NOT IN (relation.relowner, runtime_role.oid)
        ) AS unexpected_column_grant,
        EXISTS (
          SELECT 1
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace procedure_namespace
            ON procedure_namespace.oid = procedure.pronamespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(procedure.proacl, pg_catalog.acldefault('f', procedure.proowner))
          ) AS function_acl
          WHERE procedure_namespace.nspname = $1
            AND function_acl.grantee NOT IN (0, procedure.proowner, runtime_role.oid)
        ) AS unexpected_function_grant,
        (
          SELECT count(*)
          FROM pg_catalog.pg_class relation
          JOIN pg_catalog.pg_namespace relation_namespace
            ON relation_namespace.oid = relation.relnamespace
          WHERE relation_namespace.nspname = $1
            AND relation.relowner <> runtime_role.oid
        ) AS unowned_relation_count,
        (
          SELECT count(*)
          FROM pg_catalog.pg_proc procedure
          JOIN pg_catalog.pg_namespace procedure_namespace
            ON procedure_namespace.oid = procedure.pronamespace
          WHERE procedure_namespace.nspname = $1
            AND procedure.proowner <> runtime_role.oid
        ) AS unowned_function_count,
        (
          SELECT count(*)
          FROM pg_catalog.pg_type type_record
          JOIN pg_catalog.pg_namespace type_namespace
            ON type_namespace.oid = type_record.typnamespace
          WHERE type_namespace.nspname = $1
            AND type_record.typowner <> runtime_role.oid
        ) AS unowned_type_count
      FROM pg_catalog.pg_namespace namespace
      JOIN pg_catalog.pg_database database
        ON database.datname = pg_catalog.current_database()
      JOIN pg_catalog.pg_roles runtime_role
        ON runtime_role.rolname = current_user
      JOIN pg_catalog.pg_roles database_owner_role
        ON database_owner_role.rolname = 'pg_database_owner'
      WHERE namespace.nspname = $1
    `,
    [schema],
  );
  const trust = rows[0];
  if (!trust || trust.runtime_owns_schema !== true) {
    throw new Error("core-repair target schema is not owned by the effective operator role");
  }
  if (trust.unexpected_create_grant === true) {
    throw new Error("core-repair target schema grants CREATE to an unreviewed role");
  }
  if (
    trust.unexpected_relation_grant === true ||
    trust.unexpected_column_grant === true ||
    trust.unexpected_function_grant === true
  ) {
    throw new Error("core-repair target objects grant privileges to an unreviewed role");
  }
  if (
    Number(trust.unowned_relation_count) !== 0 ||
    Number(trust.unowned_function_count) !== 0 ||
    Number(trust.unowned_type_count) !== 0
  ) {
    throw new Error("core-repair target schema contains objects owned by an unreviewed role");
  }
}

async function assertObservedDiscontinuity(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
): Promise<void> {
  const rows = await transaction.unsafe<{
    version_0082: boolean;
    authority_mode_0082: boolean;
    quorum_threshold_0083: boolean;
  }>(
    `
      SELECT
        EXISTS (
          SELECT 1 FROM pg_catalog.pg_attribute attribute
          JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = $1::text
            AND relation.relname = 'execution_authorization_nonces'
            AND attribute.attname = 'version'
            AND attribute.attnum > 0 AND NOT attribute.attisdropped
        ) AS version_0082,
        EXISTS (
          SELECT 1 FROM pg_catalog.pg_attribute attribute
          JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = $1::text
            AND relation.relname = 'secret_routes'
            AND attribute.attname = 'authority_mode'
            AND attribute.attnum > 0 AND NOT attribute.attisdropped
        ) AS authority_mode_0082,
        EXISTS (
          SELECT 1 FROM pg_catalog.pg_attribute attribute
          JOIN pg_catalog.pg_class relation ON relation.oid = attribute.attrelid
          JOIN pg_catalog.pg_namespace namespace ON namespace.oid = relation.relnamespace
          WHERE namespace.nspname = $1::text
            AND relation.relname = 'approval_queue'
            AND attribute.attname = 'quorum_threshold'
            AND attribute.attnum > 0 AND NOT attribute.attisdropped
        ) AS quorum_threshold_0083
    `,
    [schema],
  );
  const state = rows[0];
  if (!state || state.version_0082 || state.authority_mode_0082 || !state.quorum_threshold_0083) {
    throw new Error(
      "core-repair preflight requires the exact 0082-absent/0083-present production discontinuity",
    );
  }
}

const LOCKED_BASELINE_TABLES = [
  "agent_policies",
  "agent_wallets",
  "agents",
  "approval_queue",
  "audit_checkpoints",
  "evm_wallet_nonce_inflight",
  "evm_wallet_nonces",
  "execution_authorization_nonces",
  "intents",
  "pending_proxy_requests",
  "provider_accounts",
  "provider_action_audit_outbox",
  "provider_action_bindings",
  "provider_operations",
  "secret_routes",
  "secrets",
  "tenants",
  "transactions",
  "workspaces",
] as const;

async function lockBaselineTables(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
): Promise<void> {
  const quotedSchema = quoteStewardCoreRepairIdentifier(schema);
  const qualified = LOCKED_BASELINE_TABLES.map(
    (table) => `${quotedSchema}.${quoteStewardCoreRepairIdentifier(table)}`,
  ).join(", ");
  await transaction.unsafe(`LOCK TABLE ${qualified} IN SHARE ROW EXCLUSIVE MODE`);

  const optionalRows = await transaction.unsafe<{ relation_name: string | null }>(
    "SELECT pg_catalog.to_regclass($1)::text AS relation_name",
    [`${schema}.capability_grants`],
  );
  if (optionalRows[0]?.relation_name) {
    throw new Error(
      "capability_grants is installed, but this exact repair manifest was reviewed without the optional plugin; re-audit required",
    );
  }
}

function numericCount(value: string | number | undefined, label: string): number {
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`invalid ${label} preflight count`);
  }
  return count;
}

async function runDataPreflight(
  transaction: StewardCoreRepairExecutor,
): Promise<StewardCoreRepairPreflight> {
  const rows = await transaction.unsafe<{
    execution_ready: string | number;
    external_custody: string | number;
    google_risk: string | number;
    nonce_namespaces: string | number;
    unresolved_nonce_namespaces: string | number;
  }>(`
    WITH
    nonce_namespaces AS (
      SELECT lower(wallet_address) AS wallet_address, chain_id FROM evm_wallet_nonces
      UNION
      SELECT lower(wallet_address) AS wallet_address, chain_id FROM evm_wallet_nonce_inflight
    ),
    candidate_tenants AS (
      SELECT namespace.wallet_address, namespace.chain_id, agent.tenant_id
      FROM nonce_namespaces namespace
      JOIN agents agent ON lower(agent.wallet_address) = namespace.wallet_address
      WHERE lower(agent.wallet_address) ~ '^0x[0-9a-f]{40}$'
      UNION
      SELECT namespace.wallet_address, namespace.chain_id, agent.tenant_id
      FROM nonce_namespaces namespace
      JOIN agent_wallets wallet
        ON wallet.chain_family = 'evm' AND lower(wallet.address) = namespace.wallet_address
      JOIN agents agent ON agent.id = wallet.agent_id
    ),
    nonce_resolution AS (
      SELECT
        namespace.wallet_address,
        namespace.chain_id,
        count(DISTINCT candidate.tenant_id) AS tenant_count
      FROM nonce_namespaces namespace
      LEFT JOIN candidate_tenants candidate
        ON candidate.wallet_address = namespace.wallet_address
       AND candidate.chain_id = namespace.chain_id
      GROUP BY namespace.wallet_address, namespace.chain_id
    )
    SELECT
      (SELECT count(*) FROM provider_action_bindings
       WHERE status = 'execution_ready') AS execution_ready,
      (SELECT count(*) FROM execution_authorization_nonces
       WHERE backend = 'external-custody') AS external_custody,
      (
        SELECT count(*)
        FROM provider_operations operation
        JOIN provider_accounts account
          ON operation.provider_account_id = account.id
         AND operation.tenant_id = account.tenant_id
         AND operation.workspace_id = account.workspace_id
        WHERE account.adapter_key = 'google'
          AND operation.operation_key IN (
            'google.gmail.messages.send',
            'google.calendar.events.insert'
          )
          AND operation.risk_class <> 'consequential'
      ) AS google_risk,
      (SELECT count(*) FROM nonce_resolution) AS nonce_namespaces,
      (SELECT count(*) FROM nonce_resolution WHERE tenant_count <> 1)
        AS unresolved_nonce_namespaces
  `);
  const row = rows[0];
  if (!row) throw new Error("core-repair data preflight returned no result");
  const result = {
    executionReadyWithoutPolicyEvidence: numericCount(row.execution_ready, "execution-ready"),
    externalCustodyNoncesWithoutIdentityDigest: numericCount(
      row.external_custody,
      "external-custody",
    ),
    googleOperationsNeedingRiskUpgrade: numericCount(row.google_risk, "Google risk"),
    evmNonceNamespaces: numericCount(row.nonce_namespaces, "EVM nonce namespace"),
    unresolvedEvmNonceNamespaces: numericCount(
      row.unresolved_nonce_namespaces,
      "unresolved EVM nonce namespace",
    ),
  };

  if (
    result.executionReadyWithoutPolicyEvidence !== 0 ||
    result.externalCustodyNoncesWithoutIdentityDigest !== 0 ||
    result.googleOperationsNeedingRiskUpgrade !== 0 ||
    result.unresolvedEvmNonceNamespaces !== 0
  ) {
    throw new Error(
      "core-repair data preflight differs from the reviewed production envelope; re-audit required",
    );
  }
  return result;
}

async function applyMigration(
  transaction: StewardCoreRepairExecutor,
  source: LoadedStewardCoreRepairSource,
): Promise<void> {
  const statements = splitStewardMigrationStatements(source.rendered);
  for (let index = 0; index < statements.length; index += 1) {
    try {
      await transaction.unsafe(statements[index] as string);
    } catch (error) {
      throw new Error(
        `${source.tag} failed at statement ${index + 1}/${statements.length}; ` +
          "the entire repair transaction will roll back",
        { cause: error },
      );
    }
  }
}

function ledgerQualifiedName(schema: StewardCoreRepairSchema): string {
  return `${quoteStewardCoreRepairIdentifier(schema)}.${quoteStewardCoreRepairIdentifier(
    STEWARD_CORE_REPAIR_LEDGER,
  )}`;
}

async function ledgerExists(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
): Promise<boolean> {
  const rows = await transaction.unsafe<{ relation_name: string | null }>(
    "SELECT pg_catalog.to_regclass($1)::text AS relation_name",
    [`${schema}.${STEWARD_CORE_REPAIR_LEDGER}`],
  );
  return Boolean(rows[0]?.relation_name);
}

async function installLedger(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
  sources: LoadedStewardCoreRepairSource[],
  bundleHash: string,
): Promise<void> {
  const ledger = ledgerQualifiedName(schema);
  await transaction.unsafe(`
    CREATE TABLE ${ledger} (
      migration_order integer PRIMARY KEY CHECK (migration_order > 0),
      tag text NOT NULL UNIQUE,
      action text NOT NULL CHECK (action IN ('applied', 'verified_existing')),
      source_hash text NOT NULL CHECK (source_hash ~ '^[0-9a-f]{64}$'),
      rendered_hash text NOT NULL CHECK (rendered_hash ~ '^[0-9a-f]{64}$'),
      target_schema text NOT NULL,
      repair_version text NOT NULL,
      source_head text NOT NULL CHECK (source_head ~ '^[0-9a-f]{40}$'),
      bundle_hash text NOT NULL CHECK (bundle_hash ~ '^[0-9a-f]{64}$'),
      applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
    )
  `);
  for (const source of sources) {
    await transaction.unsafe(
      `INSERT INTO ${ledger} (
        migration_order, tag, action, source_hash, rendered_hash,
        target_schema, repair_version, source_head, bundle_hash
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        source.order,
        source.tag,
        source.action,
        source.sourceHash,
        source.renderedHash,
        schema,
        STEWARD_CORE_REPAIR_VERSION,
        STEWARD_CORE_REPAIR_SOURCE_HEAD,
        bundleHash,
      ],
    );
  }
}

async function assertLedger(
  transaction: StewardCoreRepairExecutor,
  schema: StewardCoreRepairSchema,
  sources: LoadedStewardCoreRepairSource[],
  bundleHash: string,
): Promise<void> {
  const ledger = ledgerQualifiedName(schema);
  const rows = await transaction.unsafe<LedgerRow>(`
    SELECT
      migration_order, tag, action, source_hash, rendered_hash,
      target_schema, repair_version, source_head, bundle_hash
    FROM ${ledger}
    ORDER BY migration_order
  `);
  if (rows.length !== sources.length) {
    throw new Error("Steward-owned core-repair ledger has the wrong row count");
  }
  for (let index = 0; index < sources.length; index += 1) {
    const row = rows[index];
    const source = sources[index];
    if (
      !row ||
      !source ||
      Number(row.migration_order) !== source.order ||
      row.tag !== source.tag ||
      row.action !== source.action ||
      row.source_hash !== source.sourceHash ||
      row.rendered_hash !== source.renderedHash ||
      row.target_schema !== schema ||
      row.repair_version !== STEWARD_CORE_REPAIR_VERSION ||
      row.source_head !== STEWARD_CORE_REPAIR_SOURCE_HEAD ||
      row.bundle_hash !== bundleHash
    ) {
      throw new Error(`Steward-owned core-repair ledger mismatch at order ${index + 1}`);
    }
  }
}

async function applyInTransaction(
  transaction: StewardCoreRepairExecutor,
  expectedSchema: StewardCoreRepairSchema,
): Promise<StewardCoreRepairResult> {
  await transaction.unsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await transaction.unsafe("SET LOCAL lock_timeout = '5s'");
  await transaction.unsafe("SET LOCAL statement_timeout = '15min'");
  await transaction.unsafe("SET LOCAL idle_in_transaction_session_timeout = '15min'");

  // Exclude application writes before the transaction establishes its first
  // MVCC snapshot. A lock acquired after catalog/data reads could otherwise
  // miss rows committed while waiting on an in-flight writer.
  await lockBaselineTables(transaction, expectedSchema);
  const schema = await resolveTargetSchema(transaction, expectedSchema);
  await assertTrustedRepairSchema(transaction, schema);
  const quotedSchema = quoteStewardCoreRepairIdentifier(schema);
  await transaction.unsafe(`SET LOCAL search_path TO ${quotedSchema}`);

  const manifest = getSchemaManifest(schema);
  await assertCatalogPostgresMajor(transaction, manifest);
  const sources = loadStewardCoreRepairSources(schema);
  const bundleHash = getBundleHash(schema, sources, manifest);

  if (await ledgerExists(transaction, schema)) {
    await assertLedger(transaction, schema, sources, bundleHash);
    const catalog = await queryStewardCatalog(transaction, schema);
    assertCatalogPhase(catalog, manifest.changes, "after", "already-applied");
    return {
      status: "already_applied",
      schema,
      bundleHash,
      applied: [],
      verifiedExisting: sources
        .filter((source) => source.action === "verified_existing")
        .map((source) => source.tag),
      preflight: null,
    };
  }

  const before = await queryStewardCatalog(transaction, schema);
  assertCatalogPhase(before, manifest.existing0083, "after", "0083 existing-state");
  assertCatalogPhase(before, manifest.changes, "before", "pre-repair");
  await assertObservedDiscontinuity(transaction, schema);
  const preflight = await runDataPreflight(transaction);

  for (const source of sources) {
    if (source.action === "verified_existing") continue;
    await applyMigration(transaction, source);
  }

  const after = await queryStewardCatalog(transaction, schema);
  assertCatalogPhase(after, manifest.changes, "after", "post-repair");
  assertExactCatalogDelta(before, after, manifest.changes);
  await installLedger(transaction, schema, sources, bundleHash);
  await assertLedger(transaction, schema, sources, bundleHash);
  // Re-evaluate the closed ownership/ACL boundary after every reviewed DDL
  // statement, including the provenance ledger. Runtime-role default
  // privileges can attach third-party grants only when new objects are
  // created, so the preflight trust check alone cannot detect them.
  await assertTrustedRepairSchema(transaction, schema);

  return {
    status: "applied",
    schema,
    bundleHash,
    applied: sources.filter((source) => source.action === "applied").map((source) => source.tag),
    verifiedExisting: sources
      .filter((source) => source.action === "verified_existing")
      .map((source) => source.tag),
    preflight,
  };
}

async function inspectInTransaction(
  transaction: StewardCoreRepairExecutor,
  expectedSchema: StewardCoreRepairSchema,
): Promise<StewardCoreRepairInspection> {
  await transaction.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await transaction.unsafe("SET LOCAL statement_timeout = '5min'");
  await transaction.unsafe("SET LOCAL idle_in_transaction_session_timeout = '5min'");

  const schema = await resolveTargetSchema(transaction, expectedSchema);
  await assertTrustedRepairSchema(transaction, schema);
  const quotedSchema = quoteStewardCoreRepairIdentifier(schema);
  await transaction.unsafe(`SET LOCAL search_path TO ${quotedSchema}`);
  const manifest = getSchemaManifest(schema);
  await assertCatalogPostgresMajor(transaction, manifest);
  const sources = loadStewardCoreRepairSources(schema);
  const bundleHash = getBundleHash(schema, sources, manifest);
  const verifiedExisting = sources
    .filter((source) => source.action === "verified_existing")
    .map((source) => source.tag);

  if (await ledgerExists(transaction, schema)) {
    await assertLedger(transaction, schema, sources, bundleHash);
    const catalog = await queryStewardCatalog(transaction, schema);
    assertCatalogPhase(catalog, manifest.changes, "after", "already-applied");
    return {
      status: "already_applied",
      schema,
      bundleHash,
      verifiedExisting,
      preflight: null,
    };
  }

  const catalog = await queryStewardCatalog(transaction, schema);
  assertCatalogPhase(catalog, manifest.existing0083, "after", "0083 existing-state");
  assertCatalogPhase(catalog, manifest.changes, "before", "pre-repair");
  await assertObservedDiscontinuity(transaction, schema);
  const preflight = await runDataPreflight(transaction);
  return {
    status: "eligible",
    schema,
    bundleHash,
    verifiedExisting,
    preflight,
  };
}

async function inspectAppliedInTransaction(
  transaction: StewardCoreRepairExecutor,
  expectedSchema: StewardCoreRepairSchema,
): Promise<StewardCoreRepairInspection & { status: "already_applied" }> {
  await transaction.unsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await transaction.unsafe("SET LOCAL statement_timeout = '2s'");
  await transaction.unsafe("SET LOCAL idle_in_transaction_session_timeout = '2s'");

  const schema = await resolveTargetSchema(transaction, expectedSchema);
  await assertTrustedRepairSchema(transaction, schema);
  const quotedSchema = quoteStewardCoreRepairIdentifier(schema);
  await transaction.unsafe(`SET LOCAL search_path TO ${quotedSchema}`);
  const manifest = getSchemaManifest(schema);
  await assertCatalogPostgresMajor(transaction, manifest);
  const sources = loadStewardCoreRepairSources(schema);
  const bundleHash = getBundleHash(schema, sources, manifest);
  if (!(await ledgerExists(transaction, schema))) {
    throw new Error("Steward core repair ledger is missing");
  }
  await assertLedger(transaction, schema, sources, bundleHash);
  const catalog = await queryStewardCatalog(transaction, schema);
  assertCatalogPhase(catalog, manifest.changes, "after", "release-readiness");
  return {
    status: "already_applied",
    schema,
    bundleHash,
    verifiedExisting: sources
      .filter((source) => source.action === "verified_existing")
      .map((source) => source.tag),
    preflight: null,
  };
}

/**
 * Read-only, repeatable-read inspection of the same catalog and aggregate data
 * gates used by the applying transaction. It does not lock application tables
 * and therefore cannot authorize a later mutation by itself; the applying
 * transaction repeats every check after taking its write-excluding locks.
 */
export async function inspectStewardCoreRepair(
  options: Pick<RunStewardCoreRepairOptions, "expectedSchema" | "client">,
): Promise<StewardCoreRepairInspection> {
  const ownsClient = !options.client;
  const client = options.client ?? (createPostgresClient() as unknown as StewardCoreRepairClient);
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
 * Runtime readiness variant of the operator inspector. It only accepts the
 * fully applied repair, validates both exact provenance and the live reviewed
 * catalog, and fails immediately when the ledger is absent. Unlike the
 * operator preflight it never scans production data to determine eligibility.
 */
export async function inspectAppliedStewardCoreRepair(
  options: Pick<RunStewardCoreRepairOptions, "expectedSchema" | "client">,
): Promise<StewardCoreRepairInspection & { status: "already_applied" }> {
  const ownsClient = !options.client;
  const client = options.client ?? (createPostgresClient() as unknown as StewardCoreRepairClient);
  try {
    return await client.begin((transaction) =>
      inspectAppliedInTransaction(transaction, options.expectedSchema),
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
 * Repair the exact production 0082-absent/0083-present discontinuity and then
 * apply 0084-0110 as one transaction. The Steward-owned ledger records source
 * and rendered hashes, but it is never treated as sufficient proof: both the
 * first run and idempotent inspection compare the live catalog to the checked-
 * in exact manifest. The shared Eliza/Drizzle ledger is never read or written.
 */
export async function runStewardCoreRepair(
  options: RunStewardCoreRepairOptions,
): Promise<StewardCoreRepairResult> {
  const ownsClient = !options.client;
  const client = options.client ?? (createPostgresClient() as unknown as StewardCoreRepairClient);
  const useAdvisoryLock = options.useAdvisoryLock ?? true;
  let reserved: StewardCoreRepairReservedClient | undefined;
  let clientClosed = false;

  const quarantineReservedClient = async (errors: unknown[], message: string): Promise<void> => {
    // A lost acquisition/unlock response or uncertain transaction cleanup can
    // leave a session-scoped lock behind. Close the entire disposable operator
    // client; never return that reserved session to its pool.
    reserved = undefined;
    clientClosed = true;
    const close = await captureOutcome(() => client.end({ timeout: 0 }));
    if (!close.ok) {
      throw new AggregateError([...errors, close.error], message);
    }
  };

  try {
    if (useAdvisoryLock) {
      if (typeof client.reserve !== "function") {
        throw new Error("core-repair advisory lock requires a reserved database connection");
      }
      const connection = await client.reserve();
      reserved = connection;
      const acquisition = await captureOutcome(() =>
        connection.unsafe<{ acquired: boolean }>(
          "SELECT pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended($1, 0)) AS acquired",
          [ADVISORY_LOCK_KEY],
        ),
      );
      if (!acquisition.ok) {
        await quarantineReservedClient(
          [acquisition.error],
          "core-repair advisory-lock acquisition was uncertain and its client could not be quarantined",
        );
        throw acquisition.error;
      }
      if (acquisition.value[0]?.acquired === false) {
        throw new Error("another Steward core repair already holds the advisory lock");
      }
      if (acquisition.value[0]?.acquired !== true) {
        const error = new Error("core-repair advisory-lock acquisition returned an invalid result");
        await quarantineReservedClient(
          [error],
          "core-repair advisory-lock acquisition was uncertain and its client could not be quarantined",
        );
        throw error;
      }

      const repair = await captureOutcome(() =>
        runReservedTransaction(connection, (transaction) =>
          applyInTransaction(transaction, options.expectedSchema),
        ),
      );
      const unlock = await captureOutcome(async () => {
        const rows = await connection.unsafe<{ released: boolean }>(
          "SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended($1, 0)) AS released",
          [ADVISORY_LOCK_KEY],
        );
        if (rows[0]?.released !== true) {
          throw new Error("core-repair advisory lock was not held by its reserved connection");
        }
      });
      const connectionCleanupUncertain =
        !unlock.ok || (!repair.ok && repair.error instanceof ReservedTransactionCleanupError);
      if (connectionCleanupUncertain) {
        const errors: unknown[] = [];
        if (!repair.ok) errors.push(repair.error);
        if (!unlock.ok) errors.push(unlock.error);
        await quarantineReservedClient(
          errors,
          "core repair could not prove reserved-session cleanup or quarantine its client",
        );
      }
      if (!unlock.ok) {
        if (!repair.ok) {
          throw new AggregateError(
            [repair.error, unlock.error],
            "core repair failed and its reserved advisory lock could not be released",
          );
        }
        throw unlock.error;
      }
      if (!repair.ok) {
        throw repair.error;
      }
      return repair.value;
    }

    return await client.begin((transaction) =>
      applyInTransaction(transaction, options.expectedSchema),
    );
  } finally {
    reserved?.release();
    if (ownsClient && !clientClosed) {
      await client.end({ timeout: 5 });
    }
  }
}

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  const expectedSchema = process.env.STEWARD_CORE_REPAIR_EXPECTED_SCHEMA;
  if (!expectedSchema) {
    console.error("STEWARD_CORE_REPAIR_EXPECTED_SCHEMA is required (public or steward)");
    process.exitCode = 1;
  } else {
    try {
      assertStewardCoreRepairSchema(expectedSchema);
      if (process.env.STEWARD_CORE_REPAIR_APPLY === "YES") {
        const result = await runStewardCoreRepair({ expectedSchema });
        console.log(
          `[steward-core-repair] ${result.status} ${result.applied.length} migration(s) ` +
            `in schema ${result.schema}; bundle ${result.bundleHash}`,
        );
      } else {
        const result = await inspectStewardCoreRepair({ expectedSchema });
        console.log(
          `[steward-core-repair] read-only ${result.status} in schema ${result.schema}; ` +
            `bundle ${result.bundleHash}. Set STEWARD_CORE_REPAIR_APPLY=YES only after approval.`,
        );
      }
    } catch (error) {
      console.error("Failed to run Steward core repair", redactedThrownDiagnostics(error));
      process.exitCode = 1;
    }
  }
}
