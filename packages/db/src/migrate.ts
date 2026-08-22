import { readFileSync } from "node:fs";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { sql } from "drizzle-orm";
import { readMigrationFiles } from "drizzle-orm/migrator";
import type { PostgresJsDatabase } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";

import { createDb } from "./client";

declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  exitCode?: number;
};

const MIGRATIONS_FOLDER = new URL("../drizzle", import.meta.url).pathname;
const ADVISORY_LOCK_KEY = "steward_migrations";

interface JournalEntry {
  idx: number;
  tag: string;
  when: number;
}

interface Journal {
  entries: JournalEntry[];
}

export interface CoreMigrationLedgerRow {
  id: number;
  hash: string;
  created_at: string | number | null;
}

interface CoreMigrationDatabaseShape {
  tenantsExists: boolean;
  auditEventsExists: boolean;
  legacyFingerprintMatches: boolean;
  userObjectCount: number;
  /**
   * Objects that cannot belong to a fresh Steward target. This inventory is
   * deliberately broader than `public` tables: schema-separated shared
   * databases, views, sequences, routines, and user-defined types must all
   * fail before migration bookkeeping is created.
   */
  unapprovedObjectCount?: number;
  alwaysRejectedObjectCount?: number;
  coreLedgerExists?: boolean;
  coreLedgerShapeMatches?: boolean;
}

export interface MigrationTimeouts {
  connectSeconds: number;
  advisoryLockMs: number;
  statementMs: number;
  overallMs: number;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`[migrate] ${name} must be a positive integer`);
  }
  return parsed;
}

export function resolveMigrationTimeouts(
  env: Record<string, string | undefined> = process.env,
): MigrationTimeouts {
  const connectSeconds = positiveInteger(
    env.STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS,
    15,
    "STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS",
  );
  const advisoryLockMs = positiveInteger(
    env.STEWARD_MIGRATION_LOCK_TIMEOUT_MS,
    60_000,
    "STEWARD_MIGRATION_LOCK_TIMEOUT_MS",
  );
  const statementMs = positiveInteger(
    env.STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS,
    300_000,
    "STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS",
  );
  const overallMs = positiveInteger(
    env.STEWARD_MIGRATION_OVERALL_TIMEOUT_MS,
    600_000,
    "STEWARD_MIGRATION_OVERALL_TIMEOUT_MS",
  );
  if (advisoryLockMs > overallMs || statementMs > overallMs) {
    throw new Error(
      "[migrate] migration lock/statement timeouts must not exceed the overall timeout",
    );
  }
  return { connectSeconds, advisoryLockMs, statementMs, overallMs };
}

/**
 * Drizzle trusts only the greatest `created_at` in its journal. An unrelated
 * row with a future timestamp therefore makes every Steward migration appear
 * applied. Validate the entire ledger against this repository before Drizzle
 * is allowed to use that cutoff.
 */
export function assertCoreMigrationLedgerIntegrity(
  rows: readonly CoreMigrationLedgerRow[],
  journal: Journal,
  database: CoreMigrationDatabaseShape,
  options: { requireComplete?: boolean; allowShippedTimestampCollision?: boolean } = {},
): void {
  if ((database.alwaysRejectedObjectCount ?? 0) > 0) {
    throw new Error(
      "[migrate] Database contains objects outside the verified Steward and provider inventories; refusing a shared database",
    );
  }
  const expected = journal.entries.map((entry) => ({
    ...entry,
    hash: hashMigration(entry.tag),
  }));
  const expectedByIdentity = new Map(
    expected.map((entry, index) => [`${entry.when}:${entry.hash}`, { entry, index }]),
  );
  if (expectedByIdentity.size !== expected.length) {
    throw new Error("[migrate] Checked-in migration journal contains duplicate identities");
  }

  const recordedIndices: number[] = [];
  const recordedIdentities = new Set<string>();
  for (const row of rows) {
    const createdAt = Number(row.created_at);
    if (!Number.isSafeInteger(createdAt) || createdAt < 0 || !row.hash) {
      throw new Error("[migrate] Core migration journal contains a malformed row");
    }
    const identity = `${createdAt}:${row.hash}`;
    const match = expectedByIdentity.get(identity);
    if (!match) {
      throw new Error(
        "[migrate] Core migration journal contains an entry not owned by this Steward build; " +
          "refusing to trust a possibly shared or ahead database",
      );
    }
    if (recordedIdentities.has(identity)) {
      throw new Error("[migrate] Core migration journal contains a duplicate Steward entry");
    }
    recordedIdentities.add(identity);
    recordedIndices.push(match.index);
  }

  if (
    recordedIndices.some(
      (index, position) => position > 0 && index <= recordedIndices[position - 1],
    )
  ) {
    throw new Error("[migrate] Core migration journal is not in checked-in Steward order");
  }

  if (rows.length > 0 && !database.tenantsExists) {
    throw new Error(
      "[migrate] Core migration journal exists without public.tenants; refusing the wrong database",
    );
  }
  if (database.coreLedgerExists && !database.coreLedgerShapeMatches) {
    throw new Error(
      "[migrate] drizzle.__drizzle_migrations does not match Steward's migration-ledger shape; refusing the wrong database",
    );
  }
  if (rows.length === 0 && database.tenantsExists && !database.legacyFingerprintMatches) {
    throw new Error(
      "[migrate] Non-empty database resembles Steward but does not match the complete legacy schema fingerprint; refusing to create migration bookkeeping",
    );
  }
  if (
    rows.length === 0 &&
    !database.tenantsExists &&
    (database.unapprovedObjectCount ?? database.userObjectCount) > 0
  ) {
    throw new Error(
      "[migrate] Non-empty database has no Steward migration history; refusing a shared database",
    );
  }
  const auditMigrationIndex = journal.entries.findIndex(
    (entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG,
  );
  if (
    auditMigrationIndex !== -1 &&
    recordedIndices.some((index) => index >= auditMigrationIndex) &&
    (!database.auditEventsExists || !database.legacyFingerprintMatches)
  ) {
    throw new Error(
      `[migrate] Journal claims ${LEGACY_BACKFILL_TIP_TAG} but the complete legacy schema fingerprint does not match`,
    );
  }

  if (recordedIndices.length > 0) {
    const greatestRecordedWhen = Math.max(
      ...recordedIndices.map((index) => journal.entries[index].when),
    );
    const collisionPredecessor = expected.find(
      (entry) => entry.tag === SHIPPED_COLLISION_PREDECESSOR_TAG,
    );
    const silentlySkipped = expected.filter(
      (entry) =>
        entry.when <= greatestRecordedWhen &&
        !recordedIdentities.has(`${entry.when}:${entry.hash}`) &&
        !(
          options.allowShippedTimestampCollision === true &&
          entry.tag === SHIPPED_COLLISION_SUCCESSOR_TAG &&
          collisionPredecessor?.when === entry.when &&
          recordedIdentities.has(`${collisionPredecessor.when}:${collisionPredecessor.hash}`)
        ),
    );
    if (silentlySkipped.length > 0) {
      throw new Error(
        `[migrate] Core migration journal is missing ${silentlySkipped[0].tag} below its recorded cutoff`,
      );
    }
  }

  if (options.requireComplete && recordedIdentities.size !== expected.length) {
    const missingTags = expected
      .filter((entry) => !recordedIdentities.has(`${entry.when}:${entry.hash}`))
      .map((entry) => entry.tag);
    throw new Error(
      `[migrate] Core migrator returned with an incomplete Steward journal; missing: ${missingTags.join(", ")}`,
    );
  }
}

const SHIPPED_COLLISION_PREDECESSOR_TAG = "0114_durable_wallet_claim_account_audit";
const SHIPPED_COLLISION_SUCCESSOR_TAG = "0118_generic_intent_execution_delete_fence";

/**
 * The legacy `psql -f` deploy loop was retired when this migrator was
 * introduced; the journal tip at that moment was 0024_audit_events. A legacy
 * DB is therefore only provably migrated through that tag — entries past it
 * must be APPLIED by the migrator, never seeded.
 */
export const LEGACY_BACKFILL_TIP_TAG = "0024_audit_events";

/**
 * The newest table created by the legacy psql-era tip. Before backfilling its
 * ledger, runMigrations additionally verifies the complete 0000-0024 relation,
 * migration-specific column, and critical-index fingerprint; this sentinel is
 * retained for the explicit tip lookup and diagnostics.
 */
export const LEGACY_BACKFILL_FINGERPRINT_TABLE = "public.audit_events";

/**
 * Select the journal entries a legacy DB may be seeded with: everything up to
 * and including the psql-era tip. Throws if the tip is absent from the
 * journal (should never happen — it is a historical entry).
 */
export function selectLegacyBackfillEntries(journal: Journal): JournalEntry[] {
  const tipIndex = journal.entries.findIndex((entry) => entry.tag === LEGACY_BACKFILL_TIP_TAG);
  if (tipIndex === -1) {
    throw new Error(
      `[migrate] Backfill-era tip ${LEGACY_BACKFILL_TIP_TAG} is missing from the migration journal; refusing to seed a legacy DB`,
    );
  }
  return journal.entries.slice(0, tipIndex + 1);
}

function readJournal(): Journal {
  const path = `${MIGRATIONS_FOLDER}/meta/_journal.json`;
  return JSON.parse(readFileSync(path, "utf-8")) as Journal;
}

function hashMigration(tag: string): string {
  // Drizzle hashes the raw .sql file contents with sha256.
  const crypto = require("node:crypto") as typeof import("node:crypto");
  const sql = readFileSync(`${MIGRATIONS_FOLDER}/${tag}.sql`, "utf-8");
  return crypto.createHash("sha256").update(sql).digest("hex");
}

async function recoverShippedTimestampCollision(
  db: MigrationQueryExecutor,
  rows: readonly CoreMigrationLedgerRow[],
  journal: Journal,
): Promise<boolean> {
  const predecessor = journal.entries.find(
    (entry) => entry.tag === SHIPPED_COLLISION_PREDECESSOR_TAG,
  );
  const successor = journal.entries.find((entry) => entry.tag === SHIPPED_COLLISION_SUCCESSOR_TAG);
  if (!predecessor || !successor || predecessor.when !== successor.when) return false;

  const hasPredecessor = rows.some(
    (row) =>
      row.hash === hashMigration(predecessor.tag) && Number(row.created_at) === predecessor.when,
  );
  const hasSuccessor = rows.some(
    (row) => row.hash === hashMigration(successor.tag) && Number(row.created_at) === successor.when,
  );
  if (!hasPredecessor || hasSuccessor) return false;

  const migrationSql = readFileSync(`${MIGRATIONS_FOLDER}/${successor.tag}.sql`, "utf8");
  const statements = migrationSql
    .split("--> statement-breakpoint")
    .map((statement) => statement.trim())
    .filter(Boolean);
  for (const statement of statements) await db.execute(sql.raw(statement));
  await db.execute(sql`
    INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
    VALUES (${hashMigration(successor.tag)}, ${successor.when})
  `);
  return true;
}

type MigrationQueryExecutor = {
  execute(query: ReturnType<typeof sql>): Promise<unknown>;
};

function queryRows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[];
  return ((result as { rows?: T[] } | undefined)?.rows ?? []) as T[];
}

/**
 * Exact checked-in ownership boundary for catalog objects created by the core
 * and bundled plugin migrations. Indexes, constraints, triggers, and policies
 * are subordinate to these relations; standalone schemas, relations,
 * routines, types, and other namespaced catalog objects are not.
 *
 * Run this immediately before the first write and again before commit. The
 * second check closes the inspection-to-migration gap even for DDL writers
 * that do not participate in Steward's advisory-lock convention.
 */
async function assertExactMigrationObjectInventory(db: MigrationQueryExecutor): Promise<void> {
  const result = await db.execute(sql`
    WITH
    allowed_extensions(extname) AS (
      VALUES ('neon'), ('pg_stat_statements')
    ),
    allowed_relations(schema_name, relation_name, relation_kind) AS (
      VALUES
        ('public', 'accounts', 'r'),
        ('public', 'agent_key_quorums', 'r'),
        ('public', 'agent_policies', 'r'),
        ('public', 'agent_registrations', 'r'),
        ('public', 'agent_signers', 'r'),
        ('public', 'agent_wallets', 'r'),
        ('public', 'agents', 'r'),
        ('public', 'approval_queue', 'r'),
        ('public', 'audit_archive_chunks', 'r'),
        ('public', 'audit_archives', 'r'),
        ('public', 'audit_chain_heads', 'r'),
        ('public', 'audit_checkpoints', 'r'),
        ('public', 'audit_events', 'r'),
        ('public', 'audit_retention_policies', 'r'),
        ('public', 'auth_kv_store', 'r'),
        ('public', 'authenticators', 'r'),
        ('public', 'auto_approval_rules', 'r'),
        ('public', 'condition_set_items', 'r'),
        ('public', 'condition_sets', 'r'),
        ('public', 'digital_asset_account_aggregations', 'r'),
        ('public', 'digital_asset_account_wallet_lifecycles', 'r'),
        ('public', 'digital_asset_account_wallets', 'r'),
        ('public', 'digital_asset_accounts', 'r'),
        ('public', 'encrypted_chain_keys', 'r'),
        ('public', 'encrypted_keys', 'r'),
        ('public', 'evm_wallet_nonce_inflight', 'r'),
        ('public', 'evm_wallet_nonce_owners', 'r'),
        ('public', 'evm_wallet_nonces', 'r'),
        ('public', 'execution_authorization_nonces', 'r'),
        ('public', 'global_wallet_action_confirmations', 'r'),
        ('public', 'intents', 'r'),
        ('public', 'operator_transfer_reservations', 'r'),
        ('public', 'pending_proxy_requests', 'r'),
        ('public', 'policies', 'r'),
        ('public', 'policy_templates', 'r'),
        ('public', 'provider_accounts', 'r'),
        ('public', 'provider_action_approvals', 'r'),
        ('public', 'provider_action_audit_outbox', 'r'),
        ('public', 'provider_action_bindings', 'r'),
        ('public', 'provider_action_reservation_generations', 'r'),
        ('public', 'provider_agent_budgets', 'r'),
        ('public', 'provider_authority_tenant_state', 'r'),
        ('public', 'provider_google_credential_lifecycles', 'r'),
        ('public', 'provider_grants', 'r'),
        ('public', 'provider_operations', 'r'),
        ('public', 'provider_role_bindings', 'r'),
        ('public', 'provider_x_credential_lifecycles', 'r'),
        ('public', 'pregenerated_wallet_claim_lifecycles', 'r'),
        ('public', 'proxy_audit_log', 'r'),
        ('public', 'refresh_tokens', 'r'),
        ('public', 'registry_index', 'r'),
        ('public', 'reputation_cache', 'r'),
        ('public', 'secret_routes', 'r'),
        ('public', 'secrets', 'r'),
        ('public', 'session_signers', 'r'),
        ('public', 'sessions', 'r'),
        ('public', 'sponsored_gas_events', 'r'),
        ('public', 'tenant_app_client_secrets', 'r'),
        ('public', 'tenant_app_clients', 'r'),
        ('public', 'tenant_configs', 'r'),
        ('public', 'tenant_invitations', 'r'),
        ('public', 'tenant_request_signing_keys', 'r'),
        ('public', 'tenant_saml_assertion_replays', 'r'),
        ('public', 'tenant_saml_authn_requests', 'r'),
        ('public', 'tenant_saml_sso_configs', 'r'),
        ('public', 'tenant_sso_domains', 'r'),
        ('public', 'tenants', 'r'),
        ('public', 'trade_sessions', 'r'),
        ('public', 'trade_order_recoveries', 'r'),
        ('public', 'transactions', 'r'),
        ('public', 'upstream_credential_lease_events', 'r'),
        ('public', 'upstream_credential_leases', 'r'),
        ('public', 'user_identity_subjects', 'r'),
        ('public', 'user_push_subscriptions', 'r'),
        ('public', 'user_tenants', 'r'),
        ('public', 'user_wallet_app_consents', 'r'),
        ('public', 'users', 'r'),
        ('public', 'vault_signing_freezes', 'r'),
        ('public', 'webhook_configs', 'r'),
        ('public', 'webhook_deliveries', 'r'),
        ('public', 'workspaces', 'r'),
        ('public', 'retained_user_provider_evidence', 'r'),
        ('public', 'agent_registrations_id_seq', 'S'),
        ('public', 'audit_checkpoints_id_seq', 'S'),
        ('public', 'audit_events_id_seq', 'S'),
        ('public', 'registry_index_id_seq', 'S'),
        ('public', 'reputation_cache_id_seq', 'S'),
        -- Bundled plugin-owned objects are accepted only with their exact names.
        ('public', 'capabilities', 'r'),
        ('public', 'capability_grants', 'r'),
        ('public', 'capability_invocations', 'r'),
        ('public', 'capability_rate_limit_buckets', 'r'),
        ('public', 'example_log', 'r'),
        ('public', 'example_log_id_seq', 'S')
    ),
    allowed_routines(schema_name, routine_identity) AS (
      VALUES
        ('public', 'steward_bump_provider_agent_budget_revision()'),
        ('public', 'steward_bump_secret_route_authority_revision()'),
        ('public', 'steward_fence_agent_authority_creation()'),
        ('public', 'steward_fence_provider_action_agent()'),
        ('public', 'steward_fence_provider_action_intent_tenant()'),
        ('public', 'steward_fence_upstream_lease_workspace()'),
        ('public', 'steward_guard_agent_delete()'),
        ('public', 'steward_guard_approved_agent_delete()'),
        ('public', 'steward_guard_audit_archive_immutability()'),
        ('public', 'steward_guard_audit_checkpoint_immutability()'),
        ('public', 'steward_guard_generic_intent_execution_delete()'),
        ('public', 'steward_guard_workspace_delete()'),
        ('public', 'steward_enforce_reserved_tenant_commit_state()'),
        ('public', 'steward_guard_personal_invitation_write()'),
        ('public', 'steward_guard_personal_membership_delete()'),
        ('public', 'steward_guard_personal_membership_write()'),
        ('public', 'steward_guard_wallet_tenant_owner_update()'),
        ('public', 'steward_guard_wallet_user_identity_update()'),
        ('public', 'steward_internal_job_tenant_ids_v2()'),
        ('public', 'steward_is_authoritative_wallet_identity(p_tenant_id text, p_owner_address text, p_wallet_chain text, p_wallet_address text)'),
        ('public', 'steward_is_authoritative_wallet_tenant_owner(p_tenant_id text, p_user_id uuid)'),
        ('public', 'steward_is_reserved_tenant_id(p_tenant_id text)'),
        ('public', 'steward_lock_tenant_deletion(target_tenant text)'),
        ('public', 'steward_lock_personal_lifecycle(p_user_id uuid, p_tenant_id text, p_tenant_delete boolean)'),
        ('public', 'steward_platform_delete_user_v2(p_user_id uuid)'),
        ('public', 'steward_platform_personal_tenant_delete_v2(p_tenant_id text, p_execute boolean)'),
        ('public', 'steward_platform_provision_user_v1(p_email text, p_email_verified boolean, p_name text, p_custom_metadata jsonb)'),
        ('public', 'steward_platform_set_user_deactivation_v2(p_user_id uuid, p_deactivated boolean)'),
        ('public', 'steward_platform_user_identity_v1(p_user_id uuid)'),
        ('public', 'steward_provider_action_binding_guard()'),
        ('public', 'steward_preserve_signed_artifact_evidence()'),
        ('public', 'steward_provider_reservation_generation_guard()'),
        ('public', 'steward_reject_provider_scope_move()'),
        ('public', 'steward_reject_upstream_lease_evidence_mutation()'),
        ('public', 'steward_register_user_identity_subject()'),
        ('public', 'steward_reserved_tenant_kind(p_tenant_id text)'),
        ('public', 'steward_retire_user_identity_subject()'),
        ('public', 'steward_user_token_revocation_subject_v1(p_user_id uuid)'),
        ('public', 'capability_grants_agent_fence()'),
        ('public', 'capability_grants_guard_agent_delete()'),
        ('public', 'capability_rate_limit_bucket_agent_fence()'),
        ('steward_rls', 'tenant_id()'),
        ('steward_rls', 'user_id()'),
        ('steward_bootstrap', 'agent_subject(p_agent_id text, p_tenant_id text, p_jti text)'),
        ('steward_bootstrap', 'agent_tenant_subject(p_agent_id text)'),
        ('steward_bootstrap', 'app_client_subject(p_tenant_id text, p_client_id text)'),
        ('steward_bootstrap', 'auth_app_clients_subject(p_tenant_id text)'),
        ('steward_bootstrap', 'auth_refresh_subject(p_token_hash text)'),
        ('steward_bootstrap', 'auth_sso_discovery_subject(p_domain text)'),
        ('steward_bootstrap', 'auth_sso_domain_subject(p_tenant_id text, p_domain text)'),
        ('steward_bootstrap', 'auth_tenant_config_subject(p_tenant_id text)'),
        ('steward_bootstrap', 'auth_tenant_subject(p_tenant_id text, p_user_id uuid)'),
        ('steward_bootstrap', 'auth_rotate_refresh_token(p_source_token_hash text, p_target_tenant_id text, p_successor_id text, p_successor_token_hash text, p_successor_expires_at timestamp with time zone)'),
        ('steward_bootstrap', 'ensure_default_tenant(p_api_key_hash text)'),
        ('steward_bootstrap', 'ensure_default_membership(p_user_id uuid, p_role text)'),
        ('steward_bootstrap', 'ensure_platform_tenant()'),
        ('steward_bootstrap', 'ensure_system_tenant()'),
        ('steward_bootstrap', 'platform_delete_user(p_user_id uuid)'),
        ('steward_bootstrap', 'platform_personal_tenant_delete(p_tenant_id text, p_execute boolean)'),
        ('steward_bootstrap', 'platform_provision_user(p_email text, p_email_verified boolean, p_name text, p_custom_metadata jsonb)'),
        ('steward_bootstrap', 'platform_revoke_user_refresh_tokens(p_user_id uuid)'),
        ('steward_bootstrap', 'platform_set_user_deactivation(p_user_id uuid, p_deactivated boolean)'),
        ('steward_bootstrap', 'tenant_set_user_deactivation(p_tenant_id text, p_actor_id uuid, p_user_id uuid, p_deactivated boolean)'),
        ('steward_bootstrap', 'platform_stats()'),
        ('steward_bootstrap', 'platform_tenants(p_limit integer, p_offset integer)'),
        ('steward_bootstrap', 'platform_user_identity(p_user_id uuid)'),
        ('steward_bootstrap', 'platform_user_tenant_ids(p_user_id uuid)'),
        ('steward_bootstrap', 'retention_delete_deactivated_users(p_days integer)'),
        ('steward_bootstrap', 'session_subject(p_user_id uuid, p_tenant_id text)'),
        ('steward_bootstrap', 'tenant_api_key_subject(p_tenant_id text)'),
        ('steward_bootstrap', 'tenant_ids_for_internal_job()'),
        ('steward_bootstrap', 'user_token_revocation_subject(p_user_id uuid)')
    ),
    allowed_types(type_name) AS (
      VALUES
        ('approval_queue_status'), ('chain_family'), ('execution_authorization_status'),
        ('pending_proxy_request_status'), ('policy_type'), ('provider_authority_status'),
        ('provider_environment'), ('provider_principal_type'), ('provider_risk_class'),
        ('provider_role'), ('secret_route_authority_mode'), ('transaction_status'),
        ('webhook_delivery_status')
    ),
    unexpected(kind, identity) AS (
      SELECT 'schema', namespace.nspname
      FROM pg_namespace namespace
      WHERE namespace.nspname <> 'information_schema'
        AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
        AND namespace.nspname NOT IN (
          'public', 'drizzle', 'neon', 'steward_rls', 'steward_bootstrap'
        )

      UNION ALL

      SELECT 'relation', format('%I.%I', namespace.nspname, relation.relname)
      FROM pg_class relation
      JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname <> 'information_schema'
        AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
        AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
        AND NOT EXISTS (
          SELECT 1 FROM allowed_relations allowed
          WHERE allowed.schema_name = namespace.nspname
            AND allowed.relation_name = relation.relname
            AND allowed.relation_kind = relation.relkind::text
        )
        AND NOT (
          namespace.nspname = 'drizzle'
          AND (
            relation.relname IN (
              '__drizzle_migrations',
              '__drizzle_migrations_plugin_capabilities',
              '__drizzle_migrations_plugin_example'
            )
            OR relation.relname IN (
              '__drizzle_migrations_id_seq',
              '__drizzle_migrations_plugin_capabilities_id_seq',
              '__drizzle_migrations_plugin_example_id_seq'
            )
          )
        )
        AND NOT EXISTS (
          SELECT 1
          FROM pg_depend dependency
          JOIN pg_extension extension_inventory ON extension_inventory.oid = dependency.refobjid
          JOIN allowed_extensions allowed ON allowed.extname = extension_inventory.extname
          WHERE dependency.classid = 'pg_class'::regclass
            AND dependency.objid = relation.oid
            AND dependency.objsubid = 0
            AND dependency.refclassid = 'pg_extension'::regclass
            AND dependency.deptype = 'e'
        )

      UNION ALL

      SELECT 'routine', format('%I.%s', namespace.nspname,
        routine.proname || '(' || pg_get_function_identity_arguments(routine.oid) || ')')
      FROM pg_proc routine
      JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
      WHERE namespace.nspname <> 'information_schema'
        AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
        AND NOT EXISTS (
          SELECT 1 FROM allowed_routines allowed
          WHERE allowed.schema_name = namespace.nspname
            AND allowed.routine_identity =
              routine.proname || '(' || pg_get_function_identity_arguments(routine.oid) || ')'
        )
        AND NOT EXISTS (
          SELECT 1
          FROM pg_depend dependency
          JOIN pg_extension extension_inventory ON extension_inventory.oid = dependency.refobjid
          JOIN allowed_extensions allowed ON allowed.extname = extension_inventory.extname
          WHERE dependency.classid = 'pg_proc'::regclass
            AND dependency.objid = routine.oid
            AND dependency.refclassid = 'pg_extension'::regclass
            AND dependency.deptype = 'e'
        )

      UNION ALL

      SELECT 'type', format('%I.%I', namespace.nspname, type_inventory.typname)
      FROM pg_type type_inventory
      JOIN pg_namespace namespace ON namespace.oid = type_inventory.typnamespace
      WHERE namespace.nspname <> 'information_schema'
        AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
        AND type_inventory.typrelid = 0
        AND type_inventory.typelem = 0
        AND type_inventory.typtype IN ('d', 'e', 'r', 'm')
        AND NOT (
          namespace.nspname = 'public'
          AND EXISTS (SELECT 1 FROM allowed_types allowed WHERE allowed.type_name = type_inventory.typname)
        )
        AND NOT EXISTS (
          SELECT 1
          FROM pg_depend dependency
          JOIN pg_extension extension_inventory ON extension_inventory.oid = dependency.refobjid
          JOIN allowed_extensions allowed ON allowed.extname = extension_inventory.extname
          WHERE dependency.classid = 'pg_type'::regclass
            AND dependency.objid = type_inventory.oid
            AND dependency.refclassid = 'pg_extension'::regclass
            AND dependency.deptype = 'e'
        )

      UNION ALL SELECT 'extension', extension_inventory.extname
      FROM pg_extension extension_inventory
      WHERE extension_inventory.extname <> 'plpgsql'
        AND NOT EXISTS (
          SELECT 1 FROM allowed_extensions allowed WHERE allowed.extname = extension_inventory.extname
        )
      UNION ALL SELECT 'foreign data wrapper', wrapper.fdwname FROM pg_foreign_data_wrapper wrapper
      WHERE NOT EXISTS (
        SELECT 1 FROM pg_depend dependency
        JOIN pg_extension extension_inventory ON extension_inventory.oid = dependency.refobjid
        JOIN allowed_extensions allowed ON allowed.extname = extension_inventory.extname
        WHERE dependency.classid = 'pg_foreign_data_wrapper'::regclass
          AND dependency.objid = wrapper.oid
          AND dependency.refclassid = 'pg_extension'::regclass
          AND dependency.deptype = 'e'
      )
      UNION ALL SELECT 'foreign server', server.srvname FROM pg_foreign_server server
      UNION ALL SELECT 'event trigger', trigger.evtname FROM pg_event_trigger trigger
      UNION ALL SELECT 'publication', publication.pubname FROM pg_publication publication
      UNION ALL SELECT 'large object', large_object.oid::text FROM pg_largeobject_metadata large_object
    )
    SELECT count(*)::int AS unexpected_count,
      min(kind || ':' || identity) AS first_unexpected
    FROM unexpected
  `);
  const [row] = queryRows<{ unexpected_count: number; first_unexpected: string | null }>(result);
  if ((row?.unexpected_count ?? 0) > 0) {
    throw new Error(
      `[migrate] Database contains catalog object outside the checked-in Steward inventory (${row?.first_unexpected ?? "unknown"}); refusing a shared database`,
    );
  }
}

async function assertBundledPluginLedgerIntegrity(db: MigrationQueryExecutor): Promise<void> {
  type PluginEffect =
    | { kind: "relation"; schema: string; name: string; relationKind: "r" | "S" }
    | { kind: "routine"; schema: string; name: string }
    | { kind: "trigger"; schema: string; table: string; name: string }
    | { kind: "policy"; schema: string; table: string; name: string };
  type PluginMigrationFingerprint = { tag: string; effects: PluginEffect[] };
  type BundledPlugin = {
    id: string;
    migrationsFolder: string;
    fingerprints: PluginMigrationFingerprint[];
  };

  const bundledPlugins: BundledPlugin[] = [
    {
      id: "capabilities",
      migrationsFolder: new URL("../../plugin-capabilities/drizzle", import.meta.url).pathname,
      fingerprints: [
        {
          tag: "0000_capabilities",
          effects: [
            { kind: "relation", schema: "public", name: "capabilities", relationKind: "r" },
            {
              kind: "relation",
              schema: "public",
              name: "capability_grants",
              relationKind: "r",
            },
          ],
        },
        {
          tag: "0001_capability_invocations",
          effects: [
            {
              kind: "relation",
              schema: "public",
              name: "capability_invocations",
              relationKind: "r",
            },
          ],
        },
        {
          tag: "0002_agent_grant_lifecycle",
          effects: [
            { kind: "routine", schema: "public", name: "capability_grants_agent_fence()" },
            {
              kind: "routine",
              schema: "public",
              name: "capability_grants_guard_agent_delete()",
            },
            {
              kind: "trigger",
              schema: "public",
              table: "capability_grants",
              name: "capability_grants_agent_fence",
            },
            {
              kind: "trigger",
              schema: "public",
              table: "agents",
              name: "capability_grants_guard_agent_delete",
            },
          ],
        },
        {
          tag: "0003_tenant_rls_policies",
          effects: [
            {
              kind: "policy",
              schema: "public",
              table: "capabilities",
              name: "steward_tenant_isolation",
            },
            {
              kind: "policy",
              schema: "public",
              table: "capability_grants",
              name: "steward_tenant_isolation",
            },
            {
              kind: "policy",
              schema: "public",
              table: "capability_invocations",
              name: "steward_tenant_isolation",
            },
          ],
        },
        {
          tag: "0004_capability_rate_limit_buckets",
          effects: [
            {
              kind: "relation",
              schema: "public",
              name: "capability_rate_limit_buckets",
              relationKind: "r",
            },
            {
              kind: "routine",
              schema: "public",
              name: "capability_rate_limit_bucket_agent_fence()",
            },
            {
              kind: "trigger",
              schema: "public",
              table: "capability_rate_limit_buckets",
              name: "capability_rate_limit_bucket_agent_fence",
            },
            {
              kind: "policy",
              schema: "public",
              table: "capability_rate_limit_buckets",
              name: "steward_tenant_isolation",
            },
          ],
        },
        {
          tag: "0005_activated_rls_inheritance",
          effects: [],
        },
      ],
    },
    {
      id: "example",
      migrationsFolder: new URL("../../plugin-example/drizzle", import.meta.url).pathname,
      fingerprints: [
        {
          tag: "0000_example_log",
          effects: [
            { kind: "relation", schema: "public", name: "example_log", relationKind: "r" },
            {
              kind: "relation",
              schema: "public",
              name: "example_log_id_seq",
              relationKind: "S",
            },
          ],
        },
      ],
    },
  ];

  const effectIdentity = (effect: PluginEffect): string => {
    switch (effect.kind) {
      case "relation":
        return `relation:${effect.schema}.${effect.name}:${effect.relationKind}`;
      case "routine":
        return `routine:${effect.schema}.${effect.name}`;
      case "trigger":
        return `trigger:${effect.schema}.${effect.table}.${effect.name}`;
      case "policy":
        return `policy:${effect.schema}.${effect.table}.${effect.name}`;
    }
  };

  for (const plugin of bundledPlugins) {
    const pluginJournal = JSON.parse(
      readFileSync(`${plugin.migrationsFolder}/meta/_journal.json`, "utf8"),
    ) as { entries?: Array<{ tag?: unknown; when?: unknown }> };
    if (!Array.isArray(pluginJournal.entries) || pluginJournal.entries.length === 0) {
      throw new Error(`[migrate] Bundled plugin ${plugin.id} journal is malformed`);
    }
    const pluginEntries = pluginJournal.entries;
    const crypto = require("node:crypto") as typeof import("node:crypto");
    const expectedEntries = pluginEntries.map((entry) => {
      if (typeof entry.tag !== "string" || !Number.isSafeInteger(entry.when)) {
        throw new Error(`[migrate] Bundled plugin ${plugin.id} journal is malformed`);
      }
      return {
        createdAt: entry.when as number,
        hash: crypto
          .createHash("sha256")
          .update(readFileSync(`${plugin.migrationsFolder}/${entry.tag}.sql`))
          .digest("hex"),
      };
    });
    if (
      plugin.fingerprints.length !== expectedEntries.length ||
      plugin.fingerprints.some(
        (fingerprint, index) => fingerprint.tag !== pluginEntries[index]?.tag,
      )
    ) {
      throw new Error(
        `[migrate] Bundled plugin ${plugin.id} fingerprint is out of sync with its journal`,
      );
    }

    const knownEffects = plugin.fingerprints.flatMap((fingerprint) => fingerprint.effects);
    const effectRows = knownEffects.map((effect) => {
      switch (effect.kind) {
        case "relation":
          return sql`(${effect.kind}, ${effect.schema}, ${effect.name}, ${effect.relationKind}, ${null})`;
        case "routine":
          return sql`(${effect.kind}, ${effect.schema}, ${effect.name}, ${null}, ${null})`;
        case "trigger":
        case "policy":
          return sql`(${effect.kind}, ${effect.schema}, ${effect.name}, ${null}, ${effect.table})`;
      }
    });
    const actualEffects = new Set(
      queryRows<{ identity: string }>(
        await db.execute(sql`
          WITH known_effects(effect_kind, schema_name, object_name, relation_kind, table_name) AS (
            VALUES ${sql.join(effectRows, sql`, `)}
          )
          SELECT
            'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
              relation.relkind::text AS identity
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          JOIN known_effects expected
            ON expected.effect_kind = 'relation'
            AND expected.schema_name = namespace.nspname
            AND expected.object_name = relation.relname
            AND expected.relation_kind = relation.relkind::text

          UNION ALL

          SELECT
            'routine:' || namespace.nspname || '.' || routine.proname || '(' ||
              pg_get_function_identity_arguments(routine.oid) || ')' AS identity
          FROM pg_proc routine
          JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
          JOIN known_effects expected
            ON expected.effect_kind = 'routine'
            AND expected.schema_name = namespace.nspname
            AND expected.object_name = routine.proname || '(' ||
              pg_get_function_identity_arguments(routine.oid) || ')'

          UNION ALL

          SELECT
            'trigger:' || namespace.nspname || '.' || relation.relname || '.' ||
              trigger.tgname AS identity
          FROM pg_trigger trigger
          JOIN pg_class relation ON relation.oid = trigger.tgrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          JOIN known_effects expected
            ON expected.effect_kind = 'trigger'
            AND expected.schema_name = namespace.nspname
            AND expected.table_name = relation.relname
            AND expected.object_name = trigger.tgname
          WHERE NOT trigger.tgisinternal

          UNION ALL

          SELECT
            'policy:' || namespace.nspname || '.' || relation.relname || '.' ||
              policy.polname AS identity
          FROM pg_policy policy
          JOIN pg_class relation ON relation.oid = policy.polrelid
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          JOIN known_effects expected
            ON expected.effect_kind = 'policy'
            AND expected.schema_name = namespace.nspname
            AND expected.table_name = relation.relname
            AND expected.object_name = policy.polname
        `),
      ).map((row) => row.identity),
    );

    const migrationsTable = `__drizzle_migrations_plugin_${plugin.id}`;
    const [shape] = queryRows<{ ledger_exists: boolean }>(
      await db.execute(
        sql`SELECT to_regclass(${`drizzle.${migrationsTable}`}) IS NOT NULL AS ledger_exists`,
      ),
    );
    if (!shape?.ledger_exists) {
      if (actualEffects.size > 0) {
        throw new Error(
          `[migrate] Bundled plugin ${plugin.id} objects exist without their checked-in migration ledger`,
        );
      }
      continue;
    }

    const rows = queryRows<{ hash: string; created_at: string | number | null }>(
      await db.execute(sql`
        SELECT hash, created_at
        FROM ${sql.identifier("drizzle")}.${sql.identifier(migrationsTable)}
        ORDER BY id ASC
      `),
    );
    if (rows.length > expectedEntries.length) {
      throw new Error(`[migrate] Bundled plugin ${plugin.id} ledger is ahead of this build`);
    }
    for (const [index, row] of rows.entries()) {
      const expected = expectedEntries[index];
      if (row.hash !== expected?.hash || Number(row.created_at) !== expected.createdAt) {
        throw new Error(
          `[migrate] Bundled plugin ${plugin.id} ledger is malformed or not owned by this build`,
        );
      }
    }
    const expectedEffects = new Set(
      plugin.fingerprints
        .slice(0, rows.length)
        .flatMap((fingerprint) => fingerprint.effects)
        .map(effectIdentity),
    );
    const missingEffect = [...expectedEffects].find((identity) => !actualEffects.has(identity));
    const unappliedEffect = [...actualEffects].find((identity) => !expectedEffects.has(identity));
    if (missingEffect || unappliedEffect) {
      throw new Error(
        `[migrate] Bundled plugin ${plugin.id} schema does not match its applied migration prefix` +
          ` (${missingEffect ? `missing ${missingEffect}` : `unapplied ${unappliedEffect}`})`,
      );
    }
  }
}

/**
 * Run drizzle-kit migrations under a Postgres advisory session lock so
 * concurrent API replicas don't race on startup. Returns the tags of
 * migrations applied during this call (empty if everything was up to date).
 *
 * On first run against a DB that pre-dates this migrator (the deploy script
 * used to `psql -f` each .sql by hand), we backfill `drizzle.__drizzle_migrations`
 * from the journal so the migrator doesn't try to re-apply non-idempotent DDL.
 * Heuristic: if `__drizzle_migrations` is empty AND `tenants` exists (was
 * created by 0000), the DB may have come from the psql loop. Before accepting
 * it, verify the complete 0000-0024 relation, migration-specific column, and
 * critical-index fingerprint. Then seed only entries through that tip —
 * seeding the whole current journal would silently skip every migration
 * between the DB's true tip and now, including constraint-only hardening
 * migrations whose absence produces no runtime error.
 */
export async function runMigrations(options?: {
  throughTag?: string;
}): Promise<{ applied: string[] }> {
  const timeouts = resolveMigrationTimeouts();
  const { client, db } = createDb(undefined, {
    max: 1,
    connectTimeoutSeconds: timeouts.connectSeconds,
    statementTimeoutMs: timeouts.statementMs,
    lockTimeoutMs: timeouts.advisoryLockMs,
    idleInTransactionTimeoutMs: timeouts.statementMs,
  });
  let overallTimedOut = false;
  let deadlineClose: Promise<void> | undefined;
  const overallTimer = setTimeout(() => {
    overallTimedOut = true;
    const close = client.end({ timeout: 0 });
    deadlineClose = close;
    void close.catch(() => undefined);
  }, timeouts.overallMs);
  let advisoryLockHeld = false;

  try {
    // Session-scoped advisory lock spans the whole migrator (which uses its
    // own transaction). Give this wait its own shorter server-side bound.
    await client`SELECT set_config('statement_timeout', ${`${timeouts.advisoryLockMs}ms`}, false)`;
    await client`SELECT pg_advisory_lock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
    advisoryLockHeld = true;
    await client`SELECT set_config('statement_timeout', ${`${timeouts.statementMs}ms`}, false)`;

    try {
      const journal = readJournal();
      const throughEntry = options?.throughTag
        ? journal.entries.find((entry) => entry.tag === options.throughTag)
        : undefined;
      if (options?.throughTag && !throughEntry) {
        throw new Error(`[migrate] Unknown terminal migration tag: ${options.throughTag}`);
      }
      await assertExactMigrationObjectInventory(db);
      await assertBundledPluginLedgerIntegrity(db);

      // Inspect without writing first. A privileged migration URL can be
      // misconfigured to point at an unrelated/shared database; even creating
      // our bookkeeping schema there would be an unacceptable mutation before
      // the fail-closed target check runs.
      const ledgerExists = (await client`
        SELECT to_regclass('drizzle.__drizzle_migrations') AS r
      `) as Array<{ r: string | null }>;
      const tenantsExists = (await client`
        SELECT to_regclass('public.tenants') AS r
      `) as Array<{ r: string | null }>;
      const auditEventsExists = (await client`
        SELECT to_regclass(${LEGACY_BACKFILL_FINGERPRINT_TABLE}) AS r
      `) as Array<{ r: string | null }>;
      const databaseInventory = (await client`
        WITH
        allowed_extensions(extname) AS (
          VALUES ('neon'), ('pg_stat_statements')
        ),
        ledger_shape AS (
          SELECT
            to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS ledger_exists,
            (
              NOT EXISTS (
                SELECT 1
                FROM pg_class relation
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'drizzle'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM pg_proc routine
                JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
                WHERE namespace.nspname = 'drizzle'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM pg_type type_inventory
                JOIN pg_namespace namespace ON namespace.oid = type_inventory.typnamespace
                WHERE namespace.nspname = 'drizzle'
                  AND type_inventory.typrelid = 0
                  AND type_inventory.typelem = 0
              )
            ) AS ledger_schema_empty,
            (
              EXISTS (
                SELECT 1
                FROM pg_class relation
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'drizzle'
                  AND relation.relname = '__drizzle_migrations'
                  AND relation.relkind = 'r'
              )
              AND (
                SELECT count(*) = 3
                  AND bool_or(
                    column_inventory.column_name = 'id'
                    AND column_inventory.data_type = 'integer'
                    AND column_inventory.is_nullable = 'NO'
                    AND column_inventory.column_default =
                      'nextval(''drizzle.__drizzle_migrations_id_seq''::regclass)'
                  )
                  AND bool_or(
                    column_inventory.column_name = 'hash'
                    AND column_inventory.data_type = 'text'
                    AND column_inventory.is_nullable = 'NO'
                  )
                  AND bool_or(
                    column_inventory.column_name = 'created_at'
                    AND column_inventory.data_type = 'bigint'
                    AND column_inventory.is_nullable = 'YES'
                  )
                FROM information_schema.columns column_inventory
                WHERE column_inventory.table_schema = 'drizzle'
                  AND column_inventory.table_name = '__drizzle_migrations'
              )
              AND EXISTS (
                SELECT 1
                FROM pg_constraint constraint_inventory
                WHERE constraint_inventory.conrelid =
                    to_regclass('drizzle.__drizzle_migrations')
                  AND constraint_inventory.contype = 'p'
                  AND pg_get_constraintdef(constraint_inventory.oid) = 'PRIMARY KEY (id)'
              )
              AND pg_get_serial_sequence(
                'drizzle.__drizzle_migrations',
                'id'
              ) = 'drizzle.__drizzle_migrations_id_seq'
              AND NOT EXISTS (
                SELECT 1
                FROM pg_class relation
                JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
                WHERE namespace.nspname = 'drizzle'
                  AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
                  AND NOT (
                    (relation.relname = '__drizzle_migrations' AND relation.relkind = 'r')
                    OR (
                      relation.relkind = 'r'
                      AND relation.relname ~ '^__drizzle_migrations_plugin_[a-z0-9_]+$'
                      AND (
                        SELECT count(*) = 3
                          AND bool_or(
                            column_inventory.column_name = 'id'
                            AND column_inventory.data_type = 'integer'
                            AND column_inventory.is_nullable = 'NO'
                          )
                          AND bool_or(
                            column_inventory.column_name = 'hash'
                            AND column_inventory.data_type = 'text'
                            AND column_inventory.is_nullable = 'NO'
                          )
                          AND bool_or(
                            column_inventory.column_name = 'created_at'
                            AND column_inventory.data_type = 'bigint'
                            AND column_inventory.is_nullable = 'YES'
                          )
                        FROM information_schema.columns column_inventory
                        WHERE column_inventory.table_schema = 'drizzle'
                          AND column_inventory.table_name = relation.relname
                      )
                      AND EXISTS (
                        SELECT 1
                        FROM pg_constraint constraint_inventory
                        WHERE constraint_inventory.conrelid = relation.oid
                          AND constraint_inventory.contype = 'p'
                          AND pg_get_constraintdef(constraint_inventory.oid) =
                            'PRIMARY KEY (id)'
                      )
                      AND pg_get_serial_sequence(
                        format('%I.%I', namespace.nspname, relation.relname),
                        'id'
                      ) IS NOT NULL
                    )
                    OR (
                      relation.relkind = 'S'
                      AND EXISTS (
                        SELECT 1
                        FROM pg_depend dependency
                        JOIN pg_class ledger_table
                          ON ledger_table.oid = dependency.refobjid
                        JOIN pg_namespace ledger_namespace
                          ON ledger_namespace.oid = ledger_table.relnamespace
                        JOIN pg_attribute ledger_column
                          ON ledger_column.attrelid = ledger_table.oid
                          AND ledger_column.attnum = dependency.refobjsubid
                        WHERE dependency.classid = 'pg_class'::regclass
                          AND dependency.objid = relation.oid
                          AND dependency.refclassid = 'pg_class'::regclass
                          AND dependency.deptype = 'a'
                          AND ledger_namespace.nspname = 'drizzle'
                          AND ledger_column.attname = 'id'
                          AND (
                            ledger_table.relname = '__drizzle_migrations'
                            OR ledger_table.relname ~
                              '^__drizzle_migrations_plugin_[a-z0-9_]+$'
                          )
                      )
                    )
                  )
              )
              AND NOT EXISTS (
                SELECT 1
                FROM pg_proc routine
                JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
                WHERE namespace.nspname = 'drizzle'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM pg_type type_inventory
                JOIN pg_namespace namespace ON namespace.oid = type_inventory.typnamespace
                WHERE namespace.nspname = 'drizzle'
                  AND type_inventory.typrelid = 0
                  AND type_inventory.typelem = 0
                  AND type_inventory.typtype IN ('d', 'e', 'r', 'm')
              )
            ) AS ledger_shape_matches
        ),
        namespaced_catalog_objects(classid, object_oid, namespace_oid, kind, identity) AS (
          SELECT 'pg_collation'::regclass::oid, oid, collnamespace, 'collation', collname
          FROM pg_collation
          UNION ALL
          SELECT 'pg_conversion'::regclass::oid, oid, connamespace, 'conversion', conname
          FROM pg_conversion
          UNION ALL
          SELECT 'pg_operator'::regclass::oid, oid, oprnamespace, 'operator', oprname
          FROM pg_operator
          UNION ALL
          SELECT 'pg_opclass'::regclass::oid, oid, opcnamespace, 'operator class', opcname
          FROM pg_opclass
          UNION ALL
          SELECT 'pg_opfamily'::regclass::oid, oid, opfnamespace, 'operator family', opfname
          FROM pg_opfamily
          UNION ALL
          SELECT 'pg_ts_config'::regclass::oid, oid, cfgnamespace, 'text search config', cfgname
          FROM pg_ts_config
          UNION ALL
          SELECT 'pg_ts_dict'::regclass::oid, oid, dictnamespace, 'text search dictionary', dictname
          FROM pg_ts_dict
          UNION ALL
          SELECT 'pg_ts_parser'::regclass::oid, oid, prsnamespace, 'text search parser', prsname
          FROM pg_ts_parser
          UNION ALL
          SELECT 'pg_ts_template'::regclass::oid, oid, tmplnamespace, 'text search template', tmplname
          FROM pg_ts_template
        ),
        unapproved_objects(kind, identity, always_reject) AS (
          SELECT 'schema', namespace.nspname, true
          FROM pg_namespace namespace
          CROSS JOIN ledger_shape
          WHERE namespace.nspname <> 'information_schema'
            AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            AND namespace.nspname NOT IN (
              'public', 'neon', 'steward_rls', 'steward_bootstrap'
            )
            AND NOT (
              namespace.nspname = 'drizzle'
              AND (
                ledger_shape.ledger_shape_matches
                OR ledger_shape.ledger_schema_empty
              )
            )

          UNION ALL

          SELECT
            'relation',
            format('%I.%I', namespace.nspname, relation.relname),
            namespace.nspname = 'neon'
              OR namespace.nspname NOT IN (
                'public', 'drizzle', 'steward_rls', 'steward_bootstrap'
              )
              OR (
                namespace.nspname = 'public'
                AND relation.relkind IN ('v', 'm', 'f', 'c')
              )
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN ledger_shape
          WHERE namespace.nspname <> 'information_schema'
            AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
            AND NOT (
              namespace.nspname = 'drizzle'
              AND ledger_shape.ledger_shape_matches
            )
            AND NOT EXISTS (
              SELECT 1
              FROM pg_depend dependency
              JOIN pg_extension extension_inventory
                ON extension_inventory.oid = dependency.refobjid
              JOIN allowed_extensions allowed
                ON allowed.extname = extension_inventory.extname
              WHERE dependency.classid = 'pg_class'::regclass
                AND dependency.objid = relation.oid
                AND dependency.objsubid = 0
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
            )

          UNION ALL

          SELECT
            'routine',
            format('%I.%I', namespace.nspname, routine.proname),
            namespace.nspname = 'neon'
              OR namespace.nspname NOT IN (
                'public', 'steward_rls', 'steward_bootstrap'
              )
          FROM pg_proc routine
          JOIN pg_namespace namespace ON namespace.oid = routine.pronamespace
          WHERE namespace.nspname <> 'information_schema'
            AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            AND NOT EXISTS (
              SELECT 1
              FROM pg_depend dependency
              JOIN pg_extension extension_inventory
                ON extension_inventory.oid = dependency.refobjid
              JOIN allowed_extensions allowed
                ON allowed.extname = extension_inventory.extname
              WHERE dependency.classid = 'pg_proc'::regclass
                AND dependency.objid = routine.oid
                AND dependency.objsubid = 0
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
            )

          UNION ALL

          SELECT
            'type',
            format('%I.%I', namespace.nspname, type_inventory.typname),
            namespace.nspname = 'neon'
              OR namespace.nspname NOT IN (
                'public', 'steward_rls', 'steward_bootstrap'
              )
          FROM pg_type type_inventory
          JOIN pg_namespace namespace ON namespace.oid = type_inventory.typnamespace
          WHERE namespace.nspname <> 'information_schema'
            AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            AND type_inventory.typrelid = 0
            AND type_inventory.typelem = 0
            AND type_inventory.typtype IN ('d', 'e', 'r', 'm')
            AND NOT EXISTS (
              SELECT 1
              FROM pg_depend dependency
              JOIN pg_extension extension_inventory
                ON extension_inventory.oid = dependency.refobjid
              JOIN allowed_extensions allowed
                ON allowed.extname = extension_inventory.extname
              WHERE dependency.classid = 'pg_type'::regclass
                AND dependency.objid = type_inventory.oid
                AND dependency.objsubid = 0
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
            )

          UNION ALL

          SELECT
            catalog_object.kind,
            format('%I.%I', namespace.nspname, catalog_object.identity),
            namespace.nspname = 'neon'
              OR namespace.nspname NOT IN (
                'public', 'steward_rls', 'steward_bootstrap'
              )
          FROM namespaced_catalog_objects catalog_object
          JOIN pg_namespace namespace ON namespace.oid = catalog_object.namespace_oid
          WHERE namespace.nspname <> 'information_schema'
            AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\'
            AND NOT EXISTS (
              SELECT 1
              FROM pg_depend dependency
              JOIN pg_extension extension_inventory
                ON extension_inventory.oid = dependency.refobjid
              JOIN allowed_extensions allowed
                ON allowed.extname = extension_inventory.extname
              WHERE dependency.classid = catalog_object.classid
                AND dependency.objid = catalog_object.object_oid
                AND dependency.objsubid = 0
                AND dependency.refclassid = 'pg_extension'::regclass
                AND dependency.deptype = 'e'
            )

          UNION ALL

          SELECT 'extension', extension_inventory.extname, true
          FROM pg_extension extension_inventory
          WHERE extension_inventory.extname <> 'plpgsql'
            AND NOT EXISTS (
              SELECT 1
              FROM allowed_extensions allowed
              WHERE allowed.extname = extension_inventory.extname
            )

          UNION ALL

          SELECT 'foreign data wrapper', wrapper.fdwname, true
          FROM pg_foreign_data_wrapper wrapper
          WHERE NOT EXISTS (
            SELECT 1
            FROM pg_depend dependency
            JOIN pg_extension extension_inventory
              ON extension_inventory.oid = dependency.refobjid
            JOIN allowed_extensions allowed
              ON allowed.extname = extension_inventory.extname
            WHERE dependency.classid = 'pg_foreign_data_wrapper'::regclass
              AND dependency.objid = wrapper.oid
              AND dependency.objsubid = 0
              AND dependency.refclassid = 'pg_extension'::regclass
              AND dependency.deptype = 'e'
          )

          UNION ALL

          SELECT 'foreign server', server.srvname, true FROM pg_foreign_server server

          UNION ALL

          SELECT 'event trigger', trigger.evtname, true FROM pg_event_trigger trigger

          UNION ALL

          SELECT 'publication', publication.pubname, true FROM pg_publication publication

          UNION ALL

          SELECT 'large object', large_object.oid::text, true
          FROM pg_largeobject_metadata large_object
        )
        SELECT
          (SELECT count(*)::int FROM unapproved_objects) AS user_object_count,
          (SELECT ledger_exists FROM ledger_shape) AS ledger_exists,
          (SELECT ledger_shape_matches FROM ledger_shape) AS ledger_shape_matches,
          (SELECT count(*)::int FROM unapproved_objects) AS unapproved_object_count,
          (
            SELECT count(*)::int FROM unapproved_objects WHERE always_reject
          ) AS always_rejected_object_count,
          (
            SELECT count(*) = 28
            FROM (VALUES
              ('agents'), ('approval_queue'), ('encrypted_keys'), ('policies'),
              ('tenants'), ('transactions'), ('accounts'), ('authenticators'), ('sessions'),
              ('user_tenants'), ('users'), ('agent_wallets'), ('encrypted_chain_keys'),
              ('webhook_deliveries'), ('secrets'), ('secret_routes'), ('proxy_audit_log'),
              ('tenant_configs'), ('webhook_configs'), ('auto_approval_rules'),
              ('auth_kv_store'), ('refresh_tokens'), ('policy_templates'),
              ('agent_registrations'), ('reputation_cache'), ('registry_index'),
              ('trade_sessions'), ('audit_events')
            ) AS required(relation_name)
            WHERE to_regclass('public.' || required.relation_name) IS NOT NULL
          ) AND (
            SELECT count(*) = 21
            FROM (VALUES
              ('agents', 'owner_user_id'), ('agents', 'wallet_type'),
              ('tenant_configs', 'allowed_origins'), ('tenant_configs', 'join_mode'),
              ('tenant_configs', 'email_config'), ('users', 'wallet_chain'),
              ('proxy_audit_log', 'reason'),
              ('accounts', 'access_token_iv'), ('accounts', 'access_token_tag'),
              ('accounts', 'access_token_salt'), ('accounts', 'refresh_token_iv'),
              ('accounts', 'refresh_token_tag'), ('accounts', 'refresh_token_salt'),
              ('encrypted_chain_keys', 'venue'), ('encrypted_chain_keys', 'purpose'),
              ('agent_wallets', 'venue'),
              ('audit_events', 'tenant_id'), ('audit_events', 'seq'),
              ('audit_events', 'prev_hash'), ('audit_events', 'hmac'),
              ('audit_events', 'action')
            ) AS required(relation_name, column_name)
            WHERE EXISTS (
              SELECT 1
              FROM information_schema.columns column_inventory
              WHERE column_inventory.table_schema = 'public'
                AND column_inventory.table_name = required.relation_name
                AND column_inventory.column_name = required.column_name
            )
          ) AND (
            SELECT count(*) = 6
            FROM (VALUES
              ('auth_kv_store_expires_idx'), ('refresh_tokens_token_hash_idx'),
              ('agent_registrations_tenant_agent_chain_idx'),
              ('encrypted_chain_keys_agent_chain_venue_idx'),
              ('trade_sessions_agent_venue_status_idx'), ('audit_events_tenant_seq_idx')
            ) AS required(index_name)
            WHERE to_regclass('public.' || required.index_name) IS NOT NULL
          ) AS legacy_fingerprint_matches
      `) as Array<{
        user_object_count: number;
        ledger_exists: boolean;
        ledger_shape_matches: boolean;
        unapproved_object_count: number;
        always_rejected_object_count: number;
        legacy_fingerprint_matches: boolean;
      }>;
      const databaseShape: CoreMigrationDatabaseShape = {
        tenantsExists: Boolean(tenantsExists[0]?.r),
        auditEventsExists: Boolean(auditEventsExists[0]?.r),
        legacyFingerprintMatches: databaseInventory[0]?.legacy_fingerprint_matches === true,
        userObjectCount: databaseInventory[0]?.user_object_count ?? 0,
        unapprovedObjectCount: databaseInventory[0]?.unapproved_object_count ?? 0,
        alwaysRejectedObjectCount: databaseInventory[0]?.always_rejected_object_count ?? 0,
        coreLedgerExists: databaseInventory[0]?.ledger_exists ?? false,
        coreLedgerShapeMatches: databaseInventory[0]?.ledger_shape_matches ?? false,
      };
      let existingRows: CoreMigrationLedgerRow[] = [];
      if (databaseShape.coreLedgerExists && !databaseShape.coreLedgerShapeMatches) {
        throw new Error(
          "[migrate] drizzle.__drizzle_migrations does not match Steward's migration-ledger shape; refusing the wrong database",
        );
      }
      if (ledgerExists[0]?.r) {
        existingRows = (await client`
          SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC
        `) as CoreMigrationLedgerRow[];
      }
      assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape, {
        allowShippedTimestampCollision: true,
      });
      if (existingRows.length === journal.entries.length) {
        assertCoreMigrationLedgerIntegrity(existingRows, journal, databaseShape, {
          requireComplete: true,
        });
        return { applied: [] };
      }

      // Repeat the ownership and ledger checks inside the transaction that
      // performs the migration. The earlier inspection guarantees we do not
      // write to an already-wrong target; this one prevents a concurrent DDL
      // writer from changing the target between inspection and mutation.
      return await db.transaction(async (tx) => {
        await assertExactMigrationObjectInventory(tx);
        await assertBundledPluginLedgerIntegrity(tx);
        const txDrizzleSchemaExists = queryRows<{ r: string | null }>(
          await tx.execute(sql`SELECT to_regnamespace('drizzle') AS r`),
        );
        const txLedgerExists = queryRows<{ r: string | null }>(
          await tx.execute(sql`SELECT to_regclass('drizzle.__drizzle_migrations') AS r`),
        );
        const txTenantsExists = queryRows<{ r: string | null }>(
          await tx.execute(sql`SELECT to_regclass('public.tenants') AS r`),
        );
        let transactionalRows: CoreMigrationLedgerRow[] = [];
        if (txLedgerExists[0]?.r) {
          transactionalRows = queryRows<CoreMigrationLedgerRow>(
            await tx.execute(
              sql`SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC`,
            ),
          );
        }
        assertCoreMigrationLedgerIntegrity(
          transactionalRows,
          journal,
          {
            ...databaseShape,
            tenantsExists: Boolean(txTenantsExists[0]?.r),
            coreLedgerExists: Boolean(txLedgerExists[0]?.r),
          },
          { allowShippedTimestampCollision: true },
        );

        // Only a verified empty/legacy Steward target may receive the ledger.
        // Avoid even idempotent CREATE statements once admin topology/the ledger
        // exists: PostgreSQL requires database/schema CREATE before checking IF
        // NOT EXISTS, which would make an already-complete runtime migration
        // probe depend on a release-only privilege.
        if (!txDrizzleSchemaExists[0]?.r) {
          await tx.execute(sql`CREATE SCHEMA drizzle`);
        }
        if (!txLedgerExists[0]?.r) {
          await tx.execute(sql`
          CREATE TABLE drizzle.__drizzle_migrations (
            id SERIAL PRIMARY KEY,
            hash text NOT NULL,
            created_at bigint
          )
        `);
        }

        // Backfill: legacy DB previously migrated by the psql loop.
        if (transactionalRows.length === 0 && txTenantsExists[0]?.r) {
          // Fingerprint the psql-era tip before trusting the heuristic: a DB
          // frozen at an older tip must fail loudly here, not be seeded with
          // migrations it never applied.
          if (!databaseShape.auditEventsExists) {
            throw new Error(
              `[migrate] Legacy DB detected (public.tenants exists) but fingerprint table ` +
                `${LEGACY_BACKFILL_FINGERPRINT_TABLE} is missing — the DB predates migration ` +
                `${LEGACY_BACKFILL_TIP_TAG}. Refusing to seed __drizzle_migrations: entries past ` +
                `the DB's true tip would be silently skipped (including security-hardening ` +
                `migrations). Reconcile the schema manually, then re-run migrations.`,
            );
          }
          const backfillEntries = selectLegacyBackfillEntries(journal);
          console.log(
            `[migrate] Legacy DB detected — seeding __drizzle_migrations with ${backfillEntries.length} ` +
              `entries through ${LEGACY_BACKFILL_TIP_TAG}; the migrator will apply the remaining ` +
              `${journal.entries.length - backfillEntries.length} journal entrie(s) normally`,
          );
          for (const entry of backfillEntries) {
            const hash = hashMigration(entry.tag);
            await tx.execute(sql`
            INSERT INTO drizzle.__drizzle_migrations ("hash", "created_at")
            VALUES (${hash}, ${entry.when})
          `);
          }
          transactionalRows = queryRows<CoreMigrationLedgerRow>(
            await tx.execute(
              sql`SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC`,
            ),
          );
          assertCoreMigrationLedgerIntegrity(transactionalRows, journal, databaseShape);
        }

        const beforeCount = queryRows<{ n: number }>(
          await tx.execute(sql`SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`),
        )[0].n;

        if (throughEntry) {
          const appliedIdentities = new Set(
            transactionalRows.map((row) => `${Number(row.created_at)}:${row.hash}`),
          );
          for (const migration of readMigrationFiles({ migrationsFolder: MIGRATIONS_FOLDER })) {
            if (migration.folderMillis > throughEntry.when) continue;
            const identity = `${migration.folderMillis}:${migration.hash}`;
            if (appliedIdentities.has(identity)) continue;
            for (const statement of migration.sql) await tx.execute(sql.raw(statement));
            await tx.execute(sql`
              INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
              VALUES (${migration.hash}, ${migration.folderMillis})
            `);
            appliedIdentities.add(identity);
          }
        } else {
          if (await recoverShippedTimestampCollision(tx, transactionalRows, journal)) {
            transactionalRows = queryRows<CoreMigrationLedgerRow>(
              await tx.execute(
                sql`SELECT id, hash, created_at FROM drizzle.__drizzle_migrations ORDER BY id ASC`,
              ),
            );
            assertCoreMigrationLedgerIntegrity(transactionalRows, journal, databaseShape);
          }

          // The postgres-js migrator normally opens its own transaction. We are
          // already inside the ownership-check transaction, so give it the same
          // dialect with a transaction-local session whose nested transaction is
          // the current atomic unit.
          const txInternals = tx as unknown as { dialect: unknown };
          const migrationDb = {
            dialect: txInternals.dialect,
            session: {
              execute: (query: ReturnType<typeof sql>) => tx.execute(query),
              all: async (query: ReturnType<typeof sql>) => queryRows(await tx.execute(query)),
              transaction: async <T>(use: (migrationTx: typeof tx) => Promise<T>) => use(tx),
            },
          } as unknown as PostgresJsDatabase<Record<string, unknown>>;
          await migrate(migrationDb, { migrationsFolder: MIGRATIONS_FOLDER });
        }

        const afterRows = queryRows<CoreMigrationLedgerRow>(
          await tx.execute(sql`
          SELECT id, hash, created_at
          FROM drizzle.__drizzle_migrations
          ORDER BY id ASC
        `),
        );
        const [postMigrationShape] = queryRows<{
          tenants_exists: boolean;
          audit_events_exists: boolean;
          legacy_fingerprint_matches: boolean;
          user_object_count: number;
        }>(
          await tx.execute(sql`
        SELECT
          to_regclass('public.tenants') IS NOT NULL AS tenants_exists,
          to_regclass(${LEGACY_BACKFILL_FINGERPRINT_TABLE}) IS NOT NULL AS audit_events_exists,
          (
            SELECT count(*) = 28
            FROM (VALUES
              ('agents'), ('approval_queue'), ('encrypted_keys'), ('policies'),
              ('tenants'), ('transactions'), ('accounts'), ('authenticators'), ('sessions'),
              ('user_tenants'), ('users'), ('agent_wallets'), ('encrypted_chain_keys'),
              ('webhook_deliveries'), ('secrets'), ('secret_routes'), ('proxy_audit_log'),
              ('tenant_configs'), ('webhook_configs'), ('auto_approval_rules'),
              ('auth_kv_store'), ('refresh_tokens'), ('policy_templates'),
              ('agent_registrations'), ('reputation_cache'), ('registry_index'),
              ('trade_sessions'), ('audit_events')
            ) AS required(relation_name)
            WHERE to_regclass('public.' || required.relation_name) IS NOT NULL
          ) AND (
            SELECT count(*) = 21
            FROM (VALUES
              ('agents', 'owner_user_id'), ('agents', 'wallet_type'),
              ('tenant_configs', 'allowed_origins'), ('tenant_configs', 'join_mode'),
              ('tenant_configs', 'email_config'), ('users', 'wallet_chain'),
              ('proxy_audit_log', 'reason'),
              ('accounts', 'access_token_iv'), ('accounts', 'access_token_tag'),
              ('accounts', 'access_token_salt'), ('accounts', 'refresh_token_iv'),
              ('accounts', 'refresh_token_tag'), ('accounts', 'refresh_token_salt'),
              ('encrypted_chain_keys', 'venue'), ('encrypted_chain_keys', 'purpose'),
              ('agent_wallets', 'venue'),
              ('audit_events', 'tenant_id'), ('audit_events', 'seq'),
              ('audit_events', 'prev_hash'), ('audit_events', 'hmac'),
              ('audit_events', 'action')
            ) AS required(relation_name, column_name)
            WHERE EXISTS (
              SELECT 1
              FROM information_schema.columns column_inventory
              WHERE column_inventory.table_schema = 'public'
                AND column_inventory.table_name = required.relation_name
                AND column_inventory.column_name = required.column_name
            )
          ) AND (
            SELECT count(*) = 6
            FROM (VALUES
              ('auth_kv_store_expires_idx'), ('refresh_tokens_token_hash_idx'),
              ('agent_registrations_tenant_agent_chain_idx'),
              ('encrypted_chain_keys_agent_chain_venue_idx'),
              ('trade_sessions_agent_venue_status_idx'), ('audit_events_tenant_seq_idx')
            ) AS required(index_name)
            WHERE to_regclass('public.' || required.index_name) IS NOT NULL
          ) AS legacy_fingerprint_matches,
          0::int AS user_object_count
        FROM pg_class relation
        JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
      `),
        );
        const completionJournal = throughEntry
          ? {
              ...journal,
              entries: journal.entries.slice(0, journal.entries.indexOf(throughEntry) + 1),
            }
          : journal;
        assertCoreMigrationLedgerIntegrity(
          afterRows,
          completionJournal,
          {
            tenantsExists: postMigrationShape?.tenants_exists ?? false,
            auditEventsExists: postMigrationShape?.audit_events_exists ?? false,
            legacyFingerprintMatches: postMigrationShape?.legacy_fingerprint_matches ?? false,
            userObjectCount: postMigrationShape?.user_object_count ?? 0,
          },
          {
            requireComplete: true,
          },
        );

        const newRows = afterRows.slice(beforeCount);
        const tagByHash = new Map<string, string>();
        for (const entry of journal.entries) tagByHash.set(hashMigration(entry.tag), entry.tag);
        const applied = newRows.map((r) => tagByHash.get(r.hash) ?? r.hash);

        await assertExactMigrationObjectInventory(tx);
        await assertBundledPluginLedgerIntegrity(tx);
        return { applied };
      });
    } finally {
      if (advisoryLockHeld && !overallTimedOut) {
        await client`SELECT pg_advisory_unlock(hashtextextended(${ADVISORY_LOCK_KEY}, 0))`;
      }
    }
  } catch (error) {
    if (overallTimedOut) {
      throw new Error(`[migrate] Migration exceeded the ${timeouts.overallMs}ms overall timeout`, {
        cause: error,
      });
    }
    throw error;
  } finally {
    clearTimeout(overallTimer);
    if (deadlineClose) await deadlineClose.catch(() => undefined);
    else await client.end({ timeout: 0 });
  }
}

const isEntrypoint = process.argv[1] === new URL(import.meta.url).pathname;

if (isEntrypoint) {
  runMigrations()
    .then(({ applied }) => {
      if (applied.length === 0) {
        console.log("[migrate] Already up to date.");
      } else {
        console.log(`[migrate] Applied ${applied.length} migration(s):`);
        for (const tag of applied) console.log(`  - ${tag}`);
      }
    })
    .catch((error) => {
      console.error("Failed to run migrations", redactedThrownDiagnostics(error));
      process.exitCode = 1;
    });
}
