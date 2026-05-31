import type {
  ApprovalConfig,
  PolicyExposureConfig,
  PolicyResult,
  PolicyTemplate,
  SecretRoutePreset,
  TenantFeatureFlags,
  TenantTheme,
} from "@stwd/shared";
import { relations, sql } from "drizzle-orm";
import {
  bigint,
  bigserial,
  boolean,
  customType,
  foreignKey,
  index,
  integer,
  jsonb,
  numeric,
  pgEnum,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

// Postgres BYTEA column. Typed as Uint8Array to avoid the Node `Buffer` vs
// Cloudflare workers-types Buffer conflict that bites when both type packs
// are in scope. The runtime value is whatever the driver returns; callers
// normalize it (see packages/api/src/services/audit.ts toU8 helper).
const bytea = customType<{ data: Uint8Array; default: false; notNull: false }>({
  dataType() {
    return "bytea";
  },
});

export interface TenantEmailConfig {
  /**
   * Per-tenant Resend provider config. Optional - a tenant can also leave
   * this entirely empty and only set `magicLinkBaseUrl` to override the
   * magic-link target while continuing to use the global RESEND_API_KEY.
   */
  provider?: "resend";
  apiKeyEncrypted?: string;
  from?: string;
  replyTo?: string;
  templateId?: string;
  subjectOverride?: string;
  /**
   * Optional override for the magic-link `baseUrl`. When set, magic links
   * will be built against this URL (e.g. "https://waifu.fun") instead of
   * Steward's APP_URL. Lets third-party apps own their own email-callback
   * landing page and call POST /auth/email/verify directly to mint a JWT.
   *
   * If unset, falls back to APP_URL and Steward handles the callback via
   * its built-in GET /auth/callback/email handler (which redirects to
   * EMAIL_AUTH_REDIRECT_BASE_URL/login). Existing tenants are unaffected.
   */
  magicLinkBaseUrl?: string;
  /**
   * Optional path on `magicLinkBaseUrl` that the magic link points at.
   * Defaults to "/auth/email/verify" when `magicLinkBaseUrl` is set.
   * Has no effect when `magicLinkBaseUrl` is unset.
   */
  magicLinkCallbackPath?: string;
}

export const chainFamilyEnum = pgEnum("chain_family", ["evm", "solana"]);

export const policyTypeEnum = pgEnum("policy_type", [
  "spending-limit",
  "approved-addresses",
  "auto-approve-threshold",
  "time-window",
  "rate-limit",
  "allowed-chains",
  "condition-set",
  "contract-allowlist",
  "reputation-threshold",
  "reputation-scaling",
  "venue-allowlist",
  "leverage-cap",
]);

export const transactionStatusEnum = pgEnum("transaction_status", [
  "pending",
  "approved",
  "rejected",
  "signed",
  "broadcast",
  "confirmed",
  "failed",
]);

export const approvalQueueStatusEnum = pgEnum("approval_queue_status", [
  "pending",
  "approved",
  "rejected",
]);

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow()
    .$onUpdateFn(() => sql`now()`),
};

export const tenants = pgTable("tenants", {
  id: varchar("id", { length: 64 }).primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  apiKeyHash: text("api_key_hash").notNull(),
  ownerAddress: varchar("owner_address", { length: 128 }),
  ...timestamps,
});

export const tenantConfigs = pgTable("tenant_configs", {
  tenantId: varchar("tenant_id", { length: 64 })
    .primaryKey()
    .references(() => tenants.id, { onDelete: "cascade" }),
  displayName: varchar("display_name", { length: 255 }),
  emailConfig: jsonb("email_config").$type<TenantEmailConfig>(),
  policyExposure: jsonb("policy_exposure").$type<PolicyExposureConfig>().notNull().default({}),
  policyTemplates: jsonb("policy_templates").$type<PolicyTemplate[]>().notNull().default([]),
  secretRoutePresets: jsonb("secret_route_presets")
    .$type<SecretRoutePreset[]>()
    .notNull()
    .default([]),
  approvalConfig: jsonb("approval_config").$type<ApprovalConfig>().notNull().default({}),
  featureFlags: jsonb("feature_flags").$type<TenantFeatureFlags>().notNull().default({}),
  theme: jsonb("theme").$type<TenantTheme>(),
  /** Allowed CORS origins for this tenant. Empty = fall back to wildcard (*). */
  allowedOrigins: text("allowed_origins").array().notNull().default([]),
  /** Controls how users can join: 'open' | 'invite' | 'closed'. Default 'open' for backward compat. */
  joinMode: varchar("join_mode", { length: 16 }).notNull().default("open"),
  ...timestamps,
});

export const agents = pgTable(
  "agents",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    walletAddress: varchar("wallet_address", { length: 128 }).notNull(),
    platformId: varchar("platform_id", { length: 255 }),
    erc8004TokenId: varchar("erc8004_token_id", { length: 255 }),
    ownerUserId: uuid("owner_user_id"),
    walletType: varchar("wallet_type", { length: 32 }).default("agent"),
    ...timestamps,
  },
  (table) => ({
    tenantIdIdx: index("agents_tenant_id_idx").on(table.tenantId),
  }),
);

export const encryptedKeys = pgTable(
  "encrypted_keys",
  {
    agentId: varchar("agent_id", { length: 64 })
      .primaryKey()
      .references(() => agents.id, { onDelete: "cascade" }),
    ciphertext: text("ciphertext").notNull(),
    iv: text("iv").notNull(),
    tag: text("tag").notNull(),
    salt: text("salt").notNull(),
  },
  (table) => ({
    agentIdUniqueIdx: uniqueIndex("encrypted_keys_agent_id_idx").on(table.agentId),
  }),
);

/**
 * Multi-chain wallet addresses for each agent.
 * One row per (agentId, chainFamily) pair.
 * New agents get both 'evm' and 'solana' rows from a single createAgent call.
 * Legacy agents (EVM-only) have no rows here; fall back to agents.walletAddress.
 */
export const agentWallets = pgTable(
  "agent_wallets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    chainFamily: chainFamilyEnum("chain_family").notNull(),
    address: varchar("address", { length: 128 }).notNull(),
    /**
     * Sprint 4: trading venue this wallet is scoped to (e.g. "hyperliquid").
     * NULL on legacy rows; vault lookups fall back to chainFamily when
     * venue isn't provided. See VenueId in @stwd/shared.
     */
    venue: text("venue"),
    /** Optional human-readable label, e.g. "perp", "spot", "ops". */
    purpose: text("purpose"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    agentChainVenueUniqueIdx: uniqueIndex("agent_wallets_agent_chain_venue_idx").on(
      table.agentId,
      table.chainFamily,
      sql`COALESCE(${table.venue}, '')`,
    ),
    /**
     * Sprint 4: partial unique index on the legacy NULL-venue subset.
     * Targeted by importKey()'s upsert (drizzle's onConflictDoUpdate
     * needs a named unique index, not an expression index).
     */
    agentChainLegacyIdx: uniqueIndex("agent_wallets_agent_chain_legacy_idx")
      .on(table.agentId, table.chainFamily)
      .where(sql`${table.venue} IS NULL`),
    agentIdIdx: index("agent_wallets_agent_id_idx").on(table.agentId),
  }),
);

export const agentSigners = pgTable(
  "agent_signers",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    signerType: varchar("signer_type", { length: 32 }).notNull(),
    subjectType: varchar("subject_type", { length: 32 }).notNull(),
    subjectId: varchar("subject_id", { length: 255 }).notNull(),
    address: varchar("address", { length: 128 }),
    chainFamily: chainFamilyEnum("chain_family"),
    label: varchar("label", { length: 255 }),
    permissions: text("permissions").array().notNull().default([]),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdBy: varchar("created_by", { length: 255 }),
    ...timestamps,
  },
  (table) => ({
    tenantAgentIdx: index("agent_signers_tenant_agent_idx").on(table.tenantId, table.agentId),
    agentStatusIdx: index("agent_signers_agent_status_idx").on(table.agentId, table.status),
    agentSubjectUniqueIdx: uniqueIndex("agent_signers_agent_subject_idx").on(
      table.agentId,
      table.subjectType,
      table.subjectId,
    ),
    tenantAgentFk: foreignKey({
      columns: [table.tenantId, table.agentId],
      foreignColumns: [agents.tenantId, agents.id],
      name: "agent_signers_tenant_agent_fk",
    }).onDelete("cascade"),
  }),
);

/**
 * Threshold signing/quorum policy objects for an agent wallet/account.
 * Member IDs reference `agent_signers.id` logically; they are kept as an
 * ordered text array so quorum membership can be updated atomically.
 */
export const agentKeyQuorums = pgTable(
  "agent_key_quorums",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    threshold: integer("threshold").notNull(),
    memberSignerIds: text("member_signer_ids").array().notNull().default([]),
    permissions: text("permissions").array().notNull().default([]),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdBy: varchar("created_by", { length: 255 }),
    ...timestamps,
  },
  (table) => ({
    tenantAgentIdx: index("agent_key_quorums_tenant_agent_idx").on(table.tenantId, table.agentId),
    agentStatusIdx: index("agent_key_quorums_agent_status_idx").on(table.agentId, table.status),
    tenantAgentFk: foreignKey({
      columns: [table.tenantId, table.agentId],
      foreignColumns: [agents.tenantId, agents.id],
      name: "agent_key_quorums_tenant_agent_fk",
    }).onDelete("cascade"),
  }),
);

/**
 * Encrypted private keys for each agent+chainFamily combination.
 * Composite PK: (agentId, chainFamily).
 * New agents store both 'evm' and 'solana' rows here.
 * Legacy agents (EVM-only) have no rows here; the vault falls back to `encryptedKeys`.
 */
export const encryptedChainKeys = pgTable(
  "encrypted_chain_keys",
  {
    /**
     * Sprint 4: surrogate PK so a single (agentId, chainFamily) can have
     * multiple rows, one per venue. The uniqueness invariant moves to
     * `agent_chain_venue_idx` below.
     */
    id: uuid("id").primaryKey().defaultRandom(),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    chainFamily: chainFamilyEnum("chain_family").notNull(),
    /**
     * Sprint 4: trading venue this key is scoped to (e.g. "hyperliquid").
     * NULL on legacy rows; vault lookups fall back to chainFamily when
     * venue isn't provided.
     */
    venue: text("venue"),
    /** Optional human-readable label, e.g. "perp", "spot", "ops". */
    purpose: text("purpose"),
    ciphertext: text("ciphertext").notNull(),
    iv: text("iv").notNull(),
    tag: text("tag").notNull(),
    salt: text("salt").notNull(),
  },
  (table) => ({
    agentChainVenueUniqueIdx: uniqueIndex("encrypted_chain_keys_agent_chain_venue_idx").on(
      table.agentId,
      table.chainFamily,
      sql`COALESCE(${table.venue}, '')`,
    ),
    agentIdIdx: index("encrypted_chain_keys_agent_id_idx").on(table.agentId),
  }),
);

export const policies = pgTable("policies", {
  id: varchar("id", { length: 64 }).primaryKey(),
  agentId: varchar("agent_id", { length: 64 })
    .notNull()
    .references(() => agents.id, { onDelete: "cascade" }),
  type: policyTypeEnum("type").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  config: jsonb("config").$type<Record<string, unknown>>().notNull().default({}),
  ...timestamps,
});

export const transactions = pgTable(
  "transactions",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    status: transactionStatusEnum("status").notNull(),
    toAddress: varchar("to_address", { length: 128 }).notNull(),
    value: text("value").notNull(),
    data: text("data"),
    chainId: integer("chain_id").notNull(),
    txHash: varchar("tx_hash", { length: 128 }),
    actionType: varchar("action_type", { length: 64 }),
    actionPayload: jsonb("action_payload").$type<Record<string, unknown>>(),
    policyResults: jsonb("policy_results").$type<PolicyResult[]>().notNull().default([]),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    signedAt: timestamp("signed_at", { withTimezone: true }),
    confirmedAt: timestamp("confirmed_at", { withTimezone: true }),
  },
  (table) => ({
    agentIdIdx: index("transactions_agent_id_idx").on(table.agentId),
  }),
);

export const approvalQueue = pgTable(
  "approval_queue",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    txId: varchar("tx_id", { length: 64 })
      .notNull()
      .references(() => transactions.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    status: approvalQueueStatusEnum("status").notNull().default("pending"),
    requestedAt: timestamp("requested_at", { withTimezone: true }).notNull().defaultNow(),
    requestedByType: varchar("requested_by_type", { length: 32 }),
    requestedById: varchar("requested_by_id", { length: 255 }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolvedBy: varchar("resolved_by", { length: 255 }),
    resolvedByType: varchar("resolved_by_type", { length: 32 }),
    resolvedById: varchar("resolved_by_id", { length: 255 }),
  },
  (table) => ({
    txIdUniqueIdx: uniqueIndex("approval_queue_tx_id_idx").on(table.txId),
    statusIdx: index("approval_queue_status_idx").on(table.status),
  }),
);

/**
 * First-class Privy-style intents for actions that may require authorization
 * before execution. Transaction-backed approvals keep using transactions +
 * approval_queue, while this table models generic wallet/policy/quorum intents.
 */
export const intents = pgTable(
  "intents",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 }).references(() => agents.id, {
      onDelete: "cascade",
    }),
    intentType: varchar("intent_type", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    resourceType: varchar("resource_type", { length: 64 }),
    resourceId: varchar("resource_id", { length: 255 }),
    createdByType: varchar("created_by_type", { length: 32 }).notNull().default("api"),
    createdById: varchar("created_by_id", { length: 255 }),
    createdByDisplayName: varchar("created_by_display_name", { length: 255 }),
    authorizationDetails: jsonb("authorization_details")
      .$type<Array<Record<string, unknown>>>()
      .notNull()
      .default([]),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull().default({}),
    executionResult: jsonb("execution_result").$type<Record<string, unknown>>(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    authorizedBy: varchar("authorized_by", { length: 255 }),
    canceledAt: timestamp("canceled_at", { withTimezone: true }),
    canceledBy: varchar("canceled_by", { length: 255 }),
    cancellationReason: text("cancellation_reason"),
    expiredAt: timestamp("expired_at", { withTimezone: true }),
    expiredBy: varchar("expired_by", { length: 255 }),
    rejectedAt: timestamp("rejected_at", { withTimezone: true }),
    rejectedBy: varchar("rejected_by", { length: 255 }),
    rejectionReason: text("rejection_reason"),
    executedBy: varchar("executed_by", { length: 255 }),
    failedAt: timestamp("failed_at", { withTimezone: true }),
    failedBy: varchar("failed_by", { length: 255 }),
    failureReason: text("failure_reason"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    authorizedAt: timestamp("authorized_at", { withTimezone: true }),
    executedAt: timestamp("executed_at", { withTimezone: true }),
  },
  (table) => ({
    tenantStatusIdx: index("intents_tenant_status_idx").on(table.tenantId, table.status),
    tenantCreatedIdx: index("intents_tenant_created_idx").on(table.tenantId, table.createdAt),
    agentIdx: index("intents_agent_idx").on(table.agentId),
    resourceIdx: index("intents_resource_idx").on(table.resourceType, table.resourceId),
    tenantAgentFk: foreignKey({
      columns: [table.tenantId, table.agentId],
      foreignColumns: [agents.tenantId, agents.id],
      name: "intents_tenant_agent_fk",
    }).onDelete("cascade"),
  }),
);

// ─── Standalone policy templates ─────────────────────────────────────────────

export const policyTemplates = pgTable(
  "policy_templates",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    description: text("description"),
    rules: jsonb("rules").$type<Record<string, unknown>[]>().notNull().default([]),
    isDefault: boolean("is_default").notNull().default(false),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: index("policy_templates_tenant_idx").on(table.tenantId),
  }),
);

// ─── Privy-style condition sets ──────────────────────────────────────────────

export const conditionSets = pgTable(
  "condition_sets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    description: text("description"),
    ownerId: varchar("owner_id", { length: 255 }),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: index("condition_sets_tenant_idx").on(table.tenantId),
    tenantNameUniqueIdx: uniqueIndex("condition_sets_tenant_name_idx").on(
      table.tenantId,
      table.name,
    ),
  }),
);

export const conditionSetItems = pgTable(
  "condition_set_items",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    conditionSetId: uuid("condition_set_id")
      .notNull()
      .references(() => conditionSets.id, { onDelete: "cascade" }),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    value: text("value").notNull(),
    label: varchar("label", { length: 255 }),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    ...timestamps,
  },
  (table) => ({
    conditionSetIdx: index("condition_set_items_set_idx").on(table.conditionSetId),
    tenantIdx: index("condition_set_items_tenant_idx").on(table.tenantId),
    setValueUniqueIdx: uniqueIndex("condition_set_items_set_value_idx").on(
      table.conditionSetId,
      table.value,
    ),
  }),
);

export type ConditionSetRow = typeof conditionSets.$inferSelect;
export type NewConditionSetRow = typeof conditionSets.$inferInsert;
export type ConditionSetItemRow = typeof conditionSetItems.$inferSelect;
export type NewConditionSetItemRow = typeof conditionSetItems.$inferInsert;

// ─── ERC-8004 registration and discovery tables ──────────────────────────────

export const agentRegistrations = pgTable(
  "agent_registrations",
  {
    id: serial("id").primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    chainId: integer("chain_id").notNull(),
    tokenId: varchar("token_id", { length: 256 }),
    txHash: varchar("tx_hash", { length: 128 }),
    registryAddress: varchar("registry_address", { length: 64 }).notNull(),
    agentCardUri: text("agent_card_uri"),
    agentCardJson: jsonb("agent_card_json").$type<Record<string, unknown>>(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    ...timestamps,
  },
  (table) => ({
    tenantAgentChainUnique: uniqueIndex("agent_registrations_tenant_agent_chain_idx").on(
      table.tenantId,
      table.agentId,
      table.chainId,
    ),
    tenantIdx: index("agent_registrations_tenant_idx").on(table.tenantId),
    agentIdx: index("agent_registrations_agent_idx").on(table.agentId),
  }),
);

export const reputationCache = pgTable(
  "reputation_cache",
  {
    id: serial("id").primaryKey(),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    chainId: integer("chain_id").notNull(),
    tokenId: varchar("token_id", { length: 256 }).notNull(),
    scoreOnchain: numeric("score_onchain", { precision: 5, scale: 2 }).notNull().default("0"),
    scoreInternal: numeric("score_internal", { precision: 5, scale: 2 }).notNull().default("0"),
    scoreCombined: numeric("score_combined", { precision: 5, scale: 2 }).notNull().default("0"),
    feedbackCount: integer("feedback_count").notNull().default(0),
    lastUpdated: timestamp("last_updated", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    agentChainUnique: uniqueIndex("reputation_cache_agent_chain_idx").on(
      table.agentId,
      table.chainId,
    ),
    agentIdx: index("reputation_cache_agent_idx").on(table.agentId),
  }),
);

export const registryIndex = pgTable(
  "registry_index",
  {
    id: serial("id").primaryKey(),
    chainId: integer("chain_id").notNull(),
    name: varchar("name", { length: 64 }).notNull(),
    rpcUrl: text("rpc_url").notNull(),
    registryAddress: varchar("registry_address", { length: 64 }).notNull(),
    isActive: boolean("is_active").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    chainUnique: uniqueIndex("registry_index_chain_id_idx").on(table.chainId),
  }),
);

// ─── Webhook configuration table ──────────────────────────────────────────────

export const webhookConfigs = pgTable(
  "webhook_configs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    url: text("url").notNull(),
    secret: text("secret").notNull(),
    events: jsonb("events").$type<string[]>().notNull().default([]),
    enabled: boolean("enabled").notNull().default(true),
    maxRetries: integer("max_retries").notNull().default(5),
    retryBackoffMs: integer("retry_backoff_ms").notNull().default(60000),
    description: text("description"),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: index("webhook_configs_tenant_idx").on(table.tenantId),
  }),
);

// ─── Auto-approval rules table ────────────────────────────────────────────────

export const autoApprovalRules = pgTable(
  "auto_approval_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    /** Transactions at or below this amount (in wei) are auto-approved */
    maxAmountWei: text("max_amount_wei").notNull().default("0"),
    /** Auto-deny pending approvals older than N hours (null = never) */
    autoDenyAfterHours: integer("auto_deny_after_hours"),
    /** Transactions above this amount trigger escalation webhook (null = disabled) */
    escalateAboveWei: text("escalate_above_wei"),
    enabled: boolean("enabled").notNull().default(true),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: uniqueIndex("auto_approval_rules_tenant_idx").on(table.tenantId),
  }),
);

// ─── Webhook delivery status enum ─────────────────────────────────────────────

export const webhookDeliveryStatusEnum = pgEnum("webhook_delivery_status", [
  "pending",
  "delivered",
  "failed",
  "dead",
]);

// ─── Webhook deliveries table ─────────────────────────────────────────────────

export const webhookDeliveries = pgTable(
  "webhook_deliveries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: text("tenant_id").notNull(),
    agentId: text("agent_id"),
    eventType: text("event_type").notNull(),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    url: text("url").notNull(),
    status: webhookDeliveryStatusEnum("status").notNull().default("pending"),
    attempts: integer("attempts").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    nextRetryAt: timestamp("next_retry_at", { withTimezone: true }),
    lastError: text("last_error"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
  },
  (table) => ({
    statusIdx: index("webhook_deliveries_status_idx").on(table.status),
    nextRetryIdx: index("webhook_deliveries_next_retry_idx").on(table.nextRetryAt),
    tenantIdx: index("webhook_deliveries_tenant_idx").on(table.tenantId),
  }),
);

export const policyTemplateRelations = relations(policyTemplates, ({ one }) => ({
  tenant: one(tenants, {
    fields: [policyTemplates.tenantId],
    references: [tenants.id],
  }),
}));

export const agentRegistrationRelations = relations(agentRegistrations, ({ one }) => ({
  tenant: one(tenants, {
    fields: [agentRegistrations.tenantId],
    references: [tenants.id],
  }),
  agent: one(agents, {
    fields: [agentRegistrations.agentId],
    references: [agents.id],
  }),
}));

export const reputationCacheRelations = relations(reputationCache, ({ one }) => ({
  agent: one(agents, {
    fields: [reputationCache.agentId],
    references: [agents.id],
  }),
}));

export const webhookConfigRelations = relations(webhookConfigs, ({ one }) => ({
  tenant: one(tenants, {
    fields: [webhookConfigs.tenantId],
    references: [tenants.id],
  }),
}));

export const autoApprovalRuleRelations = relations(autoApprovalRules, ({ one }) => ({
  tenant: one(tenants, {
    fields: [autoApprovalRules.tenantId],
    references: [tenants.id],
  }),
}));

export const tenantRelations = relations(tenants, ({ many, one }) => ({
  agents: many(agents),
  config: one(tenantConfigs, {
    fields: [tenants.id],
    references: [tenantConfigs.tenantId],
  }),
  policyTemplates: many(policyTemplates),
  agentRegistrations: many(agentRegistrations),
  webhookConfigs: many(webhookConfigs),
  autoApprovalRule: one(autoApprovalRules, {
    fields: [tenants.id],
    references: [autoApprovalRules.tenantId],
  }),
}));

export const tenantConfigRelations = relations(tenantConfigs, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantConfigs.tenantId],
    references: [tenants.id],
  }),
}));

export const agentRelations = relations(agents, ({ one, many }) => ({
  tenant: one(tenants, {
    fields: [agents.tenantId],
    references: [tenants.id],
  }),
  encryptedKey: one(encryptedKeys, {
    fields: [agents.id],
    references: [encryptedKeys.agentId],
  }),
  wallets: many(agentWallets),
  chainKeys: many(encryptedChainKeys),
  policies: many(policies),
  transactions: many(transactions),
  approvalQueueEntries: many(approvalQueue),
  intents: many(intents),
  signers: many(agentSigners),
  keyQuorums: many(agentKeyQuorums),
  registrations: many(agentRegistrations),
  reputationEntries: many(reputationCache),
}));

export const encryptedKeyRelations = relations(encryptedKeys, ({ one }) => ({
  agent: one(agents, {
    fields: [encryptedKeys.agentId],
    references: [agents.id],
  }),
}));

export const policyRelations = relations(policies, ({ one }) => ({
  agent: one(agents, {
    fields: [policies.agentId],
    references: [agents.id],
  }),
}));

export const transactionRelations = relations(transactions, ({ one }) => ({
  agent: one(agents, {
    fields: [transactions.agentId],
    references: [agents.id],
  }),
  approvalQueueEntry: one(approvalQueue, {
    fields: [transactions.id],
    references: [approvalQueue.txId],
  }),
}));

export const approvalQueueRelations = relations(approvalQueue, ({ one }) => ({
  agent: one(agents, {
    fields: [approvalQueue.agentId],
    references: [agents.id],
  }),
  transaction: one(transactions, {
    fields: [approvalQueue.txId],
    references: [transactions.id],
  }),
}));

export const intentRelations = relations(intents, ({ one }) => ({
  tenant: one(tenants, {
    fields: [intents.tenantId],
    references: [tenants.id],
  }),
  agent: one(agents, {
    fields: [intents.agentId],
    references: [agents.id],
  }),
}));

export const agentWalletRelations = relations(agentWallets, ({ one }) => ({
  agent: one(agents, {
    fields: [agentWallets.agentId],
    references: [agents.id],
  }),
}));

export const agentSignerRelations = relations(agentSigners, ({ one }) => ({
  tenant: one(tenants, {
    fields: [agentSigners.tenantId],
    references: [tenants.id],
  }),
  agent: one(agents, {
    fields: [agentSigners.agentId],
    references: [agents.id],
  }),
}));

export const agentKeyQuorumRelations = relations(agentKeyQuorums, ({ one }) => ({
  tenant: one(tenants, {
    fields: [agentKeyQuorums.tenantId],
    references: [tenants.id],
  }),
  agent: one(agents, {
    fields: [agentKeyQuorums.agentId],
    references: [agents.id],
  }),
}));

export const encryptedChainKeyRelations = relations(encryptedChainKeys, ({ one }) => ({
  agent: one(agents, {
    fields: [encryptedChainKeys.agentId],
    references: [agents.id],
  }),
}));

export type Tenant = typeof tenants.$inferSelect;
export type NewTenant = typeof tenants.$inferInsert;
export type TenantConfigRow = typeof tenantConfigs.$inferSelect;
export type NewTenantConfigRow = typeof tenantConfigs.$inferInsert;
export type Agent = typeof agents.$inferSelect;
export type NewAgent = typeof agents.$inferInsert;
export type EncryptedKey = typeof encryptedKeys.$inferSelect;
export type NewEncryptedKey = typeof encryptedKeys.$inferInsert;
export type Policy = typeof policies.$inferSelect;
export type NewPolicy = typeof policies.$inferInsert;
export type Transaction = typeof transactions.$inferSelect;
export type NewTransaction = typeof transactions.$inferInsert;
export type ApprovalQueueEntry = typeof approvalQueue.$inferSelect;
export type NewApprovalQueueEntry = typeof approvalQueue.$inferInsert;
export type Intent = typeof intents.$inferSelect;
export type NewIntent = typeof intents.$inferInsert;
export type AgentSigner = typeof agentSigners.$inferSelect;
export type NewAgentSigner = typeof agentSigners.$inferInsert;
export type AgentKeyQuorum = typeof agentKeyQuorums.$inferSelect;
export type NewAgentKeyQuorum = typeof agentKeyQuorums.$inferInsert;
export type AgentWallet = typeof agentWallets.$inferSelect;
export type NewAgentWallet = typeof agentWallets.$inferInsert;
export type EncryptedChainKey = typeof encryptedChainKeys.$inferSelect;
export type NewEncryptedChainKey = typeof encryptedChainKeys.$inferInsert;
export type PolicyTemplateRow = typeof policyTemplates.$inferSelect;
export type NewPolicyTemplateRow = typeof policyTemplates.$inferInsert;
export type AgentRegistration = typeof agentRegistrations.$inferSelect;
export type NewAgentRegistration = typeof agentRegistrations.$inferInsert;
export type ReputationCache = typeof reputationCache.$inferSelect;
export type NewReputationCache = typeof reputationCache.$inferInsert;
export type RegistryIndex = typeof registryIndex.$inferSelect;
export type NewRegistryIndex = typeof registryIndex.$inferInsert;
export type WebhookDelivery = typeof webhookDeliveries.$inferSelect;
export type NewWebhookDelivery = typeof webhookDeliveries.$inferInsert;
export type WebhookConfig = typeof webhookConfigs.$inferSelect;
export type NewWebhookConfig = typeof webhookConfigs.$inferInsert;
export type AutoApprovalRule = typeof autoApprovalRules.$inferSelect;
export type NewAutoApprovalRule = typeof autoApprovalRules.$inferInsert;

// ─── Secret Vault tables ──────────────────────────────────────────────────────

export const secrets = pgTable(
  "secrets",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    tenantId: text("tenant_id").notNull(),
    name: varchar("name", { length: 255 }).notNull(),
    description: text("description"),
    ciphertext: text("ciphertext").notNull(),
    iv: text("iv").notNull(),
    authTag: text("auth_tag").notNull(),
    salt: text("salt").notNull(),
    version: integer("version").notNull().default(1),
    rotatedAt: timestamp("rotated_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    deletedAt: timestamp("deleted_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantNameVersion: uniqueIndex("secrets_tenant_name_version_idx").on(
      table.tenantId,
      table.name,
      table.version,
    ),
    tenantIdx: index("secrets_tenant_idx").on(table.tenantId),
  }),
);

export const secretRoutes = pgTable(
  "secret_routes",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    tenantId: text("tenant_id").notNull(),
    secretId: uuid("secret_id").notNull(),
    hostPattern: varchar("host_pattern", { length: 512 }).notNull(),
    pathPattern: varchar("path_pattern", { length: 512 }).default("/*"),
    method: varchar("method", { length: 10 }).default("*"),
    injectAs: varchar("inject_as", { length: 50 }).notNull(),
    injectKey: varchar("inject_key", { length: 255 }).notNull(),
    injectFormat: varchar("inject_format", { length: 255 }).default("{value}"),
    priority: integer("priority").notNull().default(0),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantIdx: index("secret_routes_tenant_idx").on(table.tenantId),
    secretIdx: index("secret_routes_secret_idx").on(table.secretId),
    hostIdx: index("secret_routes_host_idx").on(table.hostPattern),
  }),
);

export const secretRelations = relations(secrets, ({ many }) => ({
  routes: many(secretRoutes),
}));

export const secretRouteRelations = relations(secretRoutes, ({ one }) => ({
  secret: one(secrets, {
    fields: [secretRoutes.secretId],
    references: [secrets.id],
  }),
}));

export type Secret = typeof secrets.$inferSelect;
export type NewSecret = typeof secrets.$inferInsert;
export type SecretRoute = typeof secretRoutes.$inferSelect;
export type NewSecretRoute = typeof secretRoutes.$inferInsert;

// ─── Proxy Audit Log ─────────────────────────────────────────────────────────

export const proxyAuditLog = pgTable(
  "proxy_audit_log",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    agentId: text("agent_id").notNull(),
    tenantId: text("tenant_id").notNull(),
    targetHost: varchar("target_host", { length: 512 }).notNull(),
    targetPath: varchar("target_path", { length: 512 }).notNull(),
    method: varchar("method", { length: 10 }).notNull(),
    statusCode: integer("status_code").notNull(),
    latencyMs: integer("latency_ms").notNull(),
    reason: text("reason"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantIdx: index("proxy_audit_log_tenant_idx").on(table.tenantId),
    agentIdx: index("proxy_audit_log_agent_idx").on(table.agentId),
    createdAtIdx: index("proxy_audit_log_created_at_idx").on(table.createdAt),
  }),
);

export type ProxyAuditLogEntry = typeof proxyAuditLog.$inferSelect;
export type NewProxyAuditLogEntry = typeof proxyAuditLog.$inferInsert;

export const tradeSessions = pgTable(
  "trade_sessions",
  {
    id: varchar("id", { length: 128 }).primaryKey(),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    venue: varchar("venue", { length: 64 }).notNull(),
    walletId: varchar("wallet_id", { length: 128 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    dailySpendUsd: numeric("daily_spend_usd", { precision: 18, scale: 6 }).notNull().default("0"),
    dailyCapUsd: numeric("daily_cap_usd", { precision: 18, scale: 6 }).notNull().default("100"),
    perOrderCapUsd: numeric("per_order_cap_usd", { precision: 18, scale: 6 }).notNull(),
    leverageCap: numeric("leverage_cap", { precision: 10, scale: 4 }).notNull(),
    allowedAssets: text("allowed_assets").array().notNull().default([]),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokedBy: varchar("revoked_by", { length: 255 }),
  },
  (table) => ({
    agentVenueStatusIdx: index("trade_sessions_agent_venue_status_idx").on(
      table.agentId,
      table.venue,
      table.status,
    ),
    tenantIdx: index("trade_sessions_tenant_idx").on(table.tenantId),
    expiresAtIdx: index("trade_sessions_expires_at_idx").on(table.expiresAt),
  }),
);

export type TradeSessionRow = typeof tradeSessions.$inferSelect;
export type NewTradeSessionRow = typeof tradeSessions.$inferInsert;

export const agentPolicies = pgTable(
  "agent_policies",
  {
    agentId: text("agent_id")
      .primaryKey()
      .references(() => agents.id, { onDelete: "cascade" }),
    tenantId: text("tenant_id").notNull(),
    dailyCapUsd: numeric("daily_cap_usd").notNull().default("1000"),
    perOrderCapUsd: numeric("per_order_cap_usd").notNull().default("500"),
    leverageCap: numeric("leverage_cap").notNull().default("10"),
    allowedAssets: text("allowed_assets").array().notNull().default(["BTC", "ETH", "BNB"]),
    allowedVenues: text("allowed_venues").array().notNull().default(["hyperliquid"]),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    updatedBy: text("updated_by").notNull(),
    updatedReason: text("updated_reason"),
  },
  (table) => ({
    tenantIdx: index("agent_policies_tenant_idx").on(table.tenantId),
  }),
);

export type AgentPolicyRow = typeof agentPolicies.$inferSelect;
export type NewAgentPolicyRow = typeof agentPolicies.$inferInsert;

// ─── Tamper-evident audit log ────────────────────────────────────────────────
//
// Per-tenant append-only HMAC chain. Each row's `hmac` commits to the previous
// row's `hmac` plus a canonical encoding of the event, so tampering with any
// historical row invalidates verification of every subsequent row. The HMAC
// key is held in app config (STEWARD_AUDIT_HMAC_KEY) separately from DB
// credentials, so DB-only write access cannot forge rows that verify.
// See packages/api/src/services/audit.ts for the writer and verifier.
export const auditEvents = pgTable(
  "audit_events",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 }).notNull(),
    seq: bigint("seq", { mode: "number" }).notNull(),
    prevHash: bytea("prev_hash").notNull(),
    hmac: bytea("hmac").notNull(),
    actorType: varchar("actor_type", { length: 32 }).notNull(),
    actorId: varchar("actor_id", { length: 255 }),
    action: varchar("action", { length: 128 }).notNull(),
    resourceType: varchar("resource_type", { length: 64 }),
    resourceId: varchar("resource_id", { length: 255 }),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    requestId: text("request_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantSeqIdx: uniqueIndex("audit_events_tenant_seq_idx").on(table.tenantId, table.seq),
    tenantCreatedIdx: index("audit_events_tenant_created_idx").on(table.tenantId, table.createdAt),
    actionIdx: index("audit_events_action_idx").on(table.action),
    actorIdx: index("audit_events_actor_idx").on(table.actorType, table.actorId),
  }),
);

export type AuditEventRow = typeof auditEvents.$inferSelect;
export type NewAuditEventRow = typeof auditEvents.$inferInsert;
