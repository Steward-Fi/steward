import type {
  ApprovalConfig,
  PolicyExposureConfig,
  PolicyResult,
  PolicyTemplate,
  SecretRoutePreset,
  TenantAppClient,
  TenantAuthAbuseConfig,
  TenantFeatureFlags,
  TenantGasSponsorshipConfig,
  TenantOidcProviderConfig,
  TenantTestAccountConfig,
  TenantTheme,
} from "@stwd/shared";
import { relations, sql } from "drizzle-orm";
import {
  bigint,
  bigserial,
  boolean,
  check,
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
  "aggregation",
  "contract-allowlist",
  "typed-data",
  "raw-signing-chain",
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

export const tenants = pgTable(
  "tenants",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    name: varchar("name", { length: 255 }).notNull(),
    apiKeyHash: text("api_key_hash").notNull(),
    ownerAddress: varchar("owner_address", { length: 128 }),
    ...timestamps,
  },
  (table) => ({
    apiKeyHashUnique: uniqueIndex("tenants_api_key_hash_unique_idx").on(table.apiKeyHash),
    ownerAddressUnique: uniqueIndex("tenants_owner_address_unique")
      .on(table.ownerAddress)
      .where(sql`${table.ownerAddress} is not null`),
  }),
);

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
  oidcProviders: jsonb("oidc_providers").$type<TenantOidcProviderConfig[]>().notNull().default([]),
  authAbuseConfig: jsonb("auth_abuse_config").$type<TenantAuthAbuseConfig>().notNull().default({}),
  testAccount: jsonb("test_account").$type<TenantTestAccountConfig>().notNull().default({}),
  gasSponsorshipConfig: jsonb("gas_sponsorship_config")
    .$type<TenantGasSponsorshipConfig>()
    .notNull()
    .default({}),
  /** Allowed CORS origins for this tenant. Empty = fall back to wildcard (*). */
  allowedOrigins: text("allowed_origins").array().notNull().default([]),
  /** OAuth/email redirect URLs for this tenant. Empty = legacy fallback to allowedOrigins. */
  allowedRedirectUrls: text("allowed_redirect_urls").array().notNull().default([]),
  /** Controls how users can join: 'open' | 'invite' | 'closed'. Default invite requires explicit opt-in for public join. */
  joinMode: varchar("join_mode", { length: 16 }).notNull().default("invite"),
  ...timestamps,
});

export const tenantAppClients = pgTable(
  "tenant_app_clients",
  {
    id: varchar("id", { length: 64 }).notNull(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 255 }).notNull(),
    environment: varchar("environment", { length: 32 }).notNull().default("production"),
    enabled: boolean("enabled").notNull().default(true),
    isDefault: boolean("is_default").notNull().default(false),
    allowedOrigins: text("allowed_origins").array().notNull().default([]),
    allowedRedirectUrls: text("allowed_redirect_urls").array().notNull().default([]),
    loginMethods: jsonb("login_methods").$type<TenantAppClient["loginMethods"]>(),
    globalWalletEnabled: boolean("global_wallet_enabled").notNull().default(false),
    globalWalletAllowedScopes: text("global_wallet_allowed_scopes")
      .array()
      .notNull()
      .default(["eth_accounts", "personal_sign"]),
    ...timestamps,
  },
  (table) => ({
    tenantClientPk: uniqueIndex("tenant_app_clients_tenant_id_id_idx").on(table.tenantId, table.id),
    tenantIdx: index("tenant_app_clients_tenant_id_idx").on(table.tenantId),
  }),
);

export const tenantAppClientSecrets = pgTable(
  "tenant_app_client_secrets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    clientId: varchar("client_id", { length: 64 }).notNull(),
    secretHash: text("secret_hash").notNull(),
    secretPrefix: varchar("secret_prefix", { length: 32 }).notNull(),
    status: varchar("status", { length: 16 }).notNull().default("active"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    tenantClientIdx: index("tenant_app_client_secrets_tenant_client_idx").on(
      table.tenantId,
      table.clientId,
    ),
    statusIdx: index("tenant_app_client_secrets_status_idx").on(table.status),
    appClientFk: foreignKey({
      columns: [table.tenantId, table.clientId],
      foreignColumns: [tenantAppClients.tenantId, tenantAppClients.id],
      name: "tenant_app_client_secrets_client_fk",
    }).onDelete("cascade"),
  }),
);

export const tenantRequestSigningKeys = pgTable(
  "tenant_request_signing_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 120 }).notNull(),
    secretCiphertext: text("secret_ciphertext").notNull(),
    secretIv: text("secret_iv").notNull(),
    secretAuthTag: text("secret_auth_tag").notNull(),
    secretSalt: text("secret_salt").notNull(),
    secretPrefix: varchar("secret_prefix", { length: 32 }).notNull(),
    status: varchar("status", { length: 16 }).notNull().default("active"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: index("tenant_request_signing_keys_tenant_idx").on(table.tenantId),
    tenantStatusIdx: index("tenant_request_signing_keys_tenant_status_idx").on(
      table.tenantId,
      table.status,
    ),
  }),
);

export const tenantSsoDomains = pgTable(
  "tenant_sso_domains",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    domain: varchar("domain", { length: 255 }).notNull(),
    verificationToken: varchar("verification_token", { length: 128 }).notNull(),
    status: varchar("status", { length: 16 }).notNull().default("pending"),
    ssoRequired: boolean("sso_required").notNull().default(false),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    tenantDomainUnique: uniqueIndex("tenant_sso_domains_tenant_domain_idx").on(
      table.tenantId,
      table.domain,
    ),
    tenantCanonicalDomainUnique: uniqueIndex("tenant_sso_domains_tenant_canonical_domain_idx").on(
      table.tenantId,
      sql`lower(trim(trailing '.' from ${table.domain}))`,
    ),
    verifiedCanonicalDomainUnique: uniqueIndex("tenant_sso_domains_verified_canonical_domain_idx")
      .on(sql`lower(trim(trailing '.' from ${table.domain}))`)
      .where(sql`${table.status} = 'verified'`),
    domainIdx: index("tenant_sso_domains_domain_idx").on(table.domain),
  }),
);

export const tenantSamlSsoConfigs = pgTable(
  "tenant_saml_sso_configs",
  {
    tenantId: varchar("tenant_id", { length: 64 })
      .primaryKey()
      .references(() => tenants.id, { onDelete: "cascade" }),
    enabled: boolean("enabled").notNull().default(false),
    status: varchar("status", { length: 16 }).notNull().default("pending"),
    idpEntityId: text("idp_entity_id").notNull(),
    idpSsoUrl: text("idp_sso_url").notNull(),
    idpCertPems: text("idp_cert_pems").array().notNull().default([]),
    spEntityId: text("sp_entity_id").notNull(),
    acsUrl: text("acs_url").notNull(),
    nameIdFormat: text("name_id_format"),
    emailAttribute: varchar("email_attribute", { length: 128 }).notNull().default("email"),
    groupsAttribute: varchar("groups_attribute", { length: 128 }),
    groupRoleMappings: jsonb("group_role_mappings")
      .$type<Array<{ group: string; role: string }>>()
      .notNull()
      .default([]),
    allowJitProvisioning: boolean("allow_jit_provisioning").notNull().default(false),
    jitDefaultRole: varchar("jit_default_role", { length: 32 }).notNull().default("viewer"),
    lastTestedAt: timestamp("last_tested_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    statusIdx: index("tenant_saml_sso_configs_status_idx").on(table.status),
    enabledIdx: index("tenant_saml_sso_configs_enabled_idx").on(table.enabled),
  }),
);

export type TenantSamlSsoConfigRow = typeof tenantSamlSsoConfigs.$inferSelect;
export type TenantSamlSsoConfigInsert = typeof tenantSamlSsoConfigs.$inferInsert;

export const tenantSamlAuthnRequests = pgTable(
  "tenant_saml_authn_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    requestId: varchar("request_id", { length: 128 }).notNull(),
    relayState: varchar("relay_state", { length: 128 }).notNull(),
    redirectUri: text("redirect_uri").notNull(),
    appClientId: varchar("app_client_id", { length: 64 }),
    codeChallenge: varchar("code_challenge", { length: 128 }).notNull(),
    codeChallengeMethod: varchar("code_challenge_method", { length: 16 }).notNull().default("S256"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => ({
    tenantIdx: index("tenant_saml_authn_requests_tenant_idx").on(table.tenantId),
    relayStateUnique: uniqueIndex("tenant_saml_authn_requests_relay_state_idx").on(
      table.relayState,
    ),
    tenantRequestUnique: uniqueIndex("tenant_saml_authn_requests_tenant_request_idx").on(
      table.tenantId,
      table.requestId,
    ),
    expiresAtIdx: index("tenant_saml_authn_requests_expires_at_idx").on(table.expiresAt),
  }),
);

export const tenantSamlAssertionReplays = pgTable(
  "tenant_saml_assertion_replays",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    assertionId: varchar("assertion_id", { length: 256 }).notNull(),
    responseId: varchar("response_id", { length: 256 }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantAssertionUnique: uniqueIndex("tenant_saml_assertion_replays_tenant_assertion_idx").on(
      table.tenantId,
      table.assertionId,
    ),
    expiresAtIdx: index("tenant_saml_assertion_replays_expires_at_idx").on(table.expiresAt),
  }),
);

export type TenantSsoDomainRow = typeof tenantSsoDomains.$inferSelect;
export type NewTenantSsoDomainRow = typeof tenantSsoDomains.$inferInsert;

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
    tenantAgentUniqueIdx: uniqueIndex("agents_tenant_id_id_idx").on(table.tenantId, table.id),
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

/**
 * Wallet ownership and delegated signer metadata for an agent wallet/account.
 * This is an authorization graph, not private-key material: signing routes can
 * use it to expose owners, service signers, quorum members, and scoped
 * delegation policies without changing custody storage.
 */
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
    /**
     * Authorization-key scheme for this signer's *request* signatures:
     *   "hmac" (default) — symmetric request signing (legacy/interchangeable).
     *   "p256"           — asymmetric ECDSA over secp256r1; `publicKey` holds
     *                      the registered key (Privy authorization-keys parity).
     * The middleware selects the verification path from this column.
     */
    keyType: varchar("key_type", { length: 16 }).notNull().default("hmac"),
    /**
     * Registered P-256 public key when `keyType="p256"`. Accepts base64 SPKI,
     * raw uncompressed `04||X||Y`, or a JWK string (see
     * `@stwd/auth` importP256PublicKey). NULL for HMAC signers.
     */
    publicKey: text("public_key"),
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
    /**
     * Nested-quorum children: ordered `agent_key_quorums.id` values that are
     * themselves quorums. A parent quorum is satisfied iff the number of
     * satisfied members (a verified leaf signer in `memberSignerIds` OR a
     * satisfied child quorum in `memberQuorumIds`) is ≥ `threshold`. Recursion
     * is bounded by a hard depth limit with cycle detection (see the
     * authorization-signature middleware); both violations fail closed.
     */
    memberQuorumIds: text("member_quorum_ids").array().notNull().default([]),
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
 * Session signers — labeled, scoped, revocable delegated signing tokens
 * (Privy "session signers" parity). Each row pins a single minted agent JWT
 * (by its `jti`) to an operator-facing label, an optional policy subset, and a
 * bounded expiry. Revocation flips `revokedAt` AND records the jti in the
 * auth revocation store, so the token is rejected even before it expires.
 *
 * Rows are append-only except for `revokedAt`/`lastUsedAt`; there is no
 * `updatedAt` because a session signer is never re-issued in place.
 */
export const sessionSigners = pgTable(
  "session_signers",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    /** Unique JWT id of the minted agent token; mirrored into the revocation store. */
    jti: varchar("jti", { length: 64 }).notNull(),
    label: varchar("label", { length: 128 }).notNull(),
    scopes: jsonb("scopes").$type<string[]>().notNull().default([]),
    /** Subset of the agent's policy ids enforced when this token signs. */
    policyIds: jsonb("policy_ids").$type<string[]>().notNull().default([]),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => ({
    jtiUniqueIdx: uniqueIndex("session_signers_jti_idx").on(table.jti),
    tenantAgentIdx: index("session_signers_tenant_agent_idx").on(table.tenantId, table.agentId),
    activeIdx: index("session_signers_active_idx")
      .on(table.agentId)
      .where(sql`${table.revokedAt} IS NULL`),
    tenantAgentFk: foreignKey({
      columns: [table.tenantId, table.agentId],
      foreignColumns: [agents.tenantId, agents.id],
      name: "session_signers_tenant_agent_fk",
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
    // `value` is a wei amount: must be a non-empty decimal digit string.
    valueIsWei: check("transactions_value_wei_chk", sql`${table.value} ~ '^[0-9]+$'`),
  }),
);

export const sponsoredGasEvents = pgTable(
  "sponsored_gas_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    tenantId: varchar("tenant_id", { length: 64 })
      .notNull()
      .references(() => tenants.id, { onDelete: "cascade" }),
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    userId: uuid("user_id"),
    txId: varchar("tx_id", { length: 64 }).references(() => transactions.id, {
      onDelete: "set null",
    }),
    chainFamily: chainFamilyEnum("chain_family").notNull().default("evm"),
    chainId: integer("chain_id"),
    caip2: varchar("caip2", { length: 64 }),
    provider: varchar("provider", { length: 64 }).notNull(),
    mode: varchar("mode", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("reserved"),
    userOperationHash: varchar("user_operation_hash", { length: 128 }),
    txHash: varchar("tx_hash", { length: 128 }),
    signature: varchar("signature", { length: 128 }),
    reservedUsd: numeric("reserved_usd", { precision: 18, scale: 6 }),
    actualUsd: numeric("actual_usd", { precision: 18, scale: 6 }),
    gasUnits: text("gas_units"),
    gasToken: varchar("gas_token", { length: 64 }),
    requestHash: varchar("request_hash", { length: 128 }),
    error: text("error"),
    metadata: jsonb("metadata").$type<Record<string, unknown>>().notNull().default({}),
    ...timestamps,
  },
  (table) => ({
    tenantCreatedIdx: index("sponsored_gas_events_tenant_created_idx").on(
      table.tenantId,
      table.createdAt,
    ),
    agentCreatedIdx: index("sponsored_gas_events_agent_created_idx").on(
      table.agentId,
      table.createdAt,
    ),
    txUniqueIdx: uniqueIndex("sponsored_gas_events_tenant_tx_id_idx")
      .on(table.tenantId, table.txId)
      .where(sql`${table.txId} is not null`),
    agentTenantFk: foreignKey({
      columns: [table.tenantId, table.agentId],
      foreignColumns: [agents.tenantId, agents.id],
      name: "sponsored_gas_events_tenant_agent_fk",
    }).onDelete("cascade"),
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
    tenantUrlUnique: uniqueIndex("webhook_configs_tenant_url_idx").on(table.tenantId, table.url),
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
    // wei thresholds must be non-empty decimal digit strings (escalate is nullable).
    maxAmountIsWei: check(
      "auto_approval_rules_max_amount_wei_chk",
      sql`${table.maxAmountWei} ~ '^[0-9]+$'`,
    ),
    escalateIsWei: check(
      "auto_approval_rules_escalate_above_wei_chk",
      sql`${table.escalateAboveWei} IS NULL OR ${table.escalateAboveWei} ~ '^[0-9]+$'`,
    ),
  }),
);

// ─── Webhook delivery status enum ─────────────────────────────────────────────

export const webhookDeliveryStatusEnum = pgEnum("webhook_delivery_status", [
  "pending",
  "processing",
  "delivered",
  "failed",
  "dead",
]);

// ─── Webhook deliveries table ─────────────────────────────────────────────────

export const webhookDeliveries = pgTable(
  "webhook_deliveries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    // No tenant FK: isolation is enforced at the app layer (every query scopes by
    // tenant_id) and deliveries may reference platform/system principals.
    tenantId: text("tenant_id").notNull(),
    webhookConfigId: uuid("webhook_config_id").references(() => webhookConfigs.id, {
      onDelete: "set null",
    }),
    agentId: text("agent_id"),
    eventType: text("event_type").notNull(),
    replayedFromDeliveryId: uuid("replayed_from_delivery_id"),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    url: text("url").notNull(),
    secret: text("secret"),
    events: jsonb("events").$type<string[]>(),
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
    webhookConfigIdx: index("webhook_deliveries_webhook_config_idx").on(table.webhookConfigId),
    replayedFromIdx: index("webhook_deliveries_replayed_from_idx").on(table.replayedFromDeliveryId),
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
  appClients: many(tenantAppClients),
  appClientSecrets: many(tenantAppClientSecrets),
  requestSigningKeys: many(tenantRequestSigningKeys),
  ssoDomains: many(tenantSsoDomains),
  autoApprovalRule: one(autoApprovalRules, {
    fields: [tenants.id],
    references: [autoApprovalRules.tenantId],
  }),
}));

export const tenantAppClientRelations = relations(tenantAppClients, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantAppClients.tenantId],
    references: [tenants.id],
  }),
}));

export const tenantAppClientSecretRelations = relations(tenantAppClientSecrets, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantAppClientSecrets.tenantId],
    references: [tenants.id],
  }),
  appClient: one(tenantAppClients, {
    fields: [tenantAppClientSecrets.tenantId, tenantAppClientSecrets.clientId],
    references: [tenantAppClients.tenantId, tenantAppClients.id],
  }),
}));

export const tenantRequestSigningKeyRelations = relations(tenantRequestSigningKeys, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantRequestSigningKeys.tenantId],
    references: [tenants.id],
  }),
}));

export const tenantSsoDomainRelations = relations(tenantSsoDomains, ({ one }) => ({
  tenant: one(tenants, {
    fields: [tenantSsoDomains.tenantId],
    references: [tenants.id],
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
export type TenantAppClientRow = typeof tenantAppClients.$inferSelect;
export type NewTenantAppClientRow = typeof tenantAppClients.$inferInsert;
export type TenantAppClientSecretRow = typeof tenantAppClientSecrets.$inferSelect;
export type NewTenantAppClientSecretRow = typeof tenantAppClientSecrets.$inferInsert;
export type TenantRequestSigningKeyRow = typeof tenantRequestSigningKeys.$inferSelect;
export type NewTenantRequestSigningKeyRow = typeof tenantRequestSigningKeys.$inferInsert;
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
export type SponsoredGasEvent = typeof sponsoredGasEvents.$inferSelect;
export type NewSponsoredGasEvent = typeof sponsoredGasEvents.$inferInsert;
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
    // No tenant FK: secrets are app-layer scoped by tenant_id; platform-scoped
    // secrets may use non-tenant principals not present in `tenants`.
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
    agentId: varchar("agent_id", { length: 64 }),
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
    agentIdx: index("secret_routes_agent_idx").on(table.agentId),
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
    // No tenant FK: proxy logs are app-layer scoped by tenant_id and may record
    // platform/system principals not present in `tenants`.
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
    // No tenant FK: audit events also record platform/system principals whose ids
    // are not rows in `tenants`. Isolation is app-layer; tamper-evidence comes from
    // the HMAC chain + audit_chain_heads high-water-mark.
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

// Out-of-band high-water-mark for each tenant's audit chain. Updated atomically
// inside the advisory-locked append transaction. Lets verification detect
// tail-truncation / whole-chain deletion that an in-band walk alone cannot:
// if rows are missing or the table is unexpectedly empty, the stored
// expected_seq / expected_count / head_hmac will not match what's on disk.
// `floor_seq`/`floor_hmac` anchor the chain after a legitimate retention sweep
// archives+drops a prefix (verification then starts from floor_seq, not seq=1).
// No FK ON DELETE: this mirrors audit_events (RESTRICT) — heads are never
// silently dropped while audit rows exist.
export const auditChainHeads = pgTable("audit_chain_heads", {
  tenantId: varchar("tenant_id", { length: 64 }).primaryKey(),
  expectedSeq: bigint("expected_seq", { mode: "number" }).notNull(),
  expectedCount: bigint("expected_count", { mode: "number" }).notNull(),
  headHmac: bytea("head_hmac").notNull(),
  floorSeq: bigint("floor_seq", { mode: "number" }).notNull().default(0),
  floorHmac: bytea("floor_hmac"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AuditChainHead = typeof auditChainHeads.$inferSelect;
export type NewAuditChainHead = typeof auditChainHeads.$inferInsert;
