import { relations, sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import type { PolicyResult } from "@stwd/shared";

export const chainFamilyEnum = pgEnum("chain_family", ["evm", "solana"]);

export const policyTypeEnum = pgEnum("policy_type", [
  "spending-limit",
  "approved-addresses",
  "auto-approve-threshold",
  "time-window",
  "rate-limit",
  "allowed-chains",
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
  ownerAddress: varchar("owner_address", { length: 42 }),
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
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    agentChainUniqueIdx: uniqueIndex("agent_wallets_agent_chain_idx").on(
      table.agentId,
      table.chainFamily,
    ),
    agentIdIdx: index("agent_wallets_agent_id_idx").on(table.agentId),
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
    agentId: varchar("agent_id", { length: 64 })
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    chainFamily: chainFamilyEnum("chain_family").notNull(),
    ciphertext: text("ciphertext").notNull(),
    iv: text("iv").notNull(),
    tag: text("tag").notNull(),
    salt: text("salt").notNull(),
  },
  (table) => ({
    pk: primaryKey({ columns: [table.agentId, table.chainFamily] }),
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
    policyResults: jsonb("policy_results")
      .$type<PolicyResult[]>()
      .notNull()
      .default([]),
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
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolvedBy: varchar("resolved_by", { length: 255 }),
  },
  (table) => ({
    txIdUniqueIdx: uniqueIndex("approval_queue_tx_id_idx").on(table.txId),
    statusIdx: index("approval_queue_status_idx").on(table.status),
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

export const tenantRelations = relations(tenants, ({ many }) => ({
  agents: many(agents),
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

export const agentWalletRelations = relations(agentWallets, ({ one }) => ({
  agent: one(agents, {
    fields: [agentWallets.agentId],
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
export type AgentWallet = typeof agentWallets.$inferSelect;
export type NewAgentWallet = typeof agentWallets.$inferInsert;
export type EncryptedChainKey = typeof encryptedChainKeys.$inferSelect;
export type NewEncryptedChainKey = typeof encryptedChainKeys.$inferInsert;
export type WebhookDelivery = typeof webhookDeliveries.$inferSelect;
export type NewWebhookDelivery = typeof webhookDeliveries.$inferInsert;
