import {
  index,
  integer,
  jsonb,
  pgTable,
  timestamp,
  uniqueIndex,
  varchar,
} from "drizzle-orm/pg-core";

/**
 * Durable execution and terminal replay authority for venue orders.
 *
 * Redis remains the fast claim/CAS layer. PostgreSQL rows are written before
 * venue I/O (phase `claim`) and after a terminal result (phase
 * `terminal`). A third immutable `release` row is committed atomically with a
 * spend decrement for terminal non-fill outcomes. A claim without a terminal
 * row is a durable reconciliation anchor, so a Redis outage or expired pending
 * marker can never authorize the same movement again.
 */
export const tradingOrderOutcomes = pgTable(
  "trading_order_outcomes",
  {
    id: varchar("id", { length: 64 }).primaryKey(),
    tenantId: varchar("tenant_id", { length: 64 }).notNull(),
    agentId: varchar("agent_id", { length: 64 }).notNull(),
    venue: varchar("venue", { length: 32 }).notNull(),
    phase: varchar("phase", { length: 16 }).notNull(),
    idempotencyKeyHash: varchar("idempotency_key_hash", { length: 64 }).notNull(),
    requestHash: varchar("request_hash", { length: 64 }).notNull(),
    httpStatus: integer("http_status").notNull(),
    response: jsonb("response").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    requestUnique: uniqueIndex("trading_order_outcomes_request_uidx").on(
      table.tenantId,
      table.agentId,
      table.venue,
      table.idempotencyKeyHash,
      table.phase,
    ),
    tenantCreated: index("trading_order_outcomes_tenant_created_idx").on(
      table.tenantId,
      table.createdAt,
    ),
  }),
);

export type TradingOrderOutcome = typeof tradingOrderOutcomes.$inferSelect;
