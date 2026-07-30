/**
 * schema.ts - the capability plugin's OWN drizzle table definitions.
 *
 * these mirror the SQL in `drizzle/0000_capabilities.sql` (the migration source
 * of truth the host applies into a per-plugin namespaced bookkeeping table). the
 * plugin OWNS this schema; the lean core never imports it. the store (`store.ts`)
 * queries through these definitions.
 *
 * a capability is a NAMED, narrowly-scoped use of a stored secret:
 *   name -> (secretId, host, pathPattern, method) + the header-injection config
 *   the paired secret_route needs. host/path/method/inject* are validated by the
 *   SHARED secret-route validator (incl. per-host strict rules) at create/update,
 *   so a capability can never be broader than a legal route.
 *
 * a grant is: agent X may use capability Y (optionally until expiresAt). the
 * grant carries the id of its paired secret_route (per-GRANT pairing - the proxy
 * matches secret_routes by exact agentId, and capabilities are tenant-wide with
 * per-agent grants, so a route materializes once per grant; see PR / index.ts).
 */

import { relations, sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

export const capabilities = pgTable(
  "capabilities",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    // No tenant FK: mirrors the core `secrets`/`secret_routes` convention
    // (secrets are app-layer scoped by tenant_id; platform-scoped principals may
    // not be present in `tenants`).
    tenantId: text("tenant_id").notNull(),
    name: text("name").notNull(),
    secretId: uuid("secret_id").notNull(),
    host: text("host").notNull(),
    pathPattern: text("path_pattern").notNull(),
    method: text("method").notNull(),
    injectAs: text("inject_as").notNull().default("header"),
    injectKey: text("inject_key").notNull(),
    injectFormat: text("inject_format").notNull().default("{value}"),
    constraints: jsonb("constraints").notNull().default(sql`'{}'::jsonb`),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    tenantNameUniq: uniqueIndex("capabilities_tenant_name_uniq").on(table.tenantId, table.name),
    tenantIdx: index("capabilities_tenant_idx").on(table.tenantId),
    secretIdx: index("capabilities_secret_idx").on(table.secretId),
  }),
);

export const capabilityGrants = pgTable(
  "capability_grants",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    tenantId: text("tenant_id").notNull(),
    agentId: varchar("agent_id", { length: 64 }).notNull(),
    capabilityId: uuid("capability_id").notNull(),
    // the paired secret_route this grant materialized (per-GRANT pairing). the
    // proxy matches secret_routes by exact agentId, so one route per grant keeps
    // the proxy's matching semantics unchanged. nullable only transiently while a
    // grant is being torn down / for a route that failed to materialize (never
    // left as an orphaned enabled route - see the lifecycle in store.ts + tests).
    secretRouteId: uuid("secret_route_id"),
    // the per-grant POLICY document (C1): constraints evaluated at invoke time
    // by @stwd/policy-engine's grant-policy module (rate / amount / venue / time
    // / approval). New rows default to the EXPLICIT permissive plain-secret
    // policy (exactly pre-policy behavior, but written down); migration 0002
    // backfills existing rows the same way. Kept NULLABLE so strict mode
    // (STEWARD_GRANT_POLICY_STRICT=true) has a fail-closed target for rows
    // written outside the migrated path: NULL denies under strict mode.
    policy: jsonb("policy").default(sql`'{"version":1,"class":"plain-secret"}'::jsonb`),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    status: text("status").notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    statusCheck: check(
      "capability_grants_status_check",
      sql`${table.status} IN ('active','revoked')`,
    ),
    tenantAgentCapabilityUniq: uniqueIndex("capability_grants_tenant_agent_capability_uniq").on(
      table.tenantId,
      table.agentId,
      table.capabilityId,
    ),
    tenantIdx: index("capability_grants_tenant_idx").on(table.tenantId),
    agentIdx: index("capability_grants_agent_idx").on(table.agentId),
    capabilityIdx: index("capability_grants_capability_idx").on(table.capabilityId),
    routeIdx: index("capability_grants_route_idx").on(table.secretRouteId),
  }),
);

/**
 * capability_invocations - the append-only audit + rate-limit source for the
 * agent invoke path (W-1c). EVERY invoke attempt records exactly one row with its
 * terminal decision (allow / deny / approval / error), regardless of outcome:
 *   - it is the audit trail (who invoked what, and how it was decided),
 *   - it is the source of the trailing-hour invoke count the `capability-intent`
 *     `maxCallsPerHour` constraint reads (count of this agent+capability rows in
 *     the last hour). recording the attempt BEFORE forwarding means the count is
 *     fail-closed: a decision is always durable before any credential leaves.
 *
 * plugin-owned + namespaced (mirrors capabilities/capability_grants). no FK to
 * core tables: an invocation is a self-contained decision record keyed by
 * tenant/agent/capability ids.
 */
export const capabilityInvocations = pgTable(
  "capability_invocations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    tenantId: text("tenant_id").notNull(),
    agentId: varchar("agent_id", { length: 64 }).notNull(),
    // nullable: an attempt can be recorded (denied/404) before a capability row
    // is resolved (e.g. unknown capability name). when set, it is the resolved
    // capability's id.
    capabilityId: uuid("capability_id"),
    decision: text("decision").notNull(),
    // policy VERDICT audit (C1): which rule decided this invoke (e.g.
    // "grant-policy:amount.perInvokeMax", "capability-intent:allow",
    // "no-usable-grant") + the human-readable reason. nullable: rows predating
    // the policy engine carry no verdict.
    verdictRule: text("verdict_rule"),
    verdictReason: text("verdict_reason"),
    // the extracted per-invoke amount (integer micros) for value-bearing
    // invokes. summed over decision IN ('allow','approval','error') rows as the
    // rolling-window cumulative amount source (pending approvals and post-
    // authorization infra errors RESERVE spend so the window can never be
    // under-counted).
    amountMicros: bigint("amount_micros", { mode: "number" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    decisionCheck: check(
      "capability_invocations_decision_check",
      sql`${table.decision} IN ('allow','deny','approval','error')`,
    ),
    // the rate-limit + audit read path: this agent's rows for a capability in a
    // time window. (agent_id, capability_id, created_at) covers the count query.
    rateIdx: index("capability_invocations_rate_idx").on(
      table.agentId,
      table.capabilityId,
      table.createdAt,
    ),
    tenantIdx: index("capability_invocations_tenant_idx").on(table.tenantId),
  }),
);

export const capabilityRelations = relations(capabilities, ({ many }) => ({
  grants: many(capabilityGrants),
}));

export const capabilityGrantRelations = relations(capabilityGrants, ({ one }) => ({
  capability: one(capabilities, {
    fields: [capabilityGrants.capabilityId],
    references: [capabilities.id],
  }),
}));

export type Capability = typeof capabilities.$inferSelect;
export type NewCapability = typeof capabilities.$inferInsert;
export type CapabilityGrant = typeof capabilityGrants.$inferSelect;
export type NewCapabilityGrant = typeof capabilityGrants.$inferInsert;
export type CapabilityInvocation = typeof capabilityInvocations.$inferSelect;
export type NewCapabilityInvocation = typeof capabilityInvocations.$inferInsert;

/** the terminal decision recorded for an invoke attempt. */
export type InvocationDecision = "allow" | "deny" | "approval" | "error";
