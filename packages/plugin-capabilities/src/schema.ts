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
