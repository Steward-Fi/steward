-- @stwd/plugin-capabilities migration 0001: capability_invocations.
--
-- the append-only audit + rate-limit source for the agent invoke path (W-1c).
-- EVERY invoke attempt records exactly one row with its terminal decision
-- (allow / deny / approval / error), regardless of outcome:
--   - audit trail: who invoked what, and how it was decided;
--   - rate source: the trailing-hour invoke count the `capability-intent`
--     `maxCallsPerHour` constraint reads (count of this agent+capability rows in
--     the last hour). recording the attempt BEFORE forwarding keeps the count
--     fail-closed (a decision is durable before any credential leaves).
--
-- plugin-owned + namespaced (applied into
-- drizzle.__drizzle_migrations_plugin_capabilities). no FK to core tables: an
-- invocation is a self-contained decision record keyed by tenant/agent/capability
-- ids (capability_id nullable so an attempt denied before capability resolution
-- is still recorded).
CREATE TABLE "capability_invocations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" text NOT NULL,
	"agent_id" varchar(64) NOT NULL,
	"capability_id" uuid,
	"decision" text NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "capability_invocations_decision_check" CHECK ("decision" IN ('allow','deny','approval','error'))
);
--> statement-breakpoint
CREATE INDEX "capability_invocations_rate_idx" ON "capability_invocations" ("agent_id","capability_id","created_at");
--> statement-breakpoint
CREATE INDEX "capability_invocations_tenant_idx" ON "capability_invocations" ("tenant_id");
