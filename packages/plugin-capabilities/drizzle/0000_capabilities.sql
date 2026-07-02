-- @stwd/plugin-capabilities OWN schema. applied by the host into a per-plugin
-- namespaced bookkeeping table (drizzle.__drizzle_migrations_plugin_capabilities),
-- never into the core's drizzle.__drizzle_migrations journal.
--
-- a capability is a NAMED, narrowly-scoped use of a stored secret:
--   name (e.g. "github.pr.comment") -> (secret_id, host, path_pattern, method)
--   + the header-injection config the paired secret_route needs, so a capability
--   compiles to exactly one legal narrow secret_route (the proxy's injection
--   mechanism). host/path/method/inject_* are validated by the SHARED
--   secret-route validator (incl. per-host strict rules) at create/update time,
--   so a capability can never be broader than a legal route.
--
-- a grant is: agent X may use capability Y (optionally until expires_at).
CREATE TABLE "capabilities" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" text NOT NULL,
	"name" text NOT NULL,
	"secret_id" uuid NOT NULL,
	"host" text NOT NULL,
	"path_pattern" text NOT NULL,
	"method" text NOT NULL,
	"inject_as" text DEFAULT 'header' NOT NULL,
	"inject_key" text NOT NULL,
	"inject_format" text DEFAULT '{value}' NOT NULL,
	"constraints" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL,
	"updated_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "capabilities_tenant_name_uniq" UNIQUE("tenant_id","name")
);
--> statement-breakpoint
CREATE TABLE "capability_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"tenant_id" text NOT NULL,
	"agent_id" varchar(64) NOT NULL,
	"capability_id" uuid NOT NULL,
	"secret_route_id" uuid,
	"expires_at" timestamptz,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "capability_grants_status_check" CHECK ("status" IN ('active','revoked')),
	CONSTRAINT "capability_grants_tenant_agent_capability_uniq" UNIQUE("tenant_id","agent_id","capability_id"),
	CONSTRAINT "capability_grants_capability_fk" FOREIGN KEY ("capability_id") REFERENCES "capabilities"("id") ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX "capabilities_tenant_idx" ON "capabilities" ("tenant_id");
--> statement-breakpoint
CREATE INDEX "capabilities_secret_idx" ON "capabilities" ("secret_id");
--> statement-breakpoint
CREATE INDEX "capability_grants_tenant_idx" ON "capability_grants" ("tenant_id");
--> statement-breakpoint
CREATE INDEX "capability_grants_agent_idx" ON "capability_grants" ("agent_id");
--> statement-breakpoint
CREATE INDEX "capability_grants_capability_idx" ON "capability_grants" ("capability_id");
--> statement-breakpoint
CREATE INDEX "capability_grants_route_idx" ON "capability_grants" ("secret_route_id");
