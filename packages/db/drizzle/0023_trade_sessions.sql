CREATE TABLE IF NOT EXISTS "trade_sessions" (
  "id" varchar(128) PRIMARY KEY NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "venue" varchar(64) NOT NULL,
  "scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "status" varchar(32) NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  "revoked_by" varchar(255)
);
--> statement-breakpoint
ALTER TABLE "trade_sessions" ADD CONSTRAINT "trade_sessions_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "trade_sessions" ADD CONSTRAINT "trade_sessions_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "trade_sessions_agent_venue_status_idx" ON "trade_sessions" USING btree ("agent_id","venue","status");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "trade_sessions_tenant_idx" ON "trade_sessions" USING btree ("tenant_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "trade_sessions_expires_at_idx" ON "trade_sessions" USING btree ("expires_at");
