CREATE TABLE IF NOT EXISTS "tenant_app_clients" (
  "id" varchar(64) NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" varchar(255) NOT NULL,
  "environment" varchar(32) DEFAULT 'production' NOT NULL,
  "enabled" boolean DEFAULT true NOT NULL,
  "is_default" boolean DEFAULT false NOT NULL,
  "allowed_origins" text[] DEFAULT '{}'::text[] NOT NULL,
  "allowed_redirect_urls" text[] DEFAULT '{}'::text[] NOT NULL,
  "login_methods" jsonb,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "tenant_app_clients_tenant_id_id_idx"
  ON "tenant_app_clients" ("tenant_id", "id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tenant_app_clients_tenant_id_idx"
  ON "tenant_app_clients" ("tenant_id");
