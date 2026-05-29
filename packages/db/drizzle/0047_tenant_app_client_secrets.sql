CREATE TABLE IF NOT EXISTS "tenant_app_client_secrets" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "client_id" varchar(64) NOT NULL,
  "secret_hash" text NOT NULL,
  "secret_prefix" varchar(32) NOT NULL,
  "status" varchar(16) DEFAULT 'active' NOT NULL,
  "expires_at" timestamp with time zone,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "tenant_app_client_secrets_client_fk"
    FOREIGN KEY ("tenant_id", "client_id")
    REFERENCES "tenant_app_clients"("tenant_id", "id")
    ON DELETE cascade
);

CREATE INDEX IF NOT EXISTS "tenant_app_client_secrets_tenant_client_idx"
  ON "tenant_app_client_secrets" ("tenant_id", "client_id");

CREATE INDEX IF NOT EXISTS "tenant_app_client_secrets_status_idx"
  ON "tenant_app_client_secrets" ("status");
