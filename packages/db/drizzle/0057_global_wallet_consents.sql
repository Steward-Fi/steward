ALTER TABLE "tenant_app_clients"
  ADD COLUMN IF NOT EXISTS "global_wallet_enabled" boolean DEFAULT false NOT NULL,
  ADD COLUMN IF NOT EXISTS "global_wallet_allowed_scopes" text[] DEFAULT ARRAY['eth_accounts','personal_sign']::text[] NOT NULL;

CREATE TABLE IF NOT EXISTS "user_wallet_app_consents" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "client_id" varchar(64) NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users"("id") ON DELETE cascade,
  "wallet_agent_id" varchar(128),
  "wallet_address" varchar(128),
  "origin" text NOT NULL,
  "redirect_uri" text,
  "scopes" text[] DEFAULT ARRAY[]::text[] NOT NULL,
  "status" varchar(16) DEFAULT 'active' NOT NULL,
  "granted_at" timestamp with time zone DEFAULT now() NOT NULL,
  "last_used_at" timestamp with time zone,
  "expires_at" timestamp with time zone,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "user_wallet_app_consents_app_client_fk"
    FOREIGN KEY ("tenant_id", "client_id")
    REFERENCES "tenant_app_clients"("tenant_id", "id")
    ON DELETE cascade
);

CREATE INDEX IF NOT EXISTS "user_wallet_app_consents_tenant_client_user_idx"
  ON "user_wallet_app_consents" ("tenant_id", "client_id", "user_id");

CREATE UNIQUE INDEX IF NOT EXISTS "user_wallet_app_consents_active_unique_idx"
  ON "user_wallet_app_consents" ("tenant_id", "client_id", "user_id", "origin")
  WHERE "status" = 'active';

CREATE TABLE IF NOT EXISTS "global_wallet_action_confirmations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "consent_id" uuid NOT NULL REFERENCES "user_wallet_app_consents"("id") ON DELETE cascade,
  "tenant_id" varchar(64) NOT NULL,
  "client_id" varchar(64) NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users"("id") ON DELETE cascade,
  "origin" text NOT NULL,
  "method" varchar(64) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "status" varchar(16) DEFAULT 'approved' NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "approved_at" timestamp with time zone DEFAULT now() NOT NULL,
  "consumed_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "global_wallet_action_confirmations_consent_idx"
  ON "global_wallet_action_confirmations" ("consent_id");

CREATE INDEX IF NOT EXISTS "global_wallet_action_confirmations_user_status_idx"
  ON "global_wallet_action_confirmations" ("user_id", "status");
