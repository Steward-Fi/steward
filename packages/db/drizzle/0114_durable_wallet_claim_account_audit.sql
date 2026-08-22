CREATE TABLE IF NOT EXISTS "digital_asset_account_wallet_lifecycles" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "account_id" varchar(64) NOT NULL,
  "wallet_agent_id" varchar(64) NOT NULL,
  "chain_family" "chain_family" NOT NULL,
  "state" varchar(24) DEFAULT 'staging' NOT NULL,
  "owner_token" uuid NOT NULL,
  "lease_expires_at" timestamp with time zone NOT NULL,
  "last_error" text,
  "provisioned_at" timestamp with time zone,
  "adopted_at" timestamp with time zone,
  "retired_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "digital_asset_account_wallet_lifecycles_tenant_id_tenants_id_fk"
    FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE cascade,
  CONSTRAINT "digital_asset_account_wallet_lifecycle_state_chk"
    CHECK ("state" IN ('staging', 'provisioned', 'adopted', 'recoverable', 'retiring', 'retired'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "digital_asset_account_wallet_lifecycle_wallet_uniq"
  ON "digital_asset_account_wallet_lifecycles" ("tenant_id", "wallet_agent_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "digital_asset_account_wallet_lifecycle_account_idx"
  ON "digital_asset_account_wallet_lifecycles" ("tenant_id", "account_id", "created_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "digital_asset_account_wallet_lifecycle_recovery_idx"
  ON "digital_asset_account_wallet_lifecycles" ("state", "lease_expires_at");
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "pregenerated_wallet_claim_lifecycles" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "claim_token_hash" varchar(64) NOT NULL,
  "original_claim_platform_id" varchar(255) NOT NULL,
  "source_tenant_id" varchar(64) NOT NULL,
  "source_agent_id" varchar(64) NOT NULL,
  "target_tenant_id" varchar(64) NOT NULL,
  "target_agent_id" varchar(64) NOT NULL,
  "user_id" uuid NOT NULL,
  "wallet_index" integer NOT NULL,
  "state" varchar(24) DEFAULT 'reserved' NOT NULL,
  "owner_token" uuid,
  "lease_expires_at" timestamp with time zone,
  "solana_imported" boolean DEFAULT false NOT NULL,
  "evm_imported" boolean DEFAULT false NOT NULL,
  "target_adopted" boolean DEFAULT false NOT NULL,
  "last_error" text,
  "completed_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "pregenerated_wallet_claim_state_chk"
    CHECK ("state" IN ('reserved', 'importing', 'adopted', 'recoverable', 'completed')),
  CONSTRAINT "pregenerated_wallet_claim_wallet_index_chk" CHECK ("wallet_index" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "pregenerated_wallet_claim_token_uniq"
  ON "pregenerated_wallet_claim_lifecycles" ("claim_token_hash");
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "pregenerated_wallet_claim_target_uniq"
  ON "pregenerated_wallet_claim_lifecycles" ("target_tenant_id", "target_agent_id");
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "pregenerated_wallet_claim_source_uniq"
  ON "pregenerated_wallet_claim_lifecycles" ("source_tenant_id", "source_agent_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "pregenerated_wallet_claim_recovery_idx"
  ON "pregenerated_wallet_claim_lifecycles" ("state", "lease_expires_at");
