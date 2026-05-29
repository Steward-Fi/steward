-- Data-integrity hardening for audit/retention + sensitive-table tenant FKs.
--
-- 1. audit_chain_heads: out-of-band high-water-mark per tenant so verification
--    can detect tail-truncation / whole-chain deletion that an in-band walk of
--    the surviving rows cannot. Updated atomically inside the advisory-locked
--    append transaction. floor_seq/floor_hmac anchor the chain after a
--    legitimate retention archive+drop of a prefix.
-- 2. Foreign keys binding free-text tenant_id columns to tenants(id).
--    - secrets, audit_events, audit_chain_heads -> ON DELETE RESTRICT
--      (sensitive / immutable: never silently dropped on tenant delete).
--    - proxy_audit_log, webhook_deliveries -> ON DELETE CASCADE
--      (operational telemetry: fine to remove with the tenant).
-- 3. CHECK constraints enforcing wei amounts are non-empty decimal digit
--    strings (transactions.value, auto_approval_rules.max_amount_wei /
--    escalate_above_wei).
--
-- All DDL is idempotent so re-running against a partially-migrated DB is safe.

CREATE TABLE IF NOT EXISTS "audit_chain_heads" (
  "tenant_id" varchar(64) PRIMARY KEY NOT NULL,
  "expected_seq" bigint NOT NULL,
  "expected_count" bigint NOT NULL,
  "head_hmac" bytea NOT NULL,
  "floor_seq" bigint DEFAULT 0 NOT NULL,
  "floor_hmac" bytea,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_chain_heads_tenant_id_tenants_id_fk') THEN
    ALTER TABLE "audit_chain_heads"
      ADD CONSTRAINT "audit_chain_heads_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE restrict;
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'secrets_tenant_id_tenants_id_fk') THEN
    ALTER TABLE "secrets"
      ADD CONSTRAINT "secrets_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE restrict;
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'audit_events_tenant_id_tenants_id_fk') THEN
    ALTER TABLE "audit_events"
      ADD CONSTRAINT "audit_events_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE restrict;
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'proxy_audit_log_tenant_id_tenants_id_fk') THEN
    ALTER TABLE "proxy_audit_log"
      ADD CONSTRAINT "proxy_audit_log_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE cascade;
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'webhook_deliveries_tenant_id_tenants_id_fk') THEN
    ALTER TABLE "webhook_deliveries"
      ADD CONSTRAINT "webhook_deliveries_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE cascade;
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'transactions_value_wei_chk') THEN
    ALTER TABLE "transactions"
      ADD CONSTRAINT "transactions_value_wei_chk" CHECK ("value" ~ '^[0-9]+$');
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'auto_approval_rules_max_amount_wei_chk') THEN
    ALTER TABLE "auto_approval_rules"
      ADD CONSTRAINT "auto_approval_rules_max_amount_wei_chk" CHECK ("max_amount_wei" ~ '^[0-9]+$');
  END IF;
END $$;
--> statement-breakpoint

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'auto_approval_rules_escalate_above_wei_chk') THEN
    ALTER TABLE "auto_approval_rules"
      ADD CONSTRAINT "auto_approval_rules_escalate_above_wei_chk"
      CHECK ("escalate_above_wei" IS NULL OR "escalate_above_wei" ~ '^[0-9]+$');
  END IF;
END $$;
