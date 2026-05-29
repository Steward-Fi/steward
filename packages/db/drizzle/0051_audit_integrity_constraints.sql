-- Data-integrity hardening for audit/retention + wei CHECK constraints.
--
-- 1. audit_chain_heads: out-of-band high-water-mark per tenant so verification
--    can detect tail-truncation / whole-chain deletion that an in-band walk of
--    the surviving rows cannot. Updated atomically inside the advisory-locked
--    append transaction. floor_seq/floor_hmac anchor the chain after a
--    legitimate retention archive+drop of a prefix.
-- 2. CHECK constraints enforcing wei amounts are non-empty decimal digit
--    strings (transactions.value, auto_approval_rules.max_amount_wei /
--    escalate_above_wei).
--
-- NOTE: We deliberately do NOT add foreign keys from tenant_id columns to
-- tenants(id). audit_events / audit_chain_heads / secrets / proxy_audit_log /
-- webhook_deliveries legitimately record platform/system principals whose ids
-- are not rows in `tenants`, and an FK would reject those inserts and block
-- tenant deletion. Cross-tenant isolation is enforced at the application layer
-- (all queries scope by tenant_id); audit tamper-evidence comes from the HMAC
-- chain + audit_chain_heads high-water-mark, not referential integrity.
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

-- Drop tenant FKs if a prior revision of this migration installed them: they
-- reject legitimate platform/system-principal audit writes and block tenant
-- deletion. Safe no-ops when the constraints were never created.
ALTER TABLE "audit_chain_heads" DROP CONSTRAINT IF EXISTS "audit_chain_heads_tenant_id_tenants_id_fk";
--> statement-breakpoint
ALTER TABLE "secrets" DROP CONSTRAINT IF EXISTS "secrets_tenant_id_tenants_id_fk";
--> statement-breakpoint
ALTER TABLE "audit_events" DROP CONSTRAINT IF EXISTS "audit_events_tenant_id_tenants_id_fk";
--> statement-breakpoint
ALTER TABLE "proxy_audit_log" DROP CONSTRAINT IF EXISTS "proxy_audit_log_tenant_id_tenants_id_fk";
--> statement-breakpoint
ALTER TABLE "webhook_deliveries" DROP CONSTRAINT IF EXISTS "webhook_deliveries_tenant_id_tenants_id_fk";
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
