-- Durable terminal replay authority for fund-moving venue orders. Redis owns
-- the fast pending claim; this immutable PostgreSQL row survives Redis CAS
-- failures, process restarts, and pending-key expiry after a definite venue
-- response.
CREATE TABLE "trading_order_outcomes" (
	"id" varchar(64) PRIMARY KEY NOT NULL,
	"tenant_id" varchar(64) NOT NULL,
	"agent_id" varchar(64) NOT NULL,
	"venue" varchar(32) NOT NULL,
	"idempotency_key_hash" varchar(64) NOT NULL,
	"request_hash" varchar(64) NOT NULL,
	"http_status" integer NOT NULL,
	"response" jsonb NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "trading_order_outcomes_status_chk" CHECK ("http_status" IN (200, 400, 502)),
	CONSTRAINT "trading_order_outcomes_key_hash_chk" CHECK ("idempotency_key_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "trading_order_outcomes_request_hash_chk" CHECK ("request_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "trading_order_outcomes_response_size_chk" CHECK (octet_length("response"::text) <= 16384)
);
--> statement-breakpoint
CREATE UNIQUE INDEX "trading_order_outcomes_request_uidx" ON "trading_order_outcomes" ("tenant_id","agent_id","venue","idempotency_key_hash");
--> statement-breakpoint
CREATE INDEX "trading_order_outcomes_tenant_created_idx" ON "trading_order_outcomes" ("tenant_id","created_at");
--> statement-breakpoint
ALTER TABLE "trading_order_outcomes" ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE "trading_order_outcomes" FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY "steward_tenant_isolation" ON "trading_order_outcomes"
	USING (tenant_id = steward_rls.tenant_id())
	WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
CREATE OR REPLACE FUNCTION trading_order_outcomes_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
	RAISE EXCEPTION 'trading order outcomes are immutable'
		USING ERRCODE = '55000';
END;
$$;
--> statement-breakpoint
CREATE TRIGGER trading_order_outcomes_immutable
BEFORE UPDATE OR DELETE ON "trading_order_outcomes"
FOR EACH ROW EXECUTE FUNCTION trading_order_outcomes_immutable();
