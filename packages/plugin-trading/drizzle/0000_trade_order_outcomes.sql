-- Durable execution + terminal replay authority for fund-moving venue orders.
-- Redis owns the fast pending claim. PostgreSQL receives one immutable `claim`
-- row before venue I/O and one immutable `terminal` row after a known result.
-- Non-fill outcomes add one immutable `release` row in the same transaction as
-- the spend decrement, making replay-driven effect draining exactly once.
-- A claim without a terminal row survives Redis expiry/restart as a fail-closed
-- reconciliation anchor and can never authorize another venue submission.
CREATE TABLE "trading_order_outcomes" (
	"id" varchar(64) PRIMARY KEY NOT NULL,
	"tenant_id" varchar(64) NOT NULL,
	"agent_id" varchar(64) NOT NULL,
	"venue" varchar(32) NOT NULL,
	"phase" varchar(16) NOT NULL,
	"idempotency_key_hash" varchar(64) NOT NULL,
	"request_hash" varchar(64) NOT NULL,
	"http_status" integer NOT NULL,
	"response" jsonb NOT NULL,
	"created_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "trading_order_outcomes_status_chk" CHECK ("http_status" IN (200, 400, 409, 502)),
	CONSTRAINT "trading_order_outcomes_phase_chk" CHECK ("phase" IN ('claim', 'terminal', 'release')),
	CONSTRAINT "trading_order_outcomes_key_hash_chk" CHECK ("idempotency_key_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "trading_order_outcomes_request_hash_chk" CHECK ("request_hash" ~ '^[0-9a-f]{64}$'),
	CONSTRAINT "trading_order_outcomes_response_size_chk" CHECK (octet_length("response"::text) <= 16384)
);
--> statement-breakpoint
CREATE UNIQUE INDEX "trading_order_outcomes_request_uidx" ON "trading_order_outcomes" ("tenant_id","agent_id","venue","idempotency_key_hash","phase");
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
