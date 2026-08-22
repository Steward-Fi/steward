CREATE TABLE "trade_order_recoveries" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "session_id" varchar(128) NOT NULL,
  "venue" varchar(32) NOT NULL,
  "idempotency_key_hash" varchar(64) NOT NULL,
  "body_hash" varchar(64) NOT NULL,
  "state" varchar(32) DEFAULT 'prepared' NOT NULL,
  "venue_identity" varchar(255),
  "venue_result" jsonb,
  "response_envelope" jsonb,
  "occurrence_at" timestamp with time zone DEFAULT now() NOT NULL,
  "submit_started_at" timestamp with time zone,
  "audit_delivered_at" timestamp with time zone,
  "claim_token" uuid NOT NULL,
  "claimed_at" timestamp with time zone DEFAULT now() NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "trade_order_recoveries_state_chk" CHECK (
    "state" IN ('prepared','submitting','ambiguous','submitted','rejected','completed')
  )
);

CREATE UNIQUE INDEX "trade_order_recoveries_replay_uidx"
  ON "trade_order_recoveries" ("tenant_id", "agent_id", "venue", "idempotency_key_hash");

CREATE INDEX "trade_order_recoveries_pending_effects_idx"
  ON "trade_order_recoveries" ("claimed_at", "created_at", "id")
  WHERE "audit_delivered_at" IS NULL;

CREATE UNIQUE INDEX "audit_events_trade_recovery_identity_uidx"
  ON "audit_events" ("tenant_id", ("metadata"->>'tradeRecoveryId'))
  WHERE "metadata" ? 'tradeRecoveryId';
