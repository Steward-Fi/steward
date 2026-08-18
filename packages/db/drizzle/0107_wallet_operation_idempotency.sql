CREATE TABLE "wallet_operation_idempotency" (
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "operation" varchar(64) NOT NULL,
  "idempotency_key_hash" varchar(64) NOT NULL,
  "request_digest" varchar(64) NOT NULL,
  "status" varchar(32) DEFAULT 'processing' NOT NULL,
  "tx_id" varchar(64) NOT NULL,
  "tx_hash" varchar(128),
  "response_status" integer,
  "response_body" jsonb,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "wallet_operation_idempotency_pk" PRIMARY KEY("tenant_id", "agent_id", "operation", "idempotency_key_hash"),
  CONSTRAINT "wallet_operation_idempotency_tx_id_idx" UNIQUE("tx_id"),
  CONSTRAINT "wallet_operation_idempotency_status_chk" CHECK ("status" in ('processing', 'submission_unknown', 'completed')),
  CONSTRAINT "wallet_operation_idempotency_key_hash_chk" CHECK ("idempotency_key_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "wallet_operation_idempotency_request_digest_chk" CHECK ("request_digest" ~ '^[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "wallet_operation_idempotency" ADD CONSTRAINT "wallet_operation_idempotency_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "wallet_operation_idempotency" ADD CONSTRAINT "wallet_operation_idempotency_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "wallet_operation_idempotency" ADD CONSTRAINT "wallet_operation_idempotency_tenant_agent_fk" FOREIGN KEY ("tenant_id", "agent_id") REFERENCES "public"."agents"("tenant_id", "id") ON DELETE cascade ON UPDATE no action;
