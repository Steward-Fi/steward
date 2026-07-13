CREATE TYPE "public"."execution_authorization_status" AS ENUM('active', 'consumed', 'expired', 'revoked');
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "execution_payload_digest" varchar(64);
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "execution_policy_revision_hash" varchar(64);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "execution_authorization_nonces" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "authorization_id" varchar(64) NOT NULL,
  "request_id" varchar(64) NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "capability" varchar(64) NOT NULL,
  "backend" varchar(64) NOT NULL,
  "payload_digest" varchar(64) NOT NULL,
  "policy_revision_hash" varchar(64),
  "approval_id" varchar(64),
  "nonce" varchar(64) NOT NULL,
  "signature" text NOT NULL,
  "idempotency_key" text,
  "status" "execution_authorization_status" DEFAULT 'active' NOT NULL,
  "issued_at" timestamp with time zone NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "consumed_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "execution_authorization_nonces" ADD CONSTRAINT "execution_authorization_nonces_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "execution_authorization_nonces" ADD CONSTRAINT "execution_authorization_nonces_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "execution_authorization_nonces_auth_id_idx" ON "execution_authorization_nonces" USING btree ("authorization_id");
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "execution_authorization_nonces_nonce_idx" ON "execution_authorization_nonces" USING btree ("nonce");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "execution_authorization_nonces_tenant_agent_status_idx" ON "execution_authorization_nonces" USING btree ("tenant_id","agent_id","status");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "execution_authorization_nonces_expires_at_idx" ON "execution_authorization_nonces" USING btree ("expires_at");
