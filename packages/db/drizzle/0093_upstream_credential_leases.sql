CREATE TABLE "upstream_credential_leases" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "workspace_id" uuid NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "grant_id" uuid NOT NULL,
  "capability_id" uuid NOT NULL,
  "issuer" varchar(64) NOT NULL,
  "resource" jsonb NOT NULL,
  "resource_hash" varchar(64) NOT NULL,
  "idempotency_key_hash" varchar(64) NOT NULL,
  "token_hash" varchar(64),
  "status" varchar(24) DEFAULT 'issuing' NOT NULL,
  "expires_at" timestamptz,
  "delivered_at" timestamptz,
  "revoked_at" timestamptz,
  "last_error" text,
  "created_at" timestamptz DEFAULT now() NOT NULL,
  "updated_at" timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT "upstream_credential_leases_status_check" CHECK ("status" IN ('issuing','active','revoking','revoked','expired','failed','needs_attention')),
  CONSTRAINT "upstream_credential_leases_agent_fk" FOREIGN KEY ("tenant_id", "agent_id") REFERENCES "agents"("tenant_id", "id") ON DELETE CASCADE,
  CONSTRAINT "upstream_credential_leases_workspace_fk" FOREIGN KEY ("tenant_id", "workspace_id") REFERENCES "workspaces"("tenant_id", "id") ON DELETE CASCADE
);
--> statement-breakpoint
CREATE UNIQUE INDEX "upstream_credential_leases_replay_uniq" ON "upstream_credential_leases" ("tenant_id", "agent_id", "idempotency_key_hash");
--> statement-breakpoint
CREATE INDEX "upstream_credential_leases_status_expiry_idx" ON "upstream_credential_leases" ("status", "expires_at");
--> statement-breakpoint
CREATE INDEX "upstream_credential_leases_binding_idx" ON "upstream_credential_leases" ("tenant_id", "workspace_id", "agent_id", "grant_id");
--> statement-breakpoint
CREATE TABLE "upstream_credential_lease_events" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "lease_id" uuid NOT NULL REFERENCES "upstream_credential_leases"("id") ON DELETE CASCADE,
  "tenant_id" varchar(64) NOT NULL,
  "action" varchar(64) NOT NULL,
  "decision" varchar(16) NOT NULL,
  "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "created_at" timestamptz DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "upstream_credential_lease_events_lease_created_idx" ON "upstream_credential_lease_events" ("lease_id", "created_at");
--> statement-breakpoint
CREATE INDEX "upstream_credential_lease_events_tenant_created_idx" ON "upstream_credential_lease_events" ("tenant_id", "created_at");
