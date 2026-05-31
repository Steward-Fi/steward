CREATE TABLE IF NOT EXISTS "tenant_invitations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "email" varchar(255) NOT NULL,
  "role" varchar(32) DEFAULT 'member' NOT NULL,
  "token_hash" varchar(64) NOT NULL,
  "status" varchar(16) DEFAULT 'pending' NOT NULL,
  "invited_by_user_id" uuid,
  "accepted_by_user_id" uuid,
  "accepted_at" timestamp with time zone,
  "revoked_at" timestamp with time zone,
  "expires_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "tenant_invitations_tenant_id_tenants_id_fk"
    FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE cascade,
  CONSTRAINT "tenant_invitations_invited_by_user_id_users_id_fk"
    FOREIGN KEY ("invited_by_user_id") REFERENCES "users"("id") ON DELETE set null,
  CONSTRAINT "tenant_invitations_accepted_by_user_id_users_id_fk"
    FOREIGN KEY ("accepted_by_user_id") REFERENCES "users"("id") ON DELETE set null,
  CONSTRAINT "tenant_invitations_status_check"
    CHECK ("status" IN ('pending', 'accepted', 'revoked', 'expired')),
  CONSTRAINT "tenant_invitations_role_check"
    CHECK ("role" IN ('admin', 'developer', 'billing', 'viewer', 'member')),
  CONSTRAINT "tenant_invitations_terminal_state_check"
    CHECK (
      ("status" = 'pending' AND "accepted_at" IS NULL AND "revoked_at" IS NULL)
      OR ("status" = 'accepted' AND "accepted_at" IS NOT NULL AND "accepted_by_user_id" IS NOT NULL)
      OR ("status" = 'revoked' AND "revoked_at" IS NOT NULL)
      OR ("status" = 'expired')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS "tenant_invitations_token_hash_idx"
  ON "tenant_invitations" ("token_hash");

CREATE INDEX IF NOT EXISTS "tenant_invitations_tenant_status_idx"
  ON "tenant_invitations" ("tenant_id", "status");

CREATE UNIQUE INDEX IF NOT EXISTS "tenant_invitations_pending_email_idx"
  ON "tenant_invitations" ("tenant_id", lower("email"))
  WHERE "status" = 'pending';
