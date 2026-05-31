CREATE TABLE IF NOT EXISTS "tenant_request_signing_keys" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" varchar(120) NOT NULL,
  "secret_ciphertext" text NOT NULL,
  "secret_iv" text NOT NULL,
  "secret_auth_tag" text NOT NULL,
  "secret_salt" text NOT NULL,
  "secret_prefix" varchar(32) NOT NULL,
  "status" varchar(16) DEFAULT 'active' NOT NULL,
  "expires_at" timestamp with time zone,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX IF NOT EXISTS "tenant_request_signing_keys_tenant_idx"
  ON "tenant_request_signing_keys" ("tenant_id");

CREATE INDEX IF NOT EXISTS "tenant_request_signing_keys_tenant_status_idx"
  ON "tenant_request_signing_keys" ("tenant_id", "status");
