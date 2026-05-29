CREATE UNIQUE INDEX IF NOT EXISTS "tenants_api_key_hash_unique_idx"
  ON "tenants" ("api_key_hash");

CREATE UNIQUE INDEX IF NOT EXISTS "tenant_sso_domains_tenant_canonical_domain_idx"
  ON "tenant_sso_domains" (
    "tenant_id",
    lower(trim(trailing '.' from "domain"))
  );

CREATE UNIQUE INDEX IF NOT EXISTS "tenant_sso_domains_verified_canonical_domain_idx"
  ON "tenant_sso_domains" (
    lower(trim(trailing '.' from "domain"))
  )
  WHERE "status" = 'verified';

CREATE UNIQUE INDEX IF NOT EXISTS "agents_tenant_id_id_idx"
  ON "agents" ("tenant_id", "id");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_signers_tenant_agent_fk'
  ) THEN
    ALTER TABLE "agent_signers"
      ADD CONSTRAINT "agent_signers_tenant_agent_fk"
      FOREIGN KEY ("tenant_id", "agent_id")
      REFERENCES "agents"("tenant_id", "id")
      ON DELETE cascade;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_key_quorums_tenant_agent_fk'
  ) THEN
    ALTER TABLE "agent_key_quorums"
      ADD CONSTRAINT "agent_key_quorums_tenant_agent_fk"
      FOREIGN KEY ("tenant_id", "agent_id")
      REFERENCES "agents"("tenant_id", "id")
      ON DELETE cascade;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'intents_tenant_agent_fk'
  ) THEN
    ALTER TABLE "intents"
      ADD CONSTRAINT "intents_tenant_agent_fk"
      FOREIGN KEY ("tenant_id", "agent_id")
      REFERENCES "agents"("tenant_id", "id")
      ON DELETE cascade;
  END IF;
END $$;

ALTER TABLE "refresh_tokens"
  ALTER COLUMN "user_id" TYPE uuid USING "user_id"::uuid,
  ALTER COLUMN "tenant_id" TYPE varchar(64);

CREATE UNIQUE INDEX IF NOT EXISTS "refresh_tokens_token_hash_unique_idx"
  ON "refresh_tokens" ("token_hash");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'refresh_tokens_user_id_users_id_fk'
  ) THEN
    ALTER TABLE "refresh_tokens"
      ADD CONSTRAINT "refresh_tokens_user_id_users_id_fk"
      FOREIGN KEY ("user_id")
      REFERENCES "users"("id")
      ON DELETE cascade;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'refresh_tokens_tenant_id_tenants_id_fk'
  ) THEN
    ALTER TABLE "refresh_tokens"
      ADD CONSTRAINT "refresh_tokens_tenant_id_tenants_id_fk"
      FOREIGN KEY ("tenant_id")
      REFERENCES "tenants"("id")
      ON DELETE cascade;
  END IF;
END $$;
