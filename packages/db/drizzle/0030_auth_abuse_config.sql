ALTER TABLE "tenant_configs" ADD COLUMN IF NOT EXISTS "auth_abuse_config" jsonb DEFAULT '{}'::jsonb NOT NULL;
