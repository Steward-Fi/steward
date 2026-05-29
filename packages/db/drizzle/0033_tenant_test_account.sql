ALTER TABLE "tenant_configs"
ADD COLUMN IF NOT EXISTS "test_account" jsonb DEFAULT '{}'::jsonb NOT NULL;
