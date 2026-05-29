ALTER TABLE "tenant_configs"
ADD COLUMN IF NOT EXISTS "allowed_redirect_urls" text[] DEFAULT '{}'::text[] NOT NULL;
