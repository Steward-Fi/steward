CREATE TABLE IF NOT EXISTS "user_push_subscriptions" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "user_id" uuid NOT NULL REFERENCES "users"("id") ON DELETE cascade,
  "tenant_id" varchar(64) REFERENCES "tenants"("id") ON DELETE cascade,
  "provider" varchar(16) NOT NULL,
  "token" text NOT NULL,
  "platform" varchar(16),
  "device_id" varchar(255),
  "app_id" varchar(255),
  "locale" varchar(64),
  "timezone" varchar(128),
  "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "status" varchar(16) DEFAULT 'active' NOT NULL,
  "last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "user_push_subscriptions_provider_check"
    CHECK ("provider" IN ('expo', 'apns', 'fcm')),
  CONSTRAINT "user_push_subscriptions_platform_check"
    CHECK ("platform" IS NULL OR "platform" IN ('ios', 'android')),
  CONSTRAINT "user_push_subscriptions_status_check"
    CHECK ("status" IN ('active', 'revoked')),
  CONSTRAINT "user_push_subscriptions_revoked_state_check"
    CHECK (("status" = 'revoked') = ("revoked_at" IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS "user_push_subscriptions_user_status_idx"
  ON "user_push_subscriptions" ("user_id", "status");

CREATE INDEX IF NOT EXISTS "user_push_subscriptions_tenant_user_idx"
  ON "user_push_subscriptions" ("tenant_id", "user_id");

CREATE UNIQUE INDEX IF NOT EXISTS "user_push_subscriptions_active_token_idx"
  ON "user_push_subscriptions" ("user_id", "provider", "token")
  WHERE "status" = 'active';
