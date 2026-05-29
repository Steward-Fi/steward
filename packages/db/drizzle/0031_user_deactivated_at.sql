ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "deactivated_at" timestamp with time zone;
