ALTER TABLE "secret_routes" ADD COLUMN IF NOT EXISTS "agent_id" varchar(64);

CREATE INDEX IF NOT EXISTS "secret_routes_agent_idx" ON "secret_routes" ("agent_id");
