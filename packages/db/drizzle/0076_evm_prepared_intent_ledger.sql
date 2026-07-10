ALTER TABLE "intents"
  ADD COLUMN IF NOT EXISTS "idempotency_key" varchar(255),
  ADD COLUMN IF NOT EXISTS "semantic_request_hash" varchar(128),
  ADD COLUMN IF NOT EXISTS "intent_hash" varchar(128);

CREATE UNIQUE INDEX IF NOT EXISTS "intents_tenant_agent_type_idempotency_unique_idx"
  ON "intents" ("tenant_id", "agent_id", "intent_type", "idempotency_key")
  WHERE "idempotency_key" IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS "intents_tenant_agent_type_intent_hash_unique_idx"
  ON "intents" ("tenant_id", "agent_id", "intent_type", "intent_hash")
  WHERE "intent_hash" IS NOT NULL;

CREATE INDEX IF NOT EXISTS "intents_tenant_agent_semantic_request_idx"
  ON "intents" ("tenant_id", "agent_id", "semantic_request_hash");
