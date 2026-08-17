-- #240: append-only, generation-specific provider policy reservations.
CREATE TABLE "provider_action_reservation_generations" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "intent_id" varchar(64) NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "generation" integer NOT NULL,
  "phase" varchar(16) NOT NULL,
  "handles" jsonb NOT NULL,
  "state" varchar(24) NOT NULL DEFAULT 'pending',
  "attempts" integer NOT NULL DEFAULT 0,
  "next_retry_at" timestamptz,
  "last_error" text,
  "claimed_at" timestamptz,
  "claimed_by" uuid,
  "reconciled_at" timestamptz,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT "provider_action_reservation_generations_intent_fk"
    FOREIGN KEY ("tenant_id","intent_id") REFERENCES "intents"("tenant_id","id") ON DELETE CASCADE,
  CONSTRAINT "provider_action_reservation_generations_intent_gen_uniq" UNIQUE ("intent_id","generation"),
  CONSTRAINT "provider_action_reservation_generations_shape_chk" CHECK (
    "generation" > 0 AND "phase" IN ('decision','execution')
    AND "state" IN ('pending','needs_attention','settled','released') AND "attempts" >= 0
    AND jsonb_typeof("handles") = 'object'
    AND "handles"->>'schemaVersion' = 'steward.provider-policy-reservations.v1'
    AND ("handles"->>'generation')::integer = "generation" AND "handles"->>'phase' = "phase"
    AND jsonb_typeof("handles"->'cumulativeSpend') = 'array'
    AND (jsonb_array_length("handles"->'cumulativeSpend') > 0 OR
      ("handles" ? 'windowedInvoke' AND "handles"->'windowedInvoke' <> 'null'::jsonb))
    AND (("state" IN ('pending','needs_attention') AND "reconciled_at" IS NULL) OR
      ("state" IN ('settled','released') AND "reconciled_at" IS NOT NULL))
  )
);
--> statement-breakpoint
CREATE INDEX "provider_action_reservation_generations_due_idx"
  ON "provider_action_reservation_generations" ("state","next_retry_at","created_at")
  WHERE "state" IN ('pending','needs_attention');
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_provider_reservation_generation_guard()
RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF OLD.intent_id IS DISTINCT FROM NEW.intent_id OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR
     OLD.generation IS DISTINCT FROM NEW.generation OR OLD.phase IS DISTINCT FROM NEW.phase OR
     OLD.handles IS DISTINCT FROM NEW.handles OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
    RAISE EXCEPTION 'provider reservation generation identity mutated' USING ERRCODE='23514';
  END IF;
  IF OLD.state IN ('settled','released') THEN
    RAISE EXCEPTION 'terminal provider reservation generation mutated' USING ERRCODE='23514';
  END IF;
  IF NEW.attempts < OLD.attempts OR NEW.attempts > OLD.attempts + 1 THEN
    RAISE EXCEPTION 'illegal provider reservation attempt transition' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $fn$;
--> statement-breakpoint
CREATE TRIGGER "provider_action_reservation_generation_guard"
BEFORE UPDATE ON "provider_action_reservation_generations"
FOR EACH ROW EXECUTE FUNCTION steward_provider_reservation_generation_guard();
--> statement-breakpoint
