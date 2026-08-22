-- 0118 depends on the coordinated 0114-0117 migration range. Keep the
-- generic intent execution fence independent from steward_guard_agent_delete
-- so those preceding migrations can extend the main lifecycle function
-- without this successor replacing or weakening their invariants.
CREATE OR REPLACE FUNCTION steward_guard_generic_intent_execution_delete()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.intents AS intent
    WHERE intent.tenant_id = OLD.tenant_id
      AND intent.agent_id = OLD.id
      AND intent.status = 'executing'
  ) THEN
    RAISE EXCEPTION 'agent has unresolved generic intent execution'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS agents_active_intent_execution_fence ON public.agents;
--> statement-breakpoint
-- PostgreSQL fires same-kind triggers alphabetically. This name deliberately
-- sorts before agents_delete_authority_guard, whose legacy provider-evidence
-- cleanup detaches terminal provider intents from the agent.
CREATE TRIGGER agents_active_intent_execution_fence
BEFORE DELETE ON public.agents
FOR EACH ROW EXECUTE FUNCTION steward_guard_generic_intent_execution_delete();
--> statement-breakpoint
-- This migration is deliberately not tolerant of partially-created objects:
-- Drizzle records it atomically, so a same-named object with a different
-- shape is evidence of schema drift and must fail instead of being accepted.
ALTER TABLE public.webhook_deliveries
  ADD COLUMN predecessor_delivery_id uuid,
  ADD COLUMN claim_token uuid;
--> statement-breakpoint
ALTER TABLE public.webhook_deliveries
  ADD CONSTRAINT webhook_deliveries_predecessor_fk
  FOREIGN KEY (predecessor_delivery_id)
  REFERENCES public.webhook_deliveries(id)
  ON DELETE CASCADE;
--> statement-breakpoint
CREATE INDEX webhook_deliveries_predecessor_idx
  ON public.webhook_deliveries(predecessor_delivery_id);
--> statement-breakpoint
DO $$
DECLARE
  predecessor_column_count integer;
  claim_column_count integer;
  predecessor_fk_count integer;
  predecessor_index_count integer;
BEGIN
  SELECT count(*) INTO predecessor_column_count
  FROM pg_attribute
  WHERE attrelid = 'public.webhook_deliveries'::regclass
    AND attname = 'predecessor_delivery_id'
    AND atttypid = 'uuid'::regtype
    AND attnotnull = false
    AND NOT attisdropped;
  SELECT count(*) INTO claim_column_count
  FROM pg_attribute
  WHERE attrelid = 'public.webhook_deliveries'::regclass
    AND attname = 'claim_token'
    AND atttypid = 'uuid'::regtype
    AND attnotnull = false
    AND NOT attisdropped;
  SELECT count(*) INTO predecessor_fk_count
  FROM pg_constraint
  WHERE conrelid = 'public.webhook_deliveries'::regclass
    AND confrelid = 'public.webhook_deliveries'::regclass
    AND conname = 'webhook_deliveries_predecessor_fk'
    AND contype = 'f'
    AND confdeltype = 'c'
    AND array_length(conkey, 1) = 1
    AND conkey[1] = (
      SELECT attnum FROM pg_attribute
      WHERE attrelid = 'public.webhook_deliveries'::regclass
        AND attname = 'predecessor_delivery_id'
    )
    AND array_length(confkey, 1) = 1
    AND confkey[1] = (
      SELECT attnum FROM pg_attribute
      WHERE attrelid = 'public.webhook_deliveries'::regclass
        AND attname = 'id'
    );
  SELECT count(*) INTO predecessor_index_count
  FROM pg_index AS index_definition
  JOIN pg_class AS index_relation ON index_relation.oid = index_definition.indexrelid
  WHERE index_definition.indrelid = 'public.webhook_deliveries'::regclass
    AND index_relation.relname = 'webhook_deliveries_predecessor_idx'
    AND index_definition.indisvalid
    AND index_definition.indpred IS NULL
    AND index_definition.indexprs IS NULL
    AND index_definition.indnkeyatts = 1
    AND index_definition.indkey[0] = (
      SELECT attnum FROM pg_attribute
      WHERE attrelid = 'public.webhook_deliveries'::regclass
        AND attname = 'predecessor_delivery_id'
    );
  IF predecessor_column_count <> 1 OR claim_column_count <> 1
     OR predecessor_fk_count <> 1 OR predecessor_index_count <> 1 THEN
    RAISE EXCEPTION '0118 webhook delivery schema invariant mismatch';
  END IF;
END;
$$;
