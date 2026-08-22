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
ALTER TABLE public.webhook_deliveries
  ADD COLUMN IF NOT EXISTS predecessor_delivery_id uuid;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'webhook_deliveries_predecessor_fk'
      AND conrelid = 'public.webhook_deliveries'::regclass
  ) THEN
    ALTER TABLE public.webhook_deliveries
      ADD CONSTRAINT webhook_deliveries_predecessor_fk
      FOREIGN KEY (predecessor_delivery_id)
      REFERENCES public.webhook_deliveries(id)
      ON DELETE CASCADE;
  END IF;
END;
$$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS webhook_deliveries_predecessor_idx
  ON public.webhook_deliveries(predecessor_delivery_id);
