CREATE OR REPLACE FUNCTION steward_guard_approved_agent_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.transactions
    WHERE agent_id = OLD.id
      AND status = 'approved'
  ) THEN
    RAISE EXCEPTION 'agent has unresolved approved execution'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS steward_guard_approved_agent_delete ON public.agents;
--> statement-breakpoint
CREATE TRIGGER steward_guard_approved_agent_delete
BEFORE DELETE ON public.agents
FOR EACH ROW EXECUTE FUNCTION steward_guard_approved_agent_delete();
