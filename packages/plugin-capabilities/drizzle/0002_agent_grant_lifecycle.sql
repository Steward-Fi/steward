-- Capability grants intentionally retain historical evidence instead of using
-- an agent FK with ON DELETE CASCADE. Fence every authority-bearing binding
-- against the core agent row so agent deletion and grant creation serialize on
-- PostgreSQL's native row locks, including writers from older application pods.
CREATE OR REPLACE FUNCTION capability_grants_agent_fence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
	PERFORM public.steward_lock_tenant_deletion(NEW.tenant_id);
	PERFORM 1
	FROM public.agents
	WHERE id = NEW.agent_id
		AND tenant_id = NEW.tenant_id
	FOR KEY SHARE;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'capability grant references a missing agent'
			USING ERRCODE = '23503';
	END IF;

	RETURN NEW;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS capability_grants_agent_fence ON public.capability_grants;
--> statement-breakpoint
CREATE TRIGGER capability_grants_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id, status, secret_route_id
ON public.capability_grants
FOR EACH ROW
WHEN (NEW.status = 'active')
EXECUTE FUNCTION capability_grants_agent_fence();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION capability_grants_guard_agent_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
	IF EXISTS (
		SELECT 1 FROM public.capability_grants
		WHERE tenant_id = OLD.tenant_id
			AND agent_id = OLD.id
			AND status = 'active'
	) THEN
		RAISE EXCEPTION 'agent has active capability grants'
			USING ERRCODE = '55000';
	END IF;
	RETURN OLD;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS capability_grants_guard_agent_delete ON public.agents;
--> statement-breakpoint
CREATE TRIGGER capability_grants_guard_agent_delete
BEFORE DELETE ON public.agents
FOR EACH ROW EXECUTE FUNCTION capability_grants_guard_agent_delete();
--> statement-breakpoint
-- Fail closed for authority orphaned before this fence existed. The paired
-- route is disabled before the grant is terminalized so no credential-injection
-- path survives a historical missing parent.
UPDATE public.secret_routes AS route
SET enabled = false
FROM public.capability_grants AS capability_grant
WHERE capability_grant.secret_route_id = route.id
	AND capability_grant.tenant_id = route.tenant_id
	AND capability_grant.status = 'active'
	AND NOT EXISTS (
		SELECT 1
		FROM public.agents
		WHERE agents.id = capability_grant.agent_id
			AND agents.tenant_id = capability_grant.tenant_id
	);
--> statement-breakpoint
UPDATE public.capability_grants AS capability_grant
SET status = 'revoked'
WHERE capability_grant.status = 'active'
	AND NOT EXISTS (
		SELECT 1
		FROM public.agents
		WHERE agents.id = capability_grant.agent_id
			AND agents.tenant_id = capability_grant.tenant_id
	);
