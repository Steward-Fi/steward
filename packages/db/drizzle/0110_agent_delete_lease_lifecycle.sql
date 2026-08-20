-- Credential lease evidence must outlive the agent authority it records. Agent
-- deletion is allowed only after each lease is terminal and secret-free;
-- retaining the composite FK would make that evidence lifecycle impossible.
ALTER TABLE "upstream_credential_leases"
  DROP CONSTRAINT IF EXISTS "upstream_credential_leases_agent_fk";
--> statement-breakpoint
ALTER TABLE "upstream_credential_leases"
  DROP CONSTRAINT IF EXISTS "upstream_credential_leases_workspace_fk";
--> statement-breakpoint
ALTER TABLE "provider_action_bindings"
  DROP CONSTRAINT IF EXISTS "provider_action_bindings_actor_fk";
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_fence_agent_authority_creation()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM 1
  FROM public.agents
  WHERE tenant_id = NEW.tenant_id AND id = NEW.agent_id
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'agent authority parent does not exist'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER upstream_credential_leases_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id, status ON upstream_credential_leases
FOR EACH ROW EXECUTE FUNCTION steward_fence_agent_authority_creation();
--> statement-breakpoint
CREATE TRIGGER pending_proxy_requests_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id, status ON pending_proxy_requests
FOR EACH ROW
EXECUTE FUNCTION steward_fence_agent_authority_creation();
--> statement-breakpoint
CREATE TRIGGER secret_routes_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id, enabled ON secret_routes
FOR EACH ROW
WHEN (NEW.agent_id IS NOT NULL AND NEW.enabled)
EXECUTE FUNCTION steward_fence_agent_authority_creation();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_fence_upstream_lease_workspace()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  PERFORM 1
  FROM public.workspaces
  WHERE tenant_id = NEW.tenant_id AND id = NEW.workspace_id
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'upstream lease workspace does not exist'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER upstream_credential_leases_workspace_fence
BEFORE INSERT OR UPDATE OF tenant_id, workspace_id, status ON upstream_credential_leases
FOR EACH ROW EXECUTE FUNCTION steward_fence_upstream_lease_workspace();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_fence_provider_action_agent()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  -- Existing terminal evidence may receive unrelated maintenance updates, but
  -- every new binding and every transition into a live state needs an agent.
  IF TG_OP = 'UPDATE' AND NEW.status NOT IN (
    'pending_approval', 'approved', 'allowed_stub',
    'execution_ready', 'executing', 'outcome_unknown'
  ) THEN
    RETURN NEW;
  END IF;
  PERFORM 1
  FROM public.agents
  WHERE tenant_id = NEW.tenant_id AND id = NEW.actor_agent_id
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider action agent does not exist'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER provider_action_bindings_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, actor_agent_id, status ON provider_action_bindings
FOR EACH ROW EXECUTE FUNCTION steward_fence_provider_action_agent();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_guard_agent_delete()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  has_active_capability_grant boolean := false;
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.upstream_credential_leases
    WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.id
      AND NOT (
        status IN ('revoked', 'expired', 'failed')
        AND token_hash IS NULL AND token_ciphertext IS NULL
        AND token_iv IS NULL AND token_auth_tag IS NULL AND token_salt IS NULL
      )
  ) THEN
    RAISE EXCEPTION 'agent has unresolved upstream credential leases'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.pending_proxy_requests
    WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.id AND status = 'executing'
  ) THEN
    RAISE EXCEPTION 'agent has executing proxy work' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.secret_routes
    WHERE tenant_id = OLD.tenant_id AND agent_id = OLD.id AND enabled
  ) THEN
    RAISE EXCEPTION 'agent has enabled secret routes' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.transactions
    WHERE agent_id = OLD.id
      AND status IN ('signed', 'broadcast', 'outcome_unknown')
  ) THEN
    RAISE EXCEPTION 'agent has unresolved transaction execution' USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.provider_action_bindings
    WHERE tenant_id = OLD.tenant_id AND actor_agent_id = OLD.id
      AND status IN ('allowed_stub', 'execution_ready', 'executing', 'outcome_unknown')
  ) THEN
    RAISE EXCEPTION 'agent has unresolved provider execution' USING ERRCODE = '55000';
  END IF;
  IF to_regclass('public.capability_grants') IS NOT NULL THEN
    EXECUTE
      'SELECT EXISTS (
         SELECT 1 FROM public.capability_grants
         WHERE tenant_id = $1 AND agent_id = $2 AND status = ''active''
       )'
      INTO has_active_capability_grant
      USING OLD.tenant_id, OLD.id;
    IF has_active_capability_grant THEN
      RAISE EXCEPTION 'agent has active capability grants' USING ERRCODE = '55000';
    END IF;
  END IF;
  -- Both historical intents FKs cascade through agents. Detach only resolved
  -- provider-action intents so their binding evidence survives this deletion.
  UPDATE public.intents AS intent
  SET agent_id = NULL
  WHERE intent.tenant_id = OLD.tenant_id
    AND intent.agent_id = OLD.id
    AND EXISTS (
      SELECT 1 FROM public.provider_action_bindings AS binding
      WHERE binding.tenant_id = OLD.tenant_id
        AND binding.actor_agent_id = OLD.id
        AND binding.intent_id = intent.id
    );
  RETURN OLD;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER agents_delete_authority_guard
BEFORE DELETE ON agents
FOR EACH ROW EXECUTE FUNCTION steward_guard_agent_delete();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_guard_workspace_delete()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM public.upstream_credential_leases
    WHERE tenant_id = OLD.tenant_id AND workspace_id = OLD.id
      AND NOT (
        status IN ('revoked', 'expired', 'failed')
        AND token_hash IS NULL AND token_ciphertext IS NULL
        AND token_iv IS NULL AND token_auth_tag IS NULL AND token_salt IS NULL
      )
  ) THEN
    RAISE EXCEPTION 'workspace has unresolved upstream credential leases'
      USING ERRCODE = '55000';
  END IF;
  RETURN OLD;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER workspaces_delete_authority_guard
BEFORE DELETE ON workspaces
FOR EACH ROW EXECUTE FUNCTION steward_guard_workspace_delete();
--> statement-breakpoint
-- Capability tables are optional, but an earlier plugin installation can leave
-- them behind while the plugin is disabled during a core upgrade. Install the
-- same parent-row fence whenever that table already exists; plugin migration
-- 0002 owns the equivalent trigger for fresh or later plugin installations.
DO $$
BEGIN
  IF to_regclass('public.capability_grants') IS NOT NULL THEN
    EXECUTE 'DROP TRIGGER IF EXISTS capability_grants_agent_fence ON public.capability_grants';
    EXECUTE $trigger$
      CREATE TRIGGER capability_grants_agent_fence
      BEFORE INSERT OR UPDATE OF tenant_id, agent_id, status ON public.capability_grants
      FOR EACH ROW
      WHEN (NEW.status = 'active')
      EXECUTE FUNCTION steward_fence_agent_authority_creation()
    $trigger$;

    EXECUTE $disable_routes$
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
        )
    $disable_routes$;

    EXECUTE $revoke_grants$
      UPDATE public.capability_grants AS capability_grant
      SET status = 'revoked'
      WHERE capability_grant.status = 'active'
        AND NOT EXISTS (
          SELECT 1
          FROM public.agents
          WHERE agents.id = capability_grant.agent_id
            AND agents.tenant_id = capability_grant.tenant_id
        )
    $revoke_grants$;
  END IF;
END;
$$;
