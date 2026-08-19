-- Credential lease evidence must outlive the agent authority it records. Agent
-- deletion first terminalizes and scrubs each lease, then removes the agent;
-- retaining the composite FK would make that lifecycle impossible.
ALTER TABLE "upstream_credential_leases"
  DROP CONSTRAINT IF EXISTS "upstream_credential_leases_agent_fk";
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_fence_agent_authority_creation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1
  FROM agents
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
BEFORE INSERT OR UPDATE OF tenant_id, agent_id ON upstream_credential_leases
FOR EACH ROW EXECUTE FUNCTION steward_fence_agent_authority_creation();
--> statement-breakpoint
CREATE TRIGGER pending_proxy_requests_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id, status ON pending_proxy_requests
FOR EACH ROW
EXECUTE FUNCTION steward_fence_agent_authority_creation();
--> statement-breakpoint
CREATE TRIGGER secret_routes_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id ON secret_routes
FOR EACH ROW
WHEN (NEW.agent_id IS NOT NULL)
EXECUTE FUNCTION steward_fence_agent_authority_creation();
