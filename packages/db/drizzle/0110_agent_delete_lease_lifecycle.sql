-- Credential lease evidence must outlive the agent authority it records. Agent
-- deletion first terminalizes and scrubs each lease, then removes the agent;
-- retaining the composite FK would make that lifecycle impossible.
ALTER TABLE "upstream_credential_leases"
  DROP CONSTRAINT IF EXISTS "upstream_credential_leases_agent_fk";
