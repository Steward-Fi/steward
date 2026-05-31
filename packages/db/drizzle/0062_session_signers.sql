-- Session signers: scoped, labeled, revocable delegated signing tokens for agents.
--
-- Each row records a signer minted via POST /agents/:agentId/session-signers.
-- The token itself is an agent JWT carrying a unique `jti`; revocation flips
-- `revoked_at` and adds the jti to the revocation store. Optional `policy_ids`
-- pin the signer to a subset of the agent's policy rows so different signers
-- can enforce different limits (e.g. one trading bot capped to 1 ETH/day, one
-- treasury rebalancer with no cap but address allowlist).
--
-- Listing and revocation are tenant-scoped at the route layer. `agent_id` is
-- varchar(64) to match `agents.id` so the FK is type-compatible.

CREATE TABLE IF NOT EXISTS "session_signers" (
  "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "jti" varchar(64) NOT NULL,
  "label" varchar(128) NOT NULL,
  "scopes" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "policy_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "revoked_at" timestamp with time zone,
  "last_used_at" timestamp with time zone,
  CONSTRAINT "session_signers_tenant_id_tenants_id_fk"
    FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE cascade,
  CONSTRAINT "session_signers_agent_id_agents_id_fk"
    FOREIGN KEY ("agent_id") REFERENCES "agents"("id") ON DELETE cascade
);

CREATE UNIQUE INDEX IF NOT EXISTS "session_signers_jti_idx"
  ON "session_signers" ("jti");

CREATE INDEX IF NOT EXISTS "session_signers_tenant_agent_idx"
  ON "session_signers" ("tenant_id", "agent_id");

CREATE INDEX IF NOT EXISTS "session_signers_active_idx"
  ON "session_signers" ("agent_id") WHERE "revoked_at" IS NULL;
