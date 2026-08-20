\set ON_ERROR_STOP on
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif

-- These SECURITY DEFINER entry points are owned by a NOLOGIN role after the
-- role split. They must therefore be replaced through this explicit admin lane,
-- never by the ordinary schema migrator. Their public implementation is owned
-- and versioned by migration 0114.
BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT format('GRANT %I TO %I', :'steward_bootstrap_role', current_user) \gexec
SELECT format('SET LOCAL ROLE %I', :'steward_bootstrap_role') \gexec

CREATE OR REPLACE FUNCTION steward_bootstrap.platform_set_user_deactivation(
  p_user_id uuid, p_deactivated boolean
)
RETURNS TABLE (
  user_id uuid, previous_deactivated_at timestamptz,
  previous_updated_at timestamptz, deactivated_at timestamptz
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  RETURN QUERY
  SELECT * FROM public.steward_platform_set_user_deactivation_v2(
    p_user_id, p_deactivated
  );
END
$$;

CREATE OR REPLACE FUNCTION steward_bootstrap.platform_delete_user(p_user_id uuid)
RETURNS TABLE (user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  RETURN QUERY SELECT * FROM public.steward_platform_delete_user_v2(p_user_id);
END
$$;

CREATE OR REPLACE FUNCTION steward_bootstrap.platform_personal_tenant_delete(
  p_tenant_id text,
  p_execute boolean DEFAULT false
)
RETURNS TABLE (
  status text,
  agent_ids text[],
  member_ids uuid[],
  active_grants_retired integer,
  terminal_grants_removed integer,
  capabilities_removed integer,
  invocation_evidence_retained integer
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  RETURN QUERY
  SELECT * FROM public.steward_platform_personal_tenant_delete_v2(
    p_tenant_id, p_execute
  );
END
$$;
REVOKE ALL ON FUNCTION steward_bootstrap.platform_personal_tenant_delete(text, boolean)
FROM PUBLIC;

RESET ROLE;
SELECT format('REVOKE %I FROM %I', :'steward_bootstrap_role', current_user) \gexec
COMMIT;
