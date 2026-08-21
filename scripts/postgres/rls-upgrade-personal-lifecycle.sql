\set ON_ERROR_STOP on
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif
\if :{?steward_app_role}
\else
  \set steward_app_role steward_app
\endif
\if :{?steward_platform_role}
\else
  \set steward_platform_role steward_platform
\endif

-- These SECURITY DEFINER entry points are owned by a NOLOGIN role after the
-- role split. They must therefore be replaced through this explicit admin lane,
-- never by the ordinary schema migrator. Their public implementation is owned
-- and versioned by migration 0114.
BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_user_token_revocation_subject_v1(uuid) TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format('GRANT %I TO %I', :'steward_bootstrap_role', current_user) \gexec
SELECT format('SET LOCAL ROLE %I', :'steward_bootstrap_role') \gexec

DROP FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid, boolean);
CREATE FUNCTION steward_bootstrap.platform_set_user_deactivation(
  p_user_id uuid, p_deactivated boolean
)
RETURNS TABLE (
  user_id uuid, previous_deactivated_at timestamptz,
  previous_updated_at timestamptz, deactivated_at timestamptz,
  tokens_revoked_before bigint
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

REVOKE ALL ON FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid, boolean)
FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid,boolean) TO %I',
  :'steward_platform_role'
) \gexec

CREATE OR REPLACE FUNCTION steward_bootstrap.user_token_revocation_subject(p_user_id uuid)
RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT public.steward_user_token_revocation_subject_v1(p_user_id)
$$;

REVOKE ALL ON FUNCTION steward_bootstrap.user_token_revocation_subject(uuid) FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.user_token_revocation_subject(uuid) TO %I',
  :'steward_app_role'
) \gexec

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
