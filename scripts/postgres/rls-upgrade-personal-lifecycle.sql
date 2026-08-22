\set ON_ERROR_STOP on
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif
\if :{?steward_migration_role}
\else
  \set steward_migration_role steward_migrator
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
-- and versioned by migration 0119.
BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT EXISTS (
  SELECT 1 FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
  WHERE granted_role.rolname = :'steward_bootstrap_role'
    AND member_role.rolname = current_user
) AS steward_had_bootstrap_membership \gset
SELECT EXISTS (
  SELECT 1 FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
  WHERE granted_role.rolname = :'steward_migration_role'
    AND member_role.rolname = current_user
) AS steward_had_migration_membership \gset
SELECT format('GRANT %I TO %I', :'steward_bootstrap_role', current_user)
WHERE NOT :'steward_had_bootstrap_membership'::boolean \gexec
SELECT format('GRANT %I TO %I', :'steward_migration_role', current_user)
WHERE NOT :'steward_had_migration_membership'::boolean \gexec

-- Restore the two immutable-0113 wrapper identities after their restricted
-- migration handoff, and remove the migrator's temporary schema authority.
SELECT format(
  'ALTER FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid,boolean) OWNER TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format(
  'ALTER FUNCTION steward_bootstrap.platform_delete_user(uuid) OWNER TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format(
  'REVOKE CREATE ON SCHEMA steward_bootstrap FROM %I',
  :'steward_migration_role'
) \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_user_token_revocation_subject_v1(uuid) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_user_token_revocation_subject_v1(uuid)') IS NOT NULL \gexec
SELECT to_regprocedure(
  'public.steward_platform_provision_user_v1(text,boolean,text,jsonb)'
) IS NOT NULL AS steward_has_platform_provision \gset
SELECT to_regprocedure(
  'public.steward_platform_user_identity_v1(uuid)'
) IS NOT NULL AS steward_has_platform_identity \gset
\if :steward_has_platform_provision
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_platform_provision_user_v1(text,boolean,text,jsonb) TO %I',
  :'steward_bootstrap_role'
) \gexec
\endif
\if :steward_has_platform_identity
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_platform_user_identity_v1(uuid) TO %I',
  :'steward_bootstrap_role'
) \gexec
\endif
SELECT format('SET LOCAL ROLE %I', :'steward_bootstrap_role') \gexec

\if :steward_has_platform_provision
CREATE OR REPLACE FUNCTION steward_bootstrap.platform_provision_user(
  p_email text,
  p_email_verified boolean,
  p_name text,
  p_custom_metadata jsonb
)
RETURNS TABLE (user_id uuid, is_new boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  RETURN QUERY SELECT * FROM public.steward_platform_provision_user_v1(
    p_email, p_email_verified, p_name, p_custom_metadata
  );
END
$$;
REVOKE ALL ON FUNCTION steward_bootstrap.platform_provision_user(
  text, boolean, text, jsonb
) FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_provision_user(text,boolean,text,jsonb) TO %I',
  :'steward_platform_role'
) \gexec
\endif

\if :steward_has_platform_identity
CREATE OR REPLACE FUNCTION steward_bootstrap.platform_user_identity(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT public.steward_platform_user_identity_v1(p_user_id)
$$;
REVOKE ALL ON FUNCTION steward_bootstrap.platform_user_identity(uuid) FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_user_identity(uuid) TO %I',
  :'steward_platform_role'
) \gexec
\endif

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
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$BEGIN RETURN public.steward_user_token_revocation_subject_v1(p_user_id); END$$;

REVOKE ALL ON FUNCTION steward_bootstrap.user_token_revocation_subject(uuid) FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.user_token_revocation_subject(uuid) TO %I',
  :'steward_app_role'
) \gexec

CREATE OR REPLACE FUNCTION steward_bootstrap.tenant_ids_for_internal_job()
RETURNS TABLE (tenant_id varchar(64))
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$BEGIN RETURN QUERY SELECT * FROM public.steward_internal_job_tenant_ids_v2(); END$$;
SELECT format(
  'REVOKE ALL ON FUNCTION steward_bootstrap.tenant_ids_for_internal_job() FROM PUBLIC, %I',
  :'steward_app_role'
) \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.tenant_ids_for_internal_job() TO %I',
  :'steward_platform_role'
) \gexec

CREATE OR REPLACE FUNCTION steward_bootstrap.ensure_default_membership(
  p_user_id uuid,
  p_role text
)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM set_config('steward.lifecycle_wrapper', 'v1', true);
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'default'
     OR NULLIF(current_setting('steward.user_id', true), '') IS DISTINCT FROM p_user_id::text
     OR p_role NOT IN ('member', 'guest') THEN
    RAISE EXCEPTION 'default membership authority denied' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.user_tenants (user_id, tenant_id, role)
  VALUES (p_user_id, 'default', p_role)
  ON CONFLICT (user_id, tenant_id) DO NOTHING;
  PERFORM set_config('steward.lifecycle_wrapper', '', true);
END
$$;
REVOKE ALL ON FUNCTION steward_bootstrap.ensure_default_membership(uuid,text) FROM PUBLIC;
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.ensure_default_membership(uuid,text) TO %I',
  :'steward_app_role'
) \gexec

CREATE OR REPLACE FUNCTION steward_bootstrap.platform_delete_user(p_user_id uuid)
RETURNS TABLE (user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM set_config('steward.lifecycle_wrapper', 'v1', true);
  RETURN QUERY SELECT * FROM public.steward_platform_delete_user_v2(p_user_id);
  PERFORM set_config('steward.lifecycle_wrapper', '', true);
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
  PERFORM set_config('steward.lifecycle_wrapper', 'v1', true);
  RETURN QUERY
  SELECT * FROM public.steward_platform_personal_tenant_delete_v2(
    p_tenant_id, p_execute
  );
  PERFORM set_config('steward.lifecycle_wrapper', '', true);
END
$$;
REVOKE ALL ON FUNCTION steward_bootstrap.platform_personal_tenant_delete(text, boolean)
FROM PUBLIC;

RESET ROLE;
SELECT format(
  'GRANT EXECUTE ON FUNCTION '
  'steward_bootstrap.platform_set_user_deactivation(uuid,boolean), '
  'steward_bootstrap.platform_delete_user(uuid), '
  'steward_bootstrap.platform_personal_tenant_delete(text,boolean), '
  'steward_bootstrap.platform_user_tenant_ids(uuid), '
  'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid), '
  'steward_bootstrap.retention_delete_deactivated_users(integer), '
  'steward_bootstrap.platform_stats(), '
  'steward_bootstrap.platform_tenants(integer,integer) TO %I',
  :'steward_platform_role'
) \gexec
SELECT format('REVOKE %I FROM %I', :'steward_migration_role', current_user)
WHERE NOT :'steward_had_migration_membership'::boolean \gexec
SELECT format('REVOKE %I FROM %I', :'steward_bootstrap_role', current_user)
WHERE NOT :'steward_had_bootstrap_membership'::boolean \gexec
COMMIT;
