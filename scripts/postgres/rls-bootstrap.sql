\set ON_ERROR_STOP on
\if :{?steward_app_role}
\else
  \set steward_app_role steward_app
\endif

\if :{?steward_migration_role}
\else
  \set steward_migration_role steward_migrator
\endif
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif
\if :{?steward_platform_role}
\else
  \set steward_platform_role steward_platform
\endif

BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT set_config('steward.bootstrap.app_role', :'steward_app_role', true);
SELECT set_config('steward.bootstrap.migration_role', :'steward_migration_role', true);
SELECT set_config('steward.bootstrap.definer_role', :'steward_bootstrap_role', true);
SELECT set_config('steward.bootstrap.platform_role', :'steward_platform_role', true);

DO $$
BEGIN
  IF current_setting('steward.bootstrap.app_role') IN (
      current_setting('steward.bootstrap.migration_role'),
      current_setting('steward.bootstrap.definer_role'),
      current_setting('steward.bootstrap.platform_role')
    ) OR current_setting('steward.bootstrap.migration_role') =
      ANY (ARRAY[
        current_setting('steward.bootstrap.definer_role'),
        current_setting('steward.bootstrap.platform_role')
      ]) OR current_setting('steward.bootstrap.definer_role') =
      current_setting('steward.bootstrap.platform_role') THEN
    RAISE EXCEPTION 'SEC-169 app, platform, migration-maintenance, and definer roles must be distinct';
  END IF;
END
$$;

-- Run as a PostgreSQL role with CREATEROLE and ownership of the migrated
-- Steward schema. Role names are identifiers and are quoted through format().
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'steward_app_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_app_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'steward_migration_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_migration_role') \gexec
SELECT format(
  'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS',
  :'steward_bootstrap_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_bootstrap_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  :'steward_platform_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_platform_role') \gexec

SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'steward_app_role') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'steward_migration_role') \gexec
SELECT format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS', :'steward_bootstrap_role') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', :'steward_platform_role') \gexec

-- Reject ownership before the normalization below can silently reassign a
-- platform-owned object and erase evidence of the authority drift.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_shdepend ownership
    JOIN pg_roles owner_role ON owner_role.oid = ownership.refobjid
    WHERE ownership.refclassid = 'pg_authid'::regclass
      AND ownership.deptype = 'o'
      AND owner_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) OR EXISTS (
    SELECT 1 FROM pg_database database_object
    JOIN pg_roles owner_role ON owner_role.oid = database_object.datdba
    WHERE owner_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) OR EXISTS (
    SELECT 1 FROM pg_namespace schema_object
    JOIN pg_roles owner_role ON owner_role.oid = schema_object.nspowner
    WHERE owner_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) OR EXISTS (
    SELECT 1 FROM pg_class relation_object
    JOIN pg_roles owner_role ON owner_role.oid = relation_object.relowner
    WHERE owner_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) OR EXISTS (
    SELECT 1 FROM pg_proc function_object
    JOIN pg_roles owner_role ON owner_role.oid = function_object.proowner
    WHERE owner_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must not own database objects';
  END IF;
END
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL PROCEDURES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_rls FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_rls FROM PUBLIC;
REVOKE ALL ON ALL PROCEDURES IN SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL PROCEDURES IN SCHEMA steward_rls FROM PUBLIC;

-- The bootstrap schema is a privileged ABI, not an extension point. Refuse to
-- bless a newly introduced SECURITY DEFINER function merely because it landed
-- in the trusted schema or inherited the trusted owner.
DO $$
DECLARE
  actual text[];
  expected constant text[] := ARRAY[
    'steward_bootstrap.agent_subject(text,text,text)',
    'steward_bootstrap.agent_tenant_subject(text)',
    'steward_bootstrap.app_client_subject(text,text)',
    'steward_bootstrap.auth_app_clients_subject(text)',
    'steward_bootstrap.auth_refresh_subject(text)',
    'steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamp with time zone)',
    'steward_bootstrap.auth_sso_discovery_subject(text)',
    'steward_bootstrap.auth_sso_domain_subject(text,text)',
    'steward_bootstrap.auth_tenant_config_subject(text)',
    'steward_bootstrap.auth_tenant_subject(text,uuid)',
    'steward_bootstrap.ensure_default_tenant(text)',
    'steward_bootstrap.ensure_platform_tenant()',
    'steward_bootstrap.ensure_system_tenant()',
    'steward_bootstrap.platform_delete_user(uuid)',
    'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid)',
    'steward_bootstrap.platform_set_user_deactivation(uuid,boolean)',
    'steward_bootstrap.platform_stats()',
    'steward_bootstrap.platform_tenants(integer,integer)',
    'steward_bootstrap.platform_user_tenant_ids(uuid)',
    'steward_bootstrap.retention_delete_deactivated_users(integer)',
    'steward_bootstrap.session_subject(uuid,text)',
    'steward_bootstrap.tenant_api_key_subject(text)',
    'steward_bootstrap.tenant_ids_for_internal_job()'
  ];
BEGIN
  SELECT array_agg(p.oid::regprocedure::text ORDER BY p.oid::regprocedure::text)
    INTO actual
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap' AND p.prosecdef;
  IF actual IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'SEC-169 bootstrap SECURITY DEFINER inventory drift'
      USING DETAIL = format('expected=%s actual=%s', expected, actual);
  END IF;
END
$$;

-- Remove stale named-role grants before installing the exact application ACL.
-- PUBLIC-only revocation is insufficient: a previously granted login could
-- otherwise retain direct access to BYPASSRLS SECURITY DEFINER functions.
SELECT format('REVOKE ALL ON SCHEMA %I FROM %I', n.nspname, grantee.rolname)
FROM pg_namespace n
CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl
JOIN pg_roles grantee ON grantee.oid = acl.grantee
WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
  AND acl.grantee <> n.nspowner
GROUP BY n.nspname, grantee.rolname
\gexec
SELECT format('REVOKE ALL ON FUNCTION %s FROM %I', p.oid::regprocedure, grantee.rolname)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
JOIN pg_roles grantee ON grantee.oid = acl.grantee
WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
  AND acl.grantee <> p.proowner
GROUP BY p.oid, grantee.rolname
\gexec

-- Reset every persisted application grant in the Steward namespaces before
-- rebuilding the runtime allowlist. GRANT is additive: without this reset a
-- stale TRUNCATE privilege would survive forever and bypass row security.
SELECT format(
  'REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I',
  database_object.datname,
  :'steward_app_role'
)
FROM pg_database database_object
CROSS JOIN LATERAL aclexplode(database_object.datacl) privilege
JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
WHERE granted_role.rolname = :'steward_app_role'
GROUP BY database_object.datname
\gexec
SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %I', namespace.nspname, :'steward_app_role')
FROM pg_namespace namespace
WHERE namespace.nspname IN ('public', 'steward_bootstrap', 'steward_rls')
\gexec
SELECT format(
  'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %I',
  CASE WHEN relation.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
  namespace.nspname,
  relation.relname,
  :'steward_app_role'
)
FROM pg_class relation
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'public' AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
\gexec
SELECT format(
  'REVOKE ALL PRIVILEGES ON %s %s FROM %I',
  CASE WHEN function_object.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
  function_object.oid::regprocedure,
  :'steward_app_role'
)
FROM pg_proc function_object
JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
WHERE namespace.nspname IN ('public', 'steward_bootstrap', 'steward_rls')
\gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL PRIVILEGES ON %s FROM %I',
  :'steward_migration_role', object_kind, :'steward_app_role'
)
FROM (VALUES ('TABLES'), ('SEQUENCES'), ('FUNCTIONS'), ('TYPES')) kinds(object_kind)
\gexec

SELECT format('GRANT %I TO %I', :'steward_migration_role', current_user) \gexec
SELECT format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format(
  'GRANT CONNECT ON DATABASE %I TO %I, %I',
  current_database(), :'steward_app_role', :'steward_migration_role'
) \gexec
SELECT format('GRANT CREATE ON DATABASE %I TO %I', current_database(), :'steward_migration_role') \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'steward_migration_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public, steward_bootstrap, steward_rls TO %I', :'steward_app_role') \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION '
  'steward_rls.tenant_id(), steward_rls.user_id(), '
  'steward_bootstrap.agent_subject(text,text,text), '
  'steward_bootstrap.agent_tenant_subject(text), '
  'steward_bootstrap.app_client_subject(text,text), '
  'steward_bootstrap.auth_app_clients_subject(text), '
  'steward_bootstrap.auth_refresh_subject(text), '
  'steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamptz), '
  'steward_bootstrap.auth_sso_discovery_subject(text), '
  'steward_bootstrap.auth_sso_domain_subject(text,text), '
  'steward_bootstrap.auth_tenant_config_subject(text), '
  'steward_bootstrap.auth_tenant_subject(text,uuid), '
  'steward_bootstrap.ensure_default_tenant(text), '
  'steward_bootstrap.ensure_platform_tenant(), '
  'steward_bootstrap.ensure_system_tenant(), '
  'steward_bootstrap.platform_user_tenant_ids(uuid), '
  'steward_bootstrap.session_subject(uuid,text), '
  'steward_bootstrap.tenant_api_key_subject(text), '
  'steward_bootstrap.tenant_ids_for_internal_job() TO %I',
  :'steward_app_role'
) \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_lock_tenant_deletion(text) TO %I',
  :'steward_app_role'
) \gexec
-- The personal lifecycle helper is migration-owned public INVOKER code used by
-- both the application route and bootstrap-owned platform wrappers. Reset its
-- complete named ACL so stale roles or grant options cannot survive a rerun.
SELECT 'REVOKE ALL PRIVILEGES ON FUNCTION public.steward_lock_personal_lifecycle(uuid,text,boolean) FROM PUBLIC'
WHERE to_regprocedure(
  'public.steward_lock_personal_lifecycle(uuid,text,boolean)'
) IS NOT NULL \gexec
SELECT format(
  'REVOKE ALL PRIVILEGES ON FUNCTION %s FROM %I',
  function_object.oid::regprocedure,
  granted_role.rolname
)
FROM pg_proc function_object
CROSS JOIN LATERAL aclexplode(
  COALESCE(function_object.proacl, acldefault('f', function_object.proowner))
) privilege
JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
WHERE function_object.oid =
    to_regprocedure('public.steward_lock_personal_lifecycle(uuid,text,boolean)')
  AND privilege.grantee <> function_object.proowner
GROUP BY function_object.oid, granted_role.rolname
\gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_lock_personal_lifecycle(uuid,text,boolean) TO %I, %I',
  :'steward_app_role', :'steward_bootstrap_role'
) WHERE to_regprocedure(
  'public.steward_lock_personal_lifecycle(uuid,text,boolean)'
) IS NOT NULL \gexec

-- The platform login is a narrow, separately credentialed authority. Reset
-- every named ACL it could have retained from an earlier bootstrap before
-- rebuilding the allowlist below. PUBLIC privileges remain governed by the
-- schema-wide revocations above.
SELECT format('REVOKE ALL PRIVILEGES ON DATABASE %I FROM %I', current_database(), :'steward_platform_role') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'steward_platform_role') \gexec
SELECT format('REVOKE ALL PRIVILEGES ON SCHEMA %I FROM %I', namespace.nspname, :'steward_platform_role')
FROM pg_namespace namespace
CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
WHERE granted_role.rolname = :'steward_platform_role'
GROUP BY namespace.nspname
\gexec
SELECT format(
  'REVOKE ALL PRIVILEGES ON %s %I.%I FROM %I',
  CASE WHEN relation.relkind = 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
  namespace.nspname,
  relation.relname,
  :'steward_platform_role'
)
FROM pg_class relation
JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
  AND granted_role.rolname = :'steward_platform_role'
GROUP BY relation.relkind, namespace.nspname, relation.relname
\gexec
SELECT format(
  'REVOKE ALL PRIVILEGES ON %s %s FROM %I',
  CASE WHEN function_object.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
  function_object.oid::regprocedure,
  :'steward_platform_role'
)
FROM pg_proc function_object
CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
WHERE granted_role.rolname = :'steward_platform_role'
GROUP BY function_object.oid, function_object.prokind
\gexec
SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL PRIVILEGES ON %s FROM %I',
  :'steward_migration_role', object_kind, :'steward_platform_role'
)
FROM (VALUES ('TABLES'), ('SEQUENCES'), ('FUNCTIONS'), ('TYPES')) kinds(object_kind)
\gexec

SELECT format('GRANT USAGE ON SCHEMA steward_bootstrap, steward_rls TO %I', :'steward_platform_role') \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT SELECT, INSERT ON public.audit_events TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT SELECT, INSERT, UPDATE ON public.audit_chain_heads TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT SELECT ON public.users, public.user_tenants TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT USAGE, SELECT ON SEQUENCE public.audit_events_id_seq TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION '
  'steward_bootstrap.platform_set_user_deactivation(uuid,boolean), '
  'steward_bootstrap.platform_delete_user(uuid), '
  'steward_bootstrap.platform_user_tenant_ids(uuid), '
  'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid), '
  'steward_bootstrap.retention_delete_deactivated_users(integer), '
  'steward_bootstrap.platform_stats(), '
  'steward_bootstrap.platform_tenants(integer,integer) TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'REVOKE ALL ON FUNCTION steward_bootstrap.platform_personal_tenant_delete(text,boolean) FROM PUBLIC, %I',
  :'steward_app_role'
) WHERE to_regprocedure('steward_bootstrap.platform_personal_tenant_delete(text,boolean)') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_personal_tenant_delete(text,boolean) TO %I',
  :'steward_platform_role'
) WHERE to_regprocedure('steward_bootstrap.platform_personal_tenant_delete(text,boolean)') IS NOT NULL \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'steward_app_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'steward_app_role') \gexec
-- User lifecycle authority is deliberately excluded from the shared app login.
-- Profile/auth flows retain only the columns they legitimately mutate; global
-- deactivation and deletion must cross the separately authenticated platform
-- authority and its bootstrap-owned lifecycle functions.
SELECT format('REVOKE INSERT, UPDATE, DELETE ON public.users FROM %I', :'steward_app_role') \gexec
SELECT format(
  'GRANT INSERT (id, email, email_verified, name, image, wallet_address, wallet_chain, '
  'steward_wallet_id, custom_metadata, is_guest, guest_expires_at, created_at, updated_at) '
  'ON public.users TO %I',
  :'steward_app_role'
) \gexec
SELECT format(
  'GRANT UPDATE (email, email_verified, name, image, wallet_address, wallet_chain, '
  'steward_wallet_id, custom_metadata, is_guest, guest_expires_at, updated_at) '
  'ON public.users TO %I',
  :'steward_app_role'
) \gexec
SELECT format(
  'REVOKE ALL ON public.user_identity_subjects, public.retained_user_provider_evidence FROM %I',
  :'steward_app_role'
) WHERE to_regclass('public.user_identity_subjects') IS NOT NULL
    AND to_regclass('public.retained_user_provider_evidence') IS NOT NULL \gexec

-- The function owner is non-login and may read only the fixed bootstrap inputs.
SELECT format(
  'GRANT SELECT ON public.tenants, public.users, public.user_tenants, public.agents, '
  'public.session_signers, public.tenant_app_clients, public.tenant_app_client_secrets, '
  'public.transactions, public.refresh_tokens, public.tenant_configs, public.tenant_sso_domains, '
  'public.tenant_invitations, public.accounts TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format('GRANT INSERT ON public.tenants TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT UPDATE ON public.tenants TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT INSERT, UPDATE, DELETE ON public.refresh_tokens TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT UPDATE, DELETE ON public.users TO %I', :'steward_bootstrap_role') \gexec
SELECT format(
  'GRANT SELECT, INSERT ON public.retained_user_provider_evidence TO %I',
  :'steward_bootstrap_role'
) WHERE to_regclass('public.retained_user_provider_evidence') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_platform_set_user_deactivation_v2(uuid, boolean) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_platform_set_user_deactivation_v2(uuid,boolean)') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_user_token_revocation_subject_v1(uuid) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_user_token_revocation_subject_v1(uuid)') IS NOT NULL \gexec
SELECT format(
  'REVOKE ALL ON FUNCTION public.steward_lock_personal_lifecycle(uuid, text, boolean) FROM %I, %I, %I',
  :'steward_app_role', :'steward_bootstrap_role', :'steward_platform_role'
) WHERE to_regprocedure('public.steward_lock_personal_lifecycle(uuid,text,boolean)') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_lock_personal_lifecycle(uuid, text, boolean) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_lock_personal_lifecycle(uuid,text,boolean)') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_platform_delete_user_v2(uuid) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_platform_delete_user_v2(uuid)') IS NOT NULL \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION public.steward_platform_personal_tenant_delete_v2(text, boolean) TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('public.steward_platform_personal_tenant_delete_v2(text,boolean)') IS NOT NULL \gexec
SELECT format('ALTER SCHEMA steward_rls OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.tenant_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.user_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER SCHEMA steward_bootstrap OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.tenant_api_key_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.session_subject(uuid,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.user_token_revocation_subject(uuid) OWNER TO %I', :'steward_bootstrap_role')
WHERE to_regprocedure('steward_bootstrap.user_token_revocation_subject(uuid)') IS NOT NULL \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.agent_subject(text,text,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.agent_tenant_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.app_client_subject(text,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.tenant_ids_for_internal_job() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.ensure_default_tenant(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.ensure_system_tenant() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.ensure_platform_tenant() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_user_tenant_ids(uuid) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid,boolean) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_delete_user(uuid) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format(
  'ALTER FUNCTION steward_bootstrap.platform_personal_tenant_delete(text,boolean) OWNER TO %I',
  :'steward_bootstrap_role'
) WHERE to_regprocedure('steward_bootstrap.platform_personal_tenant_delete(text,boolean)') IS NOT NULL \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_revoke_user_refresh_tokens(uuid) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.retention_delete_deactivated_users(integer) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_stats() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_tenants(integer,integer) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_refresh_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_tenant_subject(text,uuid) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_sso_domain_subject(text,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_sso_discovery_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_tenant_config_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_app_clients_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamptz) OWNER TO %I', :'steward_bootstrap_role') \gexec

SELECT format('ALTER TABLE %I.%I OWNER TO %I', n.nspname, c.relname, :'steward_migration_role')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p')
ORDER BY n.nspname, c.relname \gexec
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I', n.nspname, c.relname, :'steward_migration_role')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'drizzle') AND c.relkind = 'S'
ORDER BY n.nspname, c.relname \gexec
SELECT format('ALTER SCHEMA drizzle OWNER TO %I', :'steward_migration_role')
WHERE EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'drizzle') \gexec

-- Future objects inherit the same split when migrations run as the migration role.
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I', :'steward_migration_role', :'steward_app_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I', :'steward_migration_role', :'steward_app_role') \gexec
SELECT format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE EXECUTE ON ROUTINES FROM PUBLIC', :'steward_migration_role') \gexec

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname IN (
      current_setting('steward.bootstrap.app_role'),
      current_setting('steward.bootstrap.migration_role'),
      current_setting('steward.bootstrap.platform_role')
    )
      AND (rolsuper OR rolbypassrls OR rolreplication)
  ) THEN
    RAISE EXCEPTION 'SEC-169 app, migration, and platform roles must be NOSUPERUSER NOREPLICATION NOBYPASSRLS';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles app
      ON app.rolname = current_setting('steward.bootstrap.app_role')
    WHERE membership.member = app.oid OR membership.roleid = app.oid
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role membership graph must be empty';
  END IF;
  IF pg_has_role(
    current_setting('steward.bootstrap.app_role'),
    current_setting('steward.bootstrap.migration_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role must not inherit or assume migration role';
  END IF;
  IF pg_has_role(
    current_setting('steward.bootstrap.app_role'),
    current_setting('steward.bootstrap.platform_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role must not inherit or assume platform role';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
    WHERE member_role.rolname = current_setting('steward.bootstrap.platform_role')
       OR granted_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must not inherit, assume, or be assumable by another role';
  END IF;
  IF pg_has_role(
    current_setting('steward.bootstrap.app_role'),
    current_setting('steward.bootstrap.definer_role'),
    'MEMBER'
  ) OR pg_has_role(
    current_setting('steward.bootstrap.migration_role'),
    current_setting('steward.bootstrap.definer_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 login roles must not inherit or assume definer role';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_roles migration
    JOIN pg_roles candidate ON candidate.oid <> migration.oid
    WHERE migration.rolname = current_setting('steward.bootstrap.migration_role')
      AND pg_has_role(migration.oid, candidate.oid, 'MEMBER')
      AND (
        candidate.rolsuper OR candidate.rolbypassrls OR candidate.rolcreatedb
        OR candidate.rolcreaterole OR candidate.rolreplication
        OR EXISTS (
          SELECT 1 FROM pg_database database_object
          WHERE database_object.datname = current_database()
            AND database_object.datdba = candidate.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_namespace namespace
          WHERE namespace.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
            AND (namespace.nspowner = candidate.oid
              OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))
        )
      )
  ) THEN
    RAISE EXCEPTION 'SEC-169 migration role has assumable privileged or owner authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles bootstrap
      ON bootstrap.rolname = current_setting('steward.bootstrap.definer_role')
    WHERE membership.member = bootstrap.oid OR membership.roleid = bootstrap.oid
  ) THEN
    RAISE EXCEPTION 'SEC-169 definer role membership graph must be empty';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = current_setting('steward.bootstrap.definer_role')
      AND (rolcanlogin OR rolsuper OR rolreplication OR NOT rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'SEC-169 definer role must be NOLOGIN NOSUPERUSER NOREPLICATION BYPASSRLS';
  END IF;
  IF NOT has_database_privilege(
       current_setting('steward.bootstrap.platform_role'), current_database(), 'CONNECT'
     ) OR EXISTS (
    SELECT 1
    FROM pg_database database_object
    CROSS JOIN LATERAL aclexplode(
      COALESCE(database_object.datacl, acldefault('d', database_object.datdba))
    ) privilege
    WHERE database_object.datname = current_database()
      AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT'
  ) OR EXISTS (
    SELECT 1
    FROM pg_database database_object
    CROSS JOIN LATERAL aclexplode(database_object.datacl) privilege
    JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
    WHERE granted_role.rolname = current_setting('steward.bootstrap.platform_role')
      AND (database_object.datname <> current_database()
        OR privilege.privilege_type <> 'CONNECT' OR privilege.is_grantable)
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform database ACL drift';
  END IF;
  IF has_schema_privilege(current_setting('steward.bootstrap.app_role'), 'public', 'CREATE')
     OR has_schema_privilege(current_setting('steward.bootstrap.app_role'), 'steward_bootstrap', 'CREATE')
     OR has_schema_privilege(current_setting('steward.bootstrap.app_role'), 'steward_rls', 'CREATE') THEN
    RAISE EXCEPTION 'SEC-169 app role must not create schema objects';
  END IF;
  IF NOT has_schema_privilege(
       current_setting('steward.bootstrap.platform_role'), 'steward_rls', 'USAGE'
     )
     OR NOT has_function_privilege(
       current_setting('steward.bootstrap.platform_role'), 'steward_rls.tenant_id()', 'EXECUTE'
     )
     OR has_function_privilege(
       current_setting('steward.bootstrap.platform_role'), 'steward_rls.user_id()', 'EXECUTE'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_proc function_object
       JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
       WHERE namespace.nspname IN ('public', 'steward_bootstrap', 'steward_rls')
         AND has_function_privilege(
           current_setting('steward.bootstrap.platform_role'),
           function_object.oid,
           'EXECUTE'
         )
         AND function_object.oid <> ALL (ARRAY[
           'steward_bootstrap.platform_delete_user(uuid)'::regprocedure,
           'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid)'::regprocedure,
           'steward_bootstrap.platform_set_user_deactivation(uuid,boolean)'::regprocedure,
           'steward_bootstrap.platform_stats()'::regprocedure,
           'steward_bootstrap.platform_tenants(integer,integer)'::regprocedure,
           'steward_bootstrap.retention_delete_deactivated_users(integer)'::regprocedure,
           'steward_rls.tenant_id()'::regprocedure
         ])
     ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must receive only tenant RLS context access';
  END IF;
  IF (
    SELECT array_agg(
      namespace.nspname || ':' || privilege.privilege_type || ':' || privilege.is_grantable
      ORDER BY namespace.nspname, privilege.privilege_type, privilege.is_grantable
    )
    FROM pg_namespace namespace
    CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
    JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
    WHERE granted_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) IS DISTINCT FROM ARRAY[
    'steward_bootstrap:USAGE:false',
    'steward_rls:USAGE:false'
  ] THEN
    RAISE EXCEPTION 'SEC-169 platform schema ACL drift';
  END IF;
  IF (
    SELECT array_agg(
      namespace.nspname || '.' || relation.relname || ':' || privilege.privilege_type || ':' || privilege.is_grantable
      ORDER BY namespace.nspname, relation.relname, privilege.privilege_type, privilege.is_grantable
    )
    FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
    JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
    WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND granted_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) IS DISTINCT FROM ARRAY[
    'public.audit_chain_heads:INSERT:false',
    'public.audit_chain_heads:SELECT:false',
    'public.audit_chain_heads:UPDATE:false',
    'public.audit_events:INSERT:false',
    'public.audit_events:SELECT:false',
    'public.audit_events_id_seq:SELECT:false',
    'public.audit_events_id_seq:USAGE:false'
  ] THEN
    RAISE EXCEPTION 'SEC-169 platform relation ACL drift';
  END IF;
  IF (
    SELECT array_agg(
      namespace.nspname || '.' || function_object.proname || '(' ||
      pg_get_function_identity_arguments(function_object.oid) || '):' ||
      privilege.privilege_type || ':' || privilege.is_grantable
      ORDER BY namespace.nspname, function_object.proname,
        pg_get_function_identity_arguments(function_object.oid),
        privilege.privilege_type, privilege.is_grantable
    )
    FROM pg_proc function_object
    JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
    CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
    JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
    WHERE granted_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) IS DISTINCT FROM ARRAY[
    'steward_bootstrap.platform_delete_user(p_user_id uuid):EXECUTE:false',
    'steward_bootstrap.platform_revoke_user_refresh_tokens(p_user_id uuid):EXECUTE:false',
    'steward_bootstrap.platform_set_user_deactivation(p_user_id uuid, p_deactivated boolean):EXECUTE:false',
    'steward_bootstrap.platform_stats():EXECUTE:false',
    'steward_bootstrap.platform_tenants(p_limit integer, p_offset integer):EXECUTE:false',
    'steward_bootstrap.retention_delete_deactivated_users(p_days integer):EXECUTE:false',
    'steward_rls.tenant_id():EXECUTE:false'
  ] THEN
    RAISE EXCEPTION 'SEC-169 platform function ACL drift';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_default_acl defaults
    CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
    JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
    WHERE granted_role.rolname = current_setting('steward.bootstrap.platform_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must not receive default privileges';
  END IF;
  IF NOT has_sequence_privilege(
       current_setting('steward.bootstrap.platform_role'),
       'public.audit_events_id_seq',
       'USAGE,SELECT'
     )
     OR has_sequence_privilege(
       current_setting('steward.bootstrap.platform_role'),
       'public.audit_checkpoints_id_seq',
       'USAGE'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_default_acl defaults
       CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
       JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
       WHERE defaults.defaclobjtype = 'S'
         AND granted_role.rolname = current_setting('steward.bootstrap.platform_role')
     ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must receive only the audit event sequence grant';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ('public', 'drizzle') AND c.relkind IN ('r', 'p')
      AND pg_get_userbyid(c.relowner) <> current_setting('steward.bootstrap.migration_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 migrated table ownership drift';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'steward_bootstrap'
      AND pg_get_userbyid(p.proowner) <> current_setting('steward.bootstrap.definer_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 bootstrap function ownership drift';
  END IF;
END
$$;

COMMIT;
