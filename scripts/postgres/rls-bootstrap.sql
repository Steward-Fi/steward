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
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
  :'steward_app_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_app_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
  :'steward_migration_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_migration_role') \gexec
SELECT format(
  'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS',
  :'steward_bootstrap_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_bootstrap_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
  :'steward_platform_role'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'steward_platform_role') \gexec

SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'steward_app_role') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'steward_migration_role') \gexec
SELECT format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS', :'steward_bootstrap_role') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'steward_platform_role') \gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_rls FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_rls FROM PUBLIC;

SELECT format('GRANT %I TO %I', :'steward_migration_role', current_user) \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'steward_migration_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public, steward_bootstrap, steward_rls TO %I', :'steward_app_role') \gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA steward_bootstrap, steward_rls TO %I', :'steward_app_role') \gexec
SELECT format(
  'REVOKE EXECUTE ON FUNCTION '
  'steward_bootstrap.platform_set_user_deactivation(uuid,boolean), '
  'steward_bootstrap.platform_delete_user(uuid), '
  'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid), '
  'steward_bootstrap.retention_delete_deactivated_users(integer) FROM %I',
  :'steward_app_role'
) \gexec
SELECT format('GRANT USAGE ON SCHEMA steward_bootstrap, steward_rls TO %I', :'steward_platform_role') \gexec
SELECT format(
  'GRANT EXECUTE ON FUNCTION steward_rls.tenant_id() TO %I',
  :'steward_platform_role'
) \gexec
SELECT format(
  'GRANT SELECT, INSERT, UPDATE ON public.audit_events, public.audit_chain_heads TO %I',
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
  'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid), '
  'steward_bootstrap.retention_delete_deactivated_users(integer) TO %I',
  :'steward_platform_role'
) \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'steward_app_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'steward_app_role') \gexec

-- The function owner is non-login and may read only the fixed bootstrap inputs.
SELECT format(
  'GRANT SELECT ON public.tenants, public.users, public.user_tenants, public.agents, '
  'public.session_signers, public.tenant_app_clients, public.tenant_app_client_secrets, '
  'public.transactions, public.refresh_tokens, public.tenant_configs, public.tenant_sso_domains TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format('GRANT INSERT ON public.tenants TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT UPDATE ON public.tenants TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT INSERT, UPDATE, DELETE ON public.refresh_tokens TO %I', :'steward_bootstrap_role') \gexec
SELECT format('GRANT UPDATE, DELETE ON public.users TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER SCHEMA steward_rls OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.tenant_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.user_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER SCHEMA steward_bootstrap OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.tenant_api_key_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.session_subject(uuid,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
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

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname IN (
      current_setting('steward.bootstrap.app_role'),
      current_setting('steward.bootstrap.migration_role'),
      current_setting('steward.bootstrap.platform_role')
    )
      AND (rolsuper OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'SEC-169 app and migration roles must be NOSUPERUSER NOBYPASSRLS';
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
    SELECT 1 FROM pg_roles
    WHERE rolname = current_setting('steward.bootstrap.definer_role')
      AND (rolcanlogin OR rolsuper OR NOT rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'SEC-169 definer role must be NOLOGIN NOSUPERUSER BYPASSRLS';
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
     ) THEN
    RAISE EXCEPTION 'SEC-169 platform role must receive only tenant RLS context access';
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
       CROSS JOIN LATERAL aclexplode(COALESCE(defaults.defaclacl, '{}'::aclitem[])) privilege
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
