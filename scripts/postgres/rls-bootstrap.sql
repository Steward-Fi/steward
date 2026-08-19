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

SELECT set_config('steward.bootstrap.app_role', :'steward_app_role', false);
SELECT set_config('steward.bootstrap.migration_role', :'steward_migration_role', false);

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

SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'steward_app_role') \gexec
SELECT format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', :'steward_migration_role') \gexec
SELECT format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT BYPASSRLS', :'steward_bootstrap_role') \gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON SCHEMA steward_rls FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_bootstrap FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA steward_rls FROM PUBLIC;

SELECT format('GRANT %I TO %I', :'steward_migration_role', current_user) \gexec
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'steward_migration_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA public, steward_bootstrap, steward_rls TO %I', :'steward_app_role') \gexec
SELECT format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA steward_bootstrap, steward_rls TO %I', :'steward_app_role') \gexec
SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'steward_app_role') \gexec
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'steward_app_role') \gexec

-- The function owner is non-login and may read only the fixed bootstrap inputs.
SELECT format(
  'GRANT SELECT ON public.tenants, public.users, public.user_tenants, public.agents, '
  'public.session_signers, public.tenant_app_clients, public.tenant_app_client_secrets, '
  'public.transactions TO %I',
  :'steward_bootstrap_role'
) \gexec
SELECT format('GRANT INSERT ON public.tenants TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER SCHEMA steward_rls OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.tenant_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER FUNCTION steward_rls.user_id() OWNER TO %I', :'steward_migration_role') \gexec
SELECT format('ALTER SCHEMA steward_bootstrap OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.tenant_api_key_subject(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.session_subject(uuid,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.agent_subject(text,text,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.app_client_subject(text,text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.tenant_ids_for_internal_job() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.ensure_default_tenant(text) OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_stats() OWNER TO %I', :'steward_bootstrap_role') \gexec
SELECT format('ALTER FUNCTION steward_bootstrap.platform_tenants(integer,integer) OWNER TO %I', :'steward_bootstrap_role') \gexec

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
      current_setting('steward.bootstrap.migration_role')
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
END
$$;
