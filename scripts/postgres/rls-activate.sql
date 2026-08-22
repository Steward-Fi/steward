\set ON_ERROR_STOP on
\if :{?steward_app_role}
\else
  \set steward_app_role steward_app
\endif

\if :{?steward_migration_role}
\else
  \set steward_migration_role steward_migrator
\endif

SELECT set_config('steward.activation.migration_role', :'steward_migration_role', false);

BEGIN;
SET LOCAL lock_timeout = '10s';

\ir rls-policy-inventory.sql

DO $$
DECLARE
  relation_name text;
BEGIN
  IF current_user <> current_setting('steward.activation.migration_role')
     OR session_user <> current_setting('steward.activation.migration_role') THEN
    RAISE EXCEPTION 'SEC-169 activation must connect directly as the migration role';
  END IF;

  FOR relation_name IN
    SELECT inventory.relation_name
    FROM steward_expected_rls_policies inventory
    ORDER BY inventory.relation_name
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format(
      'DROP POLICY IF EXISTS steward_migration_maintenance ON public.%I', relation_name
    );
    EXECUTE format(
      'CREATE POLICY steward_migration_maintenance ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      relation_name,
      current_setting('steward.activation.migration_role')
    );
  END LOOP;
END
$$;

DO $$
DECLARE
  missing text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO missing
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relkind IN ('r', 'p')
    AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id')
    AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity);
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 activation incomplete for: %', missing;
  END IF;
END
$$;

COMMIT;
