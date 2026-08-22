\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT set_config('steward.rollback.allow_inventory_drift', 'true', true);

\ir rls-policy-inventory.sql

DO $$
DECLARE
  relation_name text;
BEGIN
  FOR relation_name IN
    SELECT c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND (c.relrowsecurity OR c.relforcerowsecurity)
    ORDER BY c.relname
  LOOP
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', relation_name);
  END LOOP;
END
$$;

COMMIT;
