\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '10s';

\ir rls-policy-inventory.sql

DO $$
DECLARE
  relation_name text;
BEGIN
  FOR relation_name IN
    SELECT inventory.relation_name
    FROM steward_expected_rls_policies inventory
    ORDER BY inventory.relation_name
  LOOP
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', relation_name);
  END LOOP;
END
$$;

COMMIT;
