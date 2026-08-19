\set ON_ERROR_STOP on

BEGIN;
SET LOCAL lock_timeout = '10s';

DO $$
DECLARE
  relation_name text;
BEGIN
  FOR relation_name IN
    SELECT DISTINCT c.relname
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND p.polname LIKE 'steward_%'
  LOOP
    EXECUTE format('ALTER TABLE public.%I NO FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I DISABLE ROW LEVEL SECURITY', relation_name);
  END LOOP;
END
$$;

COMMIT;
