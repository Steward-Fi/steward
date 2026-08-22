-- Append-only repair for four-role deployments. Migration 0003 is already
-- shipped and its bytes are part of the namespaced plugin ledger.
DO $$
DECLARE
  relation_name text;
  core_rls_active boolean;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'agents'
      AND c.relrowsecurity AND c.relforcerowsecurity
  ) INTO core_rls_active;
  FOREACH relation_name IN ARRAY ARRAY[
    'capabilities', 'capability_grants', 'capability_invocations'
  ]
  LOOP
    IF core_rls_active THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    END IF;
    EXECUTE format(
      'DROP POLICY IF EXISTS steward_migration_maintenance ON public.%I', relation_name
    );
    EXECUTE format(
      'CREATE POLICY steward_migration_maintenance ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      relation_name, current_user
    );
  END LOOP;
END
$$;
