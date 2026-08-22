-- A plugin can be enabled after the operator has already activated and forced
-- RLS on the core schema. Inherit that state without rewriting the shipped
-- tenant-policy migration identity.
DO $$
DECLARE
  relation_name text;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = 'agents'
      AND c.relrowsecurity
      AND c.relforcerowsecurity
  ) THEN
    FOREACH relation_name IN ARRAY ARRAY[
      'capabilities',
      'capability_grants',
      'capability_invocations',
      'capability_rate_limit_buckets'
    ]
    LOOP
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
      EXECUTE format(
        'DROP POLICY IF EXISTS steward_migration_maintenance ON public.%I',
        relation_name
      );
      EXECUTE format(
        'CREATE POLICY steward_migration_maintenance ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
        relation_name,
        current_user
      );
    END LOOP;
  END IF;
END
$$;
