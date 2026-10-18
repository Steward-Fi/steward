-- Reconcile the conditional maintenance-policy effects shipped in 0005.
-- Existing databases may legitimately have zero or four policies depending on
-- whether core RLS was active when 0005 ran. This append-only migration makes
-- the final plugin schema deterministic without changing 0005's ledger hash.
DO $$
DECLARE
  relation_name text;
  relation_owner name;
  relation_kind "char";
  inherit_core_rls boolean;
BEGIN
  SELECT c.relrowsecurity AND c.relforcerowsecurity
  INTO inherit_core_rls
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname = 'agents'
    AND c.relkind IN ('r', 'p');

  IF inherit_core_rls IS NULL THEN
    RAISE EXCEPTION 'required core relation public.agents is missing';
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'capabilities',
    'capability_grants',
    'capability_invocations',
    'capability_rate_limit_buckets'
  ]
  LOOP
    SELECT c.relkind, owner_role.rolname
    INTO relation_kind, relation_owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles owner_role ON owner_role.oid = c.relowner
    WHERE n.nspname = 'public'
      AND c.relname = relation_name;

    IF relation_kind IS NULL OR relation_kind NOT IN ('r', 'p') THEN
      RAISE EXCEPTION 'expected plugin relation public.% is missing or has the wrong kind', relation_name;
    END IF;
    IF relation_owner <> current_user THEN
      RAISE EXCEPTION 'plugin relation public.% is not owned by the migration role', relation_name;
    END IF;

    IF inherit_core_rls THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
      EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    END IF;
    EXECUTE format(
      'DROP POLICY IF EXISTS steward_migration_maintenance ON public.%I',
      relation_name
    );
    EXECUTE format(
      'CREATE POLICY steward_migration_maintenance ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      relation_name,
      relation_owner
    );
  END LOOP;
END
$$;
