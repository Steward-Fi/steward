-- SEC-169: capability authority is tenant-owned even though these relations
-- live in the plugin migration ledger. Install deny-by-default policies after
-- the core steward_rls.tenant_id() helper exists.
DROP POLICY IF EXISTS steward_tenant_isolation ON public.capabilities;
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capabilities
  FOR ALL
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
DROP POLICY IF EXISTS steward_tenant_isolation ON public.capability_grants;
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capability_grants
  FOR ALL
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
DROP POLICY IF EXISTS steward_tenant_isolation ON public.capability_invocations;
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capability_invocations
  FOR ALL
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
-- Plugin migrations may run either before the operator activates RLS or after
-- an already-activated deployment enables this plugin. Mirror the core state:
-- if the canonical agents table is forced, activate the new plugin relations
-- atomically and retain migration-role maintenance access.
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
      'capability_invocations'
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
