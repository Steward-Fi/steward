-- Capabilities are tenant authority, so an enabled capabilities plugin must
-- participate in the same exact RLS contract as the core schema.
CREATE POLICY steward_tenant_isolation ON public.capabilities
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capability_grants
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capability_invocations
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
