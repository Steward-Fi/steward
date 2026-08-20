-- Durable cross-replica sliding-window reservations for capability invoke and
-- manifest issuance. The array is bounded by the application limit (60/30), so
-- abandoned agents cannot leave an unbounded reservation ledger behind.
CREATE TABLE "capability_rate_limit_buckets" (
	"tenant_id" text NOT NULL,
	"agent_id" varchar(64) NOT NULL,
	"surface" text NOT NULL,
	"reservations" timestamptz[] DEFAULT ARRAY[]::timestamptz[] NOT NULL,
	"updated_at" timestamptz DEFAULT now() NOT NULL,
	CONSTRAINT "capability_rate_limit_buckets_surface_check" CHECK ("surface" IN ('invoke','issue'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX "capability_rate_limit_buckets_identity_uniq" ON "capability_rate_limit_buckets" ("tenant_id","agent_id","surface");
--> statement-breakpoint
CREATE INDEX "capability_rate_limit_buckets_updated_idx" ON "capability_rate_limit_buckets" ("updated_at");
--> statement-breakpoint
-- Every writer, including an older application pod, must serialize with tenant
-- deletion first and then hold the parent agent against deletion. This mirrors
-- the capability-grant fence and prevents a bucket from being recreated after
-- agent/tenant cleanup commits.
CREATE OR REPLACE FUNCTION capability_rate_limit_bucket_agent_fence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
	PERFORM public.steward_lock_tenant_deletion(NEW.tenant_id);
	PERFORM 1
	FROM public.agents
	WHERE tenant_id = NEW.tenant_id AND id = NEW.agent_id
	FOR KEY SHARE;

	IF NOT FOUND THEN
		RAISE EXCEPTION 'capability rate-limit bucket references a missing agent'
			USING ERRCODE = '23503';
	END IF;
	RETURN NEW;
END;
$$;
--> statement-breakpoint
CREATE TRIGGER capability_rate_limit_bucket_agent_fence
BEFORE INSERT OR UPDATE OF tenant_id, agent_id
ON public.capability_rate_limit_buckets
FOR EACH ROW EXECUTE FUNCTION capability_rate_limit_bucket_agent_fence();
--> statement-breakpoint
CREATE POLICY steward_tenant_isolation ON public.capability_rate_limit_buckets
  USING (tenant_id = steward_rls.tenant_id())
  WITH CHECK (tenant_id = steward_rls.tenant_id());
--> statement-breakpoint
-- Core RLS activation may already have completed on an existing deployment.
-- This later plugin migration must activate the full plugin graph before the
-- exact production manifest assertion runs. Repeating activation for the three
-- pre-existing tables is intentional: fresh deployments apply plugin migrations
-- after core migration 0112, while upgrades may already have activated them.
ALTER TABLE public.capabilities ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capabilities FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_grants ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_grants FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_invocations ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_invocations FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_rate_limit_buckets ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.capability_rate_limit_buckets FORCE ROW LEVEL SECURITY;
