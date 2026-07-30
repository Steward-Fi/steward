-- @stwd/plugin-capabilities migration 0002: per-grant policy + policy-verdict audit (C1).
--
-- 1. capability_grants.policy — the per-grant policy document (jsonb) evaluated
--    at invoke time by @stwd/policy-engine's grant-policy module. EXISTING grants
--    are backfilled with the EXPLICIT permissive default
--    ({"version":1,"class":"plain-secret"}) so rollout changes nothing for them:
--    a plain-secret policy with no constraints allows iff the grant is valid,
--    which is exactly the pre-policy behavior — but now it is written down
--    rather than implied. The column stays NULLABLE (with a DEFAULT for new
--    rows) so strict mode (STEWARD_GRANT_POLICY_STRICT=true) has a real
--    fail-closed target: a NULL policy denies under strict mode and allows
--    (explicitly, audited) under compatibility mode.
--
-- 2. capability_invocations gains the policy VERDICT columns: which rule fired
--    (verdict_rule), the human-readable reason (verdict_reason), and the
--    extracted per-invoke amount in integer micros (amount_micros). amount_micros
--    on decision IN ('allow','approval','error') rows is the source for the
--    rolling-window cumulative amount cap (pending approvals and post-
--    authorization infra errors RESERVE spend so the window can never be
--    under-counted).
ALTER TABLE "capability_grants" ADD COLUMN "policy" jsonb DEFAULT '{"version":1,"class":"plain-secret"}'::jsonb;
--> statement-breakpoint
UPDATE "capability_grants" SET "policy" = '{"version":1,"class":"plain-secret"}'::jsonb WHERE "policy" IS NULL;
--> statement-breakpoint
ALTER TABLE "capability_invocations" ADD COLUMN "verdict_rule" text;
--> statement-breakpoint
ALTER TABLE "capability_invocations" ADD COLUMN "verdict_reason" text;
--> statement-breakpoint
ALTER TABLE "capability_invocations" ADD COLUMN "amount_micros" bigint;
