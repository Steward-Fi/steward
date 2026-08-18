-- #417: allow the durable lifecycle journal to carry a disconnect revoke handle.
-- 0098 is already deployed on existing databases, so this constraint change is
-- intentionally a separate migration rather than an edit to 0098.
ALTER TABLE "provider_google_credential_lifecycles"
  DROP CONSTRAINT "provider_google_lifecycle_kind_check";
--> statement-breakpoint
ALTER TABLE "provider_google_credential_lifecycles"
  ADD CONSTRAINT "provider_google_lifecycle_kind_check"
  CHECK ("kind" IN ('connect_exchange', 'refresh_rotation', 'disconnect_revoke'));
