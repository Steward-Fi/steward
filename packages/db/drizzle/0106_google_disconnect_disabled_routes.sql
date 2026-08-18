-- Disconnect recovery records the enabled routes it disabled, with their
-- authority revisions, so a later reconnect can restore only unchanged routes.
ALTER TABLE "provider_google_credential_lifecycles"
  ADD COLUMN "disabled_routes" jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD CONSTRAINT "provider_google_lifecycle_disabled_routes_array_check"
    CHECK (jsonb_typeof("disabled_routes") = 'array');
