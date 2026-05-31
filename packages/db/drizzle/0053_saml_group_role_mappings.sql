ALTER TABLE "tenant_saml_sso_configs"
  ADD COLUMN IF NOT EXISTS "group_role_mappings" jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE "tenant_saml_sso_configs"
  DROP CONSTRAINT IF EXISTS "tenant_saml_sso_configs_group_role_mappings_array_check";

ALTER TABLE "tenant_saml_sso_configs"
  ADD CONSTRAINT "tenant_saml_sso_configs_group_role_mappings_array_check"
    CHECK (jsonb_typeof("group_role_mappings") = 'array');
