-- SEC-169 checked-in semantic policy manifest.
--
-- This migration is deliberately independent of pg_policy: it records the
-- exact expressions installed by 0111 and refuses to bless catalog drift.
CREATE TABLE "steward_rls"."policy_manifest" (
  "relation_name" text NOT NULL,
  "policy_name" text NOT NULL,
  "canonical_expression" text NOT NULL,
  "required" boolean NOT NULL DEFAULT true,
  PRIMARY KEY ("relation_name", "policy_name")
);

REVOKE ALL ON TABLE "steward_rls"."policy_manifest" FROM PUBLIC;

WITH direct(relation_name, text_tenant_id, required) AS (
  VALUES
    ('agent_key_quorums',false,true),('agent_policies',true,true),
    ('agent_registrations',false,true),('agent_signers',false,true),('agents',false,true),
    ('audit_archives',false,true),('audit_chain_heads',false,true),
    ('audit_checkpoints',false,true),('audit_events',false,true),
    ('audit_retention_policies',false,true),('auto_approval_rules',false,true),
    ('condition_set_items',false,true),('condition_sets',false,true),
    ('digital_asset_account_aggregations',false,true),
    ('digital_asset_account_wallets',false,true),('digital_asset_accounts',false,true),
    ('evm_wallet_nonce_inflight',false,true),('evm_wallet_nonce_owners',false,true),
    ('evm_wallet_nonces',false,true),('execution_authorization_nonces',false,true),
    ('global_wallet_action_confirmations',false,true),('intents',false,true),
    ('operator_transfer_reservations',false,true),('pending_proxy_requests',true,true),
    ('policy_templates',false,true),('provider_accounts',false,true),
    ('provider_action_approvals',false,true),('provider_action_audit_outbox',false,true),
    ('provider_action_bindings',false,true),
    ('provider_action_reservation_generations',false,true),
    ('provider_agent_budgets',false,true),('provider_authority_tenant_state',false,true),
    ('provider_google_credential_lifecycles',false,true),('provider_grants',false,true),
    ('provider_operations',false,true),('provider_role_bindings',false,true),
    ('provider_x_credential_lifecycles',false,true),('proxy_audit_log',true,true),
    ('refresh_tokens',false,true),('secret_routes',true,true),('secrets',true,true),
    ('session_signers',false,true),('sponsored_gas_events',false,true),
    ('tenant_app_client_secrets',false,true),('tenant_app_clients',false,true),
    ('tenant_configs',false,true),('tenant_invitations',false,true),
    ('tenant_request_signing_keys',false,true),('tenant_saml_assertion_replays',false,true),
    ('tenant_saml_authn_requests',false,true),('tenant_saml_sso_configs',false,true),
    ('tenant_sso_domains',false,true),('trade_sessions',false,true),
    ('upstream_credential_lease_events',false,true),
    ('upstream_credential_leases',false,true),('user_tenants',false,true),
    ('user_wallet_app_consents',false,true),('vault_signing_freezes',false,true),
    ('webhook_configs',false,true),('webhook_deliveries',true,true),('workspaces',false,true),
    ('capabilities',true,false),('capability_grants',true,false),
    ('capability_invocations',true,false)
)
INSERT INTO "steward_rls"."policy_manifest"(
  relation_name, policy_name, canonical_expression, required
)
SELECT relation_name, 'steward_tenant_isolation',
  CASE WHEN text_tenant_id
    THEN '(tenant_id=steward_rls.tenant_id())'
    ELSE '((tenant_id)::text=steward_rls.tenant_id())'
  END,
  required
FROM direct;

INSERT INTO "steward_rls"."policy_manifest" VALUES
  ('tenants','steward_tenant_isolation','((id)::text=steward_rls.tenant_id())',true),
  ('approval_queue','steward_tenant_direct','((tenant_id)::text=steward_rls.tenant_id())',true),
  ('approval_queue','steward_tenant_derived',
    '((tenant_idisnull)and(exists(select1fromagentsparentwhere(((parent.id)::text=(approval_queue.agent_id)::text)and((parent.tenant_id)::text=steward_rls.tenant_id())))))',true),
  ('user_push_subscriptions','steward_tenant_subscription',
    '((tenant_id)::text=steward_rls.tenant_id())',true),
  ('user_push_subscriptions','steward_global_user_subscription',
    '((tenant_idisnull)and(user_id=steward_rls.user_id()))',true),
  ('audit_archive_chunks','steward_tenant_isolation',
    '(exists(select1fromaudit_archivesparentwhere((parent.id=audit_archive_chunks.archive_id)and((parent.tenant_id)::text=steward_rls.tenant_id()))))',true);

WITH indirect(relation_name) AS (
  VALUES ('agent_wallets'),('encrypted_chain_keys'),('encrypted_keys'),
    ('policies'),('reputation_cache'),('transactions')
)
INSERT INTO "steward_rls"."policy_manifest"
SELECT relation_name, 'steward_tenant_isolation',
  format(
    '(exists(select1fromagentsparentwhere(((parent.id)::text=(%s.agent_id)::text)and((parent.tenant_id)::text=steward_rls.tenant_id()))))',
    relation_name
  ), true
FROM indirect;

DO $$
DECLARE mismatch text;
BEGIN
  IF (SELECT count(*) FROM steward_rls.policy_manifest WHERE required) <> 73
     OR (SELECT count(*) FROM steward_rls.policy_manifest WHERE NOT required) <> 3 THEN
    RAISE EXCEPTION 'SEC-169 checked-in manifest must contain 73 core and 3 optional policies';
  END IF;

  WITH expected AS (
    SELECT * FROM steward_rls.policy_manifest WHERE required
  ), actual AS (
    SELECT c.relname AS relation_name, p.polname AS policy_name,
      p.polcmd, p.polpermissive, p.polroles,
      lower(regexp_replace(pg_get_expr(p.polqual, p.polrelid), '[[:space:]]', '', 'g'))
        AS canonical_using,
      lower(regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), '[[:space:]]', '', 'g'))
        AS canonical_check
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND p.polname <> 'steward_migration_maintenance'
  ), differences AS (
    SELECT coalesce(expected.relation_name, actual.relation_name) AS relation_name,
      coalesce(expected.policy_name, actual.policy_name) AS policy_name
    FROM expected FULL JOIN actual USING (relation_name, policy_name)
    WHERE expected.relation_name IS NULL OR actual.relation_name IS NULL
      OR actual.polcmd <> '*' OR NOT actual.polpermissive
      OR actual.polroles <> ARRAY[0]::oid[]
      OR actual.canonical_using IS DISTINCT FROM expected.canonical_expression
      OR actual.canonical_check IS DISTINCT FROM expected.canonical_expression
  )
  SELECT string_agg(relation_name || ':' || policy_name, ', ' ORDER BY relation_name, policy_name)
  INTO mismatch FROM differences;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 installed policies drift from checked-in manifest: %', mismatch;
  END IF;
END
$$;

COMMENT ON TABLE "steward_rls"."policy_manifest" IS
  'SEC-169 checked-in canonical policy contract installed by migration 0112.';
