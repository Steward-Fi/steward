-- Canonical SEC-169 activation inventory. Keep this in sync with
-- packages/db/src/rls-inventory.ts and migration 0111. The second column is
-- the exact number of tenant policies installed before the maintenance policy.
CREATE TEMP TABLE steward_expected_rls_policies (
  relation_name text PRIMARY KEY,
  expected_policy_count integer NOT NULL CHECK (expected_policy_count > 0)
) ON COMMIT DROP;

INSERT INTO steward_expected_rls_policies(relation_name, expected_policy_count) VALUES
  ('agent_key_quorums',1),('agent_policies',1),('agent_registrations',1),
  ('agent_signers',1),('agent_wallets',1),('agents',1),('approval_queue',2),
  ('audit_archive_chunks',1),('audit_archives',1),('audit_chain_heads',1),
  ('audit_checkpoints',1),('audit_events',1),('audit_retention_policies',1),
  ('auto_approval_rules',1),('condition_set_items',1),('condition_sets',1),
  ('digital_asset_account_aggregations',1),('digital_asset_account_wallets',1),
  ('digital_asset_accounts',1),('encrypted_chain_keys',1),('encrypted_keys',1),
  ('evm_wallet_nonce_inflight',1),('evm_wallet_nonce_owners',1),
  ('evm_wallet_nonces',1),('execution_authorization_nonces',1),
  ('global_wallet_action_confirmations',1),('intents',1),
  ('operator_transfer_reservations',1),('pending_proxy_requests',1),('policies',1),
  ('policy_templates',1),('provider_accounts',1),('provider_action_approvals',1),
  ('provider_action_audit_outbox',1),('provider_action_bindings',1),
  ('provider_action_reservation_generations',1),('provider_agent_budgets',1),
  ('provider_authority_tenant_state',1),('provider_google_credential_lifecycles',1),
  ('provider_grants',1),('provider_operations',1),('provider_role_bindings',1),
  ('provider_x_credential_lifecycles',1),('proxy_audit_log',1),('refresh_tokens',1),
  ('reputation_cache',1),('secret_routes',1),('secrets',1),('session_signers',1),
  ('sponsored_gas_events',1),('tenant_app_client_secrets',1),('tenant_app_clients',1),
  ('tenant_configs',1),('tenant_invitations',1),('tenant_request_signing_keys',1),
  ('tenant_saml_assertion_replays',1),('tenant_saml_authn_requests',1),
  ('tenant_saml_sso_configs',1),('tenant_sso_domains',1),('tenants',1),
  ('trade_sessions',1),('transactions',1),('upstream_credential_lease_events',1),
  ('upstream_credential_leases',1),('user_push_subscriptions',2),('user_tenants',1),
  ('user_wallet_app_consents',1),('vault_signing_freezes',1),('webhook_configs',1),
  ('webhook_deliveries',1),('workspaces',1);

DO $$
DECLARE
  mismatch text;
BEGIN
  IF (SELECT count(*) FROM steward_expected_rls_policies) <> 71
     OR (SELECT sum(expected_policy_count) FROM steward_expected_rls_policies) <> 73 THEN
    RAISE EXCEPTION 'SEC-169 policy inventory must contain exactly 71 relations and 73 policies';
  END IF;

  SELECT string_agg(i.relation_name, ', ' ORDER BY i.relation_name) INTO mismatch
  FROM steward_expected_rls_policies i
  LEFT JOIN pg_class c ON c.relname = i.relation_name
  LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  WHERE n.oid IS NULL OR c.relkind NOT IN ('r', 'p');
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 inventory relations missing from public schema: %', mismatch;
  END IF;

  WITH actual AS (
    SELECT c.relname, count(*)::integer AS policy_count
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND p.polname <> 'steward_migration_maintenance'
    GROUP BY c.relname
  ), differences AS (
    SELECT coalesce(i.relation_name, a.relname) AS relation_name
    FROM steward_expected_rls_policies i
    FULL JOIN actual a ON a.relname = i.relation_name
    WHERE i.expected_policy_count IS DISTINCT FROM a.policy_count
  )
  SELECT string_agg(relation_name, ', ' ORDER BY relation_name) INTO mismatch FROM differences;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 installed policies drift from inventory: %', mismatch;
  END IF;
END
$$;
