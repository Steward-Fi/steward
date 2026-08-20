-- Canonical SEC-169 activation inventory. Keep this in sync with
-- packages/db/src/rls-inventory.ts and migration 0111. The second column is
-- the exact number of tenant policies installed before the maintenance policy.
CREATE TEMP TABLE steward_expected_rls_policies (
  relation_name text PRIMARY KEY,
  expected_policy_count integer NOT NULL CHECK (expected_policy_count > 0),
  required boolean NOT NULL DEFAULT true,
  policy_shape text NOT NULL DEFAULT 'direct'
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

-- Plugin-owned relations are absent from lean-core deployments. Once present,
-- however, they are part of the same fail-closed activation boundary.
INSERT INTO steward_expected_rls_policies(
  relation_name,
  expected_policy_count,
  required
) VALUES
  ('capabilities',1,false),
  ('capability_grants',1,false),
  ('capability_invocations',1,false);

UPDATE steward_expected_rls_policies
SET policy_shape = 'root'
WHERE relation_name = 'tenants';

UPDATE steward_expected_rls_policies
SET policy_shape = 'indirect_agents'
WHERE relation_name IN (
  'agent_wallets', 'encrypted_chain_keys', 'encrypted_keys', 'policies',
  'reputation_cache', 'transactions'
);

UPDATE steward_expected_rls_policies
SET policy_shape = 'indirect_archives'
WHERE relation_name = 'audit_archive_chunks';

UPDATE steward_expected_rls_policies
SET policy_shape = 'approval_hybrid'
WHERE relation_name = 'approval_queue';

UPDATE steward_expected_rls_policies
SET policy_shape = 'subscription_hybrid'
WHERE relation_name = 'user_push_subscriptions';

CREATE TEMP TABLE steward_expected_global_relations (
  relation_name text PRIMARY KEY,
  required boolean NOT NULL DEFAULT true,
  rationale text NOT NULL CHECK (length(rationale) > 20)
) ON COMMIT DROP;

INSERT INTO steward_expected_global_relations(relation_name, required, rationale) VALUES
  ('accounts',true,'global user OAuth identities; tenant access derives through user_tenants'),
  ('auth_kv_store',true,'global one-time authentication state keyed by opaque digests'),
  ('authenticators',true,'global user WebAuthn identities; tenant access derives through user_tenants'),
  ('registry_index',true,'public chain registry cache, not tenant-owned'),
  ('sessions',true,'global user sessions; tenant membership is checked separately'),
  ('users',true,'global user identity; tenant access derives through user_tenants'),
  ('example_log',false,'example plugin demonstration log contains no tenant or authority data');

CREATE TEMP TABLE steward_expected_policy_definitions (
  relation_name text NOT NULL,
  policy_name text NOT NULL,
  canonical_expression text NOT NULL,
  PRIMARY KEY (relation_name, policy_name)
) ON COMMIT DROP;

INSERT INTO steward_expected_policy_definitions
SELECT
  relation_name,
  'steward_tenant_isolation',
  CASE
    WHEN relation_name IN (
      'agent_policies','pending_proxy_requests','proxy_audit_log','secret_routes',
      'secrets','webhook_deliveries','capabilities','capability_grants',
      'capability_invocations'
    ) THEN '(tenant_id=steward_rls.tenant_id())'
    ELSE '((tenant_id)::text=steward_rls.tenant_id())'
  END
FROM steward_expected_rls_policies WHERE policy_shape = 'direct';

INSERT INTO steward_expected_policy_definitions VALUES
  ('tenants','steward_tenant_isolation','((id)::text=steward_rls.tenant_id())'),
  ('approval_queue','steward_tenant_direct','((tenant_id)::text=steward_rls.tenant_id())'),
  ('approval_queue','steward_tenant_derived',
    '((tenant_idisnull)and(exists(select1fromagentsparentwhere(((parent.id)::text=(approval_queue.agent_id)::text)and((parent.tenant_id)::text=steward_rls.tenant_id())))))'),
  ('user_push_subscriptions','steward_tenant_subscription','((tenant_id)::text=steward_rls.tenant_id())'),
  ('user_push_subscriptions','steward_global_user_subscription',
    '((tenant_idisnull)and(user_id=steward_rls.user_id()))'),
  ('audit_archive_chunks','steward_tenant_isolation',
    '(exists(select1fromaudit_archivesparentwhere((parent.id=audit_archive_chunks.archive_id)and((parent.tenant_id)::text=steward_rls.tenant_id()))))');

INSERT INTO steward_expected_policy_definitions
SELECT
  relation_name,
  'steward_tenant_isolation',
  format(
    '(exists(select1fromagentsparentwhere(((parent.id)::text=(%s.agent_id)::text)and((parent.tenant_id)::text=steward_rls.tenant_id()))))',
    relation_name
  )
FROM steward_expected_rls_policies WHERE policy_shape = 'indirect_agents';

CREATE TEMP TABLE steward_expected_bootstrap_functions (
  function_name text NOT NULL,
  identity_arguments text NOT NULL,
  result_type text NOT NULL,
  volatility "char" NOT NULL,
  language_name text NOT NULL,
  source_md5 text NOT NULL CHECK (length(source_md5) = 32),
  PRIMARY KEY (function_name, identity_arguments)
) ON COMMIT DROP;

INSERT INTO steward_expected_bootstrap_functions VALUES
  ('agent_subject','p_agent_id text, p_tenant_id text, p_jti text','TABLE(agent_id character varying, agent_name character varying, wallet_address character varying, signer_id uuid, signer_policy_ids jsonb, signer_expires_at timestamp with time zone, signer_revoked_at timestamp with time zone)','s','sql','5e03c2a25a11ee0e0ce66315f96bfcce'),
  ('agent_tenant_subject','p_agent_id text','TABLE(tenant_id character varying)','s','sql','e16949bbcfaecf61b833eb5c992b2098'),
  ('app_client_subject','p_tenant_id text, p_client_id text','TABLE(secret_id uuid, secret_hash text, secret_status character varying, expires_at timestamp with time zone, revoked_at timestamp with time zone, client_enabled boolean)','s','sql','bdf585ea6ddb3da04631478cbebdf95f'),
  ('auth_app_clients_subject','p_tenant_id text','TABLE(id character varying, allowed_redirect_urls text[], login_methods jsonb, allowed_bundle_ids text[], allowed_package_names text[])','s','sql','2ee252db3c428095ef6b02e0c97cb86c'),
  ('auth_refresh_subject','p_token_hash text','TABLE(user_id uuid, tenant_id character varying, expires_at timestamp with time zone)','s','sql','fee018b0f7f2f0cb1fe05c371bb7d88b'),
  ('auth_rotate_refresh_token','p_source_token_hash text, p_target_tenant_id text, p_successor_id text, p_successor_token_hash text, p_successor_expires_at timestamp with time zone','TABLE(id text, user_id uuid, tenant_id character varying, token_hash text, expires_at timestamp with time zone, created_at timestamp with time zone)','v','plpgsql','b9c19c7595dbadac562b6a36ee6c953a'),
  ('auth_sso_discovery_subject','p_domain text','TABLE(tenant_id character varying, domain character varying, sso_required boolean)','s','sql','4c1dd6a873c1fe120b98b301df3ae144'),
  ('auth_sso_domain_subject','p_tenant_id text, p_domain text','TABLE(tenant_id character varying, sso_required boolean)','s','sql','b5d698d14a1e380c4a2eec5d19c987b0'),
  ('auth_tenant_config_subject','p_tenant_id text','TABLE(auth_abuse_config jsonb, allowed_origins text[], email_config jsonb, oidc_providers jsonb, test_account jsonb, allowed_redirect_urls text[])','s','sql','6feada7acb2f1291ef6c6f60130b789c'),
  ('auth_tenant_subject','p_tenant_id text, p_user_id uuid','TABLE(tenant_id character varying, membership_role character varying, join_mode character varying)','s','sql','49c42eed03a472b396ddd687badf9873'),
  ('ensure_default_tenant','p_api_key_hash text','void','v','sql','36dd5e97a72d032a505fb6b1df0d9f92'),
  ('ensure_platform_tenant','','text','v','sql','5dcceabf9c2707787fbe73462bd63c3d'),
  ('ensure_system_tenant','','text','v','sql','f0641c720c843bf104a5c964b18a51a8'),
  ('platform_delete_user','p_user_id uuid','TABLE(user_id uuid)','v','plpgsql','235b5e978b9122dd1627928e9d42edf7'),
  ('platform_revoke_user_refresh_tokens','p_user_id uuid','bigint','v','plpgsql','4aef47d6e03942e9386f5490ad19773c'),
  ('platform_set_user_deactivation','p_user_id uuid, p_deactivated boolean','TABLE(user_id uuid, previous_deactivated_at timestamp with time zone, previous_updated_at timestamp with time zone, deactivated_at timestamp with time zone)','v','plpgsql','ac85814ee129ddc857eeb4945d6eb70d'),
  ('platform_stats','','TABLE(tenant_count bigint, agent_count bigint, transaction_count bigint)','s','sql','9a7bb34e3705ff5265dfeeccfe03f72c'),
  ('platform_tenants','p_limit integer, p_offset integer','TABLE(id character varying, name character varying, owner_address character varying, created_at timestamp with time zone, updated_at timestamp with time zone)','s','sql','4f5f7e0f936b6b1a881e2e688206de85'),
  ('platform_user_tenant_ids','p_user_id uuid','TABLE(tenant_id character varying)','s','sql','9c0a6fb1959536cf7cccec152f7691f4'),
  ('retention_delete_deactivated_users','p_days integer','bigint','v','plpgsql','ca567283f5ee114fd4197cfd34974744'),
  ('session_subject','p_user_id uuid, p_tenant_id text','TABLE(deactivated_at timestamp with time zone, is_guest boolean, guest_expires_at timestamp with time zone, membership_role character varying)','s','sql','e9c808c3e644b38e94e6f972e7630354'),
  ('tenant_api_key_subject','p_tenant_id text','TABLE(id character varying, name character varying, api_key_hash text, owner_address character varying, created_at timestamp with time zone, updated_at timestamp with time zone)','s','sql','c48f38fdf24b5ad36d1d2d15f525e93f'),
  ('tenant_ids_for_internal_job','','TABLE(tenant_id character varying)','s','sql','6e4257e377897ac797b3c0ee297600de');

DO $$
DECLARE
  mismatch text;
BEGIN
  -- Emergency rollback still needs the canonical relation lists, but it must
  -- not be prevented by the very catalog drift it is intended to contain.
  IF current_setting('steward.rollback.allow_inventory_drift', true) = 'true' THEN
    RETURN;
  END IF;
  IF (SELECT count(*) FROM steward_expected_rls_policies WHERE required) <> 71
     OR (SELECT sum(expected_policy_count) FROM steward_expected_rls_policies WHERE required) <> 73
     OR (SELECT count(*) FROM steward_expected_rls_policies WHERE NOT required) <> 3
     OR (SELECT count(*) FROM steward_expected_global_relations WHERE required) <> 6
     OR (SELECT count(*) FROM steward_expected_policy_definitions) <> 76
     OR (SELECT count(*) FROM steward_expected_bootstrap_functions) <> 23 THEN
    RAISE EXCEPTION 'SEC-169 policy inventory must contain exactly 71 relations and 73 policies';
  END IF;

  SELECT string_agg(i.relation_name, ', ' ORDER BY i.relation_name) INTO mismatch
  FROM steward_expected_rls_policies i
  LEFT JOIN pg_class c ON c.relname = i.relation_name
  LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  WHERE i.required AND (n.oid IS NULL OR c.relkind NOT IN ('r', 'p'));
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 inventory relations missing from public schema: %', mismatch;
  END IF;

  WITH expected_present AS (
    SELECT d.*
    FROM steward_expected_policy_definitions d
    JOIN steward_expected_rls_policies i ON i.relation_name = d.relation_name
    JOIN pg_class c ON c.relname = i.relation_name AND c.relkind IN ('r', 'p')
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  ), actual AS (
    SELECT
      c.relname AS relation_name,
      p.polname AS policy_name,
      p.polcmd,
      p.polpermissive,
      p.polroles,
      lower(regexp_replace(pg_get_expr(p.polqual, p.polrelid), '[[:space:]]', '', 'g'))
        AS canonical_using,
      lower(regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), '[[:space:]]', '', 'g'))
        AS canonical_check
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND p.polname <> 'steward_migration_maintenance'
  ), differences AS (
    SELECT coalesce(i.relation_name, a.relation_name) AS relation_name
    FROM expected_present i
    FULL JOIN actual a
      ON a.relation_name = i.relation_name AND a.policy_name = i.policy_name
    WHERE i.relation_name IS NULL
      OR a.relation_name IS NULL
      OR a.polcmd <> '*'
      OR NOT a.polpermissive
      OR a.polroles <> ARRAY[0]::oid[]
      OR a.canonical_using IS DISTINCT FROM i.canonical_expression
      OR a.canonical_check IS DISTINCT FROM i.canonical_expression
  )
  SELECT string_agg(relation_name, ', ' ORDER BY relation_name) INTO mismatch FROM differences;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 installed policies drift from inventory: %', mismatch;
  END IF;

  SELECT string_agg(i.relation_name, ', ' ORDER BY i.relation_name) INTO mismatch
  FROM steward_expected_global_relations i
  LEFT JOIN pg_class c ON c.relname = i.relation_name AND c.relkind IN ('r', 'p')
  LEFT JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  WHERE i.required AND n.oid IS NULL;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 global inventory relations missing from public schema: %', mismatch;
  END IF;

  -- Direct access to a partition does not rely on a caller using its parent.
  -- Every child therefore needs an explicit inventory entry and policy rather
  -- than being implicitly trusted merely because its root is protected.
  WITH protected_roots AS (
    SELECT c.oid
    FROM steward_expected_rls_policies i
    JOIN pg_class c ON c.relname = i.relation_name AND c.relkind = 'p'
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  ), descendants AS (
    SELECT child.relname
    FROM protected_roots root
    CROSS JOIN LATERAL pg_partition_tree(root.oid) tree
    JOIN pg_class child ON child.oid = tree.relid
    WHERE tree.relid <> root.oid
  )
  SELECT string_agg(d.relname, ', ' ORDER BY d.relname) INTO mismatch
  FROM descendants d
  LEFT JOIN steward_expected_rls_policies i ON i.relation_name = d.relname
  WHERE i.relation_name IS NULL;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 partition descendants need explicit policy inventory: %', mismatch;
  END IF;

  -- A new table or partition must be classified before activation. This is the
  -- future-migration gate: tenant data cannot silently appear outside RLS.
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO mismatch
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  LEFT JOIN steward_expected_rls_policies p ON p.relation_name = c.relname
  LEFT JOIN steward_expected_global_relations g ON g.relation_name = c.relname
  WHERE n.nspname = 'public'
    AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND p.relation_name IS NULL
    AND g.relation_name IS NULL;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 unclassified public relations or partitions: %', mismatch;
  END IF;
END
$$;
