CREATE OR REPLACE FUNCTION public.steward_reserved_tenant_kind(p_tenant_id text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN p_tenant_id IS NULL THEN NULL
    WHEN lower(p_tenant_id) IN ('platform', 'system', 'default', 'personal') THEN 'fixed'
    WHEN lower(p_tenant_id) LIKE 'personal-%' THEN 'personal'
    WHEN lower(p_tenant_id) LIKE 'eth:%'
      OR lower(p_tenant_id) LIKE 't-%'
      OR lower(p_tenant_id) LIKE 'solana:%' THEN 'wallet'
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION public.steward_is_reserved_tenant_id(p_tenant_id text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT public.steward_reserved_tenant_kind(p_tenant_id) IS NOT NULL
$$;

-- Platform provisioning is a deliberately narrow global-identity mutation.
-- The restricted platform login has no table privileges; it reaches this
-- migrator-owned implementation only through the bootstrap-owned wrapper.
CREATE OR REPLACE FUNCTION public.steward_platform_provision_user_v1(
  p_email text,
  p_email_verified boolean,
  p_name text,
  p_custom_metadata jsonb
)
RETURNS TABLE (user_id uuid, is_new boolean)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  provisioned_id uuid;
BEGIN
  IF p_email IS NULL OR btrim(p_email) = '' THEN
    RAISE EXCEPTION 'A valid email is required' USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('platform_user_email_' || lower(btrim(p_email)), 0)
  );
  SELECT u.id INTO provisioned_id
  FROM public.users u
  WHERE u.email = lower(btrim(p_email));
  IF provisioned_id IS NOT NULL THEN
    RETURN QUERY SELECT provisioned_id, false;
    RETURN;
  END IF;
  INSERT INTO public.users (email, email_verified, name, custom_metadata)
  VALUES (
    lower(btrim(p_email)),
    COALESCE(p_email_verified, false),
    p_name,
    COALESCE(p_custom_metadata, '{}'::jsonb)
  )
  RETURNING id INTO provisioned_id;
  RETURN QUERY SELECT provisioned_id, true;
END
$$;

REVOKE ALL ON FUNCTION public.steward_platform_provision_user_v1(
  text, boolean, text, jsonb
) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.steward_platform_user_identity_v1(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT jsonb_build_object(
    'userId', u.id,
    'email', u.email,
    'emailVerified', u.email_verified,
    'name', u.name,
    'image', u.image,
    'walletAddress', u.wallet_address,
    'walletChain', u.wallet_chain,
    'customMetadata', COALESCE(u.custom_metadata, '{}'::jsonb),
    'deactivatedAt', u.deactivated_at,
    'createdAt', u.created_at,
    'updatedAt', u.updated_at,
    'tenantIds', COALESCE((
      SELECT jsonb_agg(ut.tenant_id ORDER BY ut.tenant_id)
      FROM public.user_tenants ut WHERE ut.user_id = u.id
    ), '[]'::jsonb),
    'linkedAccounts', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'id', a.id,
        'provider', a.provider,
        'providerAccountId', a.provider_account_id,
        'expiresAt', a.expires_at
      ) ORDER BY a.id)
      FROM public.accounts a WHERE a.user_id = u.id
    ), '[]'::jsonb)
  )
  FROM public.users u
  WHERE u.id = p_user_id
$$;

REVOKE ALL ON FUNCTION public.steward_platform_user_identity_v1(uuid) FROM PUBLIC;

-- Wallet-owned reserved tenants are intentionally joinable only by the user
-- whose persisted wallet identity matches the tenant's persisted owner. The
-- check is database-verifiable and does not trust a route-supplied address.
CREATE OR REPLACE FUNCTION public.steward_is_authoritative_wallet_tenant_owner(
  p_tenant_id text,
  p_user_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(EXISTS (
    SELECT 1
    FROM public.tenants t
    JOIN public.users u ON u.id = p_user_id
    WHERE t.id = p_tenant_id
      AND t.owner_address IS NOT NULL
      AND (
        (
          lower(p_tenant_id) LIKE 'eth:%'
          AND lower(t.owner_address) = substring(lower(p_tenant_id) FROM 5)
          AND lower(u.wallet_chain) = 'ethereum'
          AND lower(u.wallet_address) = lower(t.owner_address)
        )
        OR (
          lower(p_tenant_id) LIKE 'solana:%'
          AND t.owner_address = p_tenant_id
          AND lower(u.wallet_chain) = 'solana'
          AND u.wallet_address = substring(p_tenant_id FROM 8)
        )
        OR (
          lower(p_tenant_id) LIKE 't-%'
          AND (
            (lower(u.wallet_chain) = 'ethereum'
              AND lower(u.wallet_address) = lower(t.owner_address))
            OR (lower(u.wallet_chain) = 'solana'
              AND t.owner_address = 'solana:' || u.wallet_address)
          )
        )
      )
  ), false)
$$;

CREATE OR REPLACE FUNCTION public.steward_is_authoritative_wallet_identity(
  p_tenant_id text,
  p_owner_address text,
  p_wallet_chain text,
  p_wallet_address text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT COALESCE(
    p_owner_address IS NOT NULL AND (
      (lower(p_tenant_id) LIKE 'eth:%'
        AND lower(p_owner_address) = substring(lower(p_tenant_id) FROM 5)
        AND lower(p_wallet_chain) = 'ethereum'
        AND lower(p_wallet_address) = lower(p_owner_address))
      OR (lower(p_tenant_id) LIKE 'solana:%'
        AND p_owner_address = p_tenant_id
        AND lower(p_wallet_chain) = 'solana'
        AND p_wallet_address = substring(p_tenant_id FROM 8))
      OR (lower(p_tenant_id) LIKE 't-%' AND (
        (lower(p_wallet_chain) = 'ethereum'
          AND lower(p_wallet_address) = lower(p_owner_address))
        OR (lower(p_wallet_chain) = 'solana'
          AND p_owner_address = 'solana:' || p_wallet_address)
      ))
    ),
    false
  )
$$;

CREATE OR REPLACE FUNCTION public.steward_guard_wallet_user_identity_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  wallet_tenant record;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('platform_user_account_' || OLD.id::text, 0)
  );
  FOR wallet_tenant IN
    SELECT ut.tenant_id, t.owner_address
    FROM public.user_tenants ut
    JOIN public.tenants t ON t.id = ut.tenant_id
    WHERE ut.user_id = OLD.id
      AND ut.role = 'owner'
      AND public.steward_reserved_tenant_kind(ut.tenant_id) = 'wallet'
    ORDER BY ut.tenant_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('tenant_owner_lifecycle_' || wallet_tenant.tenant_id, 0)
    );
    IF NOT public.steward_is_authoritative_wallet_identity(
      wallet_tenant.tenant_id,
      wallet_tenant.owner_address,
      NEW.wallet_chain,
      NEW.wallet_address
    ) THEN
      RAISE EXCEPTION 'Wallet tenant owner identity is immutable while membership exists'
        USING ERRCODE = '23514';
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;

CREATE TRIGGER users_wallet_identity_authority_guard
BEFORE UPDATE OF wallet_address, wallet_chain ON public.users
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_wallet_user_identity_update();

CREATE OR REPLACE FUNCTION public.steward_guard_wallet_tenant_owner_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  wallet_owner record;
BEGIN
  IF public.steward_reserved_tenant_kind(OLD.id) IS DISTINCT FROM 'wallet' THEN
    RETURN NEW;
  END IF;
  FOR wallet_owner IN
    SELECT ut.user_id, u.wallet_chain, u.wallet_address
    FROM public.user_tenants ut
    JOIN public.users u ON u.id = ut.user_id
    WHERE ut.tenant_id = OLD.id AND ut.role = 'owner'
    ORDER BY ut.user_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('platform_user_account_' || wallet_owner.user_id::text, 0)
    );
  END LOOP;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('tenant_owner_lifecycle_' || OLD.id, 0)
  );
  FOR wallet_owner IN
    SELECT ut.user_id, u.wallet_chain, u.wallet_address
    FROM public.user_tenants ut
    JOIN public.users u ON u.id = ut.user_id
    WHERE ut.tenant_id = OLD.id AND ut.role = 'owner'
    ORDER BY ut.user_id
  LOOP
    IF NOT public.steward_is_authoritative_wallet_identity(
      OLD.id,
      NEW.owner_address,
      wallet_owner.wallet_chain,
      wallet_owner.wallet_address
    ) THEN
      RAISE EXCEPTION 'Wallet tenant owner identity is immutable while membership exists'
        USING ERRCODE = '23514';
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenants_wallet_owner_authority_guard
BEFORE UPDATE OF owner_address ON public.tenants
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_wallet_tenant_owner_update();

ALTER TABLE public.users
  ADD COLUMN tokens_revoked_before bigint NOT NULL DEFAULT -1;

CREATE TABLE public.user_identity_subjects (
  user_id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CONSTRAINT user_identity_subjects_retirement_order_check
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

INSERT INTO public.user_identity_subjects (user_id, created_at)
SELECT id, created_at FROM public.users
ON CONFLICT (user_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.steward_register_user_identity_subject()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  subject_retired_at timestamptz;
BEGIN
  INSERT INTO public.user_identity_subjects (user_id, created_at)
  VALUES (NEW.id, COALESCE(NEW.created_at, now()))
  ON CONFLICT (user_id) DO NOTHING;

  SELECT retired_at INTO subject_retired_at
  FROM public.user_identity_subjects
  WHERE user_id = NEW.id
  FOR UPDATE;
  IF subject_retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'Retired user identity cannot be reused' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION public.steward_register_user_identity_subject() FROM PUBLIC;

CREATE TRIGGER users_identity_subject_guard
BEFORE INSERT ON public.users
FOR EACH ROW EXECUTE FUNCTION public.steward_register_user_identity_subject();

CREATE OR REPLACE FUNCTION public.steward_retire_user_identity_subject()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  UPDATE public.user_identity_subjects AS identity_subject
  SET retired_at = COALESCE(identity_subject.retired_at, now())
  WHERE identity_subject.user_id = OLD.id;
  RETURN OLD;
END
$$;

REVOKE ALL ON FUNCTION public.steward_retire_user_identity_subject() FROM PUBLIC;

CREATE TRIGGER users_identity_subject_retirement
BEFORE DELETE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.steward_retire_user_identity_subject();

ALTER TABLE public.users
  ADD CONSTRAINT users_identity_subject_fk
  FOREIGN KEY (id) REFERENCES public.user_identity_subjects(user_id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION public.steward_lock_personal_lifecycle(
  p_user_id uuid,
  p_tenant_id text,
  p_tenant_delete boolean DEFAULT false
)
RETURNS TABLE (user_exists boolean, tenant_exists boolean)
LANGUAGE plpgsql
AS $$
DECLARE
  owner_tenant record;
BEGIN
  IF p_tenant_id IS DISTINCT FROM 'personal-' || p_user_id::text THEN
    RAISE EXCEPTION 'Personal tenant id does not match canonical owner' USING ERRCODE = '23514';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('platform_user_account_' || p_user_id::text, 0));
  SELECT true INTO user_exists FROM public.users u WHERE u.id = p_user_id FOR UPDATE;
  user_exists := COALESCE(user_exists, false);

  -- Take every owner-lifecycle lock before any tenant row. Membership writers
  -- use the same advisory locks, so the ordered set cannot change underneath
  -- the subsequent sole-owner checks.
  FOR owner_tenant IN
    SELECT tenant_id
    FROM (
      SELECT p_tenant_id AS tenant_id
      UNION
      SELECT ut.tenant_id
      FROM public.user_tenants ut
      WHERE ut.user_id = p_user_id AND ut.role = 'owner'
    ) owned
    ORDER BY tenant_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('tenant_owner_lifecycle_' || owner_tenant.tenant_id, 0)
    );
  END LOOP;
  IF p_tenant_delete THEN
    PERFORM public.steward_lock_tenant_deletion(p_tenant_id);
  END IF;
  SELECT true INTO tenant_exists FROM public.tenants t WHERE t.id = p_tenant_id FOR UPDATE;
  tenant_exists := COALESCE(tenant_exists, false);
  RETURN NEXT;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_platform_personal_tenant_delete_v2(
  p_tenant_id text,
  p_execute boolean DEFAULT false
)
RETURNS TABLE (
  status text,
  agent_ids text[],
  member_ids uuid[],
  active_grants_retired integer,
  terminal_grants_removed integer,
  capabilities_removed integer,
  invocation_evidence_retained integer
)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  owner_id uuid;
  lifecycle record;
  membership_count bigint;
  owner_count bigint;
  invitation_count bigint;
  cross_tenant_capability_grant boolean := false;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  IF p_tenant_id !~ '^personal-[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    status := 'blocked_by_personal_membership';
    RETURN NEXT;
    RETURN;
  END IF;
  owner_id := substring(p_tenant_id FROM 10)::uuid;
  SELECT * INTO lifecycle
  FROM public.steward_lock_personal_lifecycle(owner_id, p_tenant_id, true);
  IF NOT lifecycle.tenant_exists THEN
    status := 'missing';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT count(*), count(*) FILTER (
    WHERE ut.user_id = owner_id AND ut.role = 'owner'
  ) INTO membership_count, owner_count
  FROM public.user_tenants ut WHERE ut.tenant_id = p_tenant_id;
  SELECT count(*) INTO invitation_count
  FROM public.tenant_invitations ti WHERE ti.tenant_id = p_tenant_id;
  IF NOT lifecycle.user_exists OR membership_count <> 1 OR owner_count <> 1
     OR invitation_count <> 0 THEN
    status := 'blocked_by_personal_membership';
    RETURN NEXT;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.upstream_credential_leases lease
    WHERE lease.tenant_id = p_tenant_id AND (
      lease.status NOT IN ('revoked', 'expired', 'failed')
      OR lease.token_hash IS NOT NULL OR lease.token_ciphertext IS NOT NULL
      OR lease.token_iv IS NOT NULL OR lease.token_auth_tag IS NOT NULL
      OR lease.token_salt IS NOT NULL
    )
  ) THEN
    status := 'blocked_by_lease';
    RETURN NEXT;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.intents intent
    WHERE intent.tenant_id = p_tenant_id AND intent.intent_type = 'provider-action'
  ) OR EXISTS (
    SELECT 1 FROM public.provider_action_bindings binding
    WHERE binding.tenant_id = p_tenant_id
  ) THEN
    status := 'blocked_by_provider';
    RETURN NEXT;
    RETURN;
  END IF;

  SELECT COALESCE(array_agg(a.id ORDER BY a.id), ARRAY[]::text[])
  INTO agent_ids FROM public.agents a WHERE a.tenant_id = p_tenant_id;
  SELECT COALESCE(array_agg(ut.user_id ORDER BY ut.user_id), ARRAY[]::uuid[])
  INTO member_ids FROM public.user_tenants ut WHERE ut.tenant_id = p_tenant_id;
  active_grants_retired := 0;
  terminal_grants_removed := 0;
  capabilities_removed := 0;
  invocation_evidence_retained := 0;

  IF to_regclass('public.capability_grants') IS NOT NULL THEN
    EXECUTE $query$
      SELECT
        count(*) FILTER (WHERE status = 'active')::int,
        count(*) FILTER (WHERE status <> 'active')::int
      FROM public.capability_grants WHERE tenant_id = $1
    $query$ INTO active_grants_retired, terminal_grants_removed USING p_tenant_id;
    IF to_regclass('public.capabilities') IS NOT NULL THEN
      EXECUTE $query$
        SELECT EXISTS (
          SELECT 1 FROM public.capability_grants capability_grant
          JOIN public.capabilities capability
            ON capability.id = capability_grant.capability_id
          WHERE capability.tenant_id = $1
            AND capability_grant.tenant_id <> $1
        )
      $query$ INTO cross_tenant_capability_grant USING p_tenant_id;
    END IF;
  END IF;
  IF cross_tenant_capability_grant THEN
    status := 'blocked_by_capability_integrity';
    RETURN NEXT;
    RETURN;
  END IF;
  IF to_regclass('public.capabilities') IS NOT NULL THEN
    EXECUTE 'SELECT count(*)::int FROM public.capabilities WHERE tenant_id = $1'
      INTO capabilities_removed USING p_tenant_id;
  END IF;
  IF to_regclass('public.capability_invocations') IS NOT NULL THEN
    EXECUTE 'SELECT count(*)::int FROM public.capability_invocations WHERE tenant_id = $1'
      INTO invocation_evidence_retained USING p_tenant_id;
  END IF;

  IF NOT p_execute THEN
    status := 'prepared';
    RETURN NEXT;
    RETURN;
  END IF;
  IF to_regclass('public.capability_grants') IS NOT NULL THEN
    EXECUTE 'UPDATE public.capability_grants SET status = ''revoked'' WHERE tenant_id = $1 AND status = ''active'''
      USING p_tenant_id;
    EXECUTE 'DELETE FROM public.capability_grants WHERE tenant_id = $1' USING p_tenant_id;
  END IF;
  IF to_regclass('public.capabilities') IS NOT NULL THEN
    EXECUTE 'DELETE FROM public.capabilities WHERE tenant_id = $1' USING p_tenant_id;
  END IF;
  DELETE FROM public.refresh_tokens token WHERE token.tenant_id = p_tenant_id;
  DELETE FROM public.secret_routes route WHERE route.tenant_id = p_tenant_id;
  DELETE FROM public.secrets secret WHERE secret.tenant_id = p_tenant_id;
  DELETE FROM public.proxy_audit_log log WHERE log.tenant_id = p_tenant_id;
  DELETE FROM public.tenants tenant WHERE tenant.id = p_tenant_id;
  status := 'deleted';
  RETURN NEXT;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_platform_set_user_deactivation_v2(
  p_user_id uuid,
  p_deactivated boolean
)
RETURNS TABLE (
  user_id uuid,
  previous_deactivated_at timestamptz,
  previous_updated_at timestamptz,
  deactivated_at timestamptz,
  tokens_revoked_before bigint
)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  existing public.users%ROWTYPE;
  owner_tenant record;
  updated_deactivated_at timestamptz;
  updated_tokens_revoked_before bigint;
  personal_tenant_id text := 'personal-' || p_user_id::text;
  personal_membership_count bigint;
  personal_owner_count bigint;
  personal_invitation_count bigint;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  PERFORM * FROM public.steward_lock_personal_lifecycle(
    p_user_id, personal_tenant_id, false
  );
  SELECT u.* INTO existing FROM public.users u WHERE u.id = p_user_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

  IF p_deactivated THEN
    PERFORM 1 FROM public.tenants t WHERE t.id = personal_tenant_id;
    IF FOUND THEN
      SELECT count(*), count(*) FILTER (
        WHERE ut.user_id = p_user_id AND ut.role = 'owner'
      )
      INTO personal_membership_count, personal_owner_count
      FROM public.user_tenants ut WHERE ut.tenant_id = personal_tenant_id;
      SELECT count(*) INTO personal_invitation_count
      FROM public.tenant_invitations ti WHERE ti.tenant_id = personal_tenant_id;
      IF personal_membership_count <> 1 OR personal_owner_count <> 1
         OR personal_invitation_count <> 0 THEN
        RAISE EXCEPTION 'Personal tenant membership invariant violated';
      END IF;
    END IF;

    FOR owner_tenant IN
      SELECT ut.tenant_id FROM public.user_tenants ut
      WHERE ut.user_id = p_user_id AND ut.role = 'owner' ORDER BY ut.tenant_id
    LOOP
      IF owner_tenant.tenant_id = personal_tenant_id THEN CONTINUE; END IF;
      IF NOT EXISTS (
        SELECT 1 FROM public.user_tenants other
        JOIN public.users u ON u.id = other.user_id
        WHERE other.tenant_id = owner_tenant.tenant_id
          AND other.role = 'owner' AND other.user_id <> p_user_id
          AND u.deactivated_at IS NULL
      ) THEN
        RAISE EXCEPTION 'Cannot deactivate the sole active tenant owner';
      END IF;
    END LOOP;
  END IF;

  UPDATE public.users u
  SET deactivated_at = CASE WHEN p_deactivated THEN now() ELSE NULL END,
      tokens_revoked_before = GREATEST(
        u.tokens_revoked_before,
        floor(extract(epoch FROM clock_timestamp()))::bigint
      ),
      updated_at = now()
  WHERE u.id = p_user_id
  RETURNING u.deactivated_at, u.tokens_revoked_before
  INTO updated_deactivated_at, updated_tokens_revoked_before;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  RETURN QUERY SELECT
    existing.id, existing.deactivated_at, existing.updated_at,
    updated_deactivated_at, updated_tokens_revoked_before;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_user_token_revocation_subject_v1(p_user_id uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT u.tokens_revoked_before FROM public.users u WHERE u.id = p_user_id
$$;

CREATE OR REPLACE FUNCTION public.steward_platform_delete_user_v2(p_user_id uuid)
RETURNS TABLE (user_id uuid)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  owner_tenant record;
  personal_tenant_id text := 'personal-' || p_user_id::text;
  personal_membership_count bigint;
  personal_owner_count bigint;
  personal_invitation_count bigint;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  PERFORM * FROM public.steward_lock_personal_lifecycle(
    p_user_id, personal_tenant_id, false
  );
  PERFORM 1 FROM public.users u WHERE u.id = p_user_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

  PERFORM 1 FROM public.tenants t WHERE t.id = personal_tenant_id;
  IF FOUND THEN
    SELECT count(*), count(*) FILTER (
      WHERE ut.user_id = p_user_id AND ut.role = 'owner'
    )
    INTO personal_membership_count, personal_owner_count
    FROM public.user_tenants ut WHERE ut.tenant_id = personal_tenant_id;
    SELECT count(*) INTO personal_invitation_count
    FROM public.tenant_invitations ti WHERE ti.tenant_id = personal_tenant_id;
    IF personal_membership_count <> 1 OR personal_owner_count <> 1
       OR personal_invitation_count <> 0 THEN
      RAISE EXCEPTION 'Personal tenant membership invariant violated';
    END IF;
    RAISE EXCEPTION 'Personal tenant must be deleted before its user identity';
  END IF;

  FOR owner_tenant IN
    SELECT ut.tenant_id FROM public.user_tenants ut
    WHERE ut.user_id = p_user_id AND ut.role = 'owner' ORDER BY ut.tenant_id
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM public.user_tenants other
      JOIN public.users u ON u.id = other.user_id
      WHERE other.tenant_id = owner_tenant.tenant_id
        AND other.role = 'owner' AND other.user_id <> p_user_id
        AND u.deactivated_at IS NULL
    ) THEN
      RAISE EXCEPTION 'Cannot delete the sole active tenant owner';
    END IF;
  END LOOP;

  INSERT INTO public.retained_user_provider_evidence (
    account_id, deleted_user_id, provider, provider_account_id
  )
  SELECT a.id, a.user_id, a.provider, a.provider_account_id
  FROM public.accounts a WHERE a.user_id = p_user_id
  ON CONFLICT (account_id) DO NOTHING;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  DELETE FROM public.users u WHERE u.id = p_user_id;
  RETURN QUERY SELECT p_user_id;
END
$$;

REVOKE ALL ON FUNCTION public.steward_lock_personal_lifecycle(uuid, text, boolean)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_platform_personal_tenant_delete_v2(text, boolean)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_platform_set_user_deactivation_v2(uuid, boolean)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_user_token_revocation_subject_v1(uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_platform_delete_user_v2(uuid)
FROM PUBLIC;

-- Preserve deleted-tenant revocation jobs in the retained audit chain. The
-- bootstrap wrapper may enumerate a deleted tenant id until its idempotent
-- cache-revocation completion marker is committed under the same chain.
CREATE OR REPLACE FUNCTION public.steward_internal_job_tenant_ids_v2()
RETURNS TABLE (tenant_id varchar(64))
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT jobs.tenant_id
  FROM (
    SELECT t.id AS tenant_id FROM public.tenants t
    WHERE t.id NOT IN ('system', 'platform')
    UNION
    SELECT source.tenant_id
    FROM public.audit_events source
    WHERE source.action = 'tenant.delete'
      AND source.metadata ? 'revocationJobId'
      AND NOT EXISTS (
        SELECT 1 FROM public.audit_events completion
        WHERE completion.tenant_id = source.tenant_id
          AND completion.action = 'tenant.delete.token_revocation_completed'
          AND completion.metadata->>'revocationJobId' = source.metadata->>'revocationJobId'
      )
  ) jobs
  ORDER BY jobs.tenant_id
$$;
REVOKE ALL ON FUNCTION public.steward_internal_job_tenant_ids_v2() FROM PUBLIC;

-- PGLite has no operator role-split lane. It may refresh the tiny wrappers only
-- when its current migration identity already owns them. On a split production
-- database this branch is false; the admin script is the sole replacement path.
DO $$
DECLARE
  deactivation_owner name;
  deletion_owner name;
  personal_tenant_deletion_owner name;
BEGIN
  SELECT pg_get_userbyid(p.proowner) INTO deactivation_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap'
    AND p.proname = 'platform_set_user_deactivation'
    AND oidvectortypes(p.proargtypes) = 'uuid, boolean';
  SELECT pg_get_userbyid(p.proowner) INTO deletion_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap'
    AND p.proname = 'platform_delete_user'
    AND oidvectortypes(p.proargtypes) = 'uuid';
  SELECT pg_get_userbyid(p.proowner) INTO personal_tenant_deletion_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap'
    AND p.proname = 'platform_personal_tenant_delete'
    AND oidvectortypes(p.proargtypes) = 'text, boolean';

  IF deactivation_owner = current_user AND deletion_owner = current_user
     AND (personal_tenant_deletion_owner = current_user
          OR personal_tenant_deletion_owner IS NULL) THEN
    EXECUTE 'DROP FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid, boolean)';
    EXECUTE $ddl$
      CREATE FUNCTION steward_bootstrap.platform_set_user_deactivation(
        p_user_id uuid, p_deactivated boolean
      )
      RETURNS TABLE (
        user_id uuid, previous_deactivated_at timestamptz,
        previous_updated_at timestamptz, deactivated_at timestamptz,
        tokens_revoked_before bigint
      )
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_set_user_deactivation_v2(p_user_id, p_deactivated); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.user_token_revocation_subject(p_user_id uuid)
      RETURNS bigint
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN public.steward_user_token_revocation_subject_v1(p_user_id); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.tenant_ids_for_internal_job()
      RETURNS TABLE (tenant_id varchar(64))
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_internal_job_tenant_ids_v2(); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.ensure_default_membership(
        p_user_id uuid, p_role text
      )
      RETURNS void
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN
        PERFORM set_config(''steward.lifecycle_wrapper'', ''v1'', true);
        IF NULLIF(current_setting(''steward.tenant_id'', true), '''') IS DISTINCT FROM ''default''
           OR NULLIF(current_setting(''steward.user_id'', true), '''') IS DISTINCT FROM p_user_id::text
           OR p_role NOT IN (''member'', ''guest'') THEN
          RAISE EXCEPTION ''default membership authority denied'' USING ERRCODE = ''42501'';
        END IF;
        INSERT INTO public.user_tenants (user_id, tenant_id, role)
        VALUES (p_user_id, ''default'', p_role)
        ON CONFLICT (user_id, tenant_id) DO NOTHING;
        PERFORM set_config(''steward.lifecycle_wrapper'', '''', true);
      END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.platform_delete_user(p_user_id uuid)
      RETURNS TABLE (user_id uuid)
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN PERFORM set_config(''steward.lifecycle_wrapper'', ''v1'', true); RETURN QUERY SELECT * FROM public.steward_platform_delete_user_v2(p_user_id); PERFORM set_config(''steward.lifecycle_wrapper'', '''', true); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.platform_personal_tenant_delete(
        p_tenant_id text, p_execute boolean DEFAULT false
      )
      RETURNS TABLE (
        status text, agent_ids text[], member_ids uuid[],
        active_grants_retired integer, terminal_grants_removed integer,
        capabilities_removed integer, invocation_evidence_retained integer
      )
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN PERFORM set_config(''steward.lifecycle_wrapper'', ''v1'', true); RETURN QUERY SELECT * FROM public.steward_platform_personal_tenant_delete_v2(p_tenant_id, p_execute); PERFORM set_config(''steward.lifecycle_wrapper'', '''', true); END'
    $ddl$;
  END IF;
END
$$;

-- Earlier lifecycle wrappers predated the scoped authority marker. Clear any
-- transaction-local value inherited while upgrading before ordinary callers
-- can exercise the guards below.
SELECT set_config('steward.lifecycle_wrapper', '', true);

-- Triggers are prospective. Refuse to bless legacy rows that already violate
-- the reserved-namespace invariant; silently carrying them forward would leave
-- an authorization grant that no post-upgrade writer could create or repair.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.user_tenants membership
    WHERE CASE public.steward_reserved_tenant_kind(membership.tenant_id)
      WHEN 'fixed' THEN NOT (
        lower(membership.tenant_id) = 'default'
        AND membership.role IN ('member', 'guest')
      )
      WHEN 'personal' THEN membership.tenant_id IS DISTINCT FROM
        'personal-' || membership.user_id::text OR membership.role IS DISTINCT FROM 'owner'
      WHEN 'wallet' THEN membership.role IS DISTINCT FROM 'owner'
        OR NOT public.steward_is_authoritative_wallet_tenant_owner(
          membership.tenant_id, membership.user_id
        )
      ELSE false
    END
  ) THEN
    RAISE EXCEPTION 'Legacy reserved tenant membership violates authoritative invariant'
      USING ERRCODE = '23514';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_invitations invitation
    WHERE public.steward_is_reserved_tenant_id(invitation.tenant_id)
  ) THEN
    RAISE EXCEPTION 'Legacy reserved tenant invitation violates authoritative invariant'
      USING ERRCODE = '23514';
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_guard_personal_membership_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  reserved_kind text;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('platform_user_account_' || NEW.user_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('tenant_owner_lifecycle_' || NEW.tenant_id, 0)
  );
  IF TG_OP = 'UPDATE'
    AND public.steward_is_reserved_tenant_id(OLD.tenant_id)
    AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.user_id IS DISTINCT FROM OLD.user_id
    OR NEW.role IS DISTINCT FROM OLD.role
  ) THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  reserved_kind := public.steward_reserved_tenant_kind(NEW.tenant_id);
  IF NEW.role = 'owner' AND NOT EXISTS (
    SELECT 1 FROM public.users u
    WHERE u.id = NEW.user_id AND u.deactivated_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Inactive user cannot own a tenant' USING ERRCODE = '23514';
  END IF;
  IF reserved_kind = 'fixed' AND NOT COALESCE((
    lower(NEW.tenant_id) = 'default'
    AND NEW.role IN ('member', 'guest')
    AND NEW.user_id::text = NULLIF(current_setting('steward.user_id', true), '')
    AND NULLIF(current_setting('steward.lifecycle_wrapper', true), '') = 'v1'
    AND current_user = COALESCE(
      (
        SELECT pg_get_userbyid(p.proowner)
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'steward_bootstrap'
          AND p.proname = 'ensure_default_membership'
          AND oidvectortypes(p.proargtypes) = 'uuid, text'
      ),
      ''
    )
  ), false) THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  ELSIF reserved_kind = 'personal' THEN
    IF NEW.tenant_id IS DISTINCT FROM 'personal-' || NEW.user_id::text
      OR NEW.role IS DISTINCT FROM 'owner' THEN
      RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
    END IF;
  ELSIF reserved_kind = 'wallet' THEN
    IF NEW.role IS DISTINCT FROM 'owner'
      OR NOT public.steward_is_authoritative_wallet_tenant_owner(NEW.tenant_id, NEW.user_id) THEN
      RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER user_tenants_personal_authority_guard
BEFORE INSERT OR UPDATE OF tenant_id, user_id, role ON public.user_tenants
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_membership_write();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_membership_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended('platform_user_account_' || OLD.user_id::text, 0)
  );
  PERFORM pg_advisory_xact_lock(
    hashtextextended('tenant_owner_lifecycle_' || OLD.tenant_id, 0)
  );
  IF public.steward_is_reserved_tenant_id(OLD.tenant_id)
    AND NOT COALESCE((
      current_user = COALESCE(
        (
          SELECT pg_get_userbyid(p.proowner)
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'steward_bootstrap'
            AND p.proname = 'ensure_default_membership'
            AND oidvectortypes(p.proargtypes) = 'uuid, text'
        ),
        ''
      )
      AND NULLIF(current_setting('steward.lifecycle_wrapper', true), '') = 'v1'
      AND (
        NULLIF(current_setting('steward.tenant_id', true), '') = 'platform'
        OR (
          lower(OLD.tenant_id) = 'default'
          AND OLD.role IN ('member', 'guest')
          AND OLD.user_id::text = NULLIF(current_setting('steward.user_id', true), '')
        )
      )
    ), false)
    AND EXISTS (
    SELECT 1 FROM public.tenants t WHERE t.id = OLD.tenant_id
  ) THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END
$$;

REVOKE ALL ON FUNCTION public.steward_guard_personal_membership_delete()
FROM PUBLIC;

CREATE TRIGGER user_tenants_personal_authority_delete_guard
BEFORE DELETE ON public.user_tenants
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_membership_delete();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_invitation_write()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF public.steward_is_reserved_tenant_id(NEW.tenant_id) THEN
    RAISE EXCEPTION 'Reserved tenant invitations are forbidden' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenant_invitations_personal_authority_guard
BEFORE INSERT OR UPDATE OF tenant_id ON public.tenant_invitations
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_invitation_write();

CREATE TABLE public.retained_user_provider_evidence (
  account_id uuid PRIMARY KEY,
  deleted_user_id uuid NOT NULL,
  provider varchar(64) NOT NULL,
  provider_account_id varchar(255) NOT NULL,
  retained_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX retained_user_provider_evidence_identity_idx
ON public.retained_user_provider_evidence (deleted_user_id, provider, provider_account_id);
ALTER TABLE public.retained_user_provider_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.retained_user_provider_evidence FORCE ROW LEVEL SECURITY;

-- Preserve immutable actor UUIDs while detaching the FKs that otherwise make
-- compliant identity deletion permanently impossible.
DO $$
DECLARE
  target record;
BEGIN
  FOR target IN
    SELECT c.conrelid::regclass AS relation_name, c.conname
    FROM pg_constraint c
    WHERE c.contype = 'f'
      AND c.confrelid = 'public.users'::regclass
      AND c.conrelid IN (
        'public.workspaces'::regclass,
        'public.provider_role_bindings'::regclass,
        'public.provider_grants'::regclass
      )
      AND EXISTS (
        SELECT 1
        FROM unnest(c.conkey) AS key_column(attnum)
        JOIN pg_attribute a
          ON a.attrelid = c.conrelid AND a.attnum = key_column.attnum
        WHERE a.attname IN ('created_by', 'granted_by_user_id', 'revoked_by_user_id')
      )
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', target.relation_name, target.conname);
  END LOOP;
END
$$;

-- Rebind durable actor provenance to the non-reusable identity registry. This
-- permits deletion of the mutable users row while rejecting invented actor
-- UUIDs from direct writers and retaining historical attribution forever.
ALTER TABLE public.workspaces
  ADD CONSTRAINT workspaces_created_by_identity_subject_fk
  FOREIGN KEY (created_by) REFERENCES public.user_identity_subjects(user_id)
  ON DELETE RESTRICT NOT VALID;
ALTER TABLE public.provider_role_bindings
  ADD CONSTRAINT provider_role_bindings_granted_by_identity_subject_fk
  FOREIGN KEY (granted_by_user_id) REFERENCES public.user_identity_subjects(user_id)
  ON DELETE RESTRICT NOT VALID;
ALTER TABLE public.provider_grants
  ADD CONSTRAINT provider_grants_granted_by_identity_subject_fk
  FOREIGN KEY (granted_by_user_id) REFERENCES public.user_identity_subjects(user_id)
  ON DELETE RESTRICT NOT VALID;
ALTER TABLE public.provider_grants
  ADD CONSTRAINT provider_grants_revoked_by_identity_subject_fk
  FOREIGN KEY (revoked_by_user_id) REFERENCES public.user_identity_subjects(user_id)
  ON DELETE RESTRICT NOT VALID;

ALTER TABLE public.workspaces
  VALIDATE CONSTRAINT workspaces_created_by_identity_subject_fk;
ALTER TABLE public.provider_role_bindings
  VALIDATE CONSTRAINT provider_role_bindings_granted_by_identity_subject_fk;
ALTER TABLE public.provider_grants
  VALIDATE CONSTRAINT provider_grants_granted_by_identity_subject_fk;
ALTER TABLE public.provider_grants
  VALIDATE CONSTRAINT provider_grants_revoked_by_identity_subject_fk;
