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
SECURITY DEFINER
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
  deactivated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  existing public.users%ROWTYPE;
  owner_tenant record;
  updated_deactivated_at timestamptz;
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
      updated_at = now()
  WHERE u.id = p_user_id
  RETURNING u.deactivated_at INTO updated_deactivated_at;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  RETURN QUERY SELECT
    existing.id, existing.deactivated_at, existing.updated_at, updated_deactivated_at;
END
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
REVOKE ALL ON FUNCTION public.steward_platform_delete_user_v2(uuid)
FROM PUBLIC;

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
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.platform_set_user_deactivation(
        p_user_id uuid, p_deactivated boolean
      )
      RETURNS TABLE (
        user_id uuid, previous_deactivated_at timestamptz,
        previous_updated_at timestamptz, deactivated_at timestamptz
      )
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_set_user_deactivation_v2(p_user_id, p_deactivated); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.platform_delete_user(p_user_id uuid)
      RETURNS TABLE (user_id uuid)
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_delete_user_v2(p_user_id); END'
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
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_personal_tenant_delete_v2(p_tenant_id, p_execute); END'
    $ddl$;
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_guard_personal_membership_write()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.tenant_id LIKE 'personal-%' AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.user_id IS DISTINCT FROM OLD.user_id
    OR NEW.role IS DISTINCT FROM 'owner'
  ) THEN
    RAISE EXCEPTION 'Personal tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  IF NEW.tenant_id LIKE 'personal-%' AND (
    NEW.tenant_id IS DISTINCT FROM 'personal-' || NEW.user_id::text
    OR NEW.role IS DISTINCT FROM 'owner'
  ) THEN
    RAISE EXCEPTION 'Personal tenant membership is immutable' USING ERRCODE = '23514';
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
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  IF OLD.tenant_id LIKE 'personal-%' AND EXISTS (
    SELECT 1 FROM public.tenants t WHERE t.id = OLD.tenant_id
  ) THEN
    RAISE EXCEPTION 'Personal tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END
$$;

CREATE CONSTRAINT TRIGGER user_tenants_personal_authority_delete_guard
AFTER DELETE ON public.user_tenants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_membership_delete();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_invitation_write()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.tenant_id LIKE 'personal-%' THEN
    RAISE EXCEPTION 'Personal tenant invitations are forbidden' USING ERRCODE = '23514';
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
